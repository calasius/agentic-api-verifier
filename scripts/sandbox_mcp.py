from __future__ import annotations

import subprocess
import tempfile
import uuid
from pathlib import Path

import typer
from common import DemoError, require_binary, write_json
from models import SandboxExecution

app = typer.Typer(help="Execute PoC code in an isolated Podman runner.")


def execute_in_sandbox(
    poc_code: str,
    target_url: str,
    timeout: int = 20,
    image: str = "strike-demo/poc-runner:latest",
    runtime: str = "podman",
) -> SandboxExecution:
    runtime_path = require_binary(runtime)
    with tempfile.TemporaryDirectory(prefix="strike-demo-poc-") as tmp:
        poc_path = Path(tmp) / "poc.py"
        poc_path.write_text(poc_code)

        container_name = f"strike-poc-{uuid.uuid4().hex[:10]}"
        command = [
            runtime_path,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "host",
            "--read-only",
            "--memory",
            "512m",
            "--pids-limit",
            "128",
            "-e",
            f"TARGET_URL={target_url}",
            "-v",
            f"{poc_path}:/workspace/poc.py:ro,Z",
            image,
            "python",
            "/workspace/poc.py",
        ]

        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            return SandboxExecution(
                command=command,
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxExecution(
                command=command,
                stdout=exc.stdout or "",
                stderr=exc.stderr or f"Timed out after {timeout}s",
                exit_code=None,
                timed_out=True,
            )


@app.command()
def run(
    poc_file: Path,
    target_url: str = "http://localhost:8888",
    timeout: int = 20,
    image: str = "strike-demo/poc-runner:latest",
    runtime: str = "podman",
    output: Path | None = None,
) -> None:
    """Run a Python PoC file in the sandbox and print JSON evidence."""
    if not poc_file.exists():
        raise typer.BadParameter(f"{poc_file} does not exist")

    try:
        result = execute_in_sandbox(
            poc_file.read_text(),
            target_url=target_url,
            timeout=timeout,
            image=image,
            runtime=runtime,
        )
    except DemoError as exc:
        raise typer.Exit(str(exc)) from exc

    payload = result.model_dump(mode="json")
    if output:
        write_json(output, payload)
    typer.echo(result.model_dump_json(indent=2))


if __name__ == "__main__":
    app()
