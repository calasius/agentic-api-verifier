from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import httpx
import typer
from common import DEFAULT_TARGET_URL, FINDINGS_DIR, ROOT, timestamp
from models import FindingSet, VerificationSet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(help="Run the end-to-end Strike demo.")
console = Console()


def load_function(script_name: str, function_name: str):
    path = Path(__file__).with_name(script_name)
    spec = importlib.util.spec_from_file_location(script_name.removesuffix(".py"), path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Could not load {script_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, function_name)


def pause(enabled: bool) -> None:
    if enabled:
        input("Press Enter to continue...")


def check_target(target_url: str, from_cache: bool) -> str:
    if from_cache:
        return "cache mode: skipped live crAPI health check"
    try:
        response = httpx.get(target_url, timeout=5)
        return f"HTTP {response.status_code} from {target_url}"
    except httpx.HTTPError as exc:
        return f"UNREACHABLE: {exc}"


def preflight(target_url: str, from_cache: bool, runtime: str, image: str) -> bool:
    if from_cache:
        return True

    ok = True
    crapi_dir = ROOT / "crAPI"
    if not crapi_dir.exists():
        console.print("[red]Missing crAPI source:[/] ./crAPI")
        console.print("Run: git clone https://github.com/OWASP/crAPI.git")
        ok = False

    if not shutil.which("codex"):
        console.print("[red]Missing Codex CLI:[/] codex is not in PATH")
        ok = False

    runtime_path = shutil.which(runtime)
    if not runtime_path:
        console.print(f"[red]Missing container runtime:[/] {runtime} is not in PATH")
        ok = False
    else:
        # Keep the image check non-fatal because the first live run may build it
        # immediately before executing the demo.
        console.print(f"Container runtime: {runtime_path}")
        console.print(f"PoC runner image expected: {image}")

    health = check_target(target_url, from_cache=False)
    console.print(f"Target check: {health}")
    if health.startswith("UNREACHABLE"):
        console.print(
            "[red]crAPI is not reachable.[/] Start it with Podman Compose before live mode."
        )
        console.print(
            "Run: cd crAPI/deploy/docker && "
            "podman compose -f docker-compose.yml --compatibility up -d"
        )
        ok = False

    return ok


def print_candidates(finding_set: FindingSet) -> None:
    table = Table(title="Candidate Findings")
    table.add_column("ID")
    table.add_column("Type")
    table.add_column("File")
    table.add_column("Confidence", justify="right")
    for finding in finding_set.findings:
        table.add_row(
            finding.id,
            finding.vulnerability_type,
            f"{finding.file}:{finding.line or '?'}",
            f"{finding.confidence_initial:.2f}",
        )
    console.print(table)


def print_verification(verification_set: VerificationSet) -> None:
    for finding in verification_set.findings:
        poc_preview = finding.poc_used[:700]
        if len(finding.poc_used) > len(poc_preview):
            poc_preview += "\n..."
        console.print(
            Panel(
                "\n".join(
                    [
                        f"Hypothesis: {finding.hypothesis}",
                        f"Generated PoC:\n{poc_preview}",
                        f"Success criterion: {finding.success_criterion}",
                        f"Sandbox exit: {finding.sandbox_execution.exit_code}",
                        f"Verdict: {finding.status}",
                        f"Evidence: {finding.evidence}",
                    ]
                ),
                title=f"{finding.id} - {finding.vulnerability_type}",
            )
        )


def print_summary(verification_set: VerificationSet) -> dict[str, int]:
    counts = {"CONFIRMED": 0, "FAILED": 0, "UNCLEAR": 0}
    table = Table(title="Final Summary")
    table.add_column("ID")
    table.add_column("Status")
    table.add_column("Confidence", justify="right")
    table.add_column("Human Review")
    for finding in verification_set.findings:
        counts[finding.status.value] += 1
        table.add_row(
            finding.id,
            finding.status.value,
            f"{finding.confidence:.2f}",
            "yes" if finding.needs_human_review else "no",
        )
    console.print(table)
    console.print(
        f"Metrics: {counts['CONFIRMED']} confirmed, "
        f"{counts['UNCLEAR']} unclear, {counts['FAILED']} failed."
    )
    return counts


@app.command()
def main(
    service: str = "identity",
    max_findings: int = 3,
    target_url: str = DEFAULT_TARGET_URL,
    from_cache: bool = False,
    no_pause: bool = False,
    model: str = "gpt-5.5",
    runtime: str = "podman",
    image: str = "strike-demo/poc-runner:latest",
) -> None:
    pause_enabled = not no_pause
    run_record: dict[str, object] = {
        "service": service,
        "target_url": target_url,
        "from_cache": from_cache,
    }

    console.print(
        Panel(
            "Auto-verification demo: detect candidate API findings, run PoCs in a Podman sandbox, "
            "and return CONFIRMED / FAILED / UNCLEAR for human triage.",
            title="Strike Demo",
        )
    )
    pause(pause_enabled)

    if not preflight(target_url=target_url, from_cache=from_cache, runtime=runtime, image=image):
        raise typer.Exit(1)

    health = check_target(target_url, from_cache)
    console.print(f"Target check: {health}")
    run_record["target_check"] = health
    pause(pause_enabled)

    detect = load_function("01_detect.py", "detect")
    candidates_path = detect(
        service=service,
        max_findings=max_findings,
        model=model,
        from_cache=from_cache,
    )
    finding_set = FindingSet.model_validate_json(candidates_path.read_text())
    print_candidates(finding_set)
    run_record["candidates_path"] = str(candidates_path)
    pause(pause_enabled)

    verify = load_function("02_verify.py", "verify")
    verified_path = verify(
        input_path=candidates_path,
        target_url=target_url,
        max_findings=max_findings,
        from_cache=from_cache,
        model=model,
        image=image,
        runtime=runtime,
    )
    verification_set = VerificationSet.model_validate_json(verified_path.read_text())
    print_verification(verification_set)
    pause(pause_enabled)

    metrics = print_summary(verification_set)
    run_record["verified_path"] = str(verified_path)
    run_record["metrics"] = metrics
    run_record["findings"] = json.loads(verification_set.model_dump_json())["findings"]

    output = FINDINGS_DIR / f"demo-run-{timestamp()}.json"
    output.write_text(json.dumps(run_record, indent=2) + "\n")
    console.print(f"Run record: {output}")


if __name__ == "__main__":
    app()
