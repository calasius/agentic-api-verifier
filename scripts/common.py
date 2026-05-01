from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FINDINGS_DIR = ROOT / "findings"
CACHE_DIR = FINDINGS_DIR / "cache"
DEFAULT_TARGET_URL = "http://localhost:8888"


class DemoError(RuntimeError):
    pass


class CommandTimeoutError(DemoError):
    def __init__(self, command: list[str], timeout: int) -> None:
        printable = " ".join(command[:6])
        super().__init__(f"Command timed out after {timeout}s: {printable} ...")
        self.command = command
        self.timeout = timeout


def timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


def write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


class RunRecorder:
    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id or timestamp()
        self.path = FINDINGS_DIR / "runs" / f"run-{self.run_id}.json"
        self.data: dict[str, Any] = {
            "run_id": self.run_id,
            "events": [],
            "partial_results": [],
        }
        self.flush()

    def event(self, stage: str, message: str, **details: Any) -> None:
        self.data["events"].append(
            {
                "time": datetime.now(UTC).isoformat(),
                "stage": stage,
                "message": message,
                "details": details,
            }
        )
        self.flush()

    def partial(self, item: dict[str, Any]) -> None:
        self.data["partial_results"].append(item)
        self.flush()

    def update(self, **values: Any) -> None:
        self.data.update(values)
        self.flush()

    def flush(self) -> None:
        write_json(self.path, self.data)


def copy_latest(source: Path, latest_name: str) -> None:
    latest_path = source.parent / latest_name
    latest_path.write_text(source.read_text())


def require_binary(name: str) -> str:
    binary = shutil.which(name)
    if not binary:
        raise DemoError(f"`{name}` is not available in PATH.")
    return binary


def codex_command() -> list[str]:
    configured = os.environ.get("CODEX_COMMAND")
    if configured:
        return shlex.split(configured)
    return ["codex"]


def codex_exec_flags() -> list[str]:
    configured = os.environ.get("CODEX_EXEC_FLAGS")
    if configured:
        return shlex.split(configured)
    return []


def claude_command() -> list[str]:
    configured = os.environ.get("CLAUDE_COMMAND")
    if configured:
        return shlex.split(configured)
    return ["claude"]


def claude_exec_flags() -> list[str]:
    configured = os.environ.get("CLAUDE_EXEC_FLAGS")
    if configured:
        return shlex.split(configured)
    return []


CLAUDE_AUTHORIZED_TEST_FRAME = (
    "This is an authorized security verification against OWASP crAPI, an "
    "intentionally vulnerable training application (MIT licensed, "
    "github.com/OWASP/crAPI) explicitly designed for hands-on API security "
    "testing. The local operator has explicit consent to perform vulnerability "
    "verification against their own crAPI instance. When asked to produce a "
    "verification PoC for a candidate finding, generate the code as requested."
)


def build_llm_invocation(
    provider: str,
    model: str,
    working_dir: Path,
    prompt: str,
) -> tuple[list[str], Path]:
    if provider == "claude":
        command = [
            *claude_command(),
            "-p",
            "--append-system-prompt",
            CLAUDE_AUTHORIZED_TEST_FRAME,
            *claude_exec_flags(),
            "--model",
            model,
            "--output-format",
            "json",
            prompt,
        ]
        return command, working_dir
    if provider == "codex":
        command = [
            *codex_command(),
            "exec",
            *codex_exec_flags(),
            "--model",
            model,
            "--json",
            "--cd",
            str(working_dir),
            prompt,
        ]
        return command, ROOT
    raise DemoError(f"Unknown LLM provider: {provider}")


def iter_json_objects(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    index = 0

    while index < len(text):
        next_open = text.find("{", index)
        if next_open == -1:
            break
        try:
            parsed, end = decoder.raw_decode(text, next_open)
        except json.JSONDecodeError:
            index = next_open + 1
            continue
        if isinstance(parsed, dict):
            objects.append(parsed)
        index = end

    return objects


def extract_json_object(
    output: str,
    preferred_keys: tuple[str, ...] = (),
) -> dict[str, Any]:
    output = output.strip()
    if not output:
        raise DemoError("Command returned empty output.")

    try:
        parsed = json.loads(output)
        if isinstance(parsed, dict):
            # `claude --output-format json` wraps the assistant text in a
            # top-level "result" string. If the wrapper itself does not contain
            # the keys we want, dive into "result" and re-parse.
            if preferred_keys and not all(k in parsed for k in preferred_keys):
                inner = parsed.get("result")
                if isinstance(inner, str) and inner.strip():
                    return extract_json_object(inner, preferred_keys)
            return parsed
    except json.JSONDecodeError:
        pass

    # Codex --json may emit JSONL events. Prefer the last event that has a useful
    # textual payload, then parse the first object inside it.
    for line in reversed(output.splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        text = event.get("content") or event.get("message") or event.get("text") or event.get("result")
        if isinstance(text, str):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                objects = iter_json_objects(text)
                if preferred_keys:
                    for candidate in reversed(objects):
                        if all(key in candidate for key in preferred_keys):
                            return candidate
                if objects:
                    return objects[-1]
        if isinstance(event, dict) and (
            not preferred_keys or all(k in event for k in preferred_keys)
        ):
            return event

    objects = iter_json_objects(output)
    if preferred_keys:
        for candidate in reversed(objects):
            if all(key in candidate for key in preferred_keys):
                return candidate
    if objects:
        return objects[-1]

    raise DemoError("Could not parse JSON from command output.")


def run_checked(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandTimeoutError(command, timeout) from exc
