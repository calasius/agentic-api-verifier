from __future__ import annotations

import json
import re
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


def timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


def write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


def copy_latest(source: Path, latest_name: str) -> None:
    latest_path = source.parent / latest_name
    latest_path.write_text(source.read_text())


def require_binary(name: str) -> str:
    binary = shutil.which(name)
    if not binary:
        raise DemoError(f"`{name}` is not available in PATH.")
    return binary


def extract_json_object(output: str) -> dict[str, Any]:
    output = output.strip()
    if not output:
        raise DemoError("Command returned empty output.")

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        pass

    # Codex --json may emit JSONL events. Prefer the last event that has a useful
    # textual payload, then parse the first object inside it.
    for line in reversed(output.splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        text = event.get("content") or event.get("message") or event.get("text")
        if isinstance(text, str):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                match = re.search(r"\{.*\}", text, flags=re.DOTALL)
                if match:
                    return json.loads(match.group(0))
        if isinstance(event, dict) and "findings" in event:
            return event

    match = re.search(r"\{.*\}", output, flags=re.DOTALL)
    if match:
        return json.loads(match.group(0))

    raise DemoError("Could not parse JSON from command output.")


def run_checked(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
