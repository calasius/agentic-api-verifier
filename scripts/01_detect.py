from __future__ import annotations

from pathlib import Path

import typer
from common import (
    CACHE_DIR,
    FINDINGS_DIR,
    ROOT,
    copy_latest,
    extract_json_object,
    run_checked,
    timestamp,
)
from models import FindingSet
from rich.console import Console

app = typer.Typer(help="Detect candidate API vulnerabilities with Codex.")
console = Console()


def detection_prompt(service: str, max_findings: int) -> str:
    return f"""
Scan services/{service} for OWASP API Top 10 vulnerabilities.

Return only JSON with this shape:
{{
  "target": "crAPI",
  "service": "{service}",
  "source": "codex",
  "findings": [
    {{
      "id": "f-001",
      "service": "{service}",
      "file": "services/{service}/...",
      "line": 123,
      "vulnerability_type": "BOLA",
      "owasp_api_category": "API1:2023",
      "hypothesis": "Concrete source-to-sink hypothesis.",
      "confidence_initial": 0.8
    }}
  ]
}}

Constraints:
- Do not read docs/challenges.md.
- Do not invent. Use concrete file and line references.
- Limit to {max_findings} findings.
- Do not propose fixes.
""".strip()


def detect(
    service: str = "identity",
    max_findings: int = 3,
    model: str = "gpt-5.5",
    from_cache: bool = False,
    timeout: int = 300,
) -> Path:
    if from_cache:
        cache_path = CACHE_DIR / f"{service}-candidates.json"
        finding_set = FindingSet.model_validate_json(cache_path.read_text())
    else:
        crapi_dir = ROOT / "crAPI"
        if not crapi_dir.exists():
            raise RuntimeError("crAPI/ is missing. Use --from-cache or clone OWASP/crAPI first.")

        command = [
            "codex",
            "exec",
            "--model",
            model,
            "--json",
            "--cwd",
            str(crapi_dir),
            detection_prompt(service, max_findings),
        ]
        completed = run_checked(command, cwd=ROOT, timeout=timeout)
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr or completed.stdout)
        finding_set = FindingSet.model_validate(extract_json_object(completed.stdout))

    output = FINDINGS_DIR / f"candidates-{timestamp()}.json"
    output.write_text(finding_set.model_dump_json(indent=2) + "\n")
    copy_latest(output, "candidates-latest.json")
    return output


@app.command()
def main(
    service: str = "identity",
    max_findings: int = 3,
    model: str = "gpt-5.5",
    from_cache: bool = False,
) -> None:
    output = detect(service=service, max_findings=max_findings, model=model, from_cache=from_cache)
    console.print(f"[green]Wrote candidate findings:[/] {output}")


if __name__ == "__main__":
    app()
