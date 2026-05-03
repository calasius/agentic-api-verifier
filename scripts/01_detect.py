from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from common import (
    CACHE_DIR,
    FINDINGS_DIR,
    ROOT,
    api_detect_and_parse,
    build_llm_invocation,
    copy_latest,
    parse_llm_response,
    run_checked,
    timestamp,
)
from models import FindingSet
from rich.console import Console

app = typer.Typer(help="Detect candidate API vulnerabilities with Codex.")
console = Console()

KEY_FILE_HINTS = (
    "config/JwtProvider.java",
    "config/JwtAuthTokenFilter.java",
    "config/WebSecurityConfig.java",
    "controller/VehicleController.java",
    "controller/UserController.java",
    "service/Impl/VehicleServiceImpl.java",
    "service/Impl/UserServiceImpl.java",
)


def numbered_excerpt(path: Path, root: Path, max_chars: int) -> str:
    text = path.read_text(errors="replace")
    if len(text) > max_chars:
        text = text[:max_chars] + "\n// ... truncated by strike-demo detector ..."

    rel_path = path.relative_to(root)
    lines = []
    for number, line in enumerate(text.splitlines(), start=1):
        lines.append(f"{number:04d}: {line}")
    return f"### {rel_path}\n```java\n" + "\n".join(lines) + "\n```"


def build_source_context(service: str, max_files: int = 7, max_chars_per_file: int = 4500) -> str:
    service_root = ROOT / "crAPI" / "services" / service
    source_root = service_root / "src" / "main" / "java"
    if not source_root.exists():
        raise RuntimeError(f"{source_root} is missing.")

    java_files = sorted(source_root.rglob("*.java"))

    def score(path: Path) -> tuple[int, str]:
        rel = path.relative_to(source_root).as_posix()
        matched = any(hint in rel for hint in KEY_FILE_HINTS)
        controller = "/controller/" in f"/{rel}"
        security = "/config/" in f"/{rel}" and ("Jwt" in rel or "Security" in rel)
        service_impl = "/service/Impl/" in f"/{rel}" and (
            "User" in rel or "Vehicle" in rel or "Otp" in rel
        )
        rank = 0
        if matched:
            rank -= 20
        if controller:
            rank -= 20
        if security:
            rank -= 15
        if service_impl:
            rank -= 10
        return rank, rel

    selected = sorted(java_files, key=score)[:max_files]
    excerpts = [numbered_excerpt(path, ROOT / "crAPI", max_chars_per_file) for path in selected]
    selected_list = "\n".join(f"- {path.relative_to(ROOT / 'crAPI')}" for path in selected)
    return (
        "Selected source files for focused analysis:\n"
        f"{selected_list}\n\n"
        "Only use the excerpts below as primary evidence. "
        "Open additional files only if essential.\n\n"
        + "\n\n".join(excerpts)
    )


def detection_prompt(service: str, max_findings: int, source_context: str) -> str:
    return f"""
Find OWASP API Top 10 vulnerabilities in services/{service}. The highest-value
areas for this demo are JWT validation and vehicle ownership authorization.

You have Read, Grep, and Glob tools available and the working directory is the
crAPI repo root. The numbered source excerpts below are a starting pack — use
them as orientation, but you are expected to navigate the rest of
services/{service} (controllers, config, service/Impl, repository, model) and
look at src/main/resources (data.sql, schema.sql, application*.properties) to
discover seeded users, vehicle UUIDs, and configuration relevant to confirming
each finding. Cross-check claims against the actual source before reporting.

For every finding the hypothesis must be operational, not just descriptive:
a downstream PoC generator (no human in the loop) must be able to translate
your output directly into HTTP calls. Avoid prose like "an attacker could ..."
without naming the concrete request.

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
      "hypothesis": "Concrete source-to-sink hypothesis with file:line references.",
      "confidence_initial": 0.8,
      "victim_identity": "Who the attacker impersonates or targets. If the exploit creates its own victim via signup, say so. If it must target a preexisting seeded user, name the email.",
      "attack_request": {{
        "method": "GET",
        "path": "/identity/api/v2/...",
        "headers": {{"Authorization": "Bearer <forged-or-stolen-token>"}},
        "body": null,
        "notes": "Anything else needed to build the request (token forgery recipe, payload shape, etc)."
      }},
      "expected_response_signal": "Concrete substring or field in the HTTP response that proves the bug fired (e.g. response JSON contains victim_email and a 200 status).",
      "setup_state": "Steps the PoC must run before the attack request: signup a victim, login, etc. If none, say 'none'.",
      "target_state_required": "Preexisting target state the PoC cannot create itself (seeded user, vehicle UUID, file on disk). Use null if the PoC is self-sufficient."
    }}
  ]
}}

Constraints:
- Do not read docs/challenges.md.
- Do not invent. Use concrete file and line references; verify with the source.
- Limit to {max_findings} findings (hard cap — return fewer if evidence is thin).
- Do not propose fixes.
- Prefer JWT/auth and vehicle-location/ownership findings.
- Stay within services/{service} unless confirming a cross-service interaction
  is essential.
- Prefer self-sufficient exploits (the PoC can create its own victim) over ones
  that require preexisting seed data. When the bug only manifests against
  preexisting data, populate target_state_required precisely (e.g. the seeded
  user email and the vehicle UUID you found in data.sql).

Source context:

{source_context}
""".strip()


def detect(
    service: str = "identity",
    max_findings: int = 3,
    model: str = "claude-sonnet-4-6",
    from_cache: bool = False,
    timeout: int = 300,
    llm: str = "claude",
    use_api: bool = False,
    server: Any | None = None,
    on_event: Callable[[str, str, dict], None] | None = None,
) -> Path:
    if from_cache:
        cache_path = CACHE_DIR / f"{service}-candidates.json"
        finding_set = FindingSet.model_validate_json(cache_path.read_text())
    elif use_api and server is not None:
        crapi_dir = ROOT / "crAPI"
        if not crapi_dir.exists():
            raise RuntimeError("crAPI/ is missing. Use --from-cache or clone OWASP/crAPI first.")
        source_context = build_source_context(service)
        prompt = detection_prompt(service, max_findings, source_context)
        parsed, usage = api_detect_and_parse(
            server, prompt, model, crapi_dir, on_event=on_event,
        )
        if on_event:
            on_event("detect.cost", "Detect LLM call cost", usage)
        finding_set = FindingSet.model_validate(parsed)
    else:
        crapi_dir = ROOT / "crAPI"
        if not crapi_dir.exists():
            raise RuntimeError("crAPI/ is missing. Use --from-cache or clone OWASP/crAPI first.")

        source_context = build_source_context(service)
        command, cwd = build_llm_invocation(
            provider=llm,
            model=model,
            working_dir=crapi_dir,
            prompt=detection_prompt(service, max_findings, source_context),
        )
        completed = run_checked(command, cwd=cwd, timeout=timeout)
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr or completed.stdout)
        parsed, usage = parse_llm_response(
            llm, completed.stdout, preferred_keys=("findings",)
        )
        if on_event:
            on_event("detect.cost", "Detect LLM call cost", usage)
        finding_set = FindingSet.model_validate(parsed)

    output = FINDINGS_DIR / f"candidates-{timestamp()}.json"
    output.write_text(finding_set.model_dump_json(indent=2) + "\n")
    copy_latest(output, "candidates-latest.json")
    return output


@app.command()
def main(
    service: str = "identity",
    max_findings: int = 3,
    model: str = "claude-sonnet-4-6",
    from_cache: bool = False,
    timeout: int = 900,
    llm: str = "claude",
) -> None:
    output = detect(
        service=service,
        max_findings=max_findings,
        model=model,
        from_cache=from_cache,
        timeout=timeout,
        llm=llm,
    )
    console.print(f"[green]Wrote candidate findings:[/] {output}")


if __name__ == "__main__":
    app()
