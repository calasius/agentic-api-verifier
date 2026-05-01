from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from common import (
    DEFAULT_TARGET_URL,
    FINDINGS_DIR,
    ROOT,
    copy_latest,
    extract_json_object,
    run_checked,
    timestamp,
)
from models import (
    Finding,
    FindingSet,
    GeneratedPoc,
    SandboxExecution,
    VerificationSet,
    VerificationStatus,
    VerifiedFinding,
)
from rich.console import Console
from sandbox_mcp import execute_in_sandbox

app = typer.Typer(help="Verify candidate findings through the Podman sandbox.")
console = Console()


def poc_prompt(finding: Finding, target_url: str) -> str:
    return f"""
You are verifying a candidate vulnerability in OWASP crAPI, an intentionally
vulnerable local training application. The operator is authorized to test it.

Generate a single Python PoC for this finding:

{finding.model_dump_json(indent=2)}

Runtime constraints:
- The PoC will run inside an isolated Podman container.
- The target base URL is available as TARGET_URL. Default to {target_url}.
- Use only Python standard library plus httpx or requests.
- Do not require shell commands.
- Do not write files.
- Keep runtime below 20 seconds.
- Print one final JSON object to stdout.
- Exit 0 only when the finding is confirmed.
- Exit 1 when the finding is disproved.
- Exit 2 when required target state, credentials, or evidence are missing.

The final stdout JSON must include:
- status: CONFIRMED, FAILED, or UNCLEAR
- evidence: concise HTTP evidence
- requests: array of method/url/status/body_excerpt objects
- reason: why the verdict follows from the evidence

If the finding needs accounts or vehicles, the PoC should create or seed them
through normal crAPI HTTP flows when possible. If that is not possible, return
UNCLEAR with a precise reason.

Return only JSON with this exact shape:
{{
  "poc_code": "complete Python code as a string",
  "success_criterion": "what confirms this finding",
  "expected_evidence": "what HTTP evidence should appear",
  "assumptions": ["short assumption"]
}}
""".strip()


def generate_poc_with_codex(
    finding: Finding,
    target_url: str,
    model: str,
    timeout: int,
) -> GeneratedPoc:
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
        poc_prompt(finding, target_url),
    ]
    completed = run_checked(command, cwd=ROOT, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr or completed.stdout)
    return GeneratedPoc.model_validate(extract_json_object(completed.stdout))


def cached_poc(finding: Finding) -> GeneratedPoc:
    poc = f"""
import json
import os
import sys

target = os.environ.get("TARGET_URL", "http://localhost:8888").rstrip("/")
status = "CONFIRMED" if {finding.id!r} in {{"f-001", "f-002"}} else "UNCLEAR"
exit_code = 0 if status == "CONFIRMED" else 2

print(json.dumps({{
    "status": status,
    "finding_id": {finding.id!r},
    "target": target,
    "evidence": "cached rehearsal evidence",
    "requests": [],
    "reason": "cache mode does not execute a live Codex-generated PoC"
}}))
sys.exit(exit_code)
""".strip()
    return GeneratedPoc(
        poc_code=poc,
        success_criterion="Cached rehearsal confirms only the demo control flow.",
        expected_evidence="Cached sandbox evidence.",
        assumptions=["cache mode"],
    )


def infer_status(
    finding: Finding, execution: SandboxExecution, from_cache: bool
) -> tuple[VerificationStatus, str, float, bool]:
    if from_cache:
        if finding.id in {"f-001", "f-002"}:
            return (
                VerificationStatus.confirmed,
                "Cached rehearsal evidence shows the hypothesis is executable "
                "against seeded crAPI state.",
                0.91 if finding.id == "f-001" else 0.88,
                False,
            )
        return (
            VerificationStatus.unclear,
            "Cached rehearsal intentionally leaves this finding for human review.",
            0.55,
            True,
        )

    if execution.exit_code == 0 and "CONFIRMED" in execution.stdout.upper():
        return VerificationStatus.confirmed, execution.stdout[:1000], 0.9, False
    if execution.timed_out:
        return VerificationStatus.unclear, "PoC timed out in sandbox.", 0.35, True
    if execution.exit_code == 2:
        evidence = execution.stdout[:1000] or execution.stderr[:1000]
        return VerificationStatus.unclear, evidence, 0.45, True
    return VerificationStatus.failed, execution.stdout[:1000] or execution.stderr[:1000], 0.4, True


def verify(
    input_path: Path,
    target_url: str = DEFAULT_TARGET_URL,
    max_findings: int = 3,
    from_cache: bool = False,
    model: str = "gpt-5.5",
    codex_timeout: int = 300,
    image: str = "strike-demo/poc-runner:latest",
    runtime: str = "podman",
) -> Path:
    finding_set = FindingSet.model_validate_json(input_path.read_text())
    verified: list[VerifiedFinding] = []

    for finding in finding_set.findings[:max_findings]:
        if from_cache:
            generated = cached_poc(finding)
            execution = SandboxExecution(
                command=["cache"],
                stdout=f"cached sandbox evidence for {finding.id}",
                stderr="",
                exit_code=0 if finding.id in {"f-001", "f-002"} else 2,
                timed_out=False,
            )
        else:
            generated = generate_poc_with_codex(
                finding=finding,
                target_url=target_url,
                model=model,
                timeout=codex_timeout,
            )
            execution = execute_in_sandbox(
                generated.poc_code,
                target_url=target_url,
                image=image,
                runtime=runtime,
            )

        status, evidence, confidence, needs_review = infer_status(finding, execution, from_cache)
        verified.append(
            VerifiedFinding(
                **finding.model_dump(),
                poc_used=generated.poc_code,
                success_criterion=generated.success_criterion,
                sandbox_execution=execution,
                status=status,
                evidence=evidence,
                confidence=confidence,
                needs_human_review=needs_review,
            )
        )

    result = VerificationSet(
        target_url=target_url,
        service=finding_set.service,
        source="cache" if from_cache else "sandbox",
        findings=verified,
    )
    output = FINDINGS_DIR / f"verified-{timestamp()}.json"
    output.write_text(result.model_dump_json(indent=2) + "\n")
    copy_latest(output, "verified-latest.json")
    return output


@app.command()
def main(
    input: Annotated[Path, typer.Option("--input", "-i")],
    target_url: str = DEFAULT_TARGET_URL,
    max_findings: int = 3,
    from_cache: bool = False,
    model: str = "gpt-5.5",
    codex_timeout: int = 300,
    image: str = "strike-demo/poc-runner:latest",
    runtime: str = "podman",
) -> None:
    output = verify(
        input_path=input,
        target_url=target_url,
        max_findings=max_findings,
        from_cache=from_cache,
        model=model,
        codex_timeout=codex_timeout,
        image=image,
        runtime=runtime,
    )
    console.print(f"[green]Wrote verified findings:[/] {output}")


if __name__ == "__main__":
    app()
