from __future__ import annotations

import importlib.util
import json
import os
import shlex
import shutil
from pathlib import Path

import httpx
import typer
from common import (
    DEFAULT_TARGET_URL,
    FINDINGS_DIR,
    ROOT,
    CommandTimeoutError,
    RunRecorder,
    format_usage,
    timestamp,
)
from models import FindingSet, VerificationSet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(help="Run the end-to-end Strike demo.")
console = Console()


def log(stage: str, message: str) -> None:
    console.print(f"[dim]{timestamp()}[/] [cyan]{stage}[/] {message}")


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


def preflight(
    target_url: str, from_cache: bool, runtime: str, image: str, llm: str
) -> str | None:
    if from_cache:
        return check_target(target_url, from_cache=True)

    ok = True
    crapi_dir = ROOT / "crAPI"
    if not crapi_dir.exists():
        console.print("[red]Missing crAPI source:[/] ./crAPI")
        console.print("Run: git clone https://github.com/OWASP/crAPI.git")
        ok = False

    if llm == "claude":
        configured = os.environ.get("CLAUDE_COMMAND")
        parts = shlex.split(configured) if configured else ["claude"]
        launcher = parts[0]
        if not shutil.which(launcher):
            console.print(f"[red]Missing Claude launcher:[/] {launcher} is not in PATH")
            console.print("Install: https://docs.anthropic.com/en/docs/claude-code/quickstart")
            ok = False
        elif configured:
            console.print(f"Claude command: {configured}")
        configured_flags = os.environ.get("CLAUDE_EXEC_FLAGS")
        if configured_flags:
            console.print(f"Claude exec flags: {configured_flags}")
    elif llm == "codex":
        configured = os.environ.get("CODEX_COMMAND")
        parts = shlex.split(configured) if configured else ["codex"]
        launcher = parts[0]
        if not shutil.which(launcher):
            console.print(f"[red]Missing Codex launcher:[/] {launcher} is not in PATH")
            ok = False
        elif configured:
            console.print(f"Codex command: {configured}")
        elif not shutil.which("node"):
            console.print("[red]Missing Node.js:[/] node is not in PATH")
            console.print("Fedora install: sudo dnf install -y nodejs")
            console.print("Toolbox alternative: CODEX_COMMAND='toolbox run codex'")
            console.print("Then verify: node --version")
            ok = False
        configured_flags = os.environ.get("CODEX_EXEC_FLAGS")
        if configured_flags:
            console.print(f"Codex exec flags: {configured_flags}")
    elif llm == "opencode":
        configured = os.environ.get("OPENCODE_COMMAND")
        parts = shlex.split(configured) if configured else ["opencode"]
        launcher = parts[0]
        if not shutil.which(launcher):
            console.print(f"[red]Missing opencode launcher:[/] {launcher} is not in PATH")
            ok = False
        elif configured:
            console.print(f"Opencode command: {configured}")
        configured_flags = os.environ.get("OPENCODE_EXEC_FLAGS")
        if configured_flags:
            console.print(f"Opencode exec flags: {configured_flags}")
    else:
        console.print(
            f"[red]Unknown LLM provider:[/] {llm}"
            " (expected 'claude', 'codex', or 'opencode')"
        )
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
            "podman compose -f docker-compose.yml up -d"
        )
        ok = False

    if not ok:
        return None
    return health


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


def print_cost_summary(events: list[dict]) -> dict[str, float]:
    cost_events = [e for e in events if e.get("stage", "").endswith(".cost")]
    if not cost_events:
        return {}
    table = Table(title="LLM Cost Summary")
    table.add_column("Stage")
    table.add_column("Model")
    table.add_column("Cost USD", justify="right")
    table.add_column("In", justify="right")
    table.add_column("Out", justify="right")
    table.add_column("Cache Read", justify="right")
    table.add_column("Cache Create", justify="right")
    totals = {
        "cost_usd": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_create_tokens": 0,
    }
    for event in cost_events:
        d = event.get("details", {}) or {}
        cost = d.get("cost_usd") or 0.0
        in_tok = d.get("input_tokens") or 0
        out_tok = d.get("output_tokens") or 0
        cache_r = d.get("cache_read_tokens") or 0
        cache_c = d.get("cache_create_tokens") or 0
        totals["cost_usd"] += float(cost)
        totals["input_tokens"] += int(in_tok)
        totals["output_tokens"] += int(out_tok)
        totals["cache_read_tokens"] += int(cache_r)
        totals["cache_create_tokens"] += int(cache_c)
        table.add_row(
            event["stage"],
            str(d.get("model") or "-"),
            f"${float(cost):.4f}" if cost else "-",
            f"{int(in_tok):,}",
            f"{int(out_tok):,}",
            f"{int(cache_r):,}",
            f"{int(cache_c):,}",
        )
    table.add_row(
        "[bold]TOTAL[/bold]",
        "",
        f"[bold]${totals['cost_usd']:.4f}[/bold]",
        f"[bold]{totals['input_tokens']:,}[/bold]",
        f"[bold]{totals['output_tokens']:,}[/bold]",
        f"[bold]{totals['cache_read_tokens']:,}[/bold]",
        f"[bold]{totals['cache_create_tokens']:,}[/bold]",
    )
    console.print(table)
    cache_total = totals["cache_read_tokens"] + totals["cache_create_tokens"]
    if cache_total:
        hit_ratio = totals["cache_read_tokens"] / cache_total
        console.print(
            f"Cache reuse: {totals['cache_read_tokens']:,} read of "
            f"{cache_total:,} cacheable input tokens ({hit_ratio:.0%})"
        )
    return totals


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
    candidates: Path | None = None,
    no_pause: bool = False,
    model: str = "claude-sonnet-4-6",
    detect_model: str | None = None,
    poc_model: str | None = None,
    detect_timeout: int = 900,
    codex_timeout: int = 900,
    poc_provider: str = "codex",
    runtime: str = "podman",
    image: str = "strike-demo/poc-runner:latest",
    llm: str = "claude",
    use_api: bool = False,
) -> None:
    effective_detect_model = detect_model or model
    effective_poc_model = poc_model or model

    if llm == "opencode" and model == "claude-sonnet-4-6":
        model = "deepseek/deepseek-v4-pro"
        effective_detect_model = detect_model or model
        effective_poc_model = poc_model or model

    server = None
    if use_api:
        from api import OpencodeServer
        console.print("[cyan]Starting opencode serve...[/]")
        server = OpencodeServer()
        port = server.start()
        console.print(f"[green]openCode API server running on port {port}[/]")

    pause_enabled = not no_pause
    recorder = RunRecorder()
    run_record: dict[str, object] = {
        "run_id": recorder.run_id,
        "service": service,
        "target_url": target_url,
        "from_cache": from_cache,
        "candidates": str(candidates) if candidates else None,
    }
    recorder.update(
        service=service,
        target_url=target_url,
        from_cache=from_cache,
        candidates=str(candidates) if candidates else None,
        model=model,
        detect_model=effective_detect_model,
        poc_model=effective_poc_model,
        max_findings=max_findings,
        poc_provider=poc_provider,
        llm=llm,
        use_api=use_api,
    )

    mode_desc = "openCode API streaming" if use_api else "Podman sandbox"
    console.print(
        Panel(
            f"Auto-verification demo ({mode_desc}): detect candidate API findings, "
            "verify via opencode, and return CONFIRMED / FAILED / UNCLEAR for human triage.",
            title="Strike Demo",
        )
    )
    pause(pause_enabled)

    log("preflight", "Checking local prerequisites")
    recorder.event("preflight.start", "Checking local prerequisites")
    health = preflight(
        target_url=target_url, from_cache=from_cache, runtime=runtime, image=image, llm=llm
    )
    if health is None:
        recorder.event("preflight.failed", "Preflight failed")
        raise typer.Exit(1)

    run_record["target_check"] = health
    recorder.update(target_check=health)
    recorder.event("preflight.done", "Preflight completed", target_check=health)
    pause(pause_enabled)

    if candidates:
        log("candidates", f"Loading seeded candidates from {candidates}")
        recorder.event("candidates.load.start", "Loading seeded candidates", path=str(candidates))
        candidates_path = candidates
        if not candidates_path.exists():
            console.print(f"[red]Candidates file does not exist:[/] {candidates_path}")
            recorder.event("candidates.load.failed", "Candidates file does not exist")
            raise typer.Exit(1)
    else:
        log(
            "detect",
            f"Starting {llm} detection model={effective_detect_model} timeout={detect_timeout}s",
        )
        recorder.event(
            "detect.start",
            f"Starting {llm} detection",
            timeout=detect_timeout,
            llm=llm,
            model=effective_detect_model,
        )

        def on_detect_event(stage: str, message: str, details: dict) -> None:
            if stage.endswith(".cost"):
                log(stage, f"{message} | {format_usage(details)}")
            else:
                log(stage, message)
            recorder.event(stage, message, **details)

        detect = load_function("01_detect.py", "detect")
        try:
            candidates_path = detect(
                service=service,
                max_findings=max_findings,
                model=effective_detect_model,
                from_cache=from_cache,
                timeout=detect_timeout,
                llm=llm,
                use_api=use_api,
                server=server,
                on_event=on_detect_event,
            )
        except CommandTimeoutError as exc:
            console.print(f"[red]{exc}[/]")
            console.print("Try increasing detection timeout with: --detect-timeout 1800")
            recorder.event("detect.timeout", str(exc), timeout=exc.timeout)
            raise typer.Exit(1) from exc
    finding_set = FindingSet.model_validate_json(candidates_path.read_text())
    log("candidates", f"Loaded {len(finding_set.findings)} candidate finding(s)")
    print_candidates(finding_set)
    run_record["candidates_path"] = str(candidates_path)
    recorder.update(candidates_path=str(candidates_path))
    recorder.event(
        "candidates.loaded",
        "Candidate findings loaded",
        count=len(finding_set.findings),
        path=str(candidates_path),
    )
    pause(pause_enabled)

    verify = load_function("02_verify.py", "verify")
    log("verify", f"Starting verification for up to {max_findings} finding(s)")
    recorder.event("verify.start", "Starting verification", max_findings=max_findings)

    def on_verify_event(stage: str, message: str, details: dict) -> None:
        if stage == "verify.text":
            console.print(message, end="")
        elif stage.endswith(".cost"):
            log(stage, f"{message} | {format_usage(details)}")
        else:
            log(stage, message)
        recorder.event(stage, message, **details)

    try:
        verified_path = verify(
            input_path=candidates_path,
            target_url=target_url,
            max_findings=max_findings,
            from_cache=from_cache,
            model=effective_poc_model,
            codex_timeout=codex_timeout,
            poc_provider=poc_provider,
            image=image,
            runtime=runtime,
            llm=llm,
            use_api=use_api,
            server=server,
            on_event=on_verify_event,
            on_partial=recorder.partial,
        )
    except CommandTimeoutError as exc:
        console.print(f"[red]{exc}[/]")
        console.print("Try increasing PoC-generation timeout with: --codex-timeout 1800")
        recorder.event("verify.timeout", str(exc), timeout=exc.timeout)
        raise typer.Exit(1) from exc
    verification_set = VerificationSet.model_validate_json(verified_path.read_text())
    recorder.event("verify.done", "Verification completed", path=str(verified_path))
    print_verification(verification_set)
    pause(pause_enabled)

    metrics = print_summary(verification_set)
    cost_totals = print_cost_summary(recorder.data.get("events", []))
    run_record["verified_path"] = str(verified_path)
    run_record["metrics"] = metrics
    run_record["findings"] = json.loads(verification_set.model_dump_json())["findings"]
    run_record["cost_totals"] = cost_totals
    recorder.update(
        verified_path=str(verified_path),
        metrics=metrics,
        status="completed",
        cost_totals=cost_totals,
    )

    output = FINDINGS_DIR / f"demo-run-{timestamp()}.json"
    output.write_text(json.dumps(run_record, indent=2) + "\n")
    recorder.update(demo_run_path=str(output))
    console.print(f"Run record: {output}")
    console.print(f"Partial run log: {recorder.path}")

    if server:
        server.stop()
        console.print("[dim]openCode API server stopped[/]")


if __name__ == "__main__":
    app()
