#!/usr/bin/env python3
"""Generate a markdown attack-chain report from an exploiter session jsonl.

Auto-detects the stream format:
  - opencode: flat events {"type":"tool_use|text|step_finish","part":{...}}
  - claude:   wrapped     {"type":"assistant","message":{"content":[...]}}

Usage:
  build-report.py <session.jsonl> <finding.json> [--verdict <verdict.json>]

Writes markdown to stdout. Pipe / redirect to save it.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def detect_format(jsonl_path: str) -> str:
    with open(jsonl_path) as f:
        for i, line in enumerate(f):
            if i > 30:
                break
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = ev.get("type", "")
            if t == "assistant" and isinstance(ev.get("message"), dict):
                return "claude"
            if t in ("tool_use", "text", "step_finish") and "part" in ev:
                return "opencode"
            if t == "system" and "session_id" in ev:
                return "claude"
    return "unknown"


JWT_RE = None  # lazy
ID_RE = None


def _redact(s: str) -> str:
    global JWT_RE, ID_RE
    import re
    if JWT_RE is None:
        # JWTs (3 dot-separated base64url chunks; the 3rd may be empty for alg:none)
        JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*")
        # Long bearer-like opaque tokens
        ID_RE = re.compile(r"\b[A-Za-z0-9_\-]{120,}\b")
    s = JWT_RE.sub("<JWT>", s)
    s = ID_RE.sub("<TOKEN>", s)
    return s


def short(s: Any, n: int = 200, keep_lines: bool = False) -> str:
    s = _redact(str(s))
    if not keep_lines:
        s = s.replace("\n", " ")
    s = s.strip()
    return (s[: n - 1] + "…") if len(s) > n else s


def tool_input_summary(name: str, inp: dict[str, Any]) -> str:
    """Pull the most informative scalar from a tool's input."""
    if not isinstance(inp, dict) or not inp:
        return ""
    keys = (
        "command",
        "file_path",
        "filePath",
        "path",
        "pattern",
        "query",
        "url",
        "description",
    )
    for k in keys:
        if k in inp and isinstance(inp[k], (str, int, float, bool)):
            return str(inp[k])
    return json.dumps(inp)[:200]


def parse_opencode(jsonl_path: str) -> dict:
    """Walk an opencode-format stream into a list of (kind, payload) events."""
    events: list[tuple[str, dict]] = []
    last_tool_status: dict[str, str] = {}
    cost = 0.0
    tokens = {"in": 0, "out": 0, "cache_read": 0}
    model = ""

    with open(jsonl_path) as f:
        for line in f:
            try:
                ev = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            etype = ev.get("type", "")
            part = ev.get("part", {}) or {}
            if etype == "text":
                txt = part.get("text", "")
                if isinstance(txt, str) and txt.strip():
                    events.append(("text", {"text": txt}))
            elif etype == "tool_use":
                tool = part.get("tool", "?")
                state = part.get("state", {}) or {}
                status = state.get("status", "")
                callid = part.get("callID", "")
                inp = state.get("input", {}) or {}
                output = state.get("output", "")
                prev = last_tool_status.get(callid)
                if status == "completed" and prev != "completed":
                    events.append(
                        (
                            "tool",
                            {
                                "name": tool,
                                "input": inp,
                                "output": output,
                            },
                        )
                    )
                last_tool_status[callid] = status
            elif etype == "step_finish":
                t = part.get("tokens", {}) or {}
                c = t.get("cache", {}) or {}
                tokens["in"] += int(t.get("total", 0) or 0)
                tokens["out"] += int(t.get("output", 0) or 0)
                tokens["cache_read"] += int(c.get("read", 0) or 0)
                pcost = part.get("cost") or 0
                try:
                    cost += float(pcost)
                except (TypeError, ValueError):
                    pass
                model = part.get("model", model)
    return {"events": events, "cost": cost, "tokens": tokens, "model": model}


def parse_claude(jsonl_path: str) -> dict:
    """Walk a Claude Code stream-json into a list of (kind, payload) events."""
    events: list[tuple[str, dict]] = []
    cost = 0.0
    tokens = {"in": 0, "out": 0, "cache_read": 0}
    model = ""

    pending_tools: dict[str, dict] = {}
    with open(jsonl_path) as f:
        for line in f:
            try:
                ev = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            t = ev.get("type", "")
            if t == "system" and ev.get("subtype") == "init":
                model = ev.get("model", model)
            elif t == "assistant":
                msg = ev.get("message", {}) or {}
                for b in msg.get("content", []) or []:
                    if not isinstance(b, dict):
                        continue
                    bt = b.get("type")
                    if bt == "text":
                        txt = b.get("text", "")
                        if isinstance(txt, str) and txt.strip():
                            events.append(("text", {"text": txt}))
                    elif bt == "tool_use":
                        pending_tools[b.get("id", "")] = {
                            "name": b.get("name", "?"),
                            "input": b.get("input", {}) or {},
                        }
                usage = msg.get("usage", {}) or {}
                tokens["in"] += int(usage.get("input_tokens", 0) or 0)
                tokens["out"] += int(usage.get("output_tokens", 0) or 0)
                tokens["cache_read"] += int(
                    usage.get("cache_read_input_tokens", 0) or 0
                )
            elif t == "user":
                msg = ev.get("message", {}) or {}
                for b in msg.get("content", []) or []:
                    if not isinstance(b, dict) or b.get("type") != "tool_result":
                        continue
                    tid = b.get("tool_use_id", "")
                    pending = pending_tools.pop(tid, None)
                    if pending is None:
                        continue
                    content = b.get("content", "")
                    if isinstance(content, list):
                        content = " ".join(
                            c.get("text", "")
                            for c in content
                            if isinstance(c, dict)
                        )
                    events.append(
                        (
                            "tool",
                            {
                                "name": pending["name"],
                                "input": pending["input"],
                                "output": str(content),
                            },
                        )
                    )
            elif t == "result":
                pcost = ev.get("total_cost_usd") or 0
                try:
                    cost += float(pcost)
                except (TypeError, ValueError):
                    pass
    return {"events": events, "cost": cost, "tokens": tokens, "model": model}


def group_into_phases(events: list[tuple[str, dict]]) -> list[dict]:
    """Group events into phases — each phase starts with a text block (the
    agent's reasoning) and contains the tool calls that follow it."""
    phases: list[dict] = []
    current = {"reasoning": "", "tools": []}
    for kind, payload in events:
        if kind == "text":
            if current["reasoning"] or current["tools"]:
                phases.append(current)
            current = {"reasoning": payload["text"], "tools": []}
        elif kind == "tool":
            current["tools"].append(payload)
    if current["reasoning"] or current["tools"]:
        phases.append(current)
    return phases


def render(
    finding: dict,
    parsed: dict,
    verdict: dict | None,
    fmt: str,
) -> str:
    fid = finding.get("id", "?")
    title = (
        finding.get("title")
        or finding.get("vulnerability_type")
        or "(no title)"
    )
    severity = finding.get("severity", "?")
    owasp = finding.get("owasp_category") or finding.get("owasp_api_category") or "?"
    file_loc = ""
    comps = finding.get("affected_components") or []
    if comps:
        file_loc = comps[0]
    elif finding.get("file"):
        file_loc = f"{finding['file']}:{finding.get('line', '?')}"
    description = finding.get("description") or finding.get("hypothesis", "")

    cost = parsed.get("cost", 0.0)
    tok = parsed.get("tokens", {})
    model = parsed.get("model", "?")

    out: list[str] = []
    out.append(f"# {fid} · {title}\n")
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| Severity | {severity} |")
    out.append(f"| OWASP | {owasp} |")
    if file_loc:
        out.append(f"| File | `{file_loc}` |")
    if verdict:
        v_status = verdict.get("status", "?")
        out.append(f"| Verdict | **{v_status}** |")
    out.append(f"| Strategy | {fmt} |")
    out.append(f"| Model | {model} |")
    out.append(f"| Cost | ${cost:.4f} |")
    out.append(
        f"| Tokens | in={tok.get('in',0):,} out={tok.get('out',0):,} cache_read={tok.get('cache_read',0):,} |"
    )
    out.append("")

    if description:
        out.append("## Hypothesis\n")
        out.append("> " + description.strip().replace("\n", "\n> "))
        out.append("")

    phases = group_into_phases(parsed["events"])
    out.append(f"## Attack chain ({len(phases)} phases, "
               f"{sum(len(p['tools']) for p in phases)} tool calls)\n")

    for i, ph in enumerate(phases, 1):
        if ph["reasoning"]:
            out.append(f"### Phase {i}\n")
            out.append("> " + short(ph["reasoning"], 600).replace("\n", "\n> "))
            out.append("")
        for tool in ph["tools"]:
            name = tool["name"]
            inp_summary = tool_input_summary(name, tool["input"])
            output = short(tool.get("output", ""), 400)
            # If tool is bash-like, render the multi-line command with newlines
            # preserved (after token redaction).
            if "bash" in name.lower():
                cmd = _redact(inp_summary).strip()
                # Cap very long commands
                if len(cmd) > 1200:
                    cmd = cmd[:1200] + "\n# … (truncated)"
                out.append("```bash")
                out.append(cmd)
                out.append("```")
            else:
                out.append(f"`{name}` — `{short(inp_summary, 200)}`")
            if output:
                out.append(f"↳ {output}")
            out.append("")

    if verdict:
        out.append("## Verdict\n")
        out.append(f"**{verdict.get('status', '?')}** — {verdict.get('reason', '')}")
        out.append("")
        if verdict.get("evidence"):
            out.append(f"**Evidence**: {verdict['evidence']}")
            out.append("")
        reqs = verdict.get("requests", []) or []
        if reqs:
            out.append("**Requests:**\n")
            out.append("| Method | URL | Status | Body excerpt |")
            out.append("|---|---|---|---|")
            for r in reqs[:10]:
                out.append(
                    f"| {r.get('method','?')} | `{short(r.get('url',''),60)}` "
                    f"| {r.get('status','?')} | {short(r.get('body_excerpt',''),60)} |"
                )
            out.append("")

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", help="exploiter session jsonl path")
    ap.add_argument("finding", help="finding JSON path (or '-' for stdin)")
    ap.add_argument("--verdict", help="verdict JSON path (optional)")
    args = ap.parse_args()

    fmt = detect_format(args.jsonl)
    if fmt == "claude":
        parsed = parse_claude(args.jsonl)
    elif fmt == "opencode":
        parsed = parse_opencode(args.jsonl)
    else:
        print(f"# Could not detect stream format for {args.jsonl}", file=sys.stderr)
        return 2

    if args.finding == "-":
        finding = json.load(sys.stdin)
    else:
        finding = json.load(open(args.finding))

    verdict = None
    if args.verdict:
        try:
            verdict = json.load(open(args.verdict))
        except (FileNotFoundError, json.JSONDecodeError):
            verdict = None

    sys.stdout.write(render(finding, parsed, verdict, fmt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
