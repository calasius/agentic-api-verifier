#!/usr/bin/env bash
# Pretty-print the live JSON-line stream from an opencode-runs phase.
#
# Usage:
#   opencode/watch.sh                # auto-detect the active phase
#   opencode/watch.sh surveyor       # surveyor phase only
#   opencode/watch.sh hunter         # hunter phase only
#   opencode/watch.sh exploiter      # the per-finding exploiter loop
#   opencode/watch.sh --run <ts>     # specify a run dir by timestamp
#
# Output legend:
#   💬  text from the assistant
#   ⚙   tool call (with inputs)
#   ↳   tool result excerpt
#   ✓   step finish event (with tokens + cost)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS_DIR="$REPO_ROOT/findings/opencode-runs"
PHASE=""
RUN_TS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run)              RUN_TS="$2"; shift 2 ;;
        -h|--help)          sed -n '2,16p' "$0" >&2; exit 0 ;;
        surveyor|hunter|exploiter|latest)
                            PHASE="$1"; shift ;;
        *)                  echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -d "$RUNS_DIR" ]]; then
    echo "No runs directory yet: $RUNS_DIR" >&2
    echo "Run opencode/run.sh first." >&2
    exit 1
fi

if [[ -n "$RUN_TS" ]]; then
    RUN="$RUNS_DIR/$RUN_TS"
    if [[ ! -d "$RUN" ]]; then
        echo "Run not found: $RUN" >&2
        exit 1
    fi
else
    RUN="$(ls -td "$RUNS_DIR"/*/ 2>/dev/null | head -1)"
    if [[ -z "$RUN" ]]; then
        echo "No runs in $RUNS_DIR yet." >&2
        exit 1
    fi
    RUN="${RUN%/}"
fi

# Pick the JSONL to follow. While the exploiter is running, the active
# stream is in `exploiter-tmp.jsonl` (per-finding temp file that gets
# appended to `exploiter.jsonl` when each verification ends).
pick_active_jsonl() {
    if [[ -e "$RUN/exploiter-tmp.jsonl" ]]; then
        echo "$RUN/exploiter-tmp.jsonl"
        return
    fi
    ls -t "$RUN"/*.jsonl 2>/dev/null | head -1
}

if [[ -z "$PHASE" || "$PHASE" == "latest" ]]; then
    for _ in $(seq 1 20); do
        FILE="$(pick_active_jsonl)"
        [[ -n "$FILE" ]] && break
        sleep 0.5
    done
    if [[ -z "$FILE" ]]; then
        echo "No *.jsonl files in $RUN yet (run may still be booting)." >&2
        exit 1
    fi
elif [[ "$PHASE" == "exploiter" && -e "$RUN/exploiter-tmp.jsonl" ]]; then
    FILE="$RUN/exploiter-tmp.jsonl"
else
    FILE="$RUN/${PHASE}.jsonl"
    if [[ ! -e "$FILE" ]]; then
        echo "Waiting for $FILE …" >&2
        for _ in $(seq 1 60); do
            [[ -e "$FILE" ]] && break
            sleep 0.5
        done
        if [[ ! -e "$FILE" ]]; then
            echo "Timed out waiting for $FILE" >&2
            exit 1
        fi
    fi
fi

echo "Tailing: $FILE" >&2
echo "(Ctrl-C to stop)" >&2
echo "" >&2

# Capture the parser into a variable via a quoted heredoc so the Python
# source keeps its own quoting (no bash-vs-python quote escaping).
PARSER=$(cat <<'PY'
import json, sys

def short(s, n=200):
    s = str(s).replace("\n", " ").strip()
    return (s[:n] + "…") if len(s) > n else s

# opencode stream-json events have a flat shape:
#   {"type":"tool_use","part":{"type":"tool","tool":"bash",
#                              "state":{"status":"running|completed",
#                                       "input":{...},"output":"..."}},
#    "sessionID":"..."}
# We track per-tool state to emit the call once + its result once.

last_tool_status = {}

for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue

    etype = ev.get("type", "")
    part = ev.get("part", {}) or {}

    if etype == "tool_use":
        tool = part.get("tool", "?")
        state = part.get("state", {}) or {}
        status = state.get("status", "")
        callid = part.get("callID", "")
        inp = state.get("input", {}) or {}
        detail = (
            inp.get("command")
            or inp.get("file_path")
            or inp.get("filePath")
            or inp.get("path")
            or inp.get("pattern")
            or inp.get("query")
            or inp.get("url")
            or inp.get("description")
            or json.dumps(inp)
        )
        prev = last_tool_status.get(callid)
        if status == "running" and prev != "running":
            print(f"⚙  {tool}  ::  {short(detail, 160)}", flush=True)
        elif status == "completed" and prev != "completed":
            output = state.get("output", "")
            if output:
                print(f"   ↳ {short(output)}", flush=True)
        last_tool_status[callid] = status
    elif etype == "text":
        txt = part.get("text", "")
        if isinstance(txt, str) and txt.strip():
            print(f"💬 {short(txt)}", flush=True)
    elif etype == "step_finish":
        tokens = part.get("tokens", {}) or {}
        cache = tokens.get("cache", {}) or {}
        cost = part.get("cost", "?")
        in_tok = tokens.get("total", "?")
        out_tok = tokens.get("output", "?")
        cache_read = cache.get("read", 0)
        line = f"\n✓ step_finish  cost=${cost}  in={in_tok}  out={out_tok}"
        if cache_read:
            line += f"  cache_read={cache_read}"
        line += "\n"
        print(line, flush=True)
PY
)

tail -F -n +1 "$FILE" | python3 -c "$PARSER"
