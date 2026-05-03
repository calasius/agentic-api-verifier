#!/usr/bin/env bash
# Pretty-print the live JSON-line stream from a claude-runs phase.
#
# Usage:
#   claude/watch.sh                # watch whichever phase is currently active
#   claude/watch.sh surveyor       # surveyor phase only
#   claude/watch.sh hunter         # hunter phase only
#   claude/watch.sh exploiter      # exploiter phase only
#   claude/watch.sh --run <ts>     # specify a run dir by timestamp
#
# Output legend:
#   💬  text from the assistant
#   ⚙   tool call (with inputs)
#   ↳   tool result excerpt
#   ✓   final result event (with cost)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS_DIR="$REPO_ROOT/findings/claude-runs"
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
    echo "Run claude/run.sh first." >&2
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

# Pick the JSONL to follow.
if [[ -z "$PHASE" || "$PHASE" == "latest" ]]; then
    # Wait briefly for the first jsonl to appear.
    for _ in $(seq 1 20); do
        FILE="$(ls -t "$RUN"/*.jsonl 2>/dev/null | head -1)"
        [[ -n "$FILE" ]] && break
        sleep 0.5
    done
    if [[ -z "$FILE" ]]; then
        echo "No *.jsonl files in $RUN yet (run may still be booting)." >&2
        exit 1
    fi
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

tail -F -n +1 "$FILE" | python3 -c '
import json, sys
def short(s, n=200):
    s = str(s).replace("\n", " ").strip()
    return (s[:n] + "…") if len(s) > n else s

for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"): continue
    try: ev = json.loads(line)
    except json.JSONDecodeError: continue
    t = ev.get("type")
    if t == "assistant":
        msg = ev.get("message", {}) or {}
        for block in msg.get("content", []) or []:
            bt = block.get("type")
            if bt == "text":
                txt = block.get("text","").strip()
                if txt:
                    print(f"💬 {short(txt)}", flush=True)
            elif bt == "tool_use":
                name = block.get("name","?")
                inp = block.get("input",{}) or {}
                # Pick the most informative scalar field
                detail = (
                    inp.get("command")
                    or inp.get("file_path")
                    or inp.get("filePath")
                    or inp.get("pattern")
                    or inp.get("description")
                    or inp.get("path")
                    or inp.get("query")
                    or inp.get("url")
                    or json.dumps(inp)
                )
                print(f"⚙  {name}  ::  {short(detail, 160)}", flush=True)
    elif t == "user":
        msg = ev.get("message", {}) or {}
        for block in msg.get("content", []) or []:
            if block.get("type") != "tool_result": continue
            content = block.get("content", "")
            if isinstance(content, list):
                content = " ".join(c.get("text","") for c in content if isinstance(c, dict))
            print(f"   ↳ {short(content)}", flush=True)
    elif t == "result":
        cost = ev.get("total_cost_usd", "?")
        usage = ev.get("usage", {}) or {}
        print(f"\n✓ result  cost=${cost}  in={usage.get(\"input_tokens\",\"?\")}  out={usage.get(\"output_tokens\",\"?\")}\n", flush=True)
'
