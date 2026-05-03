#!/usr/bin/env bash
# Auto-discover the currently-running opencode phase and `opencode attach`
# its session in the native TUI.
#
# Picks the latest run dir under findings/opencode-runs/, finds the most
# recently updated *.jsonl (or exploiter-tmp.jsonl during the verify loop),
# extracts its last sessionID, queries the running opencode serve for that
# session's `directory`, and execs `opencode attach`.
#
# Usage:
#   opencode/watch.sh                # active phase, latest run, default port
#   opencode/watch.sh --port 4097    # custom port
#   opencode/watch.sh --run <ts>     # past run by timestamp
#   opencode/watch.sh hunter         # force a phase even if it's not the most recent
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS_DIR="$REPO_ROOT/findings/opencode-runs"
PORT="${OPENCODE_PORT:-4096}"
PORT_EXPLICIT=0
PHASE=""
RUN_TS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run)              RUN_TS="$2"; shift 2 ;;
        --port)             PORT="$2"; PORT_EXPLICIT=1; shift 2 ;;
        -h|--help)          sed -n '2,16p' "$0" >&2; exit 0 ;;
        surveyor|hunter|exploiter)
                            PHASE="$1"; shift ;;
        *)                  echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -d "$RUNS_DIR" ]]; then
    echo "No runs directory yet: $RUNS_DIR" >&2
    echo "Run opencode/run.sh first." >&2
    exit 1
fi

# ─── pick the run dir ─────────────────────────────────────────────────────
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

# ─── pick the active jsonl ───────────────────────────────────────────────
# During exploiter loop, the per-finding stream lives in exploiter-tmp.jsonl
# (gets appended to exploiter.jsonl when each verify ends).
if [[ -n "$PHASE" ]]; then
    if [[ "$PHASE" == "exploiter" && -e "$RUN/exploiter-tmp.jsonl" ]]; then
        JSONL="$RUN/exploiter-tmp.jsonl"
    else
        JSONL="$RUN/${PHASE}.jsonl"
    fi
else
    if [[ -e "$RUN/exploiter-tmp.jsonl" ]]; then
        JSONL="$RUN/exploiter-tmp.jsonl"
    else
        JSONL="$(ls -t "$RUN"/*.jsonl 2>/dev/null | head -1)"
    fi
fi

if [[ -z "${JSONL:-}" || ! -e "$JSONL" ]]; then
    echo "No active phase jsonl found in $RUN" >&2
    exit 1
fi

# ─── extract last sessionID ──────────────────────────────────────────────
SID="$(grep -oE 'ses_[A-Za-z0-9]+' "$JSONL" 2>/dev/null | tail -1 || true)"
if [[ -z "$SID" ]]; then
    echo "Could not find a sessionID in $JSONL" >&2
    echo "Phase may not have started streaming yet — wait a few seconds and retry." >&2
    exit 1
fi

# If --port wasn't explicit, auto-detect the port from the run's
# opencode-serve.log (the line "opencode server listening on http://…:N").
if [[ "$PORT_EXPLICIT" -eq 0 && -f "$RUN/opencode-serve.log" ]]; then
    DETECTED="$(grep -oE 'listening on http://[^:]+:[0-9]+' "$RUN/opencode-serve.log" \
                 | grep -oE '[0-9]+$' | head -1 || true)"
    if [[ -n "$DETECTED" ]]; then
        PORT="$DETECTED"
    fi
fi

URL="http://localhost:$PORT"
SESSION_JSON="$(curl -fsS "$URL/session/$SID" 2>/dev/null || true)"
if [[ -z "$SESSION_JSON" ]]; then
    echo "Could not reach opencode serve at $URL." >&2
    echo "Tried port $PORT (auto-detected from $RUN/opencode-serve.log if present)." >&2
    echo "Pass --port <N> if the serve uses a different port, or check the run is still active." >&2
    exit 1
fi
DIR="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("directory",""))' <<<"$SESSION_JSON")"
if [[ -z "$DIR" ]]; then
    echo "Session $SID has no 'directory' — server may be returning a non-session payload." >&2
    exit 1
fi

PHASE_NAME="$(basename "$JSONL" .jsonl)"
echo "── attaching ──" >&2
echo "  run    : $(basename "$RUN")" >&2
echo "  phase  : $PHASE_NAME" >&2
echo "  session: $SID" >&2
echo "  dir    : $DIR" >&2
echo "" >&2

exec opencode attach "$URL" --session "$SID" --dir "$DIR"
