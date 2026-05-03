#!/usr/bin/env bash
# End-to-end orchestrator for the Claude Code strategy:
#   1. Build the apisec-runner container image (if missing).
#   2. Start the apisec-sandbox container with restricted filesystem.
#   3. Generate a per-run .mcp.json registering the apisec-sandbox MCP.
#   4. Install the surveyor / hunter / exploiter agents into
#      $WORKSPACE/.claude/agents/ (per-file symlinks, cleaned up).
#   5. Run `claude -p --agent surveyor` -> survey.json
#   6. Run `claude -p --agent hunter`   -> findings.json
#   7. For each finding, run `claude -p --agent exploiter` -> verdicts/<id>.json
#   8. Cleanup.
#
# Usage:
#   claude/run.sh \
#     --target-url http://localhost:8888 \
#     --workspace ./crAPI \
#     --model claude-sonnet-4-6
set -euo pipefail

# ─── defaults ────────────────────────────────────────────────────────────────
TARGET_URL="${TARGET_URL:-http://localhost:8888}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$PWD}"
MODEL="${MODEL:-claude-sonnet-4-6}"
ORACLES_URL_EMAIL="${ORACLES_URL_EMAIL:-}"
SCOPE_HINT="${SCOPE_HINT:-}"
IMAGE="${IMAGE:-localhost/apisec-runner:latest}"
CONTAINER="${CONTAINER:-apisec-sandbox}"
SKIP_BUILD="${SKIP_BUILD:-0}"
KEEP_CONTAINER="${KEEP_CONTAINER:-0}"
FINDINGS_INPUT=""
MAX_TURNS="${MAX_TURNS:-60}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-url)        TARGET_URL="$2"; shift 2 ;;
        --workspace)         WORKSPACE_DIR="$2"; shift 2 ;;
        --model)             MODEL="$2"; shift 2 ;;
        --oracles-email)     ORACLES_URL_EMAIL="$2"; shift 2 ;;
        --scope)             SCOPE_HINT="$2"; shift 2 ;;
        --skip-build)        SKIP_BUILD=1; shift ;;
        --keep-container)    KEEP_CONTAINER=1; shift ;;
        --findings)          FINDINGS_INPUT="$2"; shift 2 ;;
        --max-turns)         MAX_TURNS="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,18p' "$0" >&2; exit 0 ;;
        *)  echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd)"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$REPO_ROOT/findings/claude-runs/$TIMESTAMP"
mkdir -p "$RUN_DIR"

cd "$REPO_ROOT"

# Claude Code reads project-local agents from `<workspace>/.claude/agents/`.
# We install per-file symlinks so the source of truth stays in `claude/agents/`
# and the workspace is cleaned up at the end.
WORKSPACE_CC="$WORKSPACE_DIR/.claude"
mkdir -p "$WORKSPACE_CC/agents"
for src in "$REPO_ROOT"/claude/agents/*.md; do
    ln -sf "$src" "$WORKSPACE_CC/agents/$(basename "$src")"
done

# Generate a per-run MCP config with an absolute path to the bridge script
# (the bridge is shared with the opencode strategy via a symlink).
MCP_CFG="$RUN_DIR/mcp.json"
python3 - "$MCP_CFG" "$REPO_ROOT/opencode/mcp/apisec-bridge.py" "$CONTAINER" <<'PY'
import json, sys
out_path, bridge_path, container = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = {
    "mcpServers": {
        "apisec_sandbox": {
            "type": "stdio",
            "command": "python3",
            "args": [bridge_path],
            "env": {
                "SANDBOX_CONTAINER": container,
                "SANDBOX_RUNTIME": "podman",
                "SANDBOX_TIMEOUT": "120",
                "SANDBOX_OUT_LIMIT": "65536",
            },
        }
    }
}
with open(out_path, "w") as f:
    json.dump(cfg, f, indent=2)
PY

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# ─── 1. build image ──────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log "Building $IMAGE …"
    podman build -t "$IMAGE" "$REPO_ROOT/docker/apisec-runner"
fi

# ─── 2. start container ──────────────────────────────────────────────────────
log "Removing any stale $CONTAINER container …"
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true

log "Starting $CONTAINER from $IMAGE …"
log "  TARGET_URL inside container: $TARGET_URL"
# shellcheck disable=SC2086
podman run -d \
    --name "$CONTAINER" \
    --network host \
    --tmpfs /sandbox:rw,size=200m,mode=1777 \
    --read-only \
    --read-only-tmpfs \
    --volume "$WORKSPACE_DIR:/workspace:ro,Z" \
    --env "TARGET_URL=$TARGET_URL" \
    --env "ORACLES_URL_EMAIL=$ORACLES_URL_EMAIL" \
    --env "WORKSPACE=/workspace" \
    --env "SCRATCH=/sandbox" \
    "$IMAGE" \
    sleep infinity > /dev/null

cleanup() {
    if [[ "$KEEP_CONTAINER" -ne 1 ]]; then
        log "Cleanup: stopping $CONTAINER"
        podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    if [[ -d "$WORKSPACE_CC" ]]; then
        log "Cleanup: removing $WORKSPACE_CC"
        rm -f "$WORKSPACE_CC"/agents/*.md
        rmdir "$WORKSPACE_CC/agents" "$WORKSPACE_CC" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ─── helper: invoke a Claude agent and capture the assistant text ────────────
run_agent() {
    local agent="$1"
    local prompt="$2"
    local out_file="$3"

    # `claude -p --agent <name>` looks for project-local agents at
    # `<cwd>/.claude/agents/<name>.md` — NOT under --add-dir. We `cd` into
    # $WORKSPACE_DIR (where the per-file symlinks live) inside a subshell
    # so the host filesystem cwd matches the container's /workspace mount
    # AND Claude's agent discovery finds our agents.
    ( cd "$WORKSPACE_DIR" && claude -p \
        --output-format stream-json \
        --include-partial-messages \
        --verbose \
        --agent "$agent" \
        --mcp-config "$MCP_CFG" \
        --strict-mcp-config \
        --model "$MODEL" \
        --max-turns "$MAX_TURNS" \
        --dangerously-skip-permissions \
        "$prompt" ) \
        > "$RUN_DIR/${agent}.jsonl" 2>"$RUN_DIR/${agent}.err"

    # Multi-strategy verdict extraction (full-parse, fenced, balanced-brace,
    # shape-aware). Pass `findings` for surveyor/hunter, `status` for
    # exploiter (caller decides via $4).
    local want_key="${4:-}"
    python3 "$REPO_ROOT/claude/parse-stream.py" \
        "$RUN_DIR/${agent}.jsonl" \
        "$want_key" \
        > "$out_file"
}

if [[ -n "$FINDINGS_INPUT" ]]; then
    if [[ ! -f "$FINDINGS_INPUT" ]]; then
        log "ERROR: --findings file not found: $FINDINGS_INPUT"
        exit 2
    fi
    log "Skipping surveyor + hunter; using findings from $FINDINGS_INPUT"
    cp "$FINDINGS_INPUT" "$RUN_DIR/findings.json"
else
    # ─── 3. surveyor ─────────────────────────────────────────────────────────
    SURVEY_PROMPT="Survey the REST API codebase rooted at the working directory. \
The same files are mounted read-only at /workspace inside the apisec-sandbox \
container. \
${SCOPE_HINT:+Scope hint: $SCOPE_HINT. }\
Return the JSON structure described in your system prompt and nothing else."

    log "Running surveyor …"
    run_agent surveyor "$SURVEY_PROMPT" "$RUN_DIR/survey.json" stack
    SURVEY_BYTES=$(wc -c < "$RUN_DIR/survey.json")
    log "Survey written ($SURVEY_BYTES bytes): $RUN_DIR/survey.json"

    # ─── 4. hunter ───────────────────────────────────────────────────────────
    HUNTER_PROMPT="You have this security survey of the target. Use it as starting context. \
Then find OWASP API Top 10 vulnerabilities and return findings JSON per your system prompt.

<survey>
$(cat "$RUN_DIR/survey.json")
</survey>

The source tree is at the working directory on the host (Read/Grep/Glob); the same files are mounted at /workspace inside the apisec-sandbox container.
The live target is reachable at \$TARGET_URL = $TARGET_URL from inside the sandbox.
Use mcp__apisec_sandbox__bash for any HTTP probing or exploit scripts."

    log "Running hunter …"
    run_agent hunter "$HUNTER_PROMPT" "$RUN_DIR/findings.json" findings
    log "Findings written: $RUN_DIR/findings.json"
fi

# ─── 5. exploiter, per finding ───────────────────────────────────────────────
mkdir -p "$RUN_DIR/verdicts"
COUNT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('findings',[])))" "$RUN_DIR/findings.json" 2>/dev/null || echo 0)
log "Verifying $COUNT finding(s) …"

: > "$RUN_DIR/exploiter.jsonl"
: > "$RUN_DIR/exploiter.err"

for i in $(seq 0 $((COUNT - 1))); do
    FID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['findings'][$i]['id'])" "$RUN_DIR/findings.json")
    FINDING=$(python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['findings'][$i], indent=2))" "$RUN_DIR/findings.json")

    log "  [$FID] verifying …"

    PROMPT="Verify this finding against \$TARGET_URL = $TARGET_URL. \
Use mcp__apisec_sandbox__bash for all HTTP and exec.

<finding>
$FINDING
</finding>"

    TMP_JSONL="$RUN_DIR/exploiter-tmp.jsonl"
    ( cd "$WORKSPACE_DIR" && claude -p \
        --output-format stream-json \
        --include-partial-messages \
        --verbose \
        --agent exploiter \
        --mcp-config "$MCP_CFG" \
        --strict-mcp-config \
        --model "$MODEL" \
        --max-turns "$MAX_TURNS" \
        --dangerously-skip-permissions \
        "$PROMPT" ) \
        > "$TMP_JSONL" 2>>"$RUN_DIR/exploiter.err" || \
        log "  [$FID] claude exited non-zero (continuing)"

    cat "$TMP_JSONL" >> "$RUN_DIR/exploiter.jsonl"

    python3 "$REPO_ROOT/claude/parse-stream.py" "$TMP_JSONL" status \
        > "$RUN_DIR/verdicts/$FID.json"

    rm -f "$TMP_JSONL"
done

# ─── 6. summary ──────────────────────────────────────────────────────────────
log "── summary ──"
log "Run dir : $RUN_DIR"
python3 - "$RUN_DIR" <<'PY'
import json, os, sys
run = sys.argv[1]
verdicts = os.path.join(run, "verdicts")
counts = {"CONFIRMED": 0, "FAILED": 0, "UNCLEAR": 0, "MALFORMED": 0}
if os.path.isdir(verdicts):
    for name in sorted(os.listdir(verdicts)):
        p = os.path.join(verdicts, name)
        try:
            v = json.load(open(p))
            s = v.get("status", "MALFORMED").upper()
            counts[s] = counts.get(s, 0) + 1
            print(f"  {name}: {s} — {v.get('reason','')[:80]}")
        except Exception as e:
            counts["MALFORMED"] += 1
            print(f"  {name}: MALFORMED ({e})")
print(f"\nTotals: {counts}")
PY
