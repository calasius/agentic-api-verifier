#!/usr/bin/env bash
# End-to-end orchestrator for the opencode strategy:
#   1. Build the apisec-runner container image (if missing).
#   2. Start `opencode serve` (shared HTTP server on :4096).
#   3. Start the apisec-sandbox container with restricted network.
#   4. Run the surveyor agent  -> survey.json
#   5. Run the hunter agent    -> findings.json
#   6. For each finding, run the exploiter agent -> verdicts.json
#   7. Cleanup.
#
# Usage:
#   opencode/run.sh \
#     --target-url http://localhost:8888 \
#     --workspace ./crAPI \
#     --model deepseek/deepseek-v4-pro
set -euo pipefail

# ─── defaults ────────────────────────────────────────────────────────────────
TARGET_URL="${TARGET_URL:-http://localhost:8888}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$PWD}"
MODEL="${MODEL:-deepseek/deepseek-v4-pro}"
ORACLES_URL_EMAIL="${ORACLES_URL_EMAIL:-}"
SCOPE_HINT="${SCOPE_HINT:-}"
OPENCODE_PORT="${OPENCODE_PORT:-4096}"
IMAGE="${IMAGE:-localhost/apisec-runner:latest}"
CONTAINER="${CONTAINER:-apisec-sandbox}"
SKIP_BUILD="${SKIP_BUILD:-0}"
KEEP_CONTAINER="${KEEP_CONTAINER:-0}"
FINDINGS_INPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-url)        TARGET_URL="$2"; shift 2 ;;
        --workspace)         WORKSPACE_DIR="$2"; shift 2 ;;
        --model)             MODEL="$2"; shift 2 ;;
        --oracles-email)     ORACLES_URL_EMAIL="$2"; shift 2 ;;
        --scope)             SCOPE_HINT="$2"; shift 2 ;;
        --port)              OPENCODE_PORT="$2"; shift 2 ;;
        --skip-build)        SKIP_BUILD=1; shift ;;
        --keep-container)    KEEP_CONTAINER=1; shift ;;
        --findings)          FINDINGS_INPUT="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,18p' "$0" >&2; exit 0 ;;
        *)  echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd)"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$REPO_ROOT/findings/opencode-runs/$TIMESTAMP"
mkdir -p "$RUN_DIR"

cd "$REPO_ROOT"

# opencode discovers project-local agents at `<dir>/.opencode/agents/`
# rooted at the `opencode run --dir <D>` cwd. We pass `--dir
# $WORKSPACE_DIR` so the agent's host filesystem cwd matches what the
# container sees as `/workspace`. To make the agents discoverable there
# without permanently polluting the target tree, we drop per-file symlinks
# into `$WORKSPACE_DIR/.opencode/` and remove them in cleanup.
#
# IMPORTANT: opencode.json is *generated* (not symlinked) so the MCP
# bridge command can use an absolute path — relative paths in the static
# config break when opencode resolves them against `--dir = workspace`.
WORKSPACE_OC="$WORKSPACE_DIR/.opencode"
mkdir -p "$WORKSPACE_OC/agents"
python3 - "$WORKSPACE_OC/opencode.json" "$REPO_ROOT/opencode/mcp/apisec-bridge.py" "$CONTAINER" <<'PY'
import json, sys
out_path, bridge_path, container = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = {
    "$schema": "https://opencode.ai/config.json",
    "mcp": {
        "apisec-sandbox": {
            "type": "local",
            "command": ["python3", bridge_path],
            "environment": {
                "SANDBOX_CONTAINER": container,
                "SANDBOX_RUNTIME": "podman",
                "SANDBOX_TIMEOUT": "120",
                "SANDBOX_OUT_LIMIT": "65536",
            },
            "enabled": True,
            "timeout": 120000,
        }
    },
}
with open(out_path, "w") as f:
    json.dump(cfg, f, indent=2)
PY
for src in "$REPO_ROOT"/opencode/agents/*.md; do
    ln -sf "$src" "$WORKSPACE_OC/agents/$(basename "$src")"
done

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# ─── 1. build image ──────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log "Building $IMAGE …"
    podman build -t "$IMAGE" "$REPO_ROOT/docker/apisec-runner"
fi

# ─── 2. start container ──────────────────────────────────────────────────────
log "Removing any stale $CONTAINER container …"
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true

# `--network=host` keeps `localhost:<port>` reachable from inside the
# container exactly as on the host. Trade-off: the container shares the
# host's network namespace and can reach other local services. For an
# authorized PoC this is fine; we don't expose any ports from the
# container, and the toolkit + read-only filesystem cap blast radius.
TARGET_URL_CONTAINER="$TARGET_URL"
ORACLES_URL_EMAIL_CONTAINER="$ORACLES_URL_EMAIL"

log "Starting $CONTAINER from $IMAGE …"
log "  TARGET_URL inside container: $TARGET_URL_CONTAINER"
# shellcheck disable=SC2086
podman run -d \
    --name "$CONTAINER" \
    --network host \
    --tmpfs /sandbox:rw,size=200m,mode=1777 \
    --read-only \
    --read-only-tmpfs \
    --volume "$WORKSPACE_DIR:/workspace:ro,Z" \
    --env "TARGET_URL=$TARGET_URL_CONTAINER" \
    --env "ORACLES_URL_EMAIL=$ORACLES_URL_EMAIL_CONTAINER" \
    --env "WORKSPACE=/workspace" \
    --env "SCRATCH=/sandbox" \
    "$IMAGE" \
    sleep infinity > /dev/null

cleanup() {
    if [[ "$KEEP_CONTAINER" -ne 1 ]]; then
        log "Cleanup: stopping $CONTAINER"
        podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    if [[ -n "${SERVE_PID:-}" ]]; then
        log "Cleanup: stopping opencode serve (pid $SERVE_PID)"
        kill "$SERVE_PID" 2>/dev/null || true
    fi
    if [[ -d "$WORKSPACE_OC" ]]; then
        log "Cleanup: removing $WORKSPACE_OC"
        rm -f "$WORKSPACE_OC/opencode.json" "$WORKSPACE_OC"/agents/*.md
        rmdir "$WORKSPACE_OC/agents" "$WORKSPACE_OC" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ─── 3. start opencode serve (shared) ────────────────────────────────────────
log "Starting opencode serve on :$OPENCODE_PORT …"
opencode serve --port "$OPENCODE_PORT" --hostname 127.0.0.1 \
    > "$RUN_DIR/opencode-serve.log" 2>&1 &
SERVE_PID=$!

# wait up to 30s for /global/health
for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$OPENCODE_PORT/global/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# ─── helper: invoke an agent end-to-end and capture the assistant reply ──────
ATTACH="http://127.0.0.1:$OPENCODE_PORT"
run_agent() {
    local agent="$1"
    local prompt="$2"
    local out_file="$3"

    # opencode resolves agents from `<--dir>/.opencode/agents/`. We point
    # --dir at $WORKSPACE_DIR (where we just dropped per-file symlinks),
    # which also keeps the agent's host filesystem cwd identical to the
    # container's /workspace mount.
    opencode run \
        --attach "$ATTACH" \
        --format json \
        --dangerously-skip-permissions \
        --model "$MODEL" \
        --agent "$agent" \
        --dir "$WORKSPACE_DIR" \
        "$prompt" \
        > "$RUN_DIR/${agent}.jsonl" 2>"$RUN_DIR/${agent}.err"

    # Concatenate every "text" event's part.text to reconstruct the assistant's
    # final reply, then strip optional ```json fences.
    python3 - "$RUN_DIR/${agent}.jsonl" > "$out_file" <<'PY'
import json, re, sys
text_parts = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: ev = json.loads(line)
        except json.JSONDecodeError: continue
        if ev.get("type") == "text":
            t = (ev.get("part") or {}).get("text", "")
            if isinstance(t, str): text_parts.append(t)
text = "\n".join(text_parts).strip()
m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
if m: text = m.group(1)
sys.stdout.write(text)
PY
}

if [[ -n "$FINDINGS_INPUT" ]]; then
    if [[ ! -f "$FINDINGS_INPUT" ]]; then
        log "ERROR: --findings file not found: $FINDINGS_INPUT"
        exit 2
    fi
    log "Skipping surveyor + hunter; using findings from $FINDINGS_INPUT"
    cp "$FINDINGS_INPUT" "$RUN_DIR/findings.json"
else
    # ─── 4. surveyor ─────────────────────────────────────────────────────────
    SURVEY_PROMPT="Survey the REST API codebase rooted at the working directory. \
The same files are mounted read-only at /workspace inside the apisec-sandbox \
container. \
${SCOPE_HINT:+Scope hint: $SCOPE_HINT. }\
Return the JSON structure described in your system prompt and nothing else."

    log "Running surveyor …"
    run_agent surveyor "$SURVEY_PROMPT" "$RUN_DIR/survey.json"
    SURVEY_BYTES=$(wc -c < "$RUN_DIR/survey.json")
    log "Survey written ($SURVEY_BYTES bytes): $RUN_DIR/survey.json"

    # ─── 5. hunter ───────────────────────────────────────────────────────────
    HUNTER_PROMPT="You have this security survey of the target. Use it as starting context. \
Then find OWASP API Top 10 vulnerabilities and return findings JSON per your system prompt.

<survey>
$(cat "$RUN_DIR/survey.json")
</survey>

The source tree is at the working directory on the host (read/grep/glob); the same files are mounted at /workspace inside the apisec-sandbox container.
The live target is reachable at \$TARGET_URL = $TARGET_URL_CONTAINER from inside the sandbox.
Use apisec-sandbox_bash for any HTTP probing or exploit scripts."

    log "Running hunter …"
    run_agent hunter "$HUNTER_PROMPT" "$RUN_DIR/findings.json"
    log "Findings written: $RUN_DIR/findings.json"
fi

# ─── 6. exploiter, per finding ───────────────────────────────────────────────
mkdir -p "$RUN_DIR/verdicts"
COUNT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('findings',[])))" "$RUN_DIR/findings.json" 2>/dev/null || echo 0)
log "Verifying $COUNT finding(s) …"

# We run opencode directly here instead of run_agent so that all the
# per-finding streams are appended to a single $RUN_DIR/exploiter.jsonl
# (run_agent overwrites). Each finding's verdict still lands in its own
# verdicts/<id>.json. Each event in the stream carries its own sessionID,
# so you can demux by session if you need per-finding event slices.
: > "$RUN_DIR/exploiter.jsonl"
: > "$RUN_DIR/exploiter.err"

for i in $(seq 0 $((COUNT - 1))); do
    FID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['findings'][$i]['id'])" "$RUN_DIR/findings.json")
    FINDING=$(python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['findings'][$i], indent=2))" "$RUN_DIR/findings.json")

    log "  [$FID] verifying …"

    PROMPT="Verify this finding against \$TARGET_URL = $TARGET_URL_CONTAINER. \
Use apisec-sandbox_bash for all HTTP and exec.

<finding>
$FINDING
</finding>"

    # Write opencode's stream to a per-finding temp jsonl (avoids the
    # heredoc-stomps-pipe-stdin trap), then append it to the master
    # exploiter.jsonl, then parse the verdict text out of it.
    PER_JSONL="$RUN_DIR/exploiter-${FID}.jsonl"
    opencode run \
        --attach "$ATTACH" \
        --format json \
        --dangerously-skip-permissions \
        --model "$MODEL" \
        --agent exploiter \
        --dir "$WORKSPACE_DIR" \
        "$PROMPT" \
        > "$PER_JSONL" 2>>"$RUN_DIR/exploiter.err" || \
        log "  [$FID] opencode run exited non-zero (continuing)"

    cat "$PER_JSONL" >> "$RUN_DIR/exploiter.jsonl"

    # Pass the jsonl path as argv (don't redirect stdin) — `python3 -` plus
    # a `<<HERE` heredoc would otherwise consume stdin to read the script,
    # leaving sys.stdin empty when the script tries to iterate.
    python3 - "$PER_JSONL" > "$RUN_DIR/verdicts/$FID.json" <<'PY'
import json, re, sys
text_parts = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: ev = json.loads(line)
        except json.JSONDecodeError: continue
        if ev.get("type") == "text":
            t = (ev.get("part") or {}).get("text", "")
            if isinstance(t, str): text_parts.append(t)
text = "\n".join(text_parts).strip()
m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
if m: text = m.group(1)
sys.stdout.write(text)
PY
done

# ─── reports: one markdown attack-chain per finding ──────────────────────────
mkdir -p "$RUN_DIR/reports"
for i in $(seq 0 $((COUNT - 1))); do
    FID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['findings'][$i]['id'])" "$RUN_DIR/findings.json")
    PER_JSONL="$RUN_DIR/exploiter-${FID}.jsonl"
    [[ -e "$PER_JSONL" ]] || continue
    python3 -c "import json,sys; json.dump(json.load(open(sys.argv[1]))['findings'][$i], sys.stdout)" \
        "$RUN_DIR/findings.json" > "$RUN_DIR/reports/${FID}.finding.json"
    python3 "$REPO_ROOT/lib/build-report.py" \
        "$PER_JSONL" \
        "$RUN_DIR/reports/${FID}.finding.json" \
        --verdict "$RUN_DIR/verdicts/${FID}.json" \
        > "$RUN_DIR/reports/${FID}.md" 2>/dev/null && \
        log "  report: ${FID}.md"
    rm -f "$RUN_DIR/reports/${FID}.finding.json"
done

# ─── 7. summary ──────────────────────────────────────────────────────────────
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
