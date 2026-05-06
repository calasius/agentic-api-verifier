# Architecture

How the PoC is built, and why each piece exists.

## The three-phase pipeline

A single agent prompt asked to "find vulnerabilities and exploit them" does
poorly: it anchors on names it knows, skips boring code, and conflates
"this *looks* suspicious" with "this *is* exploitable". The PoC splits the
work into three roles, each a separate agent invocation with a different
tool surface:

```
   ┌─────────────┐     ┌────────────┐     ┌──────────────────────┐
   │  Surveyor   │ ──▶ │   Hunter   │ ──▶ │  Exploiter (×N)      │
   │ source-only │     │ source +   │     │ source + sandbox     │
   │ no naming   │     │ sandbox    │     │ one process per      │
   │             │     │            │     │ finding              │
   └──────┬──────┘     └─────┬──────┘     └──────────┬───────────┘
          ▼                  ▼                       ▼
      survey.json       findings.json          verdicts/<id>.json
```

### 1. Surveyor — map the territory, don't name the bugs

Reads source only. No bash, no MCP. Produces `survey.json`: stack, routes,
auth model, trust boundaries, seeded test data, "suspicious patterns".

The system prompt **forbids naming vulnerabilities**. The surveyor is
allowed to say "this controller dereferences `request.body.id` directly
into a SQL string" but not "SQL injection in foo.java". Why: anchoring on
known names makes the model skip code that doesn't pattern-match obvious
classes. Keeping the surveyor descriptive forces it to map the actual
attack surface.

### 2. Hunter — operational findings, not descriptions

Given the survey + source, looks for OWASP API Top 10 issues. Produces
`findings.json`. Each finding carries enough detail for an automated
exploit to be built from it without re-reading the source:

| Field | Why it matters |
|---|---|
| `victim_identity` | who the exploit targets / impersonates |
| `attack_request` | method, path, headers, body, notes |
| `expected_response_signal` | concrete substring/field that proves the bug fired |
| `setup_state` | steps the PoC runs before the attack (signup, login) |
| `target_state_required` | preexisting target state the PoC cannot create itself |

`target_state_required: null` means self-sufficient; the exploiter never
has to guess "is this finding even reachable from a fresh deploy?".

### 3. Exploiter — one process per finding, run it for real

For each finding, a fresh agent invocation generates and runs the exploit
inside the sandbox, captures HTTP evidence, and compares the response
against `expected_response_signal`. Output: `verdicts/<id>.json`.

Three possible verdicts:

- **CONFIRMED** — predicted signal observed.
- **FAILED** — exploit ran cleanly and the signal didn't fire.
- **UNCLEAR** — the agent could not prove or disprove the bug. F-13
  (command injection) returned UNCLEAR because the bug requires
  `ENABLE_SHELL_INJECTION=true` and the agent could not confirm whether
  that flag was on at runtime. **This is the correct answer.** Most
  automated scanners produce false positives or false negatives without
  admitting uncertainty; this one says "I don't know" and tells you why.

Each finding runs in its own process. A failure in one verification (a
crash, a timeout, a malformed JSON) does not poison the others.

## Brain on host, hands in sandbox

The LLM stays on the host. Only the commands it issues run inside an
isolated container.

```
   ┌─────────────────────────────────┐
   │  Coding agent on host (brain)   │  ← LLM, file reads, prompt assembly
   └─────────────────┬───────────────┘
                     │ MCP bash tool (JSON-RPC)
                     ▼
   ┌─────────────────────────────────┐
   │  apisec-sandbox (hands)         │  ← read-only rootfs, tmpfs scratch,
   │  podman exec bash -lc "..."     │    project source mounted RO
   └──────────────┬──────────────────┘
                  │ HTTP
                  ▼
   ┌─────────────────────────────────┐
   │  Target API (crAPI)             │
   └─────────────────────────────────┘
```

This split is the security model. The agent can read any file on the host
and reason about anything, but its **execution surface** is contained:

- `/workspace` — project source, read-only.
- `/sandbox` — only writable surface, 200 MB tmpfs, gone when the container
  exits.
- `--read-only` rootfs — no `pip install`, no modifying anything outside
  `/sandbox`.
- `--network host` — `localhost:<port>` reaches the target without Podman
  host-gateway aliases. Trade-off: the container shares the host's network
  namespace; acceptable for an authorized PoC against a local target. For
  a stricter setup, use a dedicated Podman network and bind the target
  there.

Every shell command both strategies ever run goes through this single
container.

## The shared sandbox: `apisec-runner`

`docker/apisec-runner/Dockerfile` builds on Debian 12 slim and pre-installs
the toolkit:

| Category   | Tools                                                           |
|------------|-----------------------------------------------------------------|
| HTTP       | `curl`, `httpie`, `wget`, python `httpx`/`requests`/`aiohttp`, node `fetch` |
| JWT/crypto | `openssl`, `jwt` (jwt-cli), `jwt_tool` (ticarpi), `pyjwt[crypto]`, `python-jose`, `cryptography` |
| JSON/parse | `jq`, `yq`, `xmlstarlet`, `base64`, `xxd`                        |
| Recon      | `ffuf`, `gobuster`, `kr` (kiterunner), `arjun`                   |
| SQL        | `sqlmap`                                                         |
| DB clients | `psql`, `mysql`, `redis-tools`                                   |
| Network    | `dig`, `nslookup`, `nc`, `socat`, `ping`                         |
| General    | `git`, `unzip`, `tar`, `tree`, `vim-tiny`                        |
| Languages  | `python3` (httpx/pyjwt/cryptography preloaded), `node 18+`       |
| Wordlists  | SecLists subset at `/usr/share/wordlists/{api-objects,api-actions,common,raft-small-words}.txt` |

Run as:

```
podman run -d \
    --name apisec-sandbox \
    --network host \
    --tmpfs /sandbox:rw,size=200m,mode=1777 \
    --read-only --read-only-tmpfs \
    --volume "$WORKSPACE_DIR:/workspace:ro" \
    --env TARGET_URL=$TARGET_URL \
    --env ORACLES_URL_EMAIL=... \
    --env WORKSPACE=/workspace \
    --env SCRATCH=/sandbox \
    apisec-runner sleep infinity
```

## TOOLS.md — the cookbook the agent reads itself into

Pre-installing tools is half the job. The other half is the agent knowing
*how to use them for this attack class*. `docker/apisec-runner/TOOLS.md`
is a markdown manifest with **recipes per attack class**: alg:none forge,
RS↔HS confusion, JKU injection, BOLA enumeration, sqlmap invocations,
ffuf wordlist discovery, etc.

The agent reads it once at session start to load the cookbook into
context. Adding a new attack capability is two edits:

1. Add the tool to `Dockerfile`.
2. Add a recipe section to `TOOLS.md`.

**No prompt change needed.** The agent picks up the new recipe on the next
run.

## The MCP bridge — ~150 lines of stdlib Python

`opencode/mcp/apisec-bridge.py` is a JSON-RPC stdio MCP server. Reads
JSON-RPC requests on stdin, dispatches to a small `TOOLS = [...]` table,
shells out to `podman exec apisec-sandbox bash -lc "..."`, returns the
result. No virtualenv. No third-party MCP framework.

Both strategies use the same bridge file — the Claude folder symlinks to
the opencode copy.

If a capability deserves to be a first-class tool (a structured
`fetch-jwks` helper, say), add it to the `TOOLS` list next to `bash`. The
wire format is documented in the bridge file.

## Per-strategy flow diagrams

### opencode

```
                 ┌─────────────────────────────────────┐
                 │  opencode serve  (host, port 4096)  │
                 └─────────────┬───────────────────────┘
                               │ opencode run --attach :4096 --agent X
                               ▼
   surveyor ──▶  Read / Grep / Glob (native)             ──▶  survey.json
                 bash, edit, write, MCP   — DENIED

   hunter   ──▶  Read / Grep / Glob (native)             ──▶  findings.json
                 apisec-sandbox_bash (MCP) — ALLOWED
                 native bash             — DENIED

   exploiter ─▶  Read / Grep / Glob (native)             ──▶  verdicts/<id>.json
                 apisec-sandbox_bash (MCP) — ALLOWED      (one per finding)
                 native bash             — DENIED
                                │ apisec-sandbox_bash
                                ▼
                  ┌──────────────────────────────────┐
                  │  MCP bridge (stdio JSON-RPC)     │
                  │  python3 apisec-bridge.py        │
                  └──────────────┬───────────────────┘
                                 │ podman exec apisec-sandbox bash -lc ...
                                 ▼
                  ┌──────────────────────────────────┐
                  │  apisec-sandbox container        │
                  └──────────────────────────────────┘
```

One persistent `opencode serve` process is shared across phases, so the
prompt cache (the survey, the source pack) hits across hunter and
per-finding exploiter calls.

### Claude Code

```
   per phase: claude -p --agent <name> --mcp-config <run>/mcp.json --strict-mcp-config
                               │
                               ▼
   surveyor ──▶  Read / Grep / Glob / LS                  ──▶  survey.json
                 (no Bash, no Edit, no Write, no WebFetch)

   hunter   ──▶  Read / Grep / Glob / LS                  ──▶  findings.json
                 mcp__apisec_sandbox__bash  — ALLOWED
                 (no native Bash)

   exploiter ─▶  Read / Grep / Glob                       ──▶  verdicts/<id>.json
                 mcp__apisec_sandbox__bash  — ALLOWED
                                │
                                ▼
                  ┌──────────────────────────────────┐
                  │  MCP bridge (stdio JSON-RPC)     │
                  │  python3 apisec-bridge.py        │
                  └──────────────┬───────────────────┘
                                 │ podman exec apisec-sandbox bash -lc ...
                                 ▼
                  ┌──────────────────────────────────┐
                  │  apisec-sandbox container        │
                  └──────────────────────────────────┘
```

Each phase is a separate `claude -p --agent <name>` process. No persistent
server; per-call cold-start is the trade-off for simpler orchestration.

## Stream output is preserved per phase

Every phase writes its raw streaming events to `*.jsonl` (opencode flat
events or Claude wrapped events). If the verdict parser breaks mid-run, no
information is lost — the `lib/build-report.py` script can re-parse the
streams offline to recover verdicts and produce the per-finding markdown
reports.

This is what makes the `docs/sample-reports/` directory possible: 26
real attack-chain reports rebuilt from saved jsonl streams of two real
runs.

## Why this maps to value the way it does

- **Three-phase split with role separation** keeps each invocation focused
  and lets each phase's tool surface be locked down independently.
- **Operational fields on findings** make the hunter→exploiter handoff
  mechanical instead of guesswork.
- **Brain/hands separation** is the security model — the LLM is unbounded,
  its execution is bounded.
- **TOOLS.md as cookbook** decouples capability from prompt. Add a tool,
  add a recipe, done.
- **Agent-portable architecture** — same sandbox, same MCP, same prompts;
  swap the coding-agent CLI to compare LLMs apples-to-apples on the same
  target.
- **`UNCLEAR` as a first-class verdict** is what separates this from
  confident-but-wrong scanners.
