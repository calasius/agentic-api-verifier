# Coding Agents for Vulnerability Discovery and Exploitation

Proof of concept for using coding agents (Claude Code, OpenAI Codex, opencode +
DeepSeek-V4-Pro) to automatically detect candidate API vulnerabilities,
generate executable proof-of-concept exploits, run them against a live target,
and return a structured verdict.

This is a research PoC, not a production scanner. The goal is to show what's
realistic today when you let an agent both reason about source and execute
HTTP requests end-to-end.

## What it does

Given a target source tree and a running instance of the application, the PoC
runs three stages:

1. **Detect** — the agent reads the source, identifies candidate vulnerabilities
   (OWASP API Top 10 by default), and emits operational findings: file/line,
   hypothesis, attack request, setup steps, expected response signal.
2. **Verify** — for each finding, the agent generates and runs an exploit
   against the live target. Two execution paths are supported:
   - PoC-in-sandbox: the agent emits Python code, the demo runs it inside an
     isolated Podman container with a fixed `TARGET_URL`.
   - Direct execution: the agent itself drives `curl`/HTTP via its `Bash` tool
     against the target (no sandbox, no Python layer).
3. **Verdict** — each finding ends as `CONFIRMED`, `FAILED`, or `UNCLEAR` with
   captured HTTP evidence (requests, responses, status codes).

`UNCLEAR` matters: a real triage tool needs to admit when it can't prove
something instead of guessing.

## Supported coding agents

Selectable via `--llm {claude,codex,opencode}`.

- **Claude Code** (`claude` CLI) — default. Recommended models:
  `claude-opus-4-7` for detection, `claude-sonnet-4-6` for PoC generation.
- **OpenAI Codex** (`codex` CLI) — works with GPT-class models.
- **opencode** — runs DeepSeek-V4-Pro (and other providers) through the
  Vercel AI SDK. Two execution modes:
  - CLI per call: `opencode run` invoked once per detect/verify.
  - Persistent server (`--use-api`): one `opencode serve` shared across calls
    via `opencode run --attach`. Faster when there are many findings.

DeepSeek-V4-Pro is interesting because it's cheap (~$0.01 per finding verified
end-to-end) and supports tool calling reliably through opencode, so it can
drive `Bash`/`Read`/`Grep`/`Glob` directly during verification.

Custom invocations are supported via env vars: `CLAUDE_COMMAND`,
`CLAUDE_EXEC_FLAGS`, `CODEX_COMMAND`, `CODEX_EXEC_FLAGS`, `OPENCODE_COMMAND`,
`OPENCODE_EXEC_FLAGS`.

## Example target: OWASP crAPI

The default target wired into the prompts is OWASP crAPI ("completely
ridiculous API"), an intentionally vulnerable Java/Spring Boot training app
with deliberate OWASP API Top 10 issues. Any other intentionally-vulnerable
app with a similar source layout (WebGoat, VAmPI, Juice Shop, DVWS) can be
swapped in by editing the prompts in `01_detect.py` and `02_verify.py`.

### crAPI architecture

```mermaid
flowchart TB
    user["Browser / API Client"]
    agent["Coding agent<br/>(detect + verify)"]
    sandbox["Podman PoC sandbox<br/>(optional)"]

    subgraph host["Local host"]
        user
        agent
        sandbox
    end

    subgraph crapi["OWASP crAPI (Podman Compose)"]
        web["crapi-web<br/>OpenResty / Web UI<br/>localhost:8888"]
        identity["crapi-identity<br/>Java<br/>users, auth, JWT, OTP, vehicles"]
        workshop["crapi-workshop<br/>Python<br/>mechanics, services, orders"]
        community["crapi-community<br/>Go<br/>posts and comments"]
        chatbot["crapi-chatbot<br/>assistant / MCP-style service"]
        gateway["gateway-service<br/>api.mypremiumdealership.com"]
        mailhog["mailhog<br/>test email inbox<br/>localhost:8025"]
        postgres[("postgresdb<br/>SQL data")]
        mongo[("mongodb<br/>NoSQL data + mail storage")]
        chroma[("chromadb<br/>chatbot retrieval store")]
    end

    user -->|"HTTP UI/API"| web
    agent -->|"source analysis"| identity
    agent -->|"generates PoC"| sandbox
    agent -->|"direct HTTP (verify mode)"| web
    sandbox -->|"HTTP evidence"| web

    web --> identity
    web --> workshop
    web --> community
    web --> chatbot
    web --> mailhog

    identity --> postgres
    identity --> mongo
    identity --> mailhog
    identity --> gateway

    workshop --> postgres
    workshop --> mongo
    workshop --> identity
    workshop --> gateway

    community --> postgres
    community --> mongo
    community --> identity

    chatbot --> identity
    chatbot --> mongo
    chatbot --> chroma

    classDef external fill:#eef2ff,stroke:#4f46e5,color:#111827,stroke-width:2px;
    classDef agentNode fill:#ecfeff,stroke:#0891b2,color:#0f172a,stroke-width:2px;
    classDef edge fill:#f8fafc,stroke:#475569,color:#0f172a,stroke-width:2px;
    classDef service fill:#f0fdf4,stroke:#16a34a,color:#052e16,stroke-width:2px;
    classDef data fill:#fff7ed,stroke:#ea580c,color:#431407,stroke-width:2px;
    classDef infra fill:#fdf2f8,stroke:#db2777,color:#500724,stroke-width:2px;

    class user external;
    class agent,sandbox agentNode;
    class web edge;
    class identity,workshop,community,chatbot service;
    class postgres,mongo,chroma data;
    class mailhog,gateway infra;
```

The bounded scope by default is `services/identity` — authentication,
authorization, JWT/OTP, account, and vehicle code paths. That keeps the run
under 5–10 minutes.

## Sample run: 5/5 confirmed against crAPI identity

Latest end-to-end run on `services/identity` returned 5 CONFIRMED findings,
0 FAILED, 0 UNCLEAR, with HTTP evidence captured per finding. Total cost
across detect + 5 verify rounds: ~$0.066 (273k input / 7k output / 265k
cache-read tokens — heavy prompt caching against the same source pack).

| ID    | OWASP    | Class                                 | File:line                                              | Verdict   |
|-------|----------|---------------------------------------|--------------------------------------------------------|-----------|
| f-001 | API1:2023 | BOLA — vehicle location PII leak      | `controller/VehicleController.java:122`                | CONFIRMED |
| f-002 | API2:2023 | `alg:none` accepted (PlainJWT fallback) | `config/JwtProvider.java:199`                        | CONFIRMED |
| f-003 | API2:2023 | RS256→HS256 algorithm confusion       | `config/JwtProvider.java:179`                          | CONFIRMED |
| f-004 | API2:2023 | JKU header → SSRF + key injection     | `config/JwtProvider.java:134`                          | CONFIRMED |
| f-005 | API2:2023 | Unauthenticated PII leak via dashboard | `service/Impl/UserServiceImpl.java:214`               | CONFIRMED |

### f-001 — BOLA on vehicle location

`GET /identity/api/v2/vehicle/{carId}/location` is wired to a method literally
named `getLocationBOLA`. `VehicleServiceImpl.getVehicleLocation` looks up the
vehicle by UUID and returns owner `fullName`, `email`, and GPS coordinates
without comparing the requesting user's identity to `vehicle.getOwner()`.

A freshly signed-up attacker's JWT successfully retrieved Adam's full PII +
GPS coordinates by querying his vehicle UUID:

```
HTTP 200
{
  "carId": "f89b5f21-7829-45cb-a650-299a61090378",
  "fullName": "Adam",
  "email": "adam007@example.com",
  "vehicleLocation": { "latitude": "32.778889", "longitude": "-91.919243" }
}
```

### f-002 — `alg:none` JWT acceptance

`JwtProvider.validateJwtToken` parses the token via `SignedJWT.parse`. When
that throws `ParseException`, the catch block falls back to
`PlainJWT.parse(authToken)` and returns `true` — accepting unsigned tokens as
valid.

Two forged unsigned tokens (`{"alg":"none"}` for `admin@example.com` and
`adam007@example.com`) were sent to `/identity/api/v2/user/dashboard` and
`/identity/api/v2/vehicle/vehicles`. Both returned HTTP 200 with full PII
matching the forged `sub` claim.

### f-003 — RS256 → HS256 algorithm confusion

When the JWT header advertises `alg=HS256`, `getJwtSecret()`
base64-encodes the RSA public key bytes and uses that string as the HMAC
secret for `MACVerifier`. The JWKS endpoint (`/identity/api/v2/jwks.json`) is
exposed unauthenticated, so the public key is trivially fetchable.

Forging a token with `alg=HS256` and signing it with the base64-encoded
public key as HMAC secret bypasses signature verification:

```
HTTP 200 GET /identity/api/v2/user/dashboard
{ "id": ..., "name": "Admin", "email": "admin@example.com",
  "role": "ROLE_ADMIN", "available_credit": 100.0 }
```

### f-004 — JKU header → SSRF + arbitrary key injection

For non-`HS256` tokens, `getKeyFromJkuHeader` extracts the `jku` (JWK Set URL)
claim from the JWT header, makes an unfettered HTTP request to that URL, and
loads the returned JWKS as a trusted key set. Any RSA public key the
attacker serves is accepted for signature verification.

Standing up a tiny HTTP server with the attacker's RSA public key:

```
http://host.containers.internal:9999/jwks.json
```

A forged RS256 token with `jku` pointing at that URL and signed with the
attacker's matching private key was accepted. Bonus: the `jku` fetch is a
classic SSRF primitive (the server will fetch any URL).

### f-005 — Unauthenticated PII leak via dashboard

`GET /identity/api/v2/user/dashboard` is `permitAll()` in `WebSecurityConfig`,
and the controller calls `getUserByRequestToken` which internally invokes
`getUserFromTokenWithoutValidation` — JWT signature is never checked. Any
unsigned JWT carrying a `sub` claim returns the corresponding user's full
profile.

```
GET /identity/api/v2/user/dashboard
Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbkBleGFtcGxlLmNvbSJ9.

HTTP 200
{ "id": 5, "name": "Admin", "email": "admin@example.com",
  "number": "9010203040", "role": "ROLE_ADMIN",
  "available_credit": 100.0 }
```

Full per-finding evidence (request log, response excerpts, source
references) is in `findings/verified-latest.json`.

## Repository layout

```text
.
├── docker/
│   └── poc-runner/        # Podman image for sandboxed PoC execution
├── findings/              # candidate JSONs + verified runs + run records
├── scripts/
│   ├── 01_detect.py       # source-aware candidate finding generation
│   ├── 02_verify.py       # PoC generation + sandbox or direct execution
│   ├── 03_demo.py         # end-to-end orchestration
│   ├── api.py             # opencode HTTP server lifecycle + run-attach helpers
│   ├── common.py          # LLM invocation, JSON parsing, run recorder
│   ├── models.py          # Pydantic schemas for findings/verifications
│   └── sandbox_mcp.py     # Podman PoC runner
├── pyproject.toml
└── uv.lock
```

## Requirements

- Python 3.12, `uv`
- One coding agent CLI on `PATH`:
  - `claude` (Claude Code), or
  - `codex` (OpenAI Codex) + Node.js, or
  - `opencode`
- Podman + `podman compose` or `podman-compose` (only required for the
  sandbox PoC path)

If a CLI lives in a Toolbox container while Podman runs on the base system,
override the launcher with `CLAUDE_COMMAND` / `CODEX_COMMAND` /
`OPENCODE_COMMAND`.

## Install

```bash
uv sync
```

If your environment has a read-only global uv cache:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv sync
```

## Cache mode (no LLM, no target)

Deterministic walk-through of the flow without the LLM, crAPI, network, or
Podman:

```bash
uv run python scripts/03_demo.py --from-cache --no-pause
```

Expected:

```text
Metrics: 2 confirmed, 1 unclear, 0 failed.
```

Drop `--no-pause` to step through each stage.

## Live setup

Clone the target into the repo root:

```bash
git clone https://github.com/OWASP/crAPI.git
```

Start it:

```bash
cd crAPI/deploy/docker
podman compose -f docker-compose.yml up -d
```

Verify:

```bash
curl -i http://localhost:8888
```

(Override the URL with `--target-url` when running against a different
deployment.)

## Build the PoC sandbox image (optional)

Only needed for the sandbox PoC path. Skip for the direct-execution path
used by `--use-api`.

```bash
podman build -t strike-demo/poc-runner:latest docker/poc-runner
```

The image contains Python, `httpx`, `requests`, `curl`, `jq`. PoCs run with
read-only filesystem, memory/PID limits, and `TARGET_URL` injected as env.

## End-to-end with Claude

```bash
uv run python scripts/03_demo.py \
  --service identity \
  --max-findings 3 \
  --target-url http://localhost:8888 \
  --llm claude \
  --model claude-opus-4-7 \
  --detect-timeout 1800 \
  --codex-timeout 1800 \
  --runtime podman \
  --no-pause
```

## End-to-end with DeepSeek via opencode

DeepSeek-V4-Pro through opencode, using the persistent-server path so the
agent can `curl` directly against the target without a Python sandbox in the
middle:

```bash
uv run python scripts/03_demo.py \
  --llm opencode --use-api \
  --model deepseek/deepseek-v4-pro \
  --candidates findings/candidates-f002-f003.json \
  --no-pause
```

The opencode provider config (in `~/.config/opencode/opencode.json`) needs
the DeepSeek provider and the auto-allow permission rules for `bash`,
`external_directory`, `webfetch` so the agent can drive curl without prompts.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "bash": "allow",
    "external_directory": "allow",
    "webfetch": "allow"
  },
  "provider": {
    "deepseek": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "DeepSeek",
      "options": {
        "baseURL": "https://api.deepseek.com",
        "apiKey": "..."
      },
      "models": {
        "deepseek-v4-pro": {
          "name": "DeepSeek-V4-Pro",
          "limit": { "context": 1048576, "output": 262144 }
        }
      }
    }
  }
}
```

## End-to-end with Codex

```bash
uv run python scripts/03_demo.py \
  --service identity \
  --max-findings 3 \
  --target-url http://localhost:8888 \
  --llm codex \
  --model gpt-5.5 \
  --detect-timeout 1800 \
  --codex-timeout 1800 \
  --runtime podman \
  --no-pause
```

## Seeded candidates (skip detect)

Useful when iterating on the verify path or running a reliable timed walk-through.

```bash
uv run python scripts/03_demo.py \
  --candidates findings/candidates-f002-f003.json \
  --max-findings 2 \
  --target-url http://localhost:8888 \
  --llm opencode --use-api \
  --model deepseek/deepseek-v4-pro \
  --no-pause
```

## Outputs

Every run produces:

- `findings/candidates-<timestamp>.json` — detect output
- `findings/verified-<timestamp>.json` — per-finding verdicts + evidence
- `findings/demo-run-<timestamp>.json` — full reproducible run record
- `findings/runs/run-<timestamp>.json` — partial state, written continuously
  during the run; `tail -f` it from another terminal to follow progress

## Operational fields on every finding

The detect step does not just emit "there's a BOLA in foo.java". Each finding
carries:

- `victim_identity` — who the exploit targets / impersonates.
- `attack_request` — method, path, headers, body, notes.
- `expected_response_signal` — concrete substring/field that proves the bug
  fired.
- `setup_state` — steps the PoC runs before the attack (signup, login).
- `target_state_required` — preexisting target state the PoC cannot create
  itself (seed users, fixed UUIDs); `null` means self-sufficient.

These are authoritative for the verifier — it builds the exploit directly
from them rather than improvise.

## Useful commands

```bash
uv run ruff check .
uv run ruff format .
```

Run the sandbox directly against an existing PoC:

```bash
uv run python scripts/sandbox_mcp.py run poc.py \
  --target-url http://localhost:8888 \
  --runtime podman
```

## Troubleshooting

### `podman` not found / `podman compose` not available

```bash
command -v podman
podman-compose -f docker-compose.yml up -d   # fallback
```

### crAPI is unreachable

```bash
podman ps
curl -i http://localhost:8888
```

### LLM is slow or unavailable

Cache mode:

```bash
uv run python scripts/03_demo.py --from-cache
```

### Claude refuses a specific finding

The verifier catches refusals, marks the finding as `UNCLEAR` with the error
in evidence, and continues. For consistent refusals, rephrase the hypothesis
(avoid "any user including admin" language) or fall back to `--llm codex` /
`--llm opencode`.

### opencode + DeepSeek silently does not run tools

If you see lots of streamed text but no tool calls, two common causes:

1. The DeepSeek model is configured as a reasoning model in opencode config
   (`reasoning: true`, `thinking: { type: "enabled" }`) — reasoning variants
   may not emit tool calls. Try `deepseek-v4-flash` or remove the reasoning
   flags.
2. Permission gates are blocking `bash` / `external_directory`. Add the
   `permission` block shown above to your opencode config.

### Codex stuck on approval prompts

```bash
CODEX_EXEC_FLAGS="--dangerously-bypass-approvals-and-sandbox" uv run python ...
```

Use only against authorized, intentionally-vulnerable local targets.
