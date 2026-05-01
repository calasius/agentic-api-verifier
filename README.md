# Strike Demo

Vulnerability auto-verification demo for OWASP crAPI.

The demo shows a 5-10 minute flow where an LLM agent (Claude by default,
Codex optional) detects candidate API vulnerabilities, generates an executable
proof of concept for each finding, runs that PoC in an isolated Podman
sandbox, and returns a structured verdict:

- `CONFIRMED`: executable evidence supports the hypothesis.
- `FAILED`: the PoC ran and did not support the hypothesis.
- `UNCLEAR`: the system could not prove the finding and should escalate it to a
  human reviewer.

The intended message is narrow: this does not replace human security reviewers.
It removes mechanical verification work when a finding can be safely reproduced.

## LLM Provider

Selectable via `--llm {claude,codex}` (default: `claude`).

- `claude` — Claude Code CLI (`claude` on PATH). Recommended. Runs on the host.
  Recommended models: `claude-opus-4-7` for detection (deeper reasoning over
  source) and `claude-sonnet-4-6` for PoC generation (faster). The demo wires
  an authorization frame via `--append-system-prompt` so the agent treats the
  run as an authorized test against an intentionally vulnerable training app.
- `codex` — OpenAI Codex CLI. Kept for compatibility. Configurable through
  `CODEX_COMMAND` and `CODEX_EXEC_FLAGS` (useful when Codex/Node.js live in a
  Toolbox container while Podman runs on the base system).

Custom invocations are supported via env vars: `CLAUDE_COMMAND`,
`CLAUDE_EXEC_FLAGS`, `CODEX_COMMAND`, `CODEX_EXEC_FLAGS`.

## Target Application: OWASP crAPI

The application under test is OWASP crAPI, the "completely ridiculous API".
It is an intentionally vulnerable B2C car-service platform built for API
security training. A user can create an account, log in, register vehicles,
request mechanic services, buy car accessories, and interact with a community
blog/comments area.

For this demo, crAPI is useful because it looks like a realistic API-backed
product while deliberately exposing OWASP API Top 10 weaknesses. The demo agent
does not need to attack a real third-party system: it can analyze and verify
findings against this authorized local target.

### crAPI Architecture

```mermaid
flowchart TB
    user["Browser / API Client"]
    demo["strike-demo<br/>LLM agent + verifier"]
    sandbox["Podman PoC sandbox<br/>strike-demo/poc-runner"]

    subgraph host["Local host"]
        user
        demo
        sandbox
    end

    subgraph crapi["OWASP crAPI running with Podman Compose"]
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
    demo -->|"source analysis"| identity
    demo -->|"generates PoC"| sandbox
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
    classDef demoNode fill:#ecfeff,stroke:#0891b2,color:#0f172a,stroke-width:2px;
    classDef edge fill:#f8fafc,stroke:#475569,color:#0f172a,stroke-width:2px;
    classDef service fill:#f0fdf4,stroke:#16a34a,color:#052e16,stroke-width:2px;
    classDef data fill:#fff7ed,stroke:#ea580c,color:#431407,stroke-width:2px;
    classDef infra fill:#fdf2f8,stroke:#db2777,color:#500724,stroke-width:2px;

    class user external;
    class demo,sandbox demoNode;
    class web edge;
    class identity,workshop,community,chatbot service;
    class postgres,mongo,chroma data;
    class mailhog,gateway infra;
```

In the live demo, the bounded scope is `services/identity`. That keeps the run
short and focuses the agent on authentication, authorization, JWT/OTP, account,
and vehicle-management code paths.

## Repository Layout

```text
strike-demo/
├── AGENTS.md
├── PLAN.md
├── README.md
├── docker/
│   └── poc-runner/
│       └── Dockerfile
├── findings/
│   ├── cache/
│   │   └── identity-candidates.json
│   └── *.json
├── scripts/
│   ├── 01_detect.py
│   ├── 02_verify.py
│   ├── 03_demo.py
│   ├── common.py
│   ├── models.py
│   └── sandbox_mcp.py
├── pyproject.toml
└── uv.lock
```

## Requirements

- Python 3.12
- `uv`
- Either:
  - Claude Code CLI (`claude`) authenticated and on PATH (default), or
  - OpenAI Codex CLI plus Node.js
- Podman
- `podman compose` or `podman-compose`

This project is configured for Podman by default. The scripts accept
`--runtime podman` explicitly when needed.

If you need to run the LLM CLI in a different environment than the host (e.g.
Codex inside a Fedora Toolbox container while Podman runs on the base system),
override the launcher via `CLAUDE_COMMAND` or `CODEX_COMMAND`:

```bash
CODEX_COMMAND="toolbox run --container dev codex" UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py \
  --service identity \
  --max-findings 3 \
  --target-url http://localhost:8888 \
  --llm codex \
  --model gpt-5.5 \
  --detect-timeout 1800 \
  --codex-timeout 1800 \
  --runtime podman
```

## Install Dependencies

```bash
uv sync
```

If your environment has a read-only global uv cache, use a writable cache:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv sync
```

## Rehearsal Mode

Use rehearsal mode when you want a deterministic demo without depending on
the LLM, crAPI, network state, or the Podman runner.

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py --from-cache --no-pause
```

Expected result:

```text
Metrics: 2 confirmed, 1 unclear, 0 failed.
```

For a live presentation, omit `--no-pause` so the script pauses between steps:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py --from-cache
```

## Live Setup With crAPI

Clone crAPI into the repository root:

```bash
git clone https://github.com/OWASP/crAPI.git
```

Start crAPI with Podman Compose:

```bash
cd crAPI/deploy/docker
podman compose -f docker-compose.yml up -d
```

If your environment uses the standalone compose wrapper:

```bash
cd crAPI/deploy/docker
podman-compose -f docker-compose.yml up -d
```

Verify the target is reachable:

```bash
curl -i http://localhost:8888
```

The scripts use `http://localhost:8888` by default. Override it with
`--target-url` if needed.

## Build the PoC Runner

From the repository root:

```bash
podman build -t strike-demo/poc-runner:latest docker/poc-runner
```

The runner image contains Python, `httpx`, `requests`, `curl`, and `jq`. PoCs are
mounted read-only into the container and executed with:

- read-only filesystem,
- memory limit,
- PID limit,
- automatic cleanup,
- target URL passed through `TARGET_URL`.

## Live Detection

Run the detector against `services/identity`:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/01_detect.py \
  --service identity \
  --llm claude \
  --model claude-opus-4-7
```

This writes:

- `findings/candidates-<timestamp>.json`
- `findings/candidates-latest.json`

Under the hood, with `--llm claude` the detector calls:

```bash
claude -p --append-system-prompt "<authorization frame>" --model <model> \
  --output-format json "<detection prompt>"
```

(working directory is set to `./crAPI`). With `--llm codex` it falls back to
`codex exec --model <model> --json --cd ./crAPI "<detection prompt>"`.

Before calling the LLM, the detector performs a local focused preselection of
the most relevant Java files: controllers, JWT/security config, user services,
vehicle services, and related repositories/models. The prompt includes numbered
source excerpts so the agent can produce concrete file/line findings without
exploring the full service tree first.

Each finding emitted is **operational**, not just descriptive. In addition to
the bug class, file, and line, every finding carries:

- `victim_identity` — who the exploit targets / impersonates.
- `attack_request` — method, path, headers, body, and notes for the request.
- `expected_response_signal` — the concrete substring/field that proves the
  bug fired.
- `setup_state` — steps the PoC runs before the attack (signup, login, etc).
- `target_state_required` — preexisting target state the PoC cannot create
  itself (seed users, fixed UUIDs); `null` means the PoC is self-sufficient.

These fields are authoritative for the PoC generator, which is instructed to
build the exploit directly from them rather than improvise endpoints.

The expected output schema is validated with Pydantic before it is written.

## Live Verification

Verify the latest candidates. In live mode, this step calls the LLM again to
generate a finding-specific Python PoC, then executes that PoC through the
Podman sandbox:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/02_verify.py \
  --input findings/candidates-latest.json \
  --target-url http://localhost:8888 \
  --llm claude \
  --model claude-opus-4-7 \
  --runtime podman
```

This writes:

- `findings/verified-<timestamp>.json`
- `findings/verified-latest.json`

If the LLM refuses, errors, or times out on a single finding, that finding is
recorded as `UNCLEAR` with the error as evidence and the loop continues with
the next finding instead of aborting the whole run.

## Seeded Candidate Flow

For the most reliable live demo, assume a scanner or security tool already
produced candidate findings. This skips open-ended discovery and demonstrates
the agentic part that matters most: PoC generation, sandbox execution, and
evidence reporting.

Seeded crAPI identity candidates live at:

```text
findings/candidates/identity-known.json
```

Run the seeded candidate flow:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py \
  --candidates findings/candidates/identity-known.json \
  --max-findings 1 \
  --target-url http://localhost:8888 \
  --llm claude \
  --model claude-sonnet-4-6 \
  --runtime podman \
  --codex-timeout 900 \
  --no-pause
```

This still uses the LLM to generate the PoC and still executes the PoC inside
the Podman sandbox. It only skips the slow discovery step.

If the LLM CLI is too slow or gets stuck, run the same seeded flow with a
deterministic template PoC for known crAPI findings:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py \
  --candidates findings/candidates/identity-known.json \
  --max-findings 1 \
  --target-url http://localhost:8888 \
  --runtime podman \
  --poc-provider template \
  --no-pause
```

This path still executes the PoC inside the Podman sandbox and still produces
the same evidence/report artifacts. It only replaces LLM PoC generation with a
predefined PoC template for known candidates.

If Codex gets stuck waiting on sandbox/approval behavior during local demo
work, pass explicit `codex exec` flags with `CODEX_EXEC_FLAGS`. For example:

```bash
CODEX_COMMAND="toolbox run --container dev codex" \
CODEX_EXEC_FLAGS="--dangerously-bypass-approvals-and-sandbox" \
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py \
  --candidates findings/candidates/identity-known.json \
  --max-findings 1 \
  --target-url http://localhost:8888 \
  --llm codex \
  --model gpt-5.5 \
  --runtime podman \
  --codex-timeout 900 \
  --no-pause
```

Use that bypass only for this local, intentionally vulnerable crAPI environment.

During a run, progress is printed to the terminal and partial state is
continuously written to:

```text
findings/runs/run-<timestamp>.json
```

In another terminal, follow partial results with:

```bash
tail -f findings/runs/run-*.json
```

## End-to-End Live Demo

Run the full flow:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py \
  --service identity \
  --max-findings 3 \
  --target-url http://localhost:8888 \
  --llm claude \
  --model claude-opus-4-7 \
  --detect-timeout 1800 \
  --codex-timeout 1800 \
  --runtime podman
```

Use `--no-pause` for automated rehearsals:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py \
  --service identity \
  --max-findings 3 \
  --target-url http://localhost:8888 \
  --llm claude \
  --runtime podman \
  --no-pause
```

Every run writes a reproducible record:

```text
findings/demo-run-<timestamp>.json
```

## Useful Commands

Run lint:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run ruff check .
```

Format files:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run ruff format .
```

Run the sandbox directly against a PoC file:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/sandbox_mcp.py run poc.py \
  --target-url http://localhost:8888 \
  --runtime podman
```

## Troubleshooting

### `podman` is not found

Install Podman or make sure it is available in `PATH`:

```bash
command -v podman
```

### `podman compose` is not available

Use `podman-compose` if it is installed:

```bash
podman-compose -f docker-compose.yml up -d
```

### crAPI is unreachable

Check containers:

```bash
podman ps
```

Then verify the HTTP endpoint:

```bash
curl -i http://localhost:8888
```

### LLM is slow or unavailable

Use cache mode for the presentation:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py --from-cache
```

### Claude refuses a specific finding

Claude's safety classifiers occasionally refuse PoC generation. The verifier
catches refusals, marks the finding as `UNCLEAR` with the error in evidence,
and continues with the next finding. If a specific finding refuses
consistently, rephrase its hypothesis (e.g. avoid "any user including admin"
language) or fall back to `--llm codex` for that run.

### Podman is on the base system but Codex/Node.js are in Toolbox

Use `CODEX_COMMAND` so only Codex runs inside Toolbox while the sandbox still
uses base-system Podman:

```bash
CODEX_COMMAND="toolbox run --container dev codex" UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/03_demo.py \
  --service identity \
  --max-findings 3 \
  --target-url http://localhost:8888 \
  --llm codex \
  --model gpt-5.5 \
  --detect-timeout 1800 \
  --codex-timeout 1800 \
  --runtime podman
```

### uv cannot write to its cache

Use a writable cache directory:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv sync
```

## Demo Narrative

1. Show the problem: human reviewers spend time validating executable findings.
2. Run candidate detection over one bounded service: `services/identity`.
3. Show the candidate table with source references, hypotheses, and the
   operational fields (`attack_request`, `setup_state`, `expected_response_signal`).
4. Show the LLM generating a PoC for each finding.
5. Run each generated PoC inside the Podman sandbox.
6. Emphasize the important distinction between `CONFIRMED` and `UNCLEAR`.
7. Close with metrics and the question of where this could reduce manual load.

Suggested questions for the CTO:

1. What percentage of current findings are mechanically verifiable?
2. Where do general-purpose models fall short in your production workflow?
3. Which part of reviewer work would be most valuable to automate first?
