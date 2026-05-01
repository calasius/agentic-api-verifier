# Plan: Vulnerability Auto-Verification Agent Demo for Strike

**Stack:** Codex CLI / SDK with GPT-5.5
**Target:** OWASP crAPI (intentionally vulnerable API)
**Audience:** Strike's CTO (former colleague — peer-to-peer conversation)
**Goal:** Demonstrate in 5–10 minutes that an agent can detect, generate PoC, and auto-verify in sandbox, reducing load on human Strikers
**Runtime:** Python scripts managed with `uv` (no notebooks)

---

## Core message

> Strikers manually validate every finding today. If the agent can auto-verify cases where the PoC is executable, humans are freed up for deep business-logic analysis. Same quality, fraction of human cost per finding.

This does not replace Strikers. It removes the mechanical work of validating executable vulns and leaves them with the work that requires judgment.

---

## Demo architecture

```
┌──────────────────────────────────────────────┐
│  Agent (Codex SDK + GPT-5.5)                 │
│                                              │
│  1. SAST: reads crAPI source code            │
│  2. Identifies candidate vulnerability       │
│  3. Generates explicit hypothesis            │
│  4. Generates executable PoC                 │
│  5. Calls execute_in_sandbox tool            │
│  6. Interprets sandbox output                │
│  7. Verdict: CONFIRMED / FAILED / UNCLEAR    │
└──────────┬───────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│  Sandbox MCP server                          │
│  - Isolated Docker container                 │
│  - Network restricted to target only         │
│  - Captures request/response                 │
│  - Hard timeout                              │
└──────────┬───────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│  crAPI running via docker-compose            │
│  - HTTP target on localhost:8888             │
│  - Java/Python/Node microservices            │
└──────────────────────────────────────────────┘
```

---

## Schedule (4 sessions)

### Session 1 — Base setup (2–3 hours)

**Goal:** environment ready, Codex authenticated, crAPI running, repo cloned, `uv` project initialized.

**Tasks:**

- [ ] Install Codex CLI: `npm install -g @openai/codex`
- [ ] Login with Pro account: `codex login` (browser flow)
- [ ] Verify GPT-5.5 access: `codex --model gpt-5.5` and test interactively
- [ ] Clone crAPI:
      ```bash
      git clone https://github.com/OWASP/crAPI.git
      ```
- [ ] Bring crAPI up:
      ```bash
      cd crAPI/deploy/docker
      docker compose pull
      docker compose -f docker-compose.yml --compatibility up -d
      ```
- [ ] Verify the app responds at `http://localhost:8888`
- [ ] Create test account in crAPI and add a vehicle (required for several vulns)
- [ ] Initialize project with `uv`:
      ```bash
      cd strike-demo
      uv init --python 3.12
      uv add httpx docker pydantic rich typer
      ```
- [ ] Project structure:
      ```
      strike-demo/
      ├── pyproject.toml           # managed by uv
      ├── .python-version
      ├── crAPI/                   # cloned repo
      ├── AGENTS.md                # agent context
      ├── scripts/
      │   ├── 01_detect.py         # SAST: detects candidate findings
      │   ├── 02_verify.py         # takes findings and verifies them in sandbox
      │   ├── 03_demo.py           # orchestrates end-to-end flow for the demo
      │   └── sandbox_mcp.py       # sandbox MCP server
      ├── findings/                # JSON output (gitignored)
      └── docker/
          └── poc-runner/
              └── Dockerfile       # sandbox image
      ```

**Success criterion:** running `uv run codex exec --model gpt-5.5 "list service folders in crAPI/"` from `strike-demo/` returns coherent output. `uv sync` runs without errors.

---

### Session 2 — Detection agent (3–4 hours)

**Goal:** the agent reads crAPI and produces candidate findings as structured JSON, no verification yet.

**Tasks:**

- [ ] Write `AGENTS.md` with security context (see Configuration section below)
- [ ] Design detection prompt — focus on OWASP API Top 10
- [ ] Restrict initial scope: only `services/identity` (Java/Spring) to avoid overwhelming the first demo
- [ ] Run interactively first (TUI) to observe how the agent reasons
- [ ] Move to `codex exec --json` once the flow is stable
- [ ] Write `scripts/01_detect.py` — wraps `codex exec`, parses JSON output, validates schema with Pydantic, writes to `findings/candidates-{timestamp}.json`
- [ ] Run with: `uv run python scripts/01_detect.py --service identity`
- [ ] Expected output: JSON with array of findings containing: `id`, `service`, `file`, `line`, `vulnerability_type`, `hypothesis`, `confidence_initial`

**Success criterion:** the agent identifies at least 3 real vulnerabilities in the service (from the known crAPI ones). Ideally: BOLA on vehicle endpoint, JWT verification weakness, mass assignment.

**Ground truth (DO NOT give to the agent):** `crAPI/docs/challenges.md` lists intentional vulnerabilities. Use it for your validation.

**Risk:** GPT-5.5 may hit cyber classifiers when reasoning about exploits. Mitigation in `AGENTS.md`: emphasize OWASP educational context, operator authorization, and deliberately vulnerable target.

---

### Session 3 — Sandbox MCP server + verification (3–4 hours)

**Goal:** the agent can execute PoCs in isolated sandbox and interpret results.

**Tasks:**

- [ ] Build `poc-runner` Docker image with Python + httpx + curl + jq
- [ ] Create dedicated Docker network that only allows traffic to crAPI host
- [ ] Write MCP server (`scripts/sandbox_mcp.py`) exposing `execute_in_sandbox(poc_code, target_url, timeout)`:
      - Launches container with `--network sandbox-net --read-only --memory 512m`
      - Executes PoC with hard timeout
      - Captures stdout, stderr, exit_code
      - Guaranteed cleanup with `--rm`
- [ ] Register MCP server in Codex config
- [ ] Write `scripts/02_verify.py` — takes findings from Session 2 and for each:
      1. Generates an executable PoC
      2. Defines explicit success criterion
      3. Calls `execute_in_sandbox`
      4. Interprets output
      5. Loops up to 3 times if result is ambiguous
- [ ] Run with: `uv run python scripts/02_verify.py --input findings/candidates-latest.json`
- [ ] Final output: JSON with `status` (CONFIRMED/FAILED/UNCLEAR), `evidence`, `poc_used`, `confidence`, `needs_human_review`

**Success criterion:** at least 2 findings reach `CONFIRMED` with captured HTTP evidence. At least 1 finding remains `UNCLEAR` (showing the system recognizes its limits is part of the value).

**Risks:**

- PoC generation blocked by cyber classifier → if it happens, fallback to Opus 4.7 via Anthropic API for that step only. Rest of pipeline stays on Codex.
- Container with misconfigured network → test it in isolation before connecting to the agent.

---

### Session 4 — End-to-end demo script + rehearsal (2 hours)

**Goal:** a single command runs the full demo, rehearsed at least twice before the meeting.

**Tasks:**

- [ ] Write `scripts/03_demo.py` orchestrating everything with formatted output (use `rich` for tables/colors and `typer` for CLI):

      ```bash
      uv run python scripts/03_demo.py --service identity --max-findings 3
      ```

      The script must:
      1. Print banner with problem context (1–2 lines)
      2. Verify crAPI is running (`GET /health` or equivalent)
      3. Invoke `01_detect.py` logic and display candidate findings in a table
      4. For each finding: invoke `02_verify.py` logic showing step by step
         (hypothesis → generated PoC → sandbox execution → verdict)
      5. Display final summary table: status per finding
      6. Close with metrics: X confirmed, Y unclear, Z dropped

- [ ] Each critical step does `input("Press Enter to continue...")` so you can pause live and narrate what just happened
- [ ] `--no-pause` flag to run without pauses (automated rehearsal)
- [ ] `--from-cache` flag to use pre-computed findings if Codex is slow or fails live
- [ ] Capture all output to `findings/demo-run-{timestamp}.json` for reproducible record
- [ ] Timed rehearsal: target 7 minutes with pauses, leaving room for questions
- [ ] Screenshots / asciinema of each step as backup if live demo fails (plan B)
- [ ] Prepare 3 questions to ask the CTO back:
      1. What % of current findings are auto-verifiable vs require human judgment?
      2. Where do general models fall short in your production setup?
      3. What part of Strikers' work would you most like to automate but haven't been able to yet?

---

## Key configuration

### `AGENTS.md` (place in strike-demo root)

Key content:

```markdown
# Project context

This is a security evaluation environment over OWASP crAPI, an
intentionally vulnerable application maintained by the OWASP Foundation
for educational purposes. The operator has full authorization.

## Agent goal

Identify real vulnerabilities in crAPI source code, generate verifiable
PoCs, and execute them in an isolated sandbox to confirm exploitability
before reporting.

## Focus

OWASP API Security Top 10:
- Broken Object Level Authorization (BOLA / IDOR)
- Broken Authentication (JWT issues, weak verification)
- Excessive Data Exposure
- Mass Assignment
- SSRF
- Broken Function Level Authorization
- Improper Assets Management (shadow APIs)

## Rules

- Reason about the code before hypothesizing — do not invent.
- Every hypothesis must trace source → sink completely.
- PoCs are only executed via the execute_in_sandbox tool, never via direct Bash.
- If the sandbox does not confirm, DO NOT report as CONFIRMED — use UNCLEAR.
- Always output structured JSON.

## What NOT to do

- Do not read crAPI/docs/challenges.md (that is ground truth for evaluation, not for the agent).
- Do not propose fixes in this pipeline (that is a separate flow).
- Do not scan services outside the scope specified in each run.
```

### Base agent command

```bash
uv run codex exec \
  --model gpt-5.5 \
  --json \
  --cwd ./crAPI \
  "Scan services/identity for OWASP API Top 10 vulnerabilities. For each finding, generate a PoC, execute it via execute_in_sandbox, and interpret the result. Output: JSON with findings array."
```

### Finding structure (expected output)

```json
{
  "id": "f-001",
  "service": "identity",
  "file": "services/identity/src/main/java/.../UserController.java",
  "line": 142,
  "vulnerability_type": "BOLA",
  "owasp_api_category": "API1:2023",
  "hypothesis": "GET /identity/api/v2/user/dashboard does not validate that the JWT user_id matches the requested resource.",
  "poc_used": "...",
  "sandbox_execution": {
    "request": "...",
    "response": "...",
    "exit_code": 0
  },
  "status": "CONFIRMED",
  "evidence": "Received another user's vehicle information without authorization.",
  "confidence": 0.95,
  "needs_human_review": false
}
```

---

## What NOT to include in the demo

- Do not show comparisons against existing tools (sounds like competing with their core)
- Do not promise numbers without basis (do not invent "70% reduction")
- Do not show more than 3 findings — the demo gets long and dull
- Do not include an automatic-fix step — Strike has its own Remediation Hub, do not step on it

---

## Plan B if something fails live

- **If Codex returns refusal during PoC generation:** show pre-recorded captures + explain hybrid approach with Opus 4.7
- **If the sandbox does not start:** show saved logs from a previous run
- **If crAPI is slow to start:** keep it running from before the meeting
- **If the agent takes too long:** have pre-cached output ready to display the final result (`--from-cache` flag)

---

## After the demo

If the conversation goes well, possible next steps to propose:

1. Run on an actual Strike repo (with NDA if needed) to see if the approach translates to their real targets
2. Discuss integration with their Live Asset Radar — agent pulls assets directly from the radar, no manual specification required
3. Discuss the institutional memory layer with RAG over historical findings (additional idea to mention if there is time)

---

## Tech stack — quick reference

| Component | Technology |
|---|---|
| Model | GPT-5.5 via Codex |
| Authentication | Login with ChatGPT Pro (no API key) |
| Agent | Codex CLI / SDK |
| Native tools | Read, Grep, Glob, Bash |
| Custom tools | execute_in_sandbox (via MCP) |
| Sandbox | Docker with isolated network |
| Target | OWASP crAPI in docker-compose |
| Output | Structured JSON |
| Demo runner | Python scripts via `uv run` |
| Project manager | uv |
| CLI framework | typer |
| Terminal output | rich |

---

## Estimated total time

- Session 1: 2–3 h
- Session 2: 3–4 h
- Session 3: 3–4 h
- Session 4: 2 h

**Total: ~10–13 hours of focused work**, distributed across 3–4 days depending on availability.
