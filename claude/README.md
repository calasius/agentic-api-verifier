# Claude Code strategy

Three-stage pipeline (`surveyor` → `hunter` → `exploiter`) running through
Claude Code, with all live execution routed through the same `apisec-sandbox`
Podman container the opencode strategy uses. The agents see the source tree
read-only and call shell commands only via an MCP server that proxies into
the container.

## Layout

```
claude/
├── agents/
│   ├── surveyor.md       # recon — produces a structured survey of the API surface
│   ├── hunter.md         # finds OWASP API Top 10 findings, given the survey
│   └── exploiter.md      # verifies one finding by attacking the live target
├── mcp/
│   └── apisec-bridge.py  # symlink → ../../opencode/mcp/apisec-bridge.py
├── run.sh                # end-to-end orchestrator
└── README.md             # this file

docker/apisec-runner/     # SHARED — toolkit container image (curl, jwt_tool, ...)
```

## How this maps to Claude Code primitives

- **Subagents** — each phase is a Claude Code subagent declared in
  `claude/agents/<name>.md` (YAML frontmatter + markdown body).
  - `name` and `description` register the agent with Claude.
  - `tools` is the strict allowlist for that agent. Anything not in the
    list is unavailable, so the hunter / exploiter cannot call native
    `Bash`/`Edit`/`Write`/`WebFetch` — only the MCP-provided
    `mcp__apisec_sandbox__bash`. The surveyor's list is even tighter
    (no shell access at all).
  - The body of the markdown file is the agent's system prompt.

- **MCP server** — `run.sh` generates a per-run `mcp.json` with an absolute
  path to the shared `apisec-bridge.py` and passes it to Claude via
  `--mcp-config <file> --strict-mcp-config`. The bridge proxies tool calls
  into the running container via `podman exec`.

- **Per-run isolation** — the agents are installed under
  `<workspace>/.claude/agents/` as per-file symlinks at run start and
  removed at run end (the `EXIT` trap in `run.sh`). Nothing persistent
  is written to the workspace.

## Why this design

The agents do not run shell commands on the host. Their `tools` frontmatter
denies all native shell tools by simply omitting them from the allowlist.
The hunter and exploiter only have access to `mcp__apisec_sandbox__bash`,
which is an MCP-provided tool that runs the command inside a container with:

- **read-only mount of the source tree** at `/workspace`
- **writable tmpfs scratch** at `/sandbox` (200 MB)
- **toolkit pre-installed** — see `/sandbox/TOOLS.md` inside the container
  (curl, httpie, jwt_tool, sqlmap, ffuf, kr, arjun, python httpx/pyjwt/
  cryptography, jq, db clients, ...)

This separates the agent's "brain" (Claude Code + Claude API) from its
"hands" (the container). Compromising the agent's exploit code cannot pivot
back to the host.

## Requirements

- `claude` Claude Code CLI on PATH
- `podman` (rootless works)
- `python3` (used by the MCP bridge — only stdlib)
- A model the user is authorized to run with `claude --model <name>`. The
  default is `claude-sonnet-4-6`. Use `claude-opus-4-7` for surveyor /
  hunter when you want more depth.

## Quickstart

From the repo root (the parent of this directory):

```bash
claude/run.sh \
    --target-url http://localhost:8888 \
    --workspace ./crAPI \
    --model claude-sonnet-4-6
```

Flags:
- `--target-url` — base URL of the API under test
- `--workspace` — directory to mount read-only at `/workspace`
- `--model` — Claude model name or alias
- `--scope` — optional hint passed to the surveyor (e.g. `services/identity only`)
- `--oracles-email` — optional URL of a test SMTP inbox
- `--findings <path>` — skip survey + hunter, verify these findings instead
- `--skip-build` — skip rebuilding the runner image
- `--keep-container` — leave the sandbox container running after the run
- `--max-turns N` — Claude per-call turn cap (default 60)

Output goes to `findings/claude-runs/<timestamp>/`:

```
survey.json           # surveyor output
findings.json         # hunter output
verdicts/<id>.json    # one per finding from exploiter
*.jsonl               # raw streamed JSON events from each agent
mcp.json              # the per-run MCP config used
```

## Customizing the toolkit

Add or remove tools by editing `docker/apisec-runner/Dockerfile` and
re-building (`run.sh` does this automatically unless `--skip-build`). The
manifest the agents read at runtime is `docker/apisec-runner/TOOLS.md` —
keep it in sync with what's actually installed.

## Troubleshooting

### "agent <name> not found"

Check `<workspace>/.claude/agents/` exists and has the symlinks. `run.sh`
creates them at startup; if the script crashed early they may not be
there. Re-run; the cleanup trap is idempotent.

### "tool mcp__apisec_sandbox__bash not available"

Most likely the MCP server failed to start. Check:
- `cat findings/claude-runs/<ts>/<agent>.err` — Claude Code logs MCP
  startup errors there.
- `python3 opencode/mcp/apisec-bridge.py` — the script should run (it
  waits for stdin; Ctrl-C exits).
- `cat findings/claude-runs/<ts>/mcp.json` — the absolute path to the
  bridge should be correct.

### Agent calls native Bash anyway

Make sure your `tools` frontmatter list does **not** include `Bash`. With
strict tools, Claude Code only exposes what's in the list.

### Container cannot reach the target

`run.sh` uses `--network host` so `localhost:8888` from inside the
container is the same as on the host. If your target is bound to a
different interface, set `--target-url http://<that-ip>:<port>`.

### Workspace trust prompt

`claude -p` (non-interactive) skips the workspace trust dialog. If you ever
run interactively from the workspace dir, you may need to approve trust
once.
