# Coding-agent strategies

The repo is a small matrix: each coding agent gets its own folder with
the orchestration glue and prompts that fit its native primitives, and
they all share a single Podman image and MCP bridge for the actual
exploit-runtime sandbox.

```
.
├── docker/apisec-runner/        # SHARED — sandbox container image + TOOLS.md
│
├── opencode/                    # opencode strategy
│   ├── agents/                  #   custom agents (markdown + YAML frontmatter)
│   ├── mcp/apisec-bridge.py     #   stdio MCP server: JSON-RPC ↔ podman exec
│   ├── opencode.json            #   project-local opencode config (template)
│   ├── run.sh                   #   end-to-end orchestrator
│   └── README.md
│
├── claude/                      # Claude Code strategy
│   ├── agents/                  #   subagents (markdown + YAML frontmatter)
│   ├── mcp/apisec-bridge.py     #   symlink → opencode/mcp/apisec-bridge.py
│   ├── run.sh                   #   end-to-end orchestrator
│   ├── watch.sh                 #   pretty-print live phase logs
│   └── README.md
│
└── findings/                    # outputs (gitignored)
    ├── opencode-runs/<ts>/
    └── claude-runs/<ts>/
```

The same three system prompts (surveyor, hunter, exploiter) are
translated into each agent's native format. Same target, same toolkit,
same prompts — different coding-agent CLI. That is what makes
apples-to-apples comparison possible.

## Side-by-side

|                         | opencode                                      | Claude Code                                    |
|-------------------------|-----------------------------------------------|------------------------------------------------|
| Agent definition        | `.opencode/agents/<name>.md`                  | `.claude/agents/<name>.md`                     |
| Tool gating             | `permission` map in frontmatter               | `tools` whitelist in frontmatter               |
| MCP tool name           | `apisec-sandbox_bash`                         | `mcp__apisec_sandbox__bash`                    |
| MCP registration        | `opencode.json` `mcp` block                   | `--mcp-config <file> --strict-mcp-config`      |
| Server lifetime         | `opencode serve` shared across phases         | one process per phase                          |
| Stream format           | flat (`type: text \| tool_use \| step_finish`) | wrapped (`assistant.message.content[].type`)   |
| Per-call cost           | warm cache after phase 1                      | full cold-start each call                      |
| Skip permission prompts | `--dangerously-skip-permissions`              | `--dangerously-skip-permissions`               |

## opencode primitives used

- **Custom agents in `.opencode/agents/<name>.md`** — YAML frontmatter
  declares `mode`, `description`, and a `permission` map that gates every
  tool. The agent body is its system prompt. opencode reads these from
  `<workspace>/.opencode/agents/`; `run.sh` installs them as per-file
  symlinks at start and cleans up on exit.
- **MCP via `opencode.json`** — registered with `type: local` and an
  absolute path to the bridge script. The agent sees the MCP's `bash`
  tool as `apisec-sandbox_bash` (server-name prefix).
- **Persistent server + `opencode run --attach`** — one `opencode serve`
  is shared across all phases, so the prompt cache (survey, source pack)
  hits across hunter and per-finding exploiter calls.
- **Streaming JSON-line output** — `opencode run --format json` emits
  `step_start`, `tool_use`, `text`, `step_finish` events; `run.sh`
  reconstructs the final response by concatenating the `text` events.

## Claude Code primitives used

- **Subagents in `.claude/agents/<name>.md`** — YAML frontmatter declares
  `name`, `description`, and a `tools` whitelist. Anything not in the
  whitelist is unavailable to the agent: omitting `Bash` is enough to
  remove host shell access. The body of the markdown file is the system
  prompt. `run.sh` installs them as per-file symlinks under
  `<workspace>/.claude/agents/`.
- **MCP via `--mcp-config <file> --strict-mcp-config`** — `run.sh`
  generates a per-run `mcp.json` with an absolute path to the bridge and
  passes it to Claude. `--strict-mcp-config` ensures only this MCP is
  loaded (no globals leak in). The MCP's `bash` tool is exposed to agents
  as `mcp__apisec_sandbox__bash`.
- **Per-call invocation** — each phase is a separate `claude -p --agent
  <name>` process. No persistent server; per-call cold-start is the
  trade-off for simpler orchestration.
- **Streaming via `--output-format stream-json`** — emits `system`,
  `assistant`, `user` (tool_results), and `result` events. `run.sh`
  reconstructs the final response by concatenating every `text` block
  inside `assistant` events. `claude/watch.sh` pretty-prints the same
  stream live in another terminal.

## Adding a new coding-agent strategy

The contract every strategy must honor:

1. Live in its own top-level folder `<agent>/`.
2. Reuse `docker/apisec-runner/` as-is (mount source RO at `/workspace`,
   tmpfs at `/sandbox`).
3. Reuse `opencode/mcp/apisec-bridge.py` as the MCP backend (link or
   copy). The bridge is stdlib-Python only; no dependencies.
4. Provide an executable `run.sh` with at minimum these flags:
   `--target-url`, `--workspace`, `--model`, `--findings <path>` (skip
   survey + hunter), `--skip-build`, `--keep-container`.
5. Produce these outputs under `findings/<agent>-runs/<timestamp>/`:
   `survey.json`, `findings.json`, `verdicts/<id>.json`, plus the raw
   per-phase `*.jsonl` streams for debugging.
6. Translate the **same** three system prompts (the body of
   `opencode/agents/{surveyor,hunter,exploiter}.md`) into whatever format
   the new agent expects (a JSON object, a markdown frontmatter, a CLI
   flag, …).

### Suggested skeleton

```
<agent>/
├── agents/                 # or wherever the agent's prompt lives
│   ├── surveyor.md
│   ├── hunter.md
│   └── exploiter.md
├── mcp/
│   └── apisec-bridge.py    # symlink → ../../opencode/mcp/apisec-bridge.py
├── run.sh
├── watch.sh                # optional but recommended
└── README.md               # how the strategy maps to the agent's primitives
```

### Things that will probably differ

- **MCP registration.** Some agents use a config file, others a CLI flag.
- **Tool naming convention.** opencode uses `<server>_<tool>`, Claude
  uses `mcp__<server>__<tool>`. Double-check on first run.
- **Tool gating.** opencode uses a `permission` map, Claude uses a
  `tools` whitelist, others may use roles. The agent's frontmatter is the
  natural home if available; otherwise fall back to CLI flags.
- **Stream format.** Each agent emits a different JSON shape; `run.sh`'s
  parser block has to match.
