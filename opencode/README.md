# opencode strategy

Three-agent pipeline (`surveyor` → `hunter` → `exploiter`) that runs through
opencode and routes all live execution through an isolated `apisec-sandbox`
Podman container. The agents see the source tree read-only and call shell
commands only via an MCP bridge that `podman exec`s into the sandbox. No
host bash, no host writes, no internet egress from the sandbox beyond the
target.

## Layout

```
opencode/
├── agents/
│   ├── surveyor.md      # recon — produces a structured survey of the API surface
│   ├── hunter.md        # finds OWASP API Top 10 findings, given the survey
│   └── exploiter.md     # verifies one finding by attacking the live target
├── mcp/
│   └── apisec-bridge.py # stdio MCP server: opencode -> podman exec apisec-sandbox
├── opencode.json        # local opencode config: registers the MCP server
├── run.sh               # end-to-end orchestrator
└── README.md            # this file

docker/apisec-runner/    # toolkit image (curl, jwt_tool, sqlmap, ffuf, ...)
```

## Why this design

The agents do not run shell commands on the host. The native `bash` tool is
denied in each agent's frontmatter. The hunter and exploiter only have
access to `apisec-sandbox_bash`, which is an MCP-provided tool that runs
the command inside a container with:

- **read-only mount of the source tree** at `/workspace`
- **writable tmpfs scratch** at `/sandbox` (200 MB)
- **network restricted** to the target API and oracles (no general internet
  egress); the host machine is reachable as `host.containers.internal`
- **toolkit pre-installed** — see `/sandbox/TOOLS.md` inside the container
  for the manifest and recipes (curl, httpie, jwt_tool, sqlmap, ffuf, kr,
  arjun, python httpx/pyjwt/cryptography, jq, db clients, ...)

This separates the agent's "brain" (opencode + LLM) from its "hands" (the
container). Compromising the agent's exploit code cannot pivot back to the
host.

## Requirements

- `opencode` ≥ 1.14.31 on PATH
- `podman` (works with rootless Podman; `slirp4netns` is the default)
- `python3` (used by the MCP bridge — only stdlib)
- A coding model configured in your opencode config
  (`~/.config/opencode/opencode.json`). DeepSeek-V4-Pro through the
  `@ai-sdk/openai-compatible` provider works well. Claude and OpenAI
  models also work.

## Quickstart

From the repo root (the parent of this directory):

```bash
opencode/run.sh \
    --target-url http://localhost:8888 \
    --workspace ./crAPI \
    --model deepseek/deepseek-v4-pro
```

Flags:
- `--target-url` — base URL of the API under test
- `--workspace` — directory to mount read-only at `/workspace`
- `--model` — opencode `provider/model` spec
- `--scope` — optional hint passed to the surveyor (e.g. `services/identity only`)
- `--oracles-email` — optional URL of a test SMTP inbox (e.g. MailHog)
- `--port` — opencode serve port (default 4096)
- `--skip-build` — skip rebuilding the runner image
- `--keep-container` — leave the sandbox container running after the run

Output goes to `findings/opencode-runs/<timestamp>/`:

```
survey.json      # surveyor output
findings.json    # hunter output
verdicts/<id>.json   # one per finding from exploiter
*.jsonl          # raw streamed JSON events from each agent
opencode-serve.log
```

## Watching progress live

In a second terminal, while `run.sh` is going:

```bash
opencode/watch.sh                  # auto-detect the active phase
opencode/watch.sh surveyor         # surveyor only
opencode/watch.sh hunter           # hunter only
opencode/watch.sh exploiter        # the per-finding exploiter loop
opencode/watch.sh --run 20260503-072300   # specific past run
```

The watcher pretty-prints the JSON-line stream:
- `⚙ <tool> :: <input>` tool call (Read/Grep/Bash/MCP/...)
- `   ↳ <output>` tool result excerpt
- `💬 <text>` text chunk from the assistant
- `✓ step_finish  cost=$…  in=… out=…  cache_read=…` per-step usage

If you prefer the native opencode TUI:

```bash
opencode attach http://localhost:4096 --dir <workspace>
```

The TUI lists active sessions; pick the one you want to follow.

## How the agents are wired

The agent markdown files declare their permission rules in YAML frontmatter:

```yaml
permission:
  bash: deny                    # native host bash — disabled
  edit: deny
  write: deny
  webfetch: deny
  read: allow                   # native filesystem read (host /workspace mount)
  grep: allow
  glob: allow
  apisec-sandbox_bash: allow    # MCP-provided bash that runs in the container
```

The MCP server is registered in `opencode/opencode.json`:

```json
{
  "mcp": {
    "apisec-sandbox": {
      "type": "local",
      "command": ["python3", "./opencode/mcp/apisec-bridge.py"],
      "environment": { "SANDBOX_CONTAINER": "apisec-sandbox" }
    }
  }
}
```

When the agent calls `apisec-sandbox_bash`, opencode forwards the request
to the bridge, which runs `podman exec apisec-sandbox bash -lc "<cmd>"` and
returns stdout / stderr / exit code as the tool result.

## Customizing the toolkit

Add or remove tools by editing `docker/apisec-runner/Dockerfile` and
re-building (`run.sh` does this automatically unless `--skip-build`). The
manifest the agents read at runtime is `docker/apisec-runner/TOOLS.md` —
keep it in sync with what's actually installed.

## Costs

A typical run against a small service (~7 source files surveyed, 3-5
findings hunted, 3-5 findings verified) with DeepSeek-V4-Pro lands around
$0.05–$0.15 total, depending on cache hit rate. Prompt caching makes
subsequent runs against the same source tree noticeably cheaper.

## Troubleshooting

### "tool not found: apisec-sandbox_bash"

The MCP server failed to register. Check:
- `opencode mcp list` — should show `apisec-sandbox`.
- `tail -f findings/opencode-runs/<timestamp>/opencode-serve.log` —
  startup errors from the bridge appear here.
- `python3 ./opencode/mcp/apisec-bridge.py` — verify the script runs
  (it'll wait for stdin; Ctrl-C to exit).

### Agent still calls native bash

Check the agent's frontmatter. `bash: deny` must be present in the
`permission:` section. The default `build` agent has bash enabled.

### Container cannot reach the target

`run.sh` uses `slirp4netns:allow_host_loopback=true`. The target's address
inside the container is `host.containers.internal:<port>`. The
surveyor/hunter/exploiter prompts already use `$TARGET_URL`, which the
orchestrator sets accordingly.

### "container apisec-sandbox not running"

If a previous run crashed, the container may be in an exited state.
`run.sh` removes any stale instance with `podman rm -f` at the start of
every run. Manually: `podman rm -f apisec-sandbox`.
