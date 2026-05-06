# Setup & quickstart

## Requirements

- `podman` (rootless works) + `podman build` / `podman run`
- `python3` — used by the MCP bridge and orchestrator helpers; only
  stdlib, no virtualenv needed
- The CLI for the strategy you want to use:
  - `opencode` ≥ 1.14.31 for the opencode strategy
  - `claude` (Claude Code CLI) for the claude strategy

## Bring up the target

The default target wired into the prompts is **OWASP crAPI**, an
intentionally vulnerable Java/Spring + Python + Go app with deliberate
OWASP API Top 10 issues. Other intentionally-vulnerable apps (WebGoat,
VAmPI, Juice Shop, DVWS) work too — at most you'd tweak the `--scope`
hint passed to the surveyor.

```bash
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy/docker
podman compose -f docker-compose.yml up -d
curl -i http://localhost:8888       # expect HTTP 200
```

## Quickstart — opencode + DeepSeek-V4-Pro

DeepSeek-V4-Pro is interesting because it's cheap (~$0.01–$0.50 per
finding depending on complexity) and supports tool calling reliably
through opencode. Configure the provider once in
`~/.config/opencode/opencode.json`:

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
        "apiKey": "sk-..."
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

Then:

```bash
opencode/run.sh \
    --target-url http://localhost:8888 \
    --workspace ./crAPI \
    --model deepseek/deepseek-v4-pro
```

## Quickstart — Claude Code

```bash
claude/run.sh \
    --target-url http://localhost:8888 \
    --workspace ./crAPI \
    --model claude-sonnet-4-6
```

## Skip survey + hunter, only verify

Both strategies accept `--findings <path-to-findings.json>`. Useful when
iterating on the exploiter, or running the same findings against a
target that's been re-deployed.

```bash
opencode/run.sh ... \
    --findings findings/opencode-runs/20260503-063112/findings.json
```

This is also how the `docs/sample-reports/` runs were produced: a single
hunter run produced `findings.json`, then both strategies were invoked
with `--findings <that-file>` to compare exploit behavior on identical
input.

## Watching live progress

`claude/watch.sh` pretty-prints the live stream-json events from any
phase:

```bash
claude/watch.sh                          # auto-detect the active phase
claude/watch.sh hunter                   # specific phase
claude/watch.sh --run 20260503-072300    # past run
```

For opencode, attach the TUI to the running serve:

```bash
opencode attach http://localhost:4096 --dir ./crAPI
```
