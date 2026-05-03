# Sample reports

Auto-generated attack-chain reports from two real runs against OWASP crAPI:

- [`claude/`](./claude/) — Claude Code (sonnet-4-6) run on 2026-05-03 16:47.
  13 findings, the agent narrated the full chain in prose; verdicts in
  these reports are **not** present because that run did not emit valid
  JSON verdicts (a known prompt-compliance issue we fixed afterwards).
  The reports are still useful — they show the actual reasoning + tool
  calls for each finding.
- [`opencode/`](./opencode/) — opencode + DeepSeek-V4-Pro run on
  2026-05-03 18:27. 13 findings, with structured JSON verdicts attached.

Both runs targeted the same crAPI deployment and produced the same
findings list (the hunter for both was Claude, surfaced at
`findings/claude-runs/20260503-164758/findings.json` — the opencode
run was invoked with `--findings <that-file>` to compare exploit
strategies on identical input).

## How to read

Each `F-XX.md` is the playbook for verifying one finding:

- Top table: severity, OWASP category, file:line, model, cost, tokens,
  verdict (where present).
- Hypothesis: copied from the hunter's finding.
- Attack chain: phases of agent reasoning (blockquoted) interleaved with
  the bash commands the agent ran (fenced) and the tool output excerpts
  (`↳`).
- Verdict (when JSON was emitted): final status, reason, request log
  table.

JWTs and other long opaque tokens are redacted as `<JWT>` / `<TOKEN>`.

## Quick comparisons

Same finding, different agent:

| Finding | Claude report | opencode report |
|---|---|---|
| F-04 — RS↔HS confusion (2 variants) | [383 lines](./claude/F-04.md) | [809 lines](./opencode/F-04.md) |
| F-08 — pincode `123456` brute-force | [556 lines](./claude/F-08.md) | [692 lines](./opencode/F-08.md) |
| F-13 — Mass-assign → SSRF → cmd inject | [366 lines](./claude/F-13.md) | [364 lines](./opencode/F-13.md) |

The opencode reports are typically longer for complex findings because
DeepSeek tends to explore more aggressively (and re-tries each variant
in detail). Claude's reports are more focused but its narration style
is denser, sometimes covering more ground per phase.

## How these were generated

`lib/build-report.py` is invoked at the end of every `run.sh` for each
finding. It auto-detects the stream format (Claude wrapped events vs.
opencode flat events) and emits this exact markdown.

To regenerate offline from a saved jsonl:

```bash
python3 lib/build-report.py \
    findings/<agent>-runs/<ts>/exploiter-F-13.jsonl \
    findings/<agent>-runs/<ts>/findings.json \
    --verdict findings/<agent>-runs/<ts>/verdicts/F-13.json \
    > F-13.md
```
