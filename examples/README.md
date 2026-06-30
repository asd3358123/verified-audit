# examples

## Minimal local run

```bash
export OPENROUTER_API_KEY=sk-or-...
python ../tool/verified_audit.py \
  --repo ~/my-go-service \
  --paths ./internal/http ./internal/auth \
  --out /tmp/report.md
```

Read the `## Confirmed` section first; `## Inconclusive` means a verify call failed and the finding was **not** cleared — re-run or check manually. A `⚠️ SCAN INCOMPLETE` banner means an audit batch failed to parse — the scan did not cover everything.

## Diff mode (only what changed)

```bash
python ../tool/verified_audit.py --repo ~/my-go-service --diff origin/main --out /tmp/report.md
```

## CI

See [`../tool/workflows/`](../tool/workflows/) for `sast.yml` (free SAST) and `verified-audit.yml` (LLM stage), and [`../tool/README.md`](../tool/README.md) for wiring them in. Edit the `<--` marked spots for your ship branches, runner, and high-risk directories.
