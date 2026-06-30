# tool — headless Go verified-audit

`verified_audit.py` runs the [method](../METHODOLOGY.md) against a Go repo: **deadcode** computes reachability deterministically, the LLM judges semantics only on reachable code, every finding is adversarially verified, and failures are surfaced (never silently treated as clean).

## Dependencies (all pinned)

```bash
pip install openai==2.44.0
go install golang.org/x/tools/cmd/deadcode@v0.47.0   # needs Go >= 1.25
export OPENROUTER_API_KEY=...    # OpenAI-compatible endpoint; Claude via OpenRouter by default
```

## Run locally

```bash
# full scan of specific high-risk dirs
python verified_audit.py --repo /path/to/repo --paths ./internal/handler ./pkg/auth --out report.md

# only what changed since a base commit (diff mode)
python verified_audit.py --repo /path/to/repo --diff <base_sha> --out report.md

# TRIAGE mode — verify/refute an existing scanner's findings (kills false positives)
gosec -no-fail -fmt sarif -out gosec.sarif ./...
python verified_audit.py --repo /path/to/repo --sarif gosec.sarif --out triage.md
```

### Two modes

- **Audit** (`--paths` / `--diff`): a strong agent raises findings, then they're verified.
- **Triage** (`--sarif`): findings come from a scanner you already run (gosec / semgrep / CodeQL); the LLM + deadcode verify or refute each one. Same verification pipeline, so dead-code findings are auto-refuted and verify failures surface as *inconclusive* — never silently cleared. This is usually the cheapest high-value use: most teams drown in SAST false positives, and this kills them with reasons attached. See [`workflows/triage-sast.yml`](workflows/triage-sast.yml).

| flag | default | meaning |
|---|---|---|
| `--repo` | `.` | repo root |
| `--paths` | — | dirs/files to audit (skips `_test.go` and `*.pb.go`) |
| `--diff <sha>` | — | audit only `.go` files changed since `<sha>` |
| `--sarif <file>` | — | **triage mode**: verify/refute a scanner's SARIF (gosec/semgrep/CodeQL) instead of auditing from scratch |
| `--audit-model` | `anthropic/claude-sonnet-4.6` | model for the audit pass |
| `--verify-model` | `anthropic/claude-sonnet-4.6` | model for the adversarial verify (tier matters less than the harness) |
| `--concurrency` | `6` | parallel verify calls |
| `--fail-on` | `never` | `confirmed` → exit 1 on a confirmed finding **or an incomplete scan** |
| `--out` | `audit-report.md` | report path |

The report has **Confirmed / Inconclusive / Refuted** sections; if an audit batch failed to parse it carries a `⚠️ SCAN INCOMPLETE` banner. `[info] auto-refuted N` on stderr tells you the dead-code refute actually fired.

## Wire into CI (pre-ship gate)

1. Copy `verified_audit.py` into your repo (e.g. `ci/verified_audit.py`).
2. Copy `workflows/sast.yml` and `workflows/verified-audit.yml` into `.gitea/workflows/` (or `.github/workflows/`).
3. Set secret `OPENROUTER_API_KEY` (and a private-module token if your repo has private deps).
4. Edit the `<--` spots: ship `branches`, `runs-on`, high-risk dirs, GOPRIVATE.
5. ⚠️ **The workflow must exist on the branch you push.** Actions reads the workflow from the pushed ref — putting it on `main` does not gate pushes to a long-lived `release` branch unless `release` also has the file.

Start `--fail-on never` (advisory: report only). Flip to `--fail-on confirmed` once you trust it.

## Cost

A full scan of a few thousand lines of high-risk code is roughly **~$1** (deadcode is free; one audit pass + per-finding verify). Diff mode on a PR is cents. The verify model tier barely affects quality once deadcode supplies reachability — a cheaper model is usually fine.

## Adapting beyond this setup

- **Not OpenRouter?** It's the OpenAI Python SDK pointed at `base_url`; swap `make_client()` for any OpenAI-compatible endpoint.
- **Not Gitea?** The workflows are plain Actions YAML; the artifact→summary workaround is only needed where `upload-artifact@v4` is unsupported.
- **Not Go?** The reachability layer is Go-specific (deadcode). The method ([METHODOLOGY.md](../METHODOLOGY.md)) is language-agnostic; you'd substitute a reachability source for your language (or run reachable-by-default and lean harder on the adversarial verify).
