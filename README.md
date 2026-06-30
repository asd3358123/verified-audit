# verified-audit

**English** | [繁體中文](README.zh-TW.md)

**For security audit, a single strong agent + load-bearing verification matches multi-agent fan-out on recall — at a fraction of the cost. Here is the method, the evidence, and a working Go CI tool.**

Most "AI code audit" does one of two things: floods you with hallucinated findings, or fans out across dozens of agents hoping that volume equals recall. This repo argues — and *measures* — the opposite:

> The value is not finding *more*. It is that what you report is **real** — trustworthy enough to run **unattended** (a CI gate, scheduled triage, a batch over many repos) without a human re-checking every finding.

## Three pieces, one story

| | What | Where |
|---|---|---|
| **Evidence** | A benchmark: recursive / fan-out decomposition vs a single strong agent, across 5 configurations. Fan-out **never won**. | [`bench/`](bench/) |
| **Method** | `verified-audit`: one strong agent → deterministic + adversarial verification → **fail loud, never silent**. | [`METHODOLOGY.md`](METHODOLOGY.md) · [`skill/`](skill/) |
| **Tool** | A headless Go security audit that wires the method into CI: `deadcode` reachability (deterministic) + an LLM for semantics (only on reachable code). | [`tool/`](tool/) |

The pieces reinforce each other: the benchmark is *why you should trust the method*; the method is *how*; the tool is *a working reference you can run today*.

## The core idea

1. **Reachability is a job for deterministic tools, not the LLM.** [`deadcode`](https://pkg.go.dev/golang.org/x/tools/cmd/deadcode) builds a whole-program call graph; a finding inside a provably-unreachable function is **auto-refuted without an LLM call**. The LLM is *told* the reachability instead of guessing it — which is what kills most false positives.

2. **Verification is load-bearing.** Every finding must survive (a) a deterministic check — the cited `file:line` really contains the claimed construct — and (b) an adversarial skeptic that tries to *refute* it, defaulting to not-a-bug. LLM self-assessment over-claims; this step is what makes the output safe to trust when no human is watching.

3. **Failure must never look like "clean."** An audit call that fails to parse marks the scan **incomplete** (banner at the top of the report), not empty. A verify call that fails sends the finding to an **inconclusive** bucket — never silently dropped, because a dropped real finding is the dangerous failure mode for a security gate.

4. **Source, not just sink.** For injection-class findings, a confirmed verdict on the *sink* is provisional until the *source* is traced — the LLM reliably spots `fmt.Sprintf`-into-SQL but routinely *assumes* the input is attacker-controlled. If every caller passes a constant, it's a hardening note, not an exploitable bug.

5. **Single strong agent, not fan-out.** Measured across 5 configs (4–46 planted defects; strong and weak models; forced and unforced decomposition; up to 90 files): fan-out **never beat** a single strong agent on recall — it only added cost and false-positive noise. See [`bench/`](bench/).

## Quick start (any Go repo)

```bash
pip install openai
go install golang.org/x/tools/cmd/deadcode@v0.47.0
export OPENROUTER_API_KEY=...     # OpenAI-compatible; uses Claude via OpenRouter by default

python tool/verified_audit.py \
  --repo /path/to/your/go/repo \
  --paths ./internal/handler ./pkg/auth \
  --out report.md
```

To wire it into Gitea / GitHub Actions as a **pre-ship security gate**, see [`tool/README.md`](tool/README.md).

## Why this exists (an honesty note)

This started life as a *recursive multi-agent framework*. Its own benchmarks disproved its headline hypothesis — recursive decomposition never beat a single strong agent. What survived, and what this repo is, is the part that held up under measurement: **one strong agent plus verification**. The benchmark that disproved the original idea is included on purpose — the evidence is the point.

## Layout

```
README.md         this file — the thesis
METHODOLOGY.md    the method, runtime-agnostic (set it up yourself)
skill/            a drop-in Claude Code skill for the method
tool/             the Go audit tool + example CI workflows
bench/            the benchmark harness + the negative result
examples/         configuration examples
```

## License
[MIT](LICENSE).
