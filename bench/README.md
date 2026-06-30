# bench — does recursive / fan-out decomposition help?

Short answer, measured: **no.** A single strong agent matched or beat fan-out on recall, while fan-out added token cost and false-positive noise. This is the evidence behind the [method](../METHODOLOGY.md)'s "single agent, not fan-out" default.

## Run it yourself

```bash
pip install openai
export OPENROUTER_API_KEY=...
python harness.py                                   # all fixtures, single vs naive fan-out
python harness.py --task vuln-api --model anthropic/claude-sonnet-4.6
```

`harness.py` is self-contained: it audits each fixture two ways — **one strong agent over the whole repo** vs a **naive per-file fan-out** — and scores recall deterministically against the planted defects (a defect is found if a finding cites its `file:line` within tolerance, or names the file + the defect keyword).

### Fixtures (synthetic, planted defects — no third-party or production code)

| task | files | planted defects | flavor |
|---|---|---|---|
| `vuln-api` | small Flask app | 4 | SQLi, missing auth, MD5, forgeable token |
| `web-shop` | 5 modules | 8 | auth / payments / crypto / storage |
| `microservices` | ~17 files, 6 services | 16 | cross-service, repeated patterns |

## The result

### Self-contained reproduction (run `harness.py` yourself)

One run on `anthropic/claude-sonnet-4.6` over the three bundled fixtures (numbers vary run to run; temperature 0):

| task | defects | single agent | naive fan-out |
|---|---|---|---|
| `microservices` | 16 | 15 | 16 |
| `vuln-api` | 4 | 4 | 4 |
| `web-shop` | 8 | 7 | 6 |
| **total** | **28** | **26** | **26** |

Recall **ties** (26/28 each) — but the fan-out spent **~8× the LLM calls** to get there (one call per file = ~24, vs one call per repo = 3). At this scale, decomposition buys nothing it didn't already have; it just costs more. That is the whole point: *more agents ≠ more recall, only more spend.* (This harness scores recall and call count; it does not score the false-positive **noise** fan-out adds — see the headline numbers below, which do.)

### Original experiment (richer orchestrator, reported)

The headline numbers below come from the **original** experiment — a richer bounded-depth *tree* orchestrator (with adversarial verification) that is **not part of this repo**; reported here as the fuller evidence, including the noise fan-out generates:

| condition | single strong agent | recursive fan-out |
|---|---|---|
| across the configs (4–46 defects; strong & weak models; forced & unforced decomposition) | matched or beat fan-out | **never won** |
| 90-file generated codebase, **forced** fan-out, low effort (the regime *most* favorable to decomposition) | 46/46 | 44/46, **+98 noise findings, ~30× the agents** |

Fan-out's predicted advantage — splitting work that overflows one context window — never materialized, because the targets never overflowed a single strong agent's context. Decomposition is expected to help only past that threshold.

## On verifying the measurement itself

Two scoring bugs were caught *in the harness* during the work — most notably a **basename collision** (`file_0.py` repeated across services) that inflated recall to a false perfect score until scoring was switched to full repo-relative paths. Catching them is the point: the measurement deserves the same "don't trust a result you haven't verified" discipline the method applies to findings. (See the note in `harness.py`'s `_found()`.)

## Takeaway

For audit-like tasks at realistic scale, the lever is not *more agents* — it's **one strong agent + load-bearing verification**. Spend the budget on verifying what you found, not on fanning out to find more.
