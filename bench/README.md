# bench — does recursive / fan-out decomposition help?

Short answer, measured: **no.** Across five configurations, a single strong agent matched or beat recursive fan-out on recall, while fan-out added token cost and false-positive noise. This is the evidence behind the [method](../METHODOLOGY.md)'s "single agent, not fan-out" default.

> **Status:** this README summarizes the result. The runnable harness + per-run data are being extracted from the original (private) research repo and de-sensitized before being added here. Targets are **synthetic** codebases with planted defects — no third-party or production code.

## Setup

- **Targets:** synthetic codebases with planted defects — `vuln-api` (4 defects), `web-shop` (8), `microservices` (16), and a generated 90-file codebase (forced fan-out).
- **Conditions:** strong and weak models; forced and unforced decomposition; an "all-opus" and an "opus-root/sonnet-leaf" profile.
- **Scoring:** deterministic — recall (planted defects found) and token cost. Findings matched to defects by **full path** (`dir/file.go`), never basename.

## Result

| condition | single strong agent | recursive fan-out |
|---|---|---|
| across all 5 configs | matched or beat fan-out on recall | **never won** |
| 90-file, forced fan-out, low-effort (the regime *most* favorable to decomposition) | 46/46 | 44/46, **+98 noise findings, ~30× the agents** |

Fan-out's predicted advantage — splitting work that overflows one context window — never materialized because the targets never overflowed a single strong agent's context. Decomposition is expected to help only past that threshold.

## A note on the harness itself

Two scoring bugs were caught *in the benchmark harness* during the work (a basename collision that inflated recall to a perfect score, among them). Catching them is the point: the same discipline the method applies to findings — **don't trust a result you haven't verified** — applies to the measurement. That's why scoring here is deterministic and matches on full paths.

## Takeaway

For audit-like tasks at realistic scale, the lever is not *more agents* — it's **one strong agent + load-bearing verification**. Spend the budget on verifying what you found, not on fanning out to find more.
