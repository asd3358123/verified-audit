# The verified-audit method

A runtime-agnostic description of the method. [`skill/SKILL.md`](skill/SKILL.md) is the Claude Code instantiation; [`tool/`](tool/) is the Go-specific automation. This file is what you'd implement on any agent runtime.

The goal: produce an audit where **every reported finding has survived verification**, so the output can be trusted without a human re-checking each one.

## 1. Scope

Pin down three things: the target (paths / files), the issue classes you care about, and what "done" means. Keep the scope tight — precision over volume.

## 2. Audit — one strong agent, structured output

Run **one** strong agent (high effort) over the target. Require **structured** findings, each with `file`, `line`, `type`, `attack` (concrete impact), `evidence` (a verbatim quote of the offending line).

**Do not fan out across many agents by default.** Measured repeatedly (see [`bench/`](bench/)): splitting the audit did not improve recall — it added token cost and false-positive noise while a single strong agent matched or beat it. Only consider fan-out if the target genuinely exceeds one agent's context window (tens of thousands of lines), and even then, score it against the single-agent baseline first.

## 3. Verify — the load-bearing step

Every finding must survive **all** of these, or it does not ship:

- **Deterministic check** (free, do it first): the cited `file:line` must exist and actually contain the claimed construct. If it doesn't, drop it — it's a hallucinated reference.
- **Reachability** (deterministic where possible): if the enclosing function is provably unreachable, the finding is dead code — auto-refute it *without* spending an LLM call. Feed the *reachable* findings the reachability fact so the verifier judges semantics, not whether the code runs. (In Go, `deadcode` gives you a whole-program call graph; match by `(file, declaration-line)`, not function name, so a same-named reachable function in the same file isn't mistaken for the dead one.)
- **Adversarial check**: an independent skeptic reads the cited code and tries to **refute** the finding. Default to not-a-bug when uncertain.
- **Source, not just sink**: for injection/taint classes, a confirmed sink is provisional until you trace where the value comes from. If every caller passes a constant, it's a hardening note, not an exploitable bug.

With more than a few findings, run the per-finding verification in **parallel**.

### Fail loud, never silent

This is the part most pipelines get wrong, and it is what makes the output safe to trust unattended:

- A verifier that **errors, times out, or returns an unparseable verdict** is **inconclusive** — neither a pass nor a refute. Put it in its own bucket and surface it. Never let it fall through silently: a dropped real finding is a false negative, the dangerous failure for a gate.
- If an **audit batch** fails to parse, the scan is **incomplete** — say so loudly (a banner), because "no findings" from a failed call is indistinguishable from "no findings because the code is clean."
- In a hard-gate mode, an incomplete scan must **not** pass.

### The failure moves up a level: watch the *rate*

Fail-loud is a **per-run** property, and "surface it" is necessary but not sufficient once the gate runs **unattended** — scheduled triage, a fleet of repos, or the advisory (report-only) phase every rollout starts in. A single red run is visible; a *slow creep* in how often runs come back inconclusive is not. Nobody is watching the trend, so the failure just moves up a level — from "a finding silently dropped" to "the scan silently degrading."

So treat the run counts as an **SLI**. `inconclusive / raised` and `audit_failed / audit_total` are the numbers to watch: a rising inconclusive rate means the verify provider is degrading, a model got deprecated, or path resolution is silently breaking — i.e. **false-negative risk is climbing**, the exact direction this whole method exists to avoid. Emit the counts every run, scrape them into whatever metrics backend you already run, and alert when the rate drifts above baseline. Keep no history *in the gate itself* — it makes the number available; the operator aggregates. (Aggregate the raw counts across runs; don't average the per-run rates — the denominators differ.)

The tool implements exactly this split: `--json-summary` writes the per-run counts + rates as JSON; storage and alerting are left to your observability stack.

## 4. Report

Output only the verified findings (each with `file:line`, the concrete attack, the verifier's reason). Then list the **refuted** findings and why — transparency is what makes the report trustworthy. Give **inconclusive** findings their own section so they aren't mistaken for cleared, and put an **⚠️ scan incomplete** banner at the top if any audit batch failed. End with one line of confidence: *"N findings, each verified deterministically + adversarially; M refuted; K inconclusive."*

## Why these defaults

- **Single agent, not fan-out** — across five benchmark configurations, recursive/fan-out decomposition never beat a single strong agent on recall; it only added cost and false-positive noise. Decomposition is predicted to help only when the input genuinely overflows one agent's context — a threshold the tests never reached. ([`bench/`](bench/))
- **Verification is load-bearing** — LLM self-assessment over-claims; a deterministic reference check plus an adversarial skeptic catch the plausible-but-wrong findings. This is precisely what makes the output safe to trust when nobody is watching.
- **Fail loud** — an unattended gate that silently treats failure as "clean" is worse than no gate: it manufactures false confidence.
