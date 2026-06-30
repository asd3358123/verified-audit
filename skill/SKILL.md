---
name: verified-audit
description: Audit a codebase for security/correctness issues where EVERY reported finding is deterministically and adversarially verified — trustworthy enough to run unattended (CI gate, scheduled triage, batch over many repos). Use when the audit output's correctness matters and no human will hand-check each finding. Defaults to a single strong agent + verification, NOT multi-agent fan-out (measured across 5 benchmarks to add cost + false-positive noise, not recall). Trigger on "verified audit", "audit this for CI", "trustworthy audit", "audit and verify every finding".
---

# Verified Audit

Produce an audit whose every finding has survived verification, so the output can be trusted **without a human re-checking it**. The value here is not finding *more* — it's that what you report is *real*.

## When to use
- **Unattended / repeatable runs**: CI audit gate on a PR, scheduled triage, batch over many repos — nobody is in the loop to catch a hallucinated finding.
- **High-stakes output** you won't manually review line by line.

## When NOT to use
- Quick interactive exploration where you'll read the output anyway — just audit directly. **You** are the verifier; the apparatus is overhead.

## Method (in order)

### 1. Scope
Pin down: the target (path / files), what classes of issue to look for, and what "done" means.

### 2. Audit — a single strong agent, structured output
Run **one** strong agent (high effort) over the target. Require **structured** findings — each with `file`, `line`, `type`, `attack` (concrete impact), and `evidence` (a verbatim quote of the offending line).

**Do NOT fan out across many agents by default.** Measured repeatedly: splitting the audit did not improve recall — it added token cost and false-positive noise while a single strong agent matched or beat it. Only consider fan-out if the target genuinely exceeds one agent's context window (tens of thousands of lines); even then, score it against the single-agent baseline (step 4) before trusting it.

### 3. Verify — the load-bearing step
Every finding must survive **both** checks, or it is dropped:

- **Deterministic check** (do this first, it's free): the cited `file:line` must exist, and the code at that line must actually contain the claimed construct. Read the file; if the line doesn't contain what the finding describes, **drop it — it's a hallucinated reference.** Also drop findings whose severity/`status` is internally inconsistent.
- **Adversarial check**: an independent skeptic reads the cited code and tries to **refute** the finding. Default to *not-a-bug* when uncertain. Drop refuted findings.
- **Fail loud, never silent**: a verifier that errors, times out, or returns an unparseable/empty verdict is **inconclusive — neither a pass nor a refute.** Put it in a separate bucket and surface it; never let it silently fall through (a dropped real finding is a false-negative — the dangerous failure for a security gate). The same applies to the *audit* pass: if a batch's response fails to parse, the scan is **incomplete** — say so loudly, because "no findings" from a failed call is indistinguishable from "no findings because the code is clean." Treat an incomplete scan as NOT passing the gate.
- **Verify the source, not just the sink**: when a finding is an injection/taint class (SQLi, SSRF, command-exec), a confirmed verdict on the *sink* is not enough — trace where the tainted value actually comes from. The LLM reliably spots `fmt.Sprintf`-into-SQL but routinely *assumes* the input is attacker-controlled; if every caller passes a constant, it's a hardening note, not an exploitable HIGH. Treat confirmed HIGH/CRITICAL as provisional until the source is traced.

With more than a few findings, run the per-finding verification **in parallel via the Workflow tool** (needs the user's opt-in to orchestration). Pattern:

```js
// findings: [{file, line, type, attack}]  — from step 2
const verdicts = await parallel(findings.map(f => () =>
  agent(
    `Adversarially verify a claimed issue. Read ${f.file} around line ${f.line}. ` +
    `Claim: "${f.type} — ${f.attack}". Is this a REAL, exploitable issue at that EXACT location? ` +
    `Default real=false if the cited line does not actually contain the described flaw.`,
    { schema: { type: 'object', properties: { real: { type: 'boolean' }, reason: { type: 'string' } },
                required: ['real', 'reason'] } }
  ).then(v => ({ ...f, verdict: v }))))
const ok           = verdicts.filter(v => v.verdict && typeof v.verdict.real === 'boolean')
const confirmed    = ok.filter(v => v.verdict.real)
const refuted      = ok.filter(v => !v.verdict.real)
const inconclusive = verdicts.filter(v => !v.verdict || typeof v.verdict.real !== 'boolean')
// inconclusive = verify call failed/empty — report it, do NOT drop (silent drop = false-negative)
```

A subtle but important measurement trap: when matching findings to files, use the **full path** (`dir/file.py`), never the basename — repeated filenames across directories silently collide and corrupt your scoring. (Learned the hard way.)

### 4. (Optional) Baseline calibration — not every run
Occasionally run a **second, independent** audit agent over the same target and diff: did the baseline surface anything the first pass missed? This tells you whether the single pass is leaving things on the table. It's a calibration check, not part of every run.

### 5. Report
Output **only the verified findings** — each with `file:line`, the concrete attack, and the verifier's reason. Then list what was **refuted** and why (transparency is what makes the report trustworthy). Give **inconclusive** findings (verify failed) their own section so they're not mistaken for cleared, and if any audit batch failed, put an **"⚠️ scan incomplete"** banner at the top — a partial scan must not read as a clean one. End with one line of confidence, e.g. *"N findings, each verified deterministically + adversarially; M candidates refuted; K inconclusive."*

## Why these defaults (the evidence behind them)
- **Single agent, not fan-out** — across five benchmark configurations (4–46 planted defects; strong and weak models; forced and unforced decomposition; up to 90 files / 30 services), recursive/fan-out decomposition **never beat** a single strong agent on recall. It only added cost and false-positive noise. Decomposition is predicted to help only when the input genuinely overflows one agent's context — a threshold those tests never reached.
- **Verification is load-bearing** — LLM self-assessment over-claims; a deterministic reference check plus an adversarial skeptic catch plausible-but-wrong findings. This is precisely what makes the output safe to trust when no human is watching.
