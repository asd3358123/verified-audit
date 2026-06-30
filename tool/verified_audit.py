#!/usr/bin/env python3
"""Headless verified-audit for CI via OpenRouter — pure-code reachability + LLM semantics.

Division of labour:
  - REACHABILITY / dead-code  -> pure code: `deadcode ./...` (whole-program call graph, deterministic).
    A finding whose enclosing function is provably unreachable is AUTO-REFUTED — no LLM call.
  - SEMANTICS (is the reachable code actually a bug, does untrusted input reach it) -> LLM (OpenRouter),
    which is TOLD the reachability deterministically instead of guessing it.

Self-contained: `pip install openai` + `go install golang.org/x/tools/cmd/deadcode@v0.47.0` + env
`OPENROUTER_API_KEY`. Uses Claude models via OpenRouter by default.

  python verified_audit.py --paths ./internal/handler ./pkg/auth --out report.md
  python verified_audit.py --diff <base_sha> --out report.md
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from openai import OpenAI

BASE_URL = "https://openrouter.ai/api/v1"

AUDIT_SYS = ("You are a senior application-security auditor. You are given source files with line "
             "numbers. Find REAL, exploitable vulnerabilities — especially the logic bugs pattern "
             "scanners miss (IDOR, missing authz, TOCTOU races, SSRF, injection, insecure crypto, "
             "hardcoded secrets, missing validation on external input). Precision over volume. "
             "Respond ONLY with a JSON object.")
VERIFY_SYS = ("You are a skeptical, adversarial security reviewer. The cited function is already known "
              "(deterministically) to be reachable from a program entry point — do NOT re-litigate dead code. "
              "Judge the SEMANTICS: is the claimed flaw real at that exact line, does a reachable path actually "
              "carry UNTRUSTED/EXTERNAL input to it, and is the exploit mechanism technically correct? Most "
              "findings are not exploitable as stated — refute the weak ones. real=true only with a concrete "
              "external attacker path; when in doubt, real=false. Respond ONLY with a JSON object.")


# ── OpenRouter ────────────────────────────────────────────────────────────────
def make_client() -> OpenAI:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        sys.exit("error: set OPENROUTER_API_KEY")
    return OpenAI(base_url=BASE_URL, api_key=key,
                  default_headers={"HTTP-Referer": "https://localhost/verified-audit",
                                   "X-Title": "verified-audit"})


def _parse_json(text: str) -> dict:
    text = (text or "").strip()
    if "```" in text:
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    return {}


_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


def chat(cli: OpenAI, model: str, system: str, user: str, retries: int = 4) -> dict:
    # 429/5xx/timeout 會 retry+backoff —— 否則被限流就靜默回 {}。回 {} 的語意 = 「呼叫失敗」，
    # 上層(run_audit / main)會把它顯式標成失敗/inconclusive，不會當成「乾淨」。
    for attempt in range(retries + 1):
        try:
            r = cli.chat.completions.create(
                model=model, temperature=0,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
            return _parse_json(r.choices[0].message.content or "")
        except Exception as e:  # noqa: BLE001
            status = getattr(e, "status_code", None) or getattr(getattr(e, "response", None), "status_code", None)
            msg = str(e).lower()
            retryable = status in _RETRY_STATUS or "429" in msg or "rate" in msg or "overloaded" in msg or "timeout" in msg
            if retryable and attempt < retries:
                delay = min(3 * (2 ** attempt), 30)  # 3,6,12,24,30…
                print(f"[warn] {model} retryable error (attempt {attempt + 1}/{retries + 1}), sleep {delay}s: {e}", file=sys.stderr)
                time.sleep(delay)
                continue
            print(f"[warn] {model} call failed: {e}", file=sys.stderr)
            return {}
    return {}


# ── files ─────────────────────────────────────────────────────────────────────
def _read(path: str) -> list[str]:
    try:
        return open(path, errors="replace").read().splitlines()
    except Exception:
        return []


def numbered(path: str) -> str:
    return "\n".join(f"{i}: {ln}" for i, ln in enumerate(_read(path), 1))


def _safe_int(x) -> int:
    # LLM 可能回 "N/A" / "123-145" / None —— 別讓非數字的 line 把整個 run 炸掉(crash = 漏掃)。
    try:
        return int(x)
    except (TypeError, ValueError):
        m = re.search(r"\d+", str(x or ""))
        return int(m.group()) if m else 0


def window(repo: str, file: str, line: int, pad: int = 30) -> str:
    lines = _read(os.path.join(repo, file))
    a, b = max(0, line - pad), min(len(lines), line + pad)
    return "\n".join(f"{i}: {lines[i - 1]}" for i in range(a + 1, b + 1))


def _auditable_go(fn: str) -> bool:
    # 只審第一方手寫 Go：跳過 generated protobuf(.pb.go) 與 test(_test.go) —— 審它們是噪音。
    return fn.endswith(".go") and not fn.endswith("_test.go") and not fn.endswith(".pb.go")


def expand(repo: str, paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        ap = os.path.join(repo, p)
        if os.path.isdir(ap):
            for dp, _, fs in os.walk(ap):
                out += [os.path.relpath(os.path.join(dp, f), repo) for f in fs if _auditable_go(f)]
        elif _auditable_go(ap) and os.path.isfile(ap):
            out.append(p)
    return sorted(set(out))


def changed_go_files(repo: str, base: str) -> list[str]:
    r = subprocess.run(["git", "-C", repo, "diff", "--name-only", f"{base}...HEAD"],
                       capture_output=True, text=True)
    return [p for p in r.stdout.splitlines()
            if _auditable_go(p) and os.path.isfile(os.path.join(repo, p))]


# ── reachability (pure code: deadcode) ──────────────────────────────────────────
def _deadcode_bin() -> str | None:
    b = shutil.which("deadcode")
    if b:
        return b
    try:
        gp = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip()
        cand = os.path.join(gp, "bin", "deadcode")
        return cand if os.path.isfile(cand) else None
    except Exception:
        return None


def _norm_repo_path(p: str, repo: str) -> str:
    """Normalize to repo-relative so deadcode output paths and LLM-returned paths compare equal
    (deadcode prints paths relative to its cwd, or absolute — either must match the LLM's repo-root path)."""
    if not p:
        return p
    if os.path.isabs(p):
        try:
            p = os.path.relpath(p, repo)
        except Exception:
            pass
    return os.path.normpath(p)


def load_deadcode(repo: str) -> set | None:
    """Run `deadcode ./...` (whole-program). Return {(repo_relpath, decl_line)} of unreachable funcs.
    Matched by PRECISE position (file + declaration line), NOT just function name — so a same-named
    *reachable* func in the same file is never mistakenly auto-refuted (a false-negative is the
    dangerous failure mode in a security gate). None if deadcode can't run (then we don't trust the
    dead-code signal and everything goes to LLM verify)."""
    b = _deadcode_bin()
    if not b:
        print("[warn] `deadcode` not found — dead-code auto-refute disabled. "
              "Install: go install golang.org/x/tools/cmd/deadcode@v0.47.0", file=sys.stderr)
        return None
    try:
        r = subprocess.run([b, "./..."], cwd=repo, capture_output=True, text=True, timeout=600)
    except Exception as e:  # noqa: BLE001
        print(f"[warn] deadcode failed ({e}) — dead-code auto-refute disabled", file=sys.stderr)
        return None
    dead: set = set()
    for ln in r.stdout.splitlines():
        # deadcode text format: "path/file.go:LINE:COL: unreachable func: NAME"
        m = re.match(r"(.+\.go):(\d+):\d+:\s*unreachable func:", ln)
        if m:
            dead.add((_norm_repo_path(m.group(1), repo), int(m.group(2))))
    print(f"[info] deadcode: {len(dead)} unreachable funcs", file=sys.stderr)
    return dead


def enclosing_func(repo: str, file: str, line: int) -> tuple[str | None, int | None]:
    """Return (func_name, decl_line) of the function enclosing `line`, or (None, None).
    decl_line is matched against deadcode's reported position for precise dead-code attribution."""
    lines = _read(os.path.join(repo, file))
    for i in range(min(line, len(lines)) - 1, -1, -1):
        # 容許泛型型別參數 func Foo[T any](...) —— 否則泛型函式匹配不到、dead-code 行號對不上
        m = re.match(r"\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\s*(?:\[[^\]]*\])?\s*\(", lines[i])
        if m:
            return m.group(1), i + 1
    return None, None


def caller_context(repo: str, name: str, k: int = 10) -> str:
    """Light grep of production call sites (for the LLM to judge untrusted-input reachability)."""
    try:
        out = subprocess.run(["grep", "-rn", "--include=*.go", f"{name}(", repo],
                             capture_output=True, text=True, timeout=30).stdout.splitlines()
    except Exception:
        out = []
    defpat = re.compile(r"\bfunc\b.*\b" + re.escape(name) + r"\s*\(")
    prod = [h for h in out
            if len(h.split(":", 2)) == 3 and not defpat.search(h.split(":", 2)[2])
            and "_test.go" not in h.split(":", 1)[0]]
    return "production call sites:\n" + "\n".join(prod[:k]) if prod else "(no direct production call sites grep'd)"


# ── audit + verify ──────────────────────────────────────────────────────────────
def batches(repo: str, files: list[str], budget: int = 160_000):
    cur, cur_len, out = [], 0, []
    for f in files:
        block = f"\n\n===== FILE: {f} =====\n{numbered(os.path.join(repo, f))}"
        if cur and cur_len + len(block) > budget:
            out.append(cur)
            cur, cur_len = [], 0
        cur.append(block)
        cur_len += len(block)
    if cur:
        out.append(cur)
    return out


def run_audit(cli: OpenAI, repo: str, files: list[str], model: str) -> tuple[list[dict], int, int]:
    """Returns (findings, failed_batches, total_batches). A batch whose response has no parseable
    'findings' key is counted as FAILED — so an API/parse failure is visible to the gate, not
    silently rendered as a clean '## Confirmed _none_'."""
    bs = batches(repo, files)
    findings: list[dict] = []
    failed = 0
    for i, group in enumerate(bs, 1):
        user = (
            "Audit these Go files (paths are relative to the repo root)." + "".join(group) + "\n\n"
            'Respond ONLY with JSON: {"findings":[{"file":"<rel path>","line":<int>,"type":"...",'
            '"severity":"low|medium|high|critical","attack":"<concrete attack>",'
            '"evidence":"<verbatim offending line>"}]}'
        )
        resp = chat(cli, model, AUDIT_SYS, user)
        if not isinstance(resp, dict) or "findings" not in resp:
            failed += 1
            print(f"[warn] audit batch {i}/{len(bs)} failed to parse (API/parse error) — scan incomplete", file=sys.stderr)
            continue
        fs = resp.get("findings", [])
        if isinstance(fs, list):
            findings += [f for f in fs if isinstance(f, dict) and f.get("file")]
    return findings, failed, len(bs)


def verify_one(cli: OpenAI, repo: str, f: dict, model: str) -> dict:
    line = _safe_int(f.get("line"))
    code = window(repo, f.get("file", ""), line)
    if not code.strip():
        # can't locate the cited code (bad/ambiguous path) → INCONCLUSIVE, never a silent refute:
        # "I couldn't see the code" must not masquerade as "it's a false positive".
        print(f"[warn] cannot locate {f.get('file')}:{f.get('line')} — reporting inconclusive", file=sys.stderr)
        return {**f, "verdict": {}}
    name = enclosing_func(repo, f.get("file", ""), line)[0] or "?"
    user = (
        f"Claim: \"{f.get('type')} — {f.get('attack')}\" at {f.get('file')}:{f.get('line')}.\n\n"
        f"Cited code (line-numbered):\n{code}\n\n"
        f"REACHABILITY (deterministic): {name}() is reachable from a program entry point.\n"
        f"{caller_context(repo, name)}\n\n"
        "Judge the SEMANTICS. real=true ONLY if: (a) the cited line literally contains the described flaw; "
        "(b) a reachable path carries UNTRUSTED/EXTERNAL input to it (not only trusted/internal); (c) the "
        "exploit mechanism is technically correct. When in doubt, real=false. "
        'Respond ONLY with JSON: {"real":<bool>,"severity":"low|medium|high|critical","reason":"<why>"}.'
    )
    v = chat(cli, model, VERIFY_SYS, user)
    return {**f, "verdict": v if isinstance(v, dict) else {}}


# ── report ──────────────────────────────────────────────────────────────────────
def render(paths: list[str], findings: list[dict], confirmed: list[dict], refuted: list[dict],
           inconclusive: list[dict], audit_failed: int, audit_total: int) -> str:
    L = ["# Verified Audit Report", ""]
    # Scan-completeness banner — a failure must NEVER look like a clean scan.
    if audit_failed or inconclusive:
        parts = []
        if audit_total and audit_failed:
            parts.append(f"{audit_failed}/{audit_total} audit batch(es) failed to parse")
        if inconclusive:
            parts.append(f"{len(inconclusive)} finding(s) could not be verified")
        L += [f"> ⚠️ **SCAN INCOMPLETE** — {'; '.join(parts)}. "
              "Absence of findings below does NOT mean the code is clean.", ""]
    L += [f"- **scope:** {', '.join(paths)}",
          f"- **raised:** {len(findings)} · **confirmed:** {len(confirmed)} · "
          f"**refuted:** {len(refuted)} · **inconclusive:** {len(inconclusive)} "
          "(dead-code refutes are deterministic, via `deadcode`)",
          "", "## Confirmed", ""]
    if not confirmed:
        L.append("_none_")
    for f in confirmed:
        v = f.get("verdict") or {}
        sev = (v.get("severity") or f.get("severity") or "").upper()
        L += [f"### {sev} · `{f.get('file')}:{f.get('line')}` — {f.get('type')}",
              f"- **Attack:** {f.get('attack')}",
              f"- **Verified:** {v.get('reason', '')}", ""]
    L += ["## Inconclusive (verify call failed — needs manual review, NOT cleared)", ""]
    if not inconclusive:
        L.append("_none_")
    for f in inconclusive:
        L.append(f"- `{f.get('file')}:{f.get('line')}` — {f.get('type')} — {f.get('attack')}")
    L += ["", "## Refuted", ""]
    if not refuted:
        L.append("_none_")
    for f in refuted:
        v = f.get("verdict") or {}
        L.append(f"- `{f.get('file')}:{f.get('line')}` — {f.get('type')} — {v.get('reason', '')}")
    return "\n".join(L) + "\n"


# ── SARIF triage (verify/refute an existing scanner's findings) ──────────────────
def _go_basename_index(repo: str) -> dict:
    idx: dict = {}
    for dp, _, fs in os.walk(repo):
        if os.sep + ".git" in dp:
            continue
        for f in fs:
            if f.endswith(".go"):
                idx.setdefault(f, []).append(os.path.relpath(os.path.join(dp, f), repo))
    return idx


def load_sarif(path: str, repo: str) -> list[dict]:
    """Parse a SARIF file (gosec / semgrep / CodeQL) into findings for the verify pipeline. Resolves
    each location to a real repo file — some scanners (e.g. gosec) emit only the basename, so we map
    it back via a basename index. An ambiguous (same basename in >1 dir) or unknown path is left
    as-is; it will surface as INCONCLUSIVE at verify time, never silently 'refuted'."""
    try:
        doc = json.load(open(path))
    except Exception as e:  # noqa: BLE001
        sys.exit(f"error: cannot read SARIF {path}: {e}")
    idx = _go_basename_index(repo)
    level_to_sev = {"error": "high", "warning": "medium", "note": "low", "none": "low"}

    def _resolve(uri: str) -> str:
        p = _norm_repo_path(uri.replace("file://", ""), repo)
        if os.path.isfile(os.path.join(repo, p)):
            return p
        cands = idx.get(os.path.basename(p), [])
        return cands[0] if len(cands) == 1 else p   # unique basename → resolve; else leave as-is

    out: list[dict] = []
    for run in doc.get("runs", []):
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name", "scanner")
        for r in run.get("results", []):
            loc = ((r.get("locations") or [{}])[0] or {}).get("physicalLocation", {})
            uri = (loc.get("artifactLocation") or {}).get("uri") or ""
            if not uri:
                continue
            out.append({
                "file": _resolve(uri),
                "line": (loc.get("region") or {}).get("startLine") or 0,
                "type": r.get("ruleId") or "finding",
                "attack": ((r.get("message") or {}).get("text") or "").strip(),
                "severity": level_to_sev.get(r.get("level", "warning"), "medium"),
                "evidence": "",
                "tool": tool,
            })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="headless verified-audit for CI (OpenRouter + deadcode)")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--paths", nargs="*")
    ap.add_argument("--diff", default=None, help="base SHA — audit only changed .go files")
    ap.add_argument("--audit-model", default="anthropic/claude-sonnet-4.6")
    ap.add_argument("--verify-model", default="anthropic/claude-sonnet-4.6")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--sarif", default=None,
                    help="triage an existing scanner's SARIF (gosec/semgrep/CodeQL) instead of auditing from scratch")
    ap.add_argument("--out", default="audit-report.md")
    ap.add_argument("--fail-on", choices=["never", "confirmed"], default="never")
    a = ap.parse_args()
    if not a.paths and not a.diff and not a.sarif:
        ap.error("give --paths, --diff, or --sarif")

    repo = os.path.abspath(a.repo)
    cli = make_client()

    if a.sarif:                                  # triage mode: findings come from the scanner
        findings = load_sarif(a.sarif, repo)
        audit_failed, audit_total = 0, 0
        scope = [f"SARIF triage: {os.path.basename(a.sarif)}"]
        print(f"[info] loaded {len(findings)} finding(s) from SARIF", file=sys.stderr)
    else:                                        # audit mode: a strong agent raises findings
        files = changed_go_files(repo, a.diff) if a.diff else expand(repo, a.paths or [])
        if not files:
            open(a.out, "w").write("# Verified Audit Report\n\n_no Go files in scope_\n")
            return 0
        findings, audit_failed, audit_total = run_audit(cli, repo, files, a.audit_model)
        scope = files if a.diff else (a.paths or [])

    if not findings:
        open(a.out, "w").write("# Verified Audit Report\n\n_no findings to verify_\n")
        return 0

    dead = load_deadcode(repo)

    # pure-code reachability: dead-code findings are auto-refuted (no LLM call). Match by
    # (repo-relpath, enclosing-func decl line) — precise position avoids same-name false matches.
    auto_refuted, to_verify = [], []
    for f in findings:
        fn, fn_line = enclosing_func(repo, f.get("file", ""), _safe_int(f.get("line")))
        key = (_norm_repo_path(f.get("file", ""), repo), fn_line)
        if dead is not None and fn_line and key in dead:
            auto_refuted.append({**f, "verdict": {"real": False, "severity": "low",
                "reason": f"enclosing func {fn}() is provably unreachable from any entry point "
                          f"(deadcode) — dead code, not exploitable."}})
        else:
            to_verify.append(f)
    print(f"[info] auto-refuted {len(auto_refuted)} dead-code finding(s); {len(to_verify)} to LLM verify", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=a.concurrency) as ex:
        verdicts = list(ex.map(lambda f: verify_one(cli, repo, f, a.verify_model), to_verify))

    # verify failure (empty verdict) → inconclusive, NOT silently bucketed into refuted (would be a
    # false-negative: a real finding dropped because the verify API hiccupped).
    confirmed, refuted, inconclusive = [], list(auto_refuted), []
    for v in verdicts:
        verdict = v.get("verdict") or {}
        if not verdict:
            inconclusive.append(v)
        elif verdict.get("real"):
            confirmed.append(v)
        else:
            refuted.append(v)
    if inconclusive:
        print(f"[warn] {len(inconclusive)} finding(s) could not be verified (LLM failure) — reported as inconclusive", file=sys.stderr)

    md = render(scope, findings, confirmed, refuted, inconclusive, audit_failed, audit_total)
    with open(a.out, "w") as fh:
        fh.write(md)
    print(md)
    # gate: when enabled, an incomplete scan (audit batch / verify failure) must NOT pass silently.
    incomplete = audit_failed > 0 or bool(inconclusive)
    if a.fail_on == "confirmed" and (confirmed or incomplete):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
