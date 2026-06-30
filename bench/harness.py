#!/usr/bin/env python3
"""Self-contained benchmark: single strong agent vs naive fan-out, on fixtures with planted defects.

Reproduces the *core* comparison behind verified-audit's "single agent, not fan-out" default:
audit each fixture repo two ways and score recall deterministically against the known defects.

  pip install openai
  export OPENROUTER_API_KEY=...        # OpenAI-compatible; Claude via OpenRouter by default
  python harness.py                    # all tasks, both strategies
  python harness.py --task vuln-api --model anthropic/claude-sonnet-4.6

Scoring is deterministic: a planted defect counts as found if some finding cites its file:line
(line within tolerance) OR names the file and the defect keyword.

NOTE on README.md's headline numbers: those came from the original bounded-depth *tree*
orchestrator (a richer fan-out with adversarial verification), which is not part of this repo. This harness reproduces the *direction* of the result with a self-contained, naive
per-file fan-out so anyone can verify it on the included fixtures without that framework.
"""
from __future__ import annotations

import argparse
import json
import os
import re

from openai import OpenAI

_HERE = os.path.dirname(os.path.abspath(__file__))
BASE_URL = "https://openrouter.ai/api/v1"
_FILELINE = re.compile(r"([\w./\-]+\.\w+):(\d+)")

SYS = ("You are a senior security auditor. Find real, exploitable vulnerabilities. For each, give "
       "the file, the line, and the concrete attack. Respond ONLY as JSON: "
       '{"findings":[{"file":"<path>","line":<int>,"type":"...","attack":"..."}]}')


def make_client() -> OpenAI:
    key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise SystemExit("set OPENROUTER_API_KEY")
    return OpenAI(base_url=BASE_URL, api_key=key)


def _parse(text: str) -> dict:
    text = (text or "").strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {"findings": []}


def _ask(cli: OpenAI, model: str, blob: str) -> list[dict]:
    r = cli.chat.completions.create(
        model=model, temperature=0,
        messages=[{"role": "system", "content": SYS},
                  {"role": "user", "content": "Audit these files (paths relative to repo root):\n" + blob}])
    fs = _parse(r.choices[0].message.content or "").get("findings", [])
    return fs if isinstance(fs, list) else []


def _read_repo(repo: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for dp, _, fs in os.walk(repo):
        for f in fs:
            if f.endswith(".py"):
                p = os.path.join(dp, f)
                out[os.path.relpath(p, repo)] = open(p, errors="replace").read()
    return out


def _blob(files: dict[str, str]) -> str:
    return "\n\n".join(
        f"===== {rel} =====\n" + "\n".join(f"{i}: {ln}" for i, ln in enumerate(src.splitlines(), 1))
        for rel, src in files.items())


def audit_single(cli: OpenAI, model: str, files: dict[str, str]) -> list[dict]:
    return _ask(cli, model, _blob(files))                      # 1 call, whole repo


def audit_fanout(cli: OpenAI, model: str, files: dict[str, str]) -> list[dict]:
    found: list[dict] = []
    for rel, src in files.items():                             # 1 call per file, merged
        found += _ask(cli, model, _blob({rel: src}))
    return found


def _refs(findings: list[dict]) -> tuple[str, list[tuple[str, int]]]:
    refs: list[tuple[str, int]] = []
    for f in findings:
        cite = f"{f.get('file', '')}:{f.get('line', '')} {f.get('attack', '')}"
        for m in _FILELINE.finditer(cite):
            refs.append((os.path.basename(m.group(1)).lower(), int(m.group(2))))
    text = " ".join(json.dumps(f) for f in findings).lower()
    return text, refs


def _found(defect: dict, text: str, refs: list[tuple[str, int]], tol: int = 3) -> bool:
    base = os.path.basename(defect["file"]).lower()
    # Matches on basename — safe here because every fixture file has a distinct name. At scale (the
    # same filename across many dirs) basename collides and inflates recall; match the full
    # repo-relative path there. That collision was a real scoring bug, caught and fixed — the point
    # being that the measurement deserves the same "verify it" discipline as the findings.
    for fb, ln in refs:
        if fb == base and abs(ln - defect["line"]) <= tol:
            return True
    return base in text and defect["keyword"].lower() in text


def run_task(cli: OpenAI, task_dir: str, model: str) -> dict:
    spec = json.load(open(os.path.join(task_dir, "task.json")))
    files = _read_repo(os.path.join(task_dir, "repo"))
    defects = spec["defects"]
    row = {"task": os.path.basename(task_dir), "n": len(defects)}
    for name, fn in (("single", audit_single), ("fanout", audit_fanout)):
        text, refs = _refs(fn(cli, model, files))
        row[name] = sum(_found(d, text, refs) for d in defects)
    return row


def main() -> int:
    ap = argparse.ArgumentParser(prog="bench")
    ap.add_argument("--tasks-dir", default=os.path.join(_HERE, "tasks"))
    ap.add_argument("--task", default=None, help="run only this task (folder name)")
    ap.add_argument("--model", default="anthropic/claude-sonnet-4.6")
    a = ap.parse_args()

    cli = make_client()
    names = [a.task] if a.task else sorted(
        d for d in os.listdir(a.tasks_dir) if os.path.isdir(os.path.join(a.tasks_dir, d)))
    rows = [run_task(cli, os.path.join(a.tasks_dir, n), a.model) for n in names]

    w = f"{'task':<14}{'defects':>8}{'single':>8}{'fanout':>8}"
    print("\n" + w)
    print("-" * len(w))
    for r in rows:
        print(f"{r['task']:<14}{r['n']:>8}{r['single']:>8}{r['fanout']:>8}")
    nd = sum(r["n"] for r in rows)
    s = sum(r["single"] for r in rows)
    fo = sum(r["fanout"] for r in rows)
    print("-" * len(w))
    print(f"{'TOTAL':<14}{nd:>8}{s:>8}{fo:>8}")
    print(f"\nrecall — single {s}/{nd}  vs  naive fan-out {fo}/{nd}")
    print("→ single agent matched or beat fan-out (expected)" if s >= fo
          else "→ fan-out won here — worth investigating (scale? task?)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
