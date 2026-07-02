"""Deterministic unit tests for the pure logic — no LLM, no network.

A tool whose whole point is "don't trust a result you haven't verified" should verify itself.
These cover the parsing, path-resolution, language, and report-formatting logic; the LLM audit/verify
calls are intentionally not exercised here (they need an API key and are non-deterministic).
"""
import json
import os

import pytest

import verified_audit as va


# ── _safe_int: a non-numeric LLM "line" must never crash the run ──────────────────
def test_safe_int():
    assert va._safe_int(145) == 145
    assert va._safe_int("145") == 145
    assert va._safe_int("123-145") == 123     # first number
    assert va._safe_int("line 60") == 60
    assert va._safe_int("N/A") == 0
    assert va._safe_int(None) == 0
    assert va._safe_int("") == 0


# ── _parse_json: fenced / bare / embedded / garbage ──────────────────────────────
def test_parse_json():
    assert va._parse_json('{"a": 1}') == {"a": 1}
    assert va._parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert va._parse_json('here you go: {"a": 1} thanks') == {"a": 1}
    assert va._parse_json("not json at all") == {}
    assert va._parse_json("") == {}


# ── language-aware file filtering ────────────────────────────────────────────────
def test_auditable_go():
    assert va._auditable("main.go", "go")
    assert not va._auditable("main_test.go", "go")
    assert not va._auditable("api.pb.go", "go")


def test_auditable_python():
    assert va._auditable("app.py", "python")
    assert not va._auditable("test_app.py", "python")
    assert not va._auditable("app_test.py", "python")


def test_auditable_typescript():
    assert va._auditable("App.tsx", "typescript")
    assert not va._auditable("App.test.tsx", "typescript")
    assert not va._auditable("types.d.ts", "typescript")


def test_auditable_language_isolation():
    # a Go file is not auditable under --lang python and vice versa
    assert not va._auditable("main.go", "python")
    assert not va._auditable("app.py", "go")


# ── enclosing_func: Go (incl. generics) and Python ───────────────────────────────
def test_enclosing_func_go(tmp_path):
    (tmp_path / "x.go").write_text("package x\n\nfunc Foo() {\n\tbar()\n}\n")
    assert va.enclosing_func(str(tmp_path), "x.go", 4, "go") == ("Foo", 3)


def test_enclosing_func_go_generic(tmp_path):
    (tmp_path / "g.go").write_text("package x\n\nfunc Map[T any](xs []T) {\n\tuse(xs)\n}\n")
    assert va.enclosing_func(str(tmp_path), "g.go", 4, "go") == ("Map", 3)


def test_enclosing_func_python(tmp_path):
    (tmp_path / "a.py").write_text("import os\n\ndef check(x):\n    return x\n")
    assert va.enclosing_func(str(tmp_path), "a.py", 4, "python") == ("check", 3)


def test_enclosing_func_none_when_no_func(tmp_path):
    (tmp_path / "c.py").write_text("X = 1\nY = 2\n")
    assert va.enclosing_func(str(tmp_path), "c.py", 2, "python") == (None, None)


# ── _norm_repo_path ──────────────────────────────────────────────────────────────
def test_norm_repo_path(tmp_path):
    repo = str(tmp_path)
    assert va._norm_repo_path("internal/foo.go", repo) == os.path.join("internal", "foo.go")
    abs_p = os.path.join(repo, "internal", "foo.go")
    assert va._norm_repo_path(abs_p, repo) == os.path.join("internal", "foo.go")


# ── load_deadcode is Go-only (returns None for other languages, no deadcode needed) ─
def test_load_deadcode_non_go_is_none(tmp_path):
    assert va.load_deadcode(str(tmp_path), "python") is None
    assert va.load_deadcode(str(tmp_path), "typescript") is None


# ── SARIF: basename resolution (gosec emits only the basename) ───────────────────
def _write_sarif(path, uri, line=2):
    path.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "gosec"}}, "results": [
        {"ruleId": "G1", "level": "warning", "message": {"text": "msg"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                             "region": {"startLine": line}}}]}]}]}))


def test_sarif_basename_resolves_to_full_path(tmp_path):
    (tmp_path / "internal").mkdir()
    (tmp_path / "internal" / "foo.go").write_text("package foo\nfunc F() {}\n")
    s = tmp_path / "s.sarif"
    _write_sarif(s, "foo.go", line=2)            # only the basename, as gosec emits
    fs = va.load_sarif(str(s), str(tmp_path), "go")
    assert len(fs) == 1
    assert fs[0]["file"] == os.path.join("internal", "foo.go")
    assert fs[0]["line"] == 2
    assert fs[0]["type"] == "G1"
    assert fs[0]["severity"] == "medium"          # warning -> medium


def test_sarif_ambiguous_basename_left_as_is(tmp_path):
    # same basename in two dirs → cannot disambiguate → left as-is (NOT wrongly resolved).
    # verify_one then can't locate it and reports it inconclusive, never a silent refute.
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "dup.go").write_text("package x\n")
    s = tmp_path / "s.sarif"
    _write_sarif(s, "dup.go")
    fs = va.load_sarif(str(s), str(tmp_path), "go")
    assert fs[0]["file"] == "dup.go"


def test_sarif_full_path_kept(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.go").write_text("package a\n")
    s = tmp_path / "s.sarif"
    _write_sarif(s, "pkg/a.go")
    fs = va.load_sarif(str(s), str(tmp_path), "go")
    assert fs[0]["file"] == os.path.join("pkg", "a.go")


# ── report: a failure must NEVER look like a clean scan ──────────────────────────
def test_render_incomplete_banner_on_inconclusive():
    inconclusive = [{"file": "a.go", "line": 1, "type": "T", "attack": "x"}]
    md = va.render(["scope"], [{}], [], [], inconclusive, 0, 0)
    assert "SCAN INCOMPLETE" in md
    assert "## Inconclusive" in md


def test_render_incomplete_banner_on_failed_audit_batch():
    md = va.render(["scope"], [], [], [], [], audit_failed=1, audit_total=3)
    assert "SCAN INCOMPLETE" in md


def test_render_clean_has_no_banner():
    md = va.render(["scope"], [], [], [], [], 0, 0)
    assert "SCAN INCOMPLETE" not in md
    assert "## Confirmed" in md and "## Refuted" in md


def test_render_confirmed_finding():
    confirmed = [{"file": "a.go", "line": 10, "type": "SQLi",
                  "attack": "inject", "verdict": {"real": True, "severity": "high", "reason": "yep"}}]
    md = va.render(["scope"], confirmed, confirmed, [], [], 0, 0)
    assert "HIGH" in md and "a.go:10" in md and "yep" in md


# ── json summary: the inconclusive/fail rate is a second-order SLI to alert on ────
def test_json_summary_counts_rates_and_incomplete(tmp_path):
    p = tmp_path / "summary.json"
    va.write_json_summary(str(p), scope=["./x"], raised=10, confirmed=2, refuted=5,
                          inconclusive=3, audit_failed=1, audit_total=4)
    d = json.loads(p.read_text())
    assert (d["raised"], d["confirmed"], d["refuted"], d["inconclusive"]) == (10, 2, 5, 3)
    assert (d["audit_failed"], d["audit_total"]) == (1, 4)
    assert d["incomplete"] is True
    assert d["inconclusive_rate"] == 0.3       # 3/10
    assert d["audit_fail_rate"] == 0.25        # 1/4


# ── scope resolution fails loud: an unscanned input must never read as "clean" ────
def test_changed_files_bad_diff_fails_loud(tmp_path):
    # not a git repo → git diff fails. An empty file list here would let the gate pass on a change
    # it never scanned (the classic shallow-clone-in-CI failure).
    with pytest.raises(SystemExit):
        va.changed_files(str(tmp_path), "deadbeef", "go")


def test_expand_nonexistent_path_fails_loud(tmp_path):
    with pytest.raises(SystemExit):
        va.expand(str(tmp_path), ["no/such/dir"], "go")


def test_expand_existing_dir_still_works(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.go").write_text("package a\n")
    assert va.expand(str(tmp_path), ["pkg"], "go") == [os.path.join("pkg", "a.go")]


def test_run_audit_non_list_findings_counts_batch_failed(tmp_path, monkeypatch):
    # "findings" present but not a list = a batch that parsed wrong; it must count as FAILED,
    # not as a successful batch that found nothing.
    (tmp_path / "a.go").write_text("package a\n")
    monkeypatch.setattr(va, "chat", lambda *a, **k: {"findings": "not-a-list"})
    findings, failed, total = va.run_audit(None, str(tmp_path), ["a.go"], "m")
    assert findings == [] and failed == 1 and total == 1


def test_sarif_result_without_location_is_kept_not_dropped(tmp_path):
    # a scanner result with no location must still surface (as inconclusive at verify time),
    # never be silently erased.
    s = tmp_path / "s.sarif"
    s.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "gosec"}}, "results": [
        {"ruleId": "G1", "level": "warning", "message": {"text": "msg"}, "locations": []}]}]}))
    fs = va.load_sarif(str(s), str(tmp_path), "go")
    assert len(fs) == 1
    assert fs[0]["file"] == "(no location)"


# ── bucket_verdicts: REFUTED requires an explicit real=false ─────────────────────
def test_bucket_verdicts_degraded_verdict_is_inconclusive():
    verdicts = [
        {"id": "yes", "verdict": {"real": True, "reason": "r"}},
        {"id": "no", "verdict": {"real": False, "reason": "r"}},
        {"id": "empty", "verdict": {}},
        {"id": "no-real-key", "verdict": {"severity": "high", "reason": "partial parse"}},
        {"id": "non-bool", "verdict": {"real": "yes"}},
    ]
    confirmed, refuted, inconclusive = va.bucket_verdicts(verdicts)
    assert [v["id"] for v in confirmed] == ["yes"]
    assert [v["id"] for v in refuted] == ["no"]
    assert [v["id"] for v in inconclusive] == ["empty", "no-real-key", "non-bool"]


def test_json_summary_zero_denominator_no_div_by_zero(tmp_path):
    # a clean run (raised=0, audit_total=0) must emit a data point with rate 0.0, not crash — the
    # time series needs a point every run or you can't compute a trend.
    p = tmp_path / "s.json"
    va.write_json_summary(str(p), scope=[], raised=0, confirmed=0, refuted=0,
                          inconclusive=0, audit_failed=0, audit_total=0)
    d = json.loads(p.read_text())
    assert d["inconclusive_rate"] == 0.0 and d["audit_fail_rate"] == 0.0
    assert d["incomplete"] is False
