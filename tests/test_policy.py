"""``gangmu policy check``: a CBOM or AIBOM read against a policy, with deadlines."""
import datetime as dt
import json
from pathlib import Path

import pytest

from gangmu.cli import main
from gangmu.policy import (PolicyError, evaluate, failing, load_policy_roots, policy_json,
                           policy_markdown, policy_roots, policy_table)

POLICY = """\
policies:
  - id: demo
    name: Demo transition
    source: {title: "Demo document", url: "https://example.org/demo", status: "draft"}
    note: Key sizes are not inspected.
    checks:
      - id: rsa
        title: RSA
        subject: cbom
        match: {algorithms: [rsa, ecdsa]}
        deprecated-after: 2030-12-31
        disallowed-after: 2035-12-31
        reference: "Table 2"
        remediation: "ML-DSA (FIPS 204)"
      - id: md5
        title: MD5 banned
        subject: cbom
        match: {algorithms: [md5]}
      - id: pqc-here
        title: post-quantum present
        subject: cbom
        match: {quantum: [pqc]}
        disallowed-after: 2020-01-01
      - id: licence
        title: Model licence declared
        subject: aibom
        match: {missing: [license]}
"""

MAIN_C = ("#include <x.h>\nint f(void) {\n mbedtls_ecdsa_sign(0);\n mbedtls_rsa_pkcs1_sign(0);\n"
          " mbedtls_md5(a, b, c);\n return 0;\n}\n")


def _pack(base: Path, text: str = POLICY, kind: str = "policy") -> Path:
    (base / "policies").mkdir(parents=True)
    (base / "rulebase.json").write_text(json.dumps({"name": "pol", "version": "1", "kind": kind}))
    (base / "policies" / "demo.yaml").write_text(text)
    return base


def _tree(tmp: Path) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "src").mkdir()
    (tmp / "src" / "main.c").write_text(MAIN_C)
    (tmp / "models").mkdir()
    (tmp / "models" / "kws.tflite").write_bytes(b"\x1c\0\0\0TFL3" + b"\0" * 16)
    return tmp


def _report(tmp_path, as_of, declare=False):
    from gangmu.aibom import scan_aibom
    from gangmu.aibom_decl import parse_declarations
    from gangmu.cbom import scan_cbom
    root = _tree(tmp_path / "fw")
    policy = load_policy_roots(policy_roots([str(_pack(tmp_path / "p"))]))[0]
    decls = parse_declarations({"models": [{"path": "models/*", "license": "MIT"}]}) \
        if declare else None
    return evaluate(policy, dt.date.fromisoformat(as_of), scan_cbom(root),
                    scan_aibom(root, declarations=decls))


def _status(report):
    return {r.check.id: r.status for r in report.results}


def test_a_dated_check_moves_from_due_to_deprecated_to_fail(tmp_path):
    (tmp_path / "a").mkdir()
    due = _report(tmp_path / "a", "2026-10-10")
    assert _status(due)["rsa"] == "due"
    rsa = next(r for r in due.results if r.check.id == "rsa")
    assert rsa.due == dt.date(2030, 12, 31)
    assert any("RSA" in f for f in rsa.findings) and any("ECDSA" in f for f in rsa.findings)
    (tmp_path / "b").mkdir()
    assert _status(_report(tmp_path / "b", "2031-06-01"))["rsa"] == "deprecated"
    (tmp_path / "c").mkdir()
    late = _report(tmp_path / "c", "2036-01-01")
    assert _status(late)["rsa"] == "fail"
    assert next(r for r in late.results if r.check.id == "rsa").due == dt.date(2035, 12, 31)


def test_the_last_day_is_still_allowed(tmp_path):
    (tmp_path / "a").mkdir()
    assert _status(_report(tmp_path / "a", "2035-12-31"))["rsa"] == "deprecated"


def test_a_check_without_dates_is_a_ban_and_a_miss_is_ok(tmp_path):
    (tmp_path / "a").mkdir()
    status = _status(_report(tmp_path / "a", "2026-10-10"))
    assert status["md5"] == "fail"
    assert status["pqc-here"] == "ok"                   # nothing post-quantum in the tree


def test_aibom_check_follows_the_declarations(tmp_path):
    (tmp_path / "a").mkdir()
    assert _status(_report(tmp_path / "a", "2026-10-10"))["licence"] == "fail"
    (tmp_path / "b").mkdir()
    assert _status(_report(tmp_path / "b", "2026-10-10", declare=True))["licence"] == "ok"


def test_report_formats_carry_the_citation_and_the_findings(tmp_path):
    (tmp_path / "a").mkdir()
    rep = _report(tmp_path / "a", "2026-10-10")
    table = policy_table([rep])
    assert "Demo transition" in table and "due" in table
    assert "Key sizes are not inspected." in table
    md = policy_markdown([rep])
    assert "[Demo document](https://example.org/demo) (draft)" in md
    assert "Move to: ML-DSA (FIPS 204)" in md and "FAIL: MD5 banned" in md
    assert "RSA**, next date 2030-12-31" in md
    doc = json.loads(policy_json([rep]))[0]
    assert doc["status"] == "fail" and doc["asOf"] == "2026-10-10"
    assert {c["id"] for c in doc["checks"]} == {"rsa", "md5", "pqc-here", "licence"}


def test_failing_picks_results_at_or_above_the_floor(tmp_path):
    (tmp_path / "a").mkdir()
    rep = _report(tmp_path / "a", "2031-06-01")
    assert {c.check.id for _, c in failing([rep], ["fail"])} == {"md5", "licence"}
    assert {c.check.id for _, c in failing([rep], ["deprecated"])} == {"md5", "licence", "rsa"}


@pytest.mark.parametrize("text, message", [
    ("policies: 3\n", "expected a list"),
    ("policies:\n  - {id: a, name: A, checks: []}\n", "non-empty list"),
    ("policies:\n  - {id: a, name: A, checks: [{id: c, title: C, subject: sbom, match: {x: [y]}}]}\n",
     "subject 'sbom'"),
    ("policies:\n  - {id: a, name: A, checks: [{id: c, title: C, subject: cbom, match: {}}]}\n",
     "'match' must say"),
    ("policies:\n  - {id: a, name: A, checks: [{id: c, title: C, subject: cbom, "
     "match: {quantum: [maybe]}}]}\n", "quantum status 'maybe'"),
    ("policies:\n  - {id: a, name: A, checks: [{id: c, title: C, subject: aibom, "
     "match: {missing: [colour]}}]}\n", "needs 'missing'"),
    ("policies:\n  - {id: a, name: A, checks: [{id: c, title: C, subject: cbom, "
     "match: {algorithms: [rsa]}, disallowed-after: tomorrow}]}\n", "not a date"),
    ("policies:\n  - {id: a, name: A, checks: [{id: c, title: C, subject: cbom, "
     "match: {algorithms: [rsa]}, deprecated-after: 2040-01-01, disallowed-after: 2030-01-01}]}\n",
     "later than"),
    ("policies:\n  - {id: a, name: A, checks: [{id: c, title: C, subject: cbom, "
     "match: {algorithms: [rsa]}}, {id: c, title: D, subject: cbom, match: {algorithms: [md5]}}]}\n",
     "duplicate check id"),
])
def test_an_invalid_policy_is_refused_with_the_reason(tmp_path, text, message):
    pack = _pack(tmp_path / "p", text)
    with pytest.raises(PolicyError, match=message):
        load_policy_roots(policy_roots([str(pack)]))


def test_only_installed_packs_of_kind_policy_are_read_by_default(tmp_path, monkeypatch):
    from gangmu.core import packs
    monkeypatch.delenv("GANGMU_RULES", raising=False)
    wrong = _pack(tmp_path / "w", kind="cbom")
    right = _pack(tmp_path / "r")
    roots = packs.default_roots(packs=[("w", wrong), ("r", right)], kind="policy")
    assert [r.path for r in roots] == [right]


def test_cli_check_gate_and_formats(tmp_path, capsys):
    root = _tree(tmp_path / "fw")
    pack = str(_pack(tmp_path / "p"))
    assert main(["policy", "check", str(root), "--policy", pack, "--as-of", "2026-10-10"]) == 1
    captured = capsys.readouterr()
    assert "Demo transition" in captured.out and "demo/md5" in captured.err
    out = tmp_path / "r.md"
    assert main(["policy", "check", str(root), "--policy", pack, "--as-of", "2026-10-10",
                 "--format", "markdown", "-o", str(out), "--fail-on", "fail"]) == 1
    assert "# Policy check" in out.read_text()
    # a declared model and no banned algorithm: the gate opens
    (root / "src" / "main.c").write_text("int main(void) { return 0; }\n")
    (root / "gangmu-aibom.yaml").write_text(
        "models:\n  - {path: 'models/*', license: MIT}\n")
    assert main(["policy", "check", str(root), "--policy", pack, "--as-of", "2026-10-10"]) == 0


def test_cli_errors(tmp_path, capsys):
    root = _tree(tmp_path / "fw")
    pack = str(_pack(tmp_path / "p"))
    assert main(["policy", "check", str(tmp_path / "nope"), "--policy", pack]) == 2
    assert main(["policy", "check", str(root), "--policy", pack, "--as-of", "soon"]) == 2
    assert "not a date" in capsys.readouterr().err
    assert main(["policy", "check", str(root), "--policy", pack, "--id", "other"]) == 2
    assert "no policy found" in capsys.readouterr().err
    bad = _pack(tmp_path / "bad", "policies: 3\n")
    assert main(["policy", "check", str(root), "--policy", str(bad)]) == 2
