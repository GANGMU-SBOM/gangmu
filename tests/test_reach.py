"""Reachability of an advisory's vulnerable function in the scanned source."""

import json

from gangmu.cli import main
from gangmu.reach import assess, build_graph, mine_symbols


def _tree(tmp_path):
    root = tmp_path / "fw"
    (root / "app").mkdir(parents=True)
    (root / "lwip").mkdir()
    (root / "app" / "main.c").write_text(
        "int main(void) { lwip_init(); return 0; }\n")
    (root / "lwip" / "core.c").write_text(
        "#define CALLIT(x) hidden_fn(x)\n"
        "static int helper_a(int x) { return x + 1; }\n"
        "int hidden_fn(int x) { return x * 2; }\n"
        "int lwip_init(void) { int v = helper_a(3); return CALLIT(v); }\n"
        "int vuln_parse(char *p) { return p[0] + p[1]; }\n"
        "int vuln_cb(int x) { return x - 1; }\n"
        "int never_used(void) { return vuln_parse(0); }\n")
    (root / "lwip" / "table.c").write_text(
        "typedef int (*cb_t)(int);\n"
        "const cb_t ops[] = { vuln_cb };\n")
    return root


def test_symbols_are_mined_from_advisory_text():
    assert mine_symbols("A flaw in `vuln_parse()` and in the lwip_input function") == \
        ["vuln_parse", "lwip_input"]
    assert mine_symbols("a buffer overflow") == []


def test_the_four_verdicts(tmp_path):
    graph = build_graph(_tree(tmp_path))
    assert assess(graph, "lwip", ["hidden_fn"], "curated").status == "reachable"   # via a macro
    r = assess(graph, "lwip", ["helper_a"], "curated")
    assert r.status == "reachable" and r.path == ["main", "lwip_init", "helper_a"]
    assert assess(graph, "lwip", ["vuln_cb"], "curated").status == "reachable"      # in a table
    assert assess(graph, "lwip", ["vuln_parse"], "curated").status == "unreachable"
    assert assess(graph, "lwip", ["not_there"], "curated").status == "absent"
    assert assess(graph, "lwip", ["not_there"], "advisory text").status == "unknown"
    assert assess(graph, "lwip", [], "curated").status == "unknown"


def _db(tmp_path, summaries):
    feed = {"vulnerabilities": [
        {"cve": {"id": cve, "descriptions": [{"lang": "en", "value": text}],
                 "configurations": [{"nodes": [{"cpeMatch": [{
                     "vulnerable": True,
                     "criteria": "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "2.2.0"}]}]}]}}
        for cve, text in summaries.items()]}
    db = tmp_path / "db"
    db.mkdir()
    (db / "nvd-2021.json").write_text(json.dumps(feed))
    return db


def _sbom(tmp_path):
    p = tmp_path / "sbom.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{"type": "library", "name": "lwip", "version": "2.1.0",
                        "bom-ref": "lwip",
                        "cpe": "cpe:2.3:a:lwip_project:lwip:2.1.0:*:*:*:*:*:*:*",
                        "properties": [{"name": "gangmu:directory", "value": "lwip"}]}]}))
    return p


def _run(tmp_path, capsys, *extra):
    db = _db(tmp_path, {"CVE-2021-0001": "overflow in `vuln_parse()`",
                        "CVE-2021-0002": "bug in `vuln_cb()`",
                        "CVE-2021-0003": "something in the stack"})
    assert main(["vuln", str(_sbom(tmp_path)), "--db", str(db), "--format", "json",
                 "--source", str(_tree(tmp_path)), *extra]) == 0
    return {m["id"]: m for m in json.loads(capsys.readouterr().out)["matches"]}


def test_report_only_leaves_the_state_alone(tmp_path, capsys):
    got = _run(tmp_path, capsys)
    assert got["CVE-2021-0001"]["reachability"]["status"] == "unreachable"
    assert got["CVE-2021-0002"]["reachability"]["status"] == "reachable"
    assert got["CVE-2021-0003"]["reachability"]["status"] == "unknown"
    assert {m["state"] for m in got.values()} == {"exploitable"}


def test_trusting_it_rules_out_what_cannot_be_reached(tmp_path, capsys):
    got = _run(tmp_path, capsys, "--reachability-vex")
    assert got["CVE-2021-0001"]["state"] == "not_affected"
    assert got["CVE-2021-0002"]["state"] == "exploitable"
    assert got["CVE-2021-0003"]["state"] == "exploitable"


def test_curated_symbols_decide_absence(tmp_path, capsys):
    sym = tmp_path / "sym.json"
    sym.write_text(json.dumps({"CVE-2021-0003": ["pruned_away"]}))
    got = _run(tmp_path, capsys, "--symbols", str(sym), "--reachability-vex")
    assert got["CVE-2021-0003"]["reachability"]["status"] == "absent"
    assert got["CVE-2021-0003"]["state"] == "not_affected"


def test_vex_carries_the_justification(tmp_path, capsys):
    db = _db(tmp_path, {"CVE-2021-0001": "overflow in `vuln_parse()`"})
    assert main(["vuln", str(_sbom(tmp_path)), "--db", str(db), "--format", "cyclonedx",
                 "--source", str(_tree(tmp_path)), "--reachability-vex"]) == 0
    vuln = json.loads(capsys.readouterr().out)["vulnerabilities"][0]
    assert vuln["analysis"]["state"] == "not_affected"
    assert vuln["analysis"]["justification"] == "code_not_reachable"
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["gangmu:reachability"] == "unreachable"
