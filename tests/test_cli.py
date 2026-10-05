import json

import pytest

from gangmu.cli import main

from community import needs_rules


def test_scan_table_runs(project_dir, rules_dir):
    assert main(["scan", str(project_dir), "--rules", str(rules_dir),
                 "--format", "table"]) == 0


def test_scan_writes_cyclonedx(project_dir, rules_dir, tmp_path):
    out = tmp_path / "bom.json"
    assert main(["scan", str(project_dir), "--rules", str(rules_dir),
                 "--format", "cyclonedx", "-o", str(out)]) == 0
    bom = json.loads(out.read_text())
    assert bom["specVersion"] == "1.6"
    assert any(c["name"] == "tinynet" for c in bom["components"])


def test_scan_writes_spdx(project_dir, rules_dir, tmp_path):
    out = tmp_path / "spdx.json"
    assert main(["scan", str(project_dir), "--rules", str(rules_dir),
                 "--format", "spdx", "-o", str(out)]) == 0
    assert json.loads(out.read_text())["spdxVersion"] == "SPDX-2.3"


def test_fail_under_gates_on_confidence(project_dir, rules_dir, tmp_path):
    out = tmp_path / "bom.json"
    code = main(["scan", str(project_dir), "--rules", str(rules_dir),
                 "--format", "cyclonedx", "-o", str(out), "--fail-under", "0.99"])
    assert code == 1


@needs_rules
def test_lint_passes_on_the_shipped_rule_base():
    assert main(["rules", "lint"]) == 0


def test_verify_against_a_local_checkout(upstream_dir, rules_dir):
    assert main(["rules", "verify", "--rules", str(rules_dir),
                 "--rule", "test/tinynet", "--checkout", str(upstream_dir)]) == 0


def test_verify_fails_against_the_wrong_tree(project_dir, rules_dir):
    code = main(["rules", "verify", "--rules", str(rules_dir),
                 "--rule", "test/tinynet",
                 "--checkout", str(project_dir / "components/net/tinynet")])
    assert code == 1


def test_fingerprint_emits_a_usable_identity_block(upstream_dir):
    assert main(["rules", "fingerprint", str(upstream_dir), "--version", "1.4.2",
                 "--include", "src/**/*.c", "--anchor", "src/core.c"]) == 0


def test_diff_reports_recall(tmp_path, project_dir, rules_dir):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    main(["scan", str(project_dir), "--rules", str(rules_dir),
          "--format", "cyclonedx", "-o", str(a)])
    bom = json.loads(a.read_text())
    bom["components"] = bom["components"] + [{
        "bom-ref": "extra", "type": "library", "name": "notfound", "version": "9"}]
    b.write_text(json.dumps(bom))
    assert main(["diff", str(a), str(b), "--fail-under", "0.9"]) == 1
    assert main(["diff", str(a), str(b)]) == 0


def test_scan_can_take_an_ide_project_instead_of_a_compile_db(rules_dir, tmp_path):
    from pathlib import Path
    fixtures = Path(__file__).resolve().parent / "fixtures"
    out = tmp_path / "bom.json"
    code = main(["scan", str(fixtures / "project"), "--rules", str(rules_dir),
                 "--project", str(fixtures / "projects" / "iar" / "app.ewp"),
                 "--configuration", "Release",
                 "--format", "cyclonedx", "-o", str(out)])
    assert code == 0
    bom = json.loads(out.read_text())
    assert any(c["name"] == "tinynet" for c in bom["components"])
    props = {p["name"]: p["value"]
             for c in bom["components"] for p in c.get("properties", [])}
    assert props.get("gangmu:compiledFiles")


def test_verify_treats_anchors_on_other_layouts_as_alternatives(upstream_dir, rules_dir,
                                                                tmp_path):
    """Tongsuo 8.4+ anchors VERSION.dat, 8.3 and earlier opensslv.h; only one
    layout exists in any one checkout, and that must not fail the rule."""
    import yaml
    rule = yaml.safe_load((rules_dir / "tinynet.yaml").read_text())
    other = {"path": "include/openssl/opensslv.h", "sha256": {"0.9.0": "0" * 64}}
    rule["identity"]["anchors"].append(other)
    (tmp_path / "r.yaml").write_text(yaml.safe_dump(rule))
    assert main(["rules", "verify", "--rules", str(tmp_path),
                 "--rule", "test/tinynet", "--checkout", str(upstream_dir)]) == 0
    # ...but a rule whose anchor files are all absent is still a failure
    rule["identity"]["anchors"] = [other]
    (tmp_path / "r.yaml").write_text(yaml.safe_dump(rule))
    assert main(["rules", "verify", "--rules", str(tmp_path),
                 "--rule", "test/tinynet", "--checkout", str(upstream_dir)]) == 1
