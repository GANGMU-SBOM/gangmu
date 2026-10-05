"""The precompiled rule index: faster to load, never different."""

import json
import shutil
from pathlib import Path

import yaml

from gangmu.cli import main
from gangmu.rules.loader import INDEX_NAME, build_index, load_rules

RULES = Path(__file__).parent / "fixtures" / "rules"


def _copy(tmp_path):
    root = tmp_path / "rules"
    shutil.copytree(RULES, root)
    return root


def _same(a, b):
    assert [r.id for r in a.rules] == [r.id for r in b.rules]
    for r, s in zip(a.rules, b.rules):
        assert r.__dict__ == s.__dict__
    assert a.errors == b.errors


def test_an_indexed_rule_base_loads_the_same_rules(tmp_path):
    root = _copy(tmp_path)
    plain = load_rules(root)
    counts = build_index(root)
    assert counts["indexed"] == len(plain.rules) > 0
    _same(plain, load_rules(root))


def test_the_index_is_used_instead_of_yaml(tmp_path, monkeypatch):
    root = _copy(tmp_path)
    build_index(root)
    calls = []
    real = yaml.safe_load
    monkeypatch.setattr(yaml, "safe_load", lambda *a, **k: calls.append(1) or real(*a, **k))
    assert len(load_rules(root).rules) > 0
    assert calls == []


def test_an_edited_rule_is_reparsed(tmp_path):
    root = _copy(tmp_path)
    build_index(root)
    target = sorted(root.rglob("*.yaml"))[0]
    before = {r.id for r in load_rules(root).rules}
    target.write_text(target.read_text().replace("id: ", "id: edited-", 1))
    after = {r.id for r in load_rules(root).rules}
    assert after != before and any(i.startswith("edited-") for i in after)


def test_a_damaged_or_foreign_index_is_ignored(tmp_path):
    root = _copy(tmp_path)
    want = [r.id for r in load_rules(root).rules]
    (root / INDEX_NAME).write_text("{not json")
    assert [r.id for r in load_rules(root).rules] == want
    (root / INDEX_NAME).write_text(json.dumps({"format": 999, "files": {}}))
    assert [r.id for r in load_rules(root).rules] == want


def test_a_file_that_does_not_survive_json_is_left_to_yaml(tmp_path):
    root = _copy(tmp_path)
    (root / "dated.yaml").write_text("id: test/dated\nreview: {added: 2026-10-05}\n")
    counts = build_index(root)
    assert counts["skipped"] >= 1
    assert "dated.yaml" not in json.loads((root / INDEX_NAME).read_text())["files"]


def test_cli_index(tmp_path, capsys):
    root = _copy(tmp_path)
    assert main(["rules", "index", str(root)]) == 0
    assert "indexed" in capsys.readouterr().out
    assert (root / INDEX_NAME).exists()
