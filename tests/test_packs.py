"""Rule roots, rule packs and command plug-ins."""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from gangmu import plugins
from gangmu.cli import build_parser, main
from gangmu.rules import packs
from gangmu.rules.loader import load_rule_roots
from gangmu.rules.packs import RulePackError, RuleRoot, default_roots


def _copy_rule(rules_dir: Path, dest: Path, **changes) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    src = next(rules_dir.rglob("*.yaml"))
    data = yaml.safe_load(src.read_text())
    data.update(changes)
    (dest / src.name).write_text(yaml.safe_dump(data))
    return dest


def test_a_later_root_replaces_a_rule_with_the_same_id(rules_dir, tmp_path):
    private = _copy_rule(rules_dir, tmp_path / "private",
                         notes="private build of the same component")
    base = load_rule_roots([rules_dir, private])
    assert len(base) == 1
    assert base.rules[0].source_path and base.errors == []
    assert len(base.overridden) == 1 and "replaces" in base.overridden[0]
    assert [r.path for r in base.roots] == [rules_dir, private]


def test_a_rule_base_for_a_newer_tool_is_refused(rules_dir, tmp_path):
    newer = _copy_rule(rules_dir, tmp_path / "newer")
    (newer / packs.MANIFEST_NAME).write_text(json.dumps(
        {"format": 1, "name": "x", "version": "1", "requires_gangmu": "99.0"}))
    with pytest.raises(RulePackError, match="need gangmu 99.0"):
        load_rule_roots([newer])
    (newer / packs.MANIFEST_NAME).write_text(json.dumps({"format": packs.RULE_FORMAT + 1}))
    with pytest.raises(RulePackError, match="rule format"):
        load_rule_roots([newer])


def test_the_cli_refuses_it_too(rules_dir, tmp_path, project_dir):
    newer = _copy_rule(rules_dir, tmp_path / "newer")
    (newer / packs.MANIFEST_NAME).write_text(json.dumps({"requires_gangmu": "99.0"}))
    with pytest.raises(SystemExit, match="need gangmu 99.0"):
        main(["scan", str(project_dir), "--rules", str(newer)])


def test_versions_compare_numerically():
    assert packs._version_tuple("0.10.0") > packs._version_tuple("0.9.9")
    assert packs._version_tuple("0.6.0rc1") == (0, 6, 0)


def test_gangmu_rules_env_replaces_everything(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    monkeypatch.setenv("GANGMU_RULES", f"{a}{__import__('os').pathsep}{b}")
    roots = default_roots(packs=[("community", tmp_path)])
    assert [r.path for r in roots] == [a, b]


def test_installed_packs_overlay_community_first(tmp_path, monkeypatch):
    monkeypatch.delenv("GANGMU_RULES", raising=False)
    found = {"zz-private": tmp_path / "p", "community": tmp_path / "c"}
    for path in found.values():
        path.mkdir()

    class EP:
        def __init__(self, name):
            self.name = name

        def load(self):
            return lambda: found[self.name]

    monkeypatch.setattr(packs, "_entry_points",
                        lambda group: [EP("zz-private"), EP("community")])
    roots = default_roots()
    assert [r.origin for r in roots] == ["pack:community", "pack:zz-private"]


def test_cwd_rules_only_when_nothing_else(tmp_path, monkeypatch):
    monkeypatch.delenv("GANGMU_RULES", raising=False)
    (tmp_path / "rules").mkdir()
    assert default_roots(packs=[], fallback=[tmp_path / "rules"])[0].origin == "./rules"
    assert [r.origin for r in default_roots(
        packs=[("community", tmp_path)], fallback=[tmp_path / "rules"])] == ["pack:community"]


def test_scan_and_lint_take_several_rules_options(rules_dir, project_dir, tmp_path, capsys):
    private = _copy_rule(rules_dir, tmp_path / "private")
    assert main(["rules", "lint", "--rules", str(rules_dir), "--rules", str(private)]) == 0
    out = capsys.readouterr().out
    assert out.count("root ") == 2 and "over test/tinynet" in out
    assert main(["scan", str(project_dir), "--rules", str(rules_dir),
                 "--rules", str(private), "--format", "json",
                 "-o", str(tmp_path / "scan.json")]) == 0


def test_the_evidence_bundle_keeps_every_root(rules_dir, tmp_path):
    private = _copy_rule(rules_dir, tmp_path / "private")
    out = tmp_path / "bundle"
    assert main(["evidence", "--out", str(out), "--rules", str(rules_dir),
                 "--rules", str(private)]) == 0
    names = sorted(p.name for p in (out / "rules").iterdir())
    assert names == [f"1-{rules_dir.name}", "2-private"]


def test_a_plugin_adds_a_command_and_a_broken_one_is_skipped(monkeypatch, capsys):
    def register(subparsers):
        p = subparsers.add_parser("hello")
        p.set_defaults(func=lambda args: 7)

    class EP:
        def __init__(self, name, target):
            self.name, self.target = name, target

        def load(self):
            if isinstance(self.target, Exception):
                raise self.target
            return self.target

    monkeypatch.setattr(plugins, "entry_points", lambda group: [
        EP("good", register), EP("bad", ImportError("no licence module"))])
    assert main(["hello"]) == 7
    assert "plug-in 'bad' could not be loaded" in capsys.readouterr().err
    assert "scan" in build_parser()._subparsers._group_actions[0].choices
