"""Weak identifications are reported, but never become SBOM components."""

from gangmu.cli import _table
from gangmu.rules.loader import load_rules
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.scan import ScanOptions, scan


def _scan(project, rules_dir, **kw):
    return scan(project, load_rules(rules_dir, strict=True), None, ScanOptions(**kw))


def test_a_confident_finding_stays_a_component(project_dir, rules_dir):
    result = _scan(project_dir, rules_dir)
    assert result.findings and not result.possible


def test_a_weak_finding_moves_to_possible(project_dir, rules_dir):
    result = _scan(project_dir, rules_dir, possible_below=1.01)
    assert not result.findings
    assert result.possible
    assert result.to_dict()["possible"]


def test_possible_findings_stay_out_of_the_sbom_but_are_listed(project_dir, rules_dir):
    result = _scan(project_dir, rules_dir, possible_below=1.01)
    bom = to_cyclonedx(result)
    assert bom["components"] == []
    props = [p for p in bom["metadata"]["properties"]
             if p["name"] == "gangmu:possibleComponent"]
    assert props and "tinynet" in props[0]["value"]


def test_the_table_lists_possible_separately(project_dir, rules_dir):
    text = _table(_scan(project_dir, rules_dir, possible_below=1.01))
    assert "POSSIBLE" in text and "tinynet" in text


def test_possible_below_zero_keeps_everything_as_before(project_dir, rules_dir):
    result = _scan(project_dir, rules_dir, possible_below=0.0)
    assert result.findings and not result.possible
