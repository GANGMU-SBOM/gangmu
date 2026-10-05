"""CRA self-check, report drafts and the evidence bundle.

The behaviour worth protecting here is restraint: the tool must never report an
obligation as met on the strength of a declaration, and must keep saying which
obligations it does not address at all.
"""

import json
from pathlib import Path

import pytest
import yaml

from gangmu.config import Config, load_config, write_template
from gangmu.cra import REPORT_STAGES, build_evidence_bundle, check_cra, draft_report
from gangmu.cra.requirements import REQUIREMENTS
from gangmu.cra.check import Verdict


def _config(**overrides) -> Config:
    raw = yaml.safe_load(Path(__file__).resolve().parents[1].joinpath()
                         .as_posix() and "") or {}
    raw = {
        "product": {"name": "Gateway", "version": "1.0.0"},
        "manufacturer": {"name": "Acme", "contact": "a@example.invalid",
                         "cvd_policy_url": "https://example.invalid/cvd",
                         "vulnerability_contact": "https://example.invalid/sec"},
        "market": {"member_states": ["DE"], "placed_on_market": "2027-03-01"},
        "reporting": {"csirt": "CERT-Bund", "assigned_representative": "J. Weber"},
        "retention": {"years": 10},
    }
    for section, values in overrides.items():
        if values is None:
            raw.pop(section, None)
        else:
            raw.setdefault(section, {}).update(values)
    return Config(path=Path("gangmu.yaml"), raw=raw)


GOOD_BOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "metadata": {"properties": [{"name": "gangmu:buildFactsUsed", "value": "true"},
                                {"name": "gangmu:unidentifiedDirectories", "value": "0"}]},
    "components": [{"bom-ref": "c1", "name": "lwIP", "version": "2.2.0",
                    "purl": "pkg:generic/lwip@2.2.0",
                    "cpe": "cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*",
                    "properties": [{"name": "gangmu:directory", "value": "d"}]}],
}
GOOD_VEX = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": GOOD_BOM["components"],
    "vulnerabilities": [{"id": "TEST-1", "affects": [{"ref": "c1"}],
                         "description": "Synthetic.",
                         "ratings": [{"severity": "high"}],
                         "analysis": {"state": "exploitable",
                                      "detail": "version is inside the range"}}],
}


# ------------------------------------------------------------- the table

def test_the_requirement_table_says_what_is_out_of_scope():
    out_of_scope = [r for r in REQUIREMENTS if not r.checkable]
    assert {r.id for r in out_of_scope} >= {"AI-II-3", "AI-II-7", "AI-II-8"}
    assert all(r.tool_role for r in REQUIREMENTS)


def test_every_requirement_quotes_its_clause():
    assert all(r.clause and r.text for r in REQUIREMENTS)


# -------------------------------------------------------------- the check

def test_a_complete_sbom_meets_the_sbom_obligation():
    result = check_cra(_config(), bom=GOOD_BOM, vex=GOOD_VEX)
    sbom = next(f for f in result.findings if f.requirement.id == "AI-II-1")
    assert sbom.verdict is Verdict.MET


def test_a_source_only_sbom_is_not_enough():
    bom = json.loads(json.dumps(GOOD_BOM))
    bom["metadata"]["properties"][0]["value"] = "false"
    result = check_cra(_config(), bom=bom, vex=GOOD_VEX)
    sbom = next(f for f in result.findings if f.requirement.id == "AI-II-1")
    assert sbom.verdict is Verdict.PARTIAL
    assert any("over-report" in g for g in sbom.gaps)


def test_unidentified_directories_block_the_top_level_claim():
    result = check_cra(_config(), bom=GOOD_BOM, vex=GOOD_VEX,
                       scan={"unidentified": ["components/mystery"]})
    sbom = next(f for f in result.findings if f.requirement.id == "AI-II-1")
    assert sbom.verdict is Verdict.PARTIAL
    assert any("not identified" in g for g in sbom.gaps)
    assert "rule" in sbom.next_step


def test_a_component_with_no_identifier_is_called_out():
    bom = json.loads(json.dumps(GOOD_BOM))
    bom["components"][0].pop("purl"); bom["components"][0].pop("cpe")
    result = check_cra(_config(), bom=bom, vex=GOOD_VEX)
    sbom = next(f for f in result.findings if f.requirement.id == "AI-II-1")
    assert any("neither a purl nor a cpe" in g for g in sbom.gaps)


def test_no_sbom_is_a_blocking_failure():
    result = check_cra(_config())
    assert "AI-II-1" in {f.requirement.id for f in result.blocking}


def test_a_declared_policy_is_declared_never_met():
    """A URL in a config file is not evidence that a policy is enforced."""
    result = check_cra(_config(), bom=GOOD_BOM, vex=GOOD_VEX)
    cvd = next(f for f in result.findings if f.requirement.id == "AI-II-5")
    assert cvd.verdict is Verdict.DECLARED


def test_a_missing_policy_blocks():
    result = check_cra(_config(manufacturer={"cvd_policy_url": ""}),
                       bom=GOOD_BOM, vex=GOOD_VEX)
    cvd = next(f for f in result.findings if f.requirement.id == "AI-II-5")
    assert cvd.verdict is Verdict.NOT_MET


def test_update_distribution_stays_out_of_scope_whatever_is_supplied():
    result = check_cra(_config(), bom=GOOD_BOM, vex=GOOD_VEX)
    for rid in ("AI-II-3", "AI-II-7", "AI-II-8"):
        finding = next(f for f in result.findings if f.requirement.id == rid)
        assert finding.verdict is Verdict.OUT_OF_SCOPE


def test_an_analysis_without_justification_is_only_partial():
    vex = json.loads(json.dumps(GOOD_VEX))
    vex["vulnerabilities"][0]["analysis"].pop("detail")
    result = check_cra(_config(), bom=GOOD_BOM, vex=vex)
    finding = next(f for f in result.findings if f.requirement.id == "AI-II-2")
    assert finding.verdict is Verdict.PARTIAL


def test_reporting_readiness_names_the_missing_field():
    result = check_cra(_config(market={"member_states": []}), bom=GOOD_BOM,
                       vex=GOOD_VEX)
    finding = next(f for f in result.findings if f.requirement.id == "ART-14")
    assert any("member_states" in g for g in finding.gaps)


# ------------------------------------------------------------- the drafts

def test_the_24_hour_draft_fills_itself_from_the_sbom_and_config():
    draft = draft_report("early-warning", _config(), "TEST-1", vex=GOOD_VEX,
                         aware_at="2027-05-14T08:12Z")
    values = {f.label: f.value for f in draft.fields}
    assert values["Manufacturer"] == "Acme"
    assert values["Product name"] == "Gateway"
    assert values["Member states where the product is available"] == "DE"
    assert values["Affected component"] == "lwIP"
    assert values["Component version"] == "2.2.0"
    assert draft.missing == []


def test_a_missing_config_field_is_shown_as_missing_not_invented():
    draft = draft_report("early-warning", _config(product={"version": ""}),
                         "TEST-1", vex=GOOD_VEX)
    assert "Product version(s) affected" in [f.label for f in draft.missing]
    assert "**— MISSING —**" in draft.to_markdown()


def test_each_stage_carries_its_own_deadline():
    for stage in REPORT_STAGES:
        draft = draft_report(stage, _config(), "TEST-1", vex=GOOD_VEX)
        assert draft.deadline
    assert "24 hours" in draft_report("early-warning", _config(), "X").deadline
    assert "72 hours" in draft_report("notification", _config(), "X").deadline
    assert "14 days" in draft_report("final", _config(), "X").deadline


def test_an_in_triage_finding_is_flagged_in_the_draft():
    vex = json.loads(json.dumps(GOOD_VEX))
    vex["vulnerabilities"][0]["analysis"]["state"] = "in_triage"
    draft = draft_report("notification", _config(), "TEST-1", vex=vex)
    assert any("triage" in n for n in draft.notes)


def test_an_unknown_stage_is_refused():
    with pytest.raises(ValueError):
        draft_report("whenever", _config(), "TEST-1")


# ------------------------------------------------------------ the bundle

def test_the_bundle_hashes_everything_it_contains(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(GOOD_BOM))
    bundle = build_evidence_bundle(tmp_path / "out", _config(), sbom=sbom)
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["files"]
    assert all(len(f["sha256"]) == 64 for f in manifest["files"])


def test_the_bundle_readme_states_the_retention_period(tmp_path):
    build_evidence_bundle(tmp_path / "out", _config())
    readme = (tmp_path / "out" / "README.md").read_text()
    assert "10 years" in readme and "2027-03-01" in readme
    assert "gangmu rules verify" in readme


def test_the_bundle_records_what_was_not_supplied(tmp_path):
    bundle = build_evidence_bundle(tmp_path / "out", _config())
    assert any("sbom.json" in n for n in bundle.notes)
    readme = (tmp_path / "out" / "README.md").read_text()
    assert "may over-report" in readme


# ------------------------------------------------------------- the config

def test_the_template_is_valid_and_marks_required_fields(tmp_path):
    path = write_template(tmp_path / "gangmu.yaml")
    config = load_config(path)
    assert config.get("retention.years") == 10
    assert "REQUIRED" in path.read_text()


def test_config_is_found_by_walking_up(tmp_path):
    write_template(tmp_path / "gangmu.yaml")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    from gangmu.config import find_config
    assert find_config(nested) == tmp_path / "gangmu.yaml"


def test_an_empty_field_reads_as_absent(tmp_path):
    path = tmp_path / "gangmu.yaml"
    path.write_text("product:\n  name: ''\n")
    assert load_config(path).product_name is None
