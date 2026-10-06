"""SPDX 3, OpenVEX and CSAF output, and the support-status field.

Each document is validated against the published JSON schema (vendored under
tests/fixtures/schemas): a writer that "looks right" is exactly what a buyer's
validator rejects.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("jsonschema")
from jsonschema import Draft202012Validator  # noqa: E402

from gangmu.model import Evidence, Finding, ScanResult, Technique
from gangmu.sbom import to_spdx, to_spdx3, to_cyclonedx
from gangmu.support import (Support, SupportError, load_overrides, parse_support,
                            stamp)
from gangmu.vuln import load_database, match
from gangmu.vuln.csaf import to_csaf
from gangmu.vuln.model import VexState
from gangmu.vuln.openvex import to_openvex

from test_vuln import DB, _lwip

SCHEMAS = Path(__file__).resolve().parent / "fixtures" / "schemas"


def _validator(name):
    return Draft202012Validator(json.loads((SCHEMAS / name).read_text(encoding="utf-8")))


def _finding(**kw):
    base = dict(
        directory="components/net/tinynet", rule_id="test/tinynet",
        upstream_name="tinynet", purl="pkg:generic/tinynet@1.4.2",
        cpe="cpe:2.3:a:tinynet_project:tinynet:1.4.2:*:*:*:*:*:*:*",
        homepage="https://example.invalid/tinynet", declared_license="MIT",
        version="1.4.2", version_source="probe", identity_confidence=0.9,
        version_confidence=0.85, vendor_patched=True,
        vendor_name="Example Semiconductor", renamed_from="exsemi_net",
        patch_hint="vendor added a reset helper",
        evidence=[Evidence(Technique.AST_FINGERPRINT, 0.9, "similarity 0.94", "x")],
        content_hash="ab" * 32, depends_on=["other"], component_name="tinynet")
    base.update(kw)
    return Finding(**base)


def _result(*findings):
    return ScanResult(root="/p", findings=list(findings) or [_finding()],
                      rules_loaded=1, build_facts_used=True)


# ------------------------------------------------------------- support

def test_support_status_is_validated():
    assert parse_support({"status": "maintained", "end_of_support": "2030-01-01"},
                         "t").status == "maintained"
    with pytest.raises(SupportError):
        parse_support({"status": "fine"}, "t")
    with pytest.raises(SupportError):
        parse_support({"status": "maintained", "end_of_support": "next year"}, "t")


def test_override_file_must_name_a_component(tmp_path):
    f = tmp_path / "support.json"
    f.write_text(json.dumps({"components": [{"status": "abandoned"}]}))
    with pytest.raises(SupportError):
        load_overrides(f)


def test_override_beats_rule_and_unnamed_components_stay_unknown(tmp_path):
    f = tmp_path / "support.yaml"
    f.write_text("components:\n  - name: TinyNet\n    version: '1.4.2'\n"
                 "    status: no_longer_maintained\n    end_of_support: 2025-06-30\n"
                 "    source: https://example.invalid/eol\n")
    overrides = load_overrides(f)
    named, other = _finding(), _finding(upstream_name="other", rule_id="test/other",
                                        directory="x")

    class R:
        support = Support("maintained")
    unknown = stamp({"test/tinynet": R()}, overrides, [named, other])
    assert named.support.status == "no_longer_maintained"
    assert named.support.end_of_support == "2025-06-30"
    assert other.support.status == "unknown" and unknown == 1


def test_a_rule_block_is_used_when_nothing_overrides_it():
    class R:
        support = Support("limited", None, "https://example.invalid", "2026-10-01")
    f = _finding()
    stamp({"test/tinynet": R()}, [], [f])
    assert f.support.status == "limited"


def test_all_three_sbom_formats_carry_support_and_say_unknown_when_nobody_did():
    known = _finding(support=Support("no_longer_maintained", "2026-12-31",
                                     "https://example.invalid/eol", "2026-10-01"))
    cdx = {p["name"]: p["value"] for p in
           to_cyclonedx(_result(known))["components"][0]["properties"]}
    assert cdx["gangmu:supportStatus"] == "no_longer_maintained"
    assert cdx["gangmu:endOfSupport"] == "2026-12-31"
    pkg = next(p for p in to_spdx(_result(known))["packages"] if p["name"] == "tinynet")
    assert pkg["validUntilDate"] == "2026-12-31T00:00:00Z"
    assert "end of support 2026-12-31" in pkg["comment"]
    pkg3 = next(e for e in to_spdx3(_result(known))["@graph"]
                if e.get("name") == "tinynet" and e["type"] == "software_Package")
    assert pkg3["supportLevel"] == ["noSupport"]
    assert pkg3["validUntilTime"] == "2026-12-31T00:00:00Z"

    silent = {p["name"]: p["value"] for p in
              to_cyclonedx(_result(_finding()))["components"][0]["properties"]}
    assert silent["gangmu:supportStatus"] == "unknown"
    pkg3 = next(e for e in to_spdx3(_result(_finding()))["@graph"]
                if e.get("name") == "tinynet" and e["type"] == "software_Package")
    assert pkg3["supportLevel"] == ["noAssertion"] and "validUntilTime" not in pkg3


# --------------------------------------------------------------- SPDX 3

def test_spdx3_validates_against_the_published_schema():
    f = _finding(support=Support("maintained", None, "https://example.invalid", "2026-10-01"))
    other = _finding(upstream_name="other", directory="components/other",
                     rule_id="test/other", purl=None, cpe=None, vendor_name=None,
                     homepage=None, declared_license=None, content_hash=None,
                     depends_on=[], component_name="other", vendor_patched=False)
    doc = to_spdx3(_result(f, other), "firmware", "1.0",
                   timestamp="2026-10-01T00:00:00Z", namespace="https://example.invalid/ns")
    errors = list(_validator("spdx-3.0.1.schema.json").iter_errors(doc))
    assert not errors, errors[0].message[:300]
    types = [e["type"] for e in doc["@graph"]]
    assert types.count("software_Sbom") == 1 and types.count("SpdxDocument") == 1


def test_spdx3_keeps_what_the_format_has_no_field_for():
    doc = to_spdx3(_result())
    pkg = next(e for e in doc["@graph"] if e.get("name") == "tinynet"
               and e["type"] == "software_Package")
    assert "VENDOR-MODIFIED" in pkg["comment"] and "identity confidence" in pkg["comment"]
    assert pkg["software_packageUrl"] == "pkg:generic/tinynet@1.4.2"
    assert pkg["externalIdentifier"][0]["externalIdentifierType"] == "cpe23"
    assert pkg["verifiedUsing"][0]["hashValue"] == "ab" * 32


def test_spdx3_is_reproducible_when_pinned():
    a = to_spdx3(_result(), timestamp="2026-10-01T00:00:00Z", namespace="https://e.invalid/n")
    b = to_spdx3(_result(), timestamp="2026-10-01T00:00:00Z", namespace="https://e.invalid/n")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---------------------------------------------------------- OpenVEX / CSAF

BOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
       "metadata": {"component": {"name": "firmware"}},
       "components": [{"bom-ref": "c1", "type": "library", "name": "lwIP",
                       "version": "2.2.0", "purl": "pkg:generic/lwip@2.2.0",
                       "cpe": "cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*",
                       "properties": [{"name": "gangmu:directory",
                                       "value": "components/lwip/lwip"}]}]}


def _matches(fork=False):
    return match([_lwip(fork=fork)], load_database(DB))


def test_openvex_validates_and_maps_states():
    found = _matches()
    assert found, "fixture should yield a match"
    for state, status in ((VexState.EXPLOITABLE, "affected"),
                          (VexState.IN_TRIAGE, "under_investigation"),
                          (VexState.RESOLVED, "fixed")):
        found[0].state = state
        doc = to_openvex(found, BOM, author="Example Co", timestamp="2026-10-01T00:00:00Z",
                         doc_id="https://example.invalid/vex/1")
        errors = list(_validator("openvex-0.2.0.schema.json").iter_errors(doc))
        assert not errors, errors[0].message
        assert doc["statements"][0]["status"] == status
    assert doc["statements"][0]["products"][0]["identifiers"]["purl"] == "pkg:generic/lwip@2.2.0"


def test_openvex_not_affected_carries_justification_only_when_it_maps_exactly():
    found = _matches()
    found[0].state, found[0].justification = VexState.NOT_AFFECTED, "code_not_reachable"
    found[0].detail = "function never called"
    s = to_openvex(found, BOM, author="x")["statements"][0]
    assert s["justification"] == "vulnerable_code_not_in_execute_path"
    found[0].justification = "requires_environment"
    s = to_openvex(found, BOM, author="x")["statements"][0]
    assert "justification" not in s and s["impact_statement"] == "function never called"


def test_openvex_and_csaf_refuse_to_invent_a_publisher():
    found = _matches()
    with pytest.raises(ValueError):
        to_openvex(found, BOM, author="")
    with pytest.raises(ValueError):
        to_csaf(found, BOM, publisher="Example Co", publisher_url="")


def test_openvex_and_csaf_cannot_express_nothing():
    with pytest.raises(ValueError):
        to_openvex([], BOM, author="x")
    with pytest.raises(ValueError):
        to_csaf([], BOM, publisher="x", publisher_url="https://example.invalid")


@pytest.mark.parametrize("state,justification", [
    (VexState.EXPLOITABLE, ""), (VexState.IN_TRIAGE, ""), (VexState.RESOLVED, ""),
    (VexState.NOT_AFFECTED, "code_not_present"), (VexState.NOT_AFFECTED, ""),
    (VexState.FALSE_POSITIVE, "")])
def test_csaf_vex_validates_for_every_state(state, justification):
    found = _matches()
    found[0].state, found[0].justification = state, justification
    doc = to_csaf(found, BOM, app_name="firmware", publisher="Example Co",
                  publisher_url="https://example.invalid", timestamp="2026-10-01T00:00:00Z")
    errors = list(_validator("csaf-2.0.schema.json").iter_errors(doc))
    assert not errors, errors[0].message[:300]
    vuln = doc["vulnerabilities"][0]
    if state is VexState.EXPLOITABLE:
        assert vuln["remediations"][0]["category"] == "none_available"
    if state is VexState.NOT_AFFECTED and justification:
        assert vuln["flags"][0]["label"] == "vulnerable_code_not_present"
    if state is VexState.NOT_AFFECTED and not justification:
        assert vuln["threats"][0]["category"] == "impact"
    assert doc["document"]["tracking"]["status"] == "draft"


def test_one_statement_per_vulnerability_and_component_when_two_channels_match():
    found = _matches()
    twin = match([_lwip()], load_database(DB))[0]
    twin.channel = "purl"
    doc = to_openvex(found + [twin], BOM, author="x")
    assert not list(_validator("openvex-0.2.0.schema.json").iter_errors(doc))
    names = [s["vulnerability"]["name"] for s in doc["statements"]]
    assert len(names) == len(set(names))


def test_a_rule_can_carry_a_support_block_and_a_bad_one_is_rejected(tmp_path):
    import shutil
    from gangmu.rules.loader import load_rules
    shutil.copytree(Path(__file__).resolve().parent / "fixtures" / "rules", tmp_path / "r")
    rule_file = next((tmp_path / "r").rglob("*.yaml"))
    original = rule_file.read_text(encoding="utf-8")
    rule_file.write_text(original.replace(
        "upstream:\n", "upstream:\n  support:\n    status: limited\n"
        "    end_of_support: 2027-01-01\n    source: https://example.invalid\n", 1),
        encoding="utf-8")
    base = load_rules(tmp_path / "r")
    assert not base.errors and base.rules[0].support.status == "limited"
    rule_file.write_text(original.replace("upstream:\n", "upstream:\n  support:\n    status: fine\n", 1),
                         encoding="utf-8")
    base = load_rules(tmp_path / "r")
    assert base.errors and "support status" in base.errors[0]
