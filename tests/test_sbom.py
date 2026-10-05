import json

from gangmu.model import Evidence, Finding, ScanResult, Technique
from gangmu.sbom import to_cyclonedx, to_spdx


def _result():
    fork = Finding(
        directory="components/net/tinynet",
        rule_id="test/tinynet",
        upstream_name="tinynet",
        purl="pkg:generic/tinynet@1.4.2",
        cpe="cpe:2.3:a:tinynet_project:tinynet:1.4.2:*:*:*:*:*:*:*",
        homepage="https://example.invalid/tinynet",
        declared_license="MIT",
        version="1.4.2",
        version_source="probe",
        identity_confidence=0.9,
        version_confidence=0.85,
        vendor_patched=True,
        vendor_name="Example Semiconductor",
        renamed_from="exsemi_net",
        patch_hint="vendor added a reset helper",
        evidence=[Evidence(Technique.AST_FINGERPRINT, 0.9, "similarity 0.94", "x")],
        compiled_files=4,
        linked=True,
    )
    return ScanResult(root="/p", findings=[fork], rules_loaded=1, build_facts_used=True)


def test_cyclonedx_is_well_formed_json_and_1_6():
    bom = to_cyclonedx(_result(), "firmware", "1.0.0")
    assert json.loads(json.dumps(bom))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["name"] == "firmware"


def test_a_fork_carries_pedigree_rather_than_pretending_to_be_upstream():
    comp = to_cyclonedx(_result())["components"][0]
    assert comp["pedigree"]["ancestors"][0]["name"] == "tinynet"
    assert comp["pedigree"]["patches"][0]["type"] == "unofficial"
    assert "reset helper" in comp["pedigree"]["notes"]


def test_identity_evidence_carries_confidence_and_methods():
    comp = to_cyclonedx(_result())["components"][0]
    identity = comp["evidence"]["identity"]
    assert {e["field"] for e in identity} == {"purl", "cpe"}
    assert all(0.0 <= e["confidence"] <= 1.0 for e in identity)
    assert identity[0]["methods"][0]["technique"] == "ast-fingerprint"


def test_build_facts_survive_into_properties():
    props = {p["name"]: p["value"] for p in to_cyclonedx(_result())["components"][0]["properties"]}
    assert props["gangmu:compiledFiles"] == "4"
    assert props["gangmu:linkedIntoImage"] == "true"
    assert props["gangmu:versionSource"] == "probe"
    assert props["gangmu:shippedAs"] == "exsemi_net"


def test_dependencies_reference_every_component():
    bom = to_cyclonedx(_result())
    refs = {c["bom-ref"] for c in bom["components"]}
    assert set(bom["dependencies"][0]["dependsOn"]) == refs


def test_output_is_reproducible_when_time_and_serial_are_pinned():
    a = to_cyclonedx(_result(), timestamp="2026-01-01T00:00:00Z", serial="urn:uuid:x")
    b = to_cyclonedx(_result(), timestamp="2026-01-01T00:00:00Z", serial="urn:uuid:x")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_spdx_keeps_the_hedging_that_the_format_cannot_model():
    doc = to_spdx(_result(), "firmware")
    assert doc["spdxVersion"] == "SPDX-2.3"
    pkg = next(p for p in doc["packages"] if p["name"] == "tinynet")
    assert "VENDOR-MODIFIED" in pkg["comment"]
    assert "identity confidence" in pkg["comment"]
    assert {r["referenceType"] for r in pkg["externalRefs"]} == {"purl", "cpe23Type"}


def test_spdx_relationships_are_complete():
    doc = to_spdx(_result(), "firmware")
    ids = {p["SPDXID"] for p in doc["packages"]}
    related = {r["relatedSpdxElement"] for r in doc["relationships"]}
    assert ids == related


def test_a_component_without_a_version_is_still_emitted():
    f = Finding(directory="d", rule_id="r", upstream_name="mystery",
                identity_confidence=0.5)
    bom = to_cyclonedx(ScanResult(root="/p", findings=[f]))
    comp = bom["components"][0]
    assert "version" not in comp
    assert comp["evidence"]["identity"][0]["field"] == "name"
