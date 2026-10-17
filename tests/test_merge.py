"""Merging CycloneDX documents."""

import json
from pathlib import Path

import pytest

from gangmu.cli import main
from gangmu.sbom.merge import MergeError, merge_boms

SCHEMAS = Path(__file__).resolve().parent / "fixtures" / "schemas"


def _doc(components, deps=(), vulns=(), root="app", spec="1.6", props=()):
    return {
        "bomFormat": "CycloneDX", "specVersion": spec, "version": 1,
        "metadata": {"component": {"type": "application", "name": root,
                                   "bom-ref": f"root-{root}"},
                     "properties": list(props)},
        "components": components,
        "dependencies": [{"ref": r, "dependsOn": d} for r, d in deps],
        "vulnerabilities": list(vulns),
    }


def _c(name, version, ref=None, purl=None, **extra):
    comp = {"type": "library", "name": name, "version": version,
            "bom-ref": ref or f"{name}-{version}", **extra}
    if purl:
        comp["purl"] = purl
    return comp


def test_the_same_purl_joins_and_the_first_document_wins():
    a = _doc([_c("zlib", "1.3.1", "a-zlib", purl="pkg:generic/zlib@1.3.1")])
    b = _doc([_c("zlib", "1.3.1", "b-zlib", purl="pkg:generic/zlib@1.3.1",
                 description="deflate", licenses=[{"license": {"id": "Zlib"}}])], root="other")
    merged, report = merge_boms([("a.json", a), ("b.json", b)])
    assert report.duplicates == 1 and len(merged["components"]) == 1
    comp = merged["components"][0]
    assert comp["bom-ref"] == "a-zlib"
    assert comp["description"] == "deflate"            # filled in from the second
    assert {"name": "gangmu:alsoIn", "value": "b.json"} in comp["properties"]


def test_different_versions_stay_twice_and_are_reported():
    a = _doc([_c("openssl", "3.0.13")])
    b = _doc([_c("openssl", "3.2.1")])
    merged, report = merge_boms([("a", a), ("b", b)])
    assert len(merged["components"]) == 2
    assert report.disagreements == [("openssl", ["3.0.13", "3.2.1"])]


def test_bom_ref_collisions_are_renamed_and_dependencies_follow():
    a = _doc([_c("x", "1", "ref"), _c("y", "1", "y1")], deps=[("root-app", ["ref"])])
    b = _doc([_c("z", "9", "ref")], deps=[("root-other", ["ref"])], root="other")
    merged, report = merge_boms([("a", a), ("b", b)])
    refs = [c["bom-ref"] for c in merged["components"]]
    assert refs == ["ref", "y1", "ref-2"] and len(set(refs)) == 3
    graph = {d["ref"]: d["dependsOn"] for d in merged["dependencies"]}
    assert graph["root-app"] == ["ref", "ref-2"]      # b's root is the product's root
    assert report.dangling_dependencies == 0


def test_dangling_dependencies_are_dropped_and_counted():
    a = _doc([_c("x", "1")], deps=[("root-app", ["x-1", "ghost"])])
    merged, report = merge_boms([("a", a)])
    assert merged["dependencies"] == [{"ref": "root-app", "dependsOn": ["x-1"]}]
    assert report.dangling_dependencies == 1


def test_vulnerabilities_join_by_id_and_keep_the_more_cautious_state():
    def vuln(ref, state):
        return {"id": "CVE-2099-1", "source": {"name": "NVD"},
                "analysis": {"state": state}, "affects": [{"ref": ref}]}
    a = _doc([_c("x", "1")], vulns=[vuln("x-1", "not_affected")])
    b = _doc([_c("y", "1")], vulns=[vuln("y-1", "exploitable")], root="other")
    merged, report = merge_boms([("a", a), ("b", b)])
    (v,) = merged["vulnerabilities"]
    assert v["analysis"]["state"] == "exploitable"
    assert {x["ref"] for x in v["affects"]} == {"x-1", "y-1"}
    assert report.state_conflicts == ["CVE-2099-1: not_affected vs exploitable"]


def test_the_highest_spec_version_is_used_and_sources_are_recorded():
    merged, _ = merge_boms([("a", _doc([], spec="1.5")), ("b", _doc([], spec="1.6"))])
    assert merged["specVersion"] == "1.6"
    assert [p["value"] for p in merged["metadata"]["properties"]
            if p["name"] == "gangmu:mergedFrom"] == ["a", "b"]


def test_a_document_that_is_not_cyclonedx_is_refused():
    with pytest.raises(MergeError):
        merge_boms([("spdx.json", {"spdxVersion": "SPDX-2.3"})])


def test_the_merged_document_is_valid_cyclonedx(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    registry = Registry()
    for name, uri in (("spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"),
                      ("jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json")):
        registry = registry.with_resource(
            uri, Resource.from_contents(json.loads((SCHEMAS / name).read_text(encoding="utf-8"))))
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    merged, _ = merge_boms([("a", _doc([_c("x", "1")], deps=[("root-app", ["x-1"])])),
                            ("b", _doc([_c("y", "2")], root="other"))])
    errors = list(jsonschema.Draft7Validator(schema, registry=registry).iter_errors(merged))
    assert not errors, errors[0].message


def test_the_command_writes_the_merged_file_and_can_fail_on_disagreement(tmp_path, capsys):
    (tmp_path / "a.json").write_text(json.dumps(_doc([_c("openssl", "3.0.13")])))
    (tmp_path / "b.json").write_text(json.dumps(_doc([_c("openssl", "3.2.1")])))
    out = tmp_path / "merged.json"
    assert main(["merge", str(tmp_path / "a.json"), str(tmp_path / "b.json"),
                 "-o", str(out)]) == 0
    assert len(json.loads(out.read_text())["components"]) == 2
    assert "disagreement: openssl is 3.0.13 and 3.2.1" in capsys.readouterr().err
    assert main(["merge", str(tmp_path / "a.json"), str(tmp_path / "b.json"),
                 "-o", str(out), "--fail-on-disagreement"]) == 1
    assert main(["merge", str(tmp_path / "missing.json")]) == 2
