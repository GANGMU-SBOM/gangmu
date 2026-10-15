"""Licence triage of a CycloneDX SBOM."""

import json

from gangmu.cli import main
from gangmu.licensecheck import check_licenses, classify_id, component_class, incompatible


def _comp(name, version, license_id=None, expression=None):
    comp = {"type": "library", "name": name, "version": version}
    if license_id:
        comp["licenses"] = [{"license": {"id": license_id}}]
    if expression:
        comp["licenses"] = [{"expression": expression}]
    return comp


def test_classes():
    assert classify_id("MIT") == "permissive"
    assert classify_id("LGPL-2.1-or-later") == "weak"
    assert classify_id("MPL-2.0") == "weak"
    assert classify_id("GPL-2.0-only") == "strong"
    assert classify_id("AGPL-3.0-only") == "network"
    assert classify_id("LicenseRef-vendor") == "unknown"


def test_an_or_expression_is_classed_by_its_most_permissive_choice():
    assert component_class("GPL-2.0-only OR MIT")[:2] == ("permissive", ["MIT"])
    assert component_class("(MIT OR Apache-2.0) AND BSD-3-Clause")[0] == "permissive"
    assert component_class("GPL-2.0-only AND MIT")[0] == "strong"


def test_a_with_exception_is_noted_not_trusted():
    klass, ids, exceptions = component_class("GPL-2.0-only WITH Classpath-exception-2.0")
    assert klass == "strong" and ids == ["GPL-2.0-only"]
    assert exceptions == ["Classpath-exception-2.0"]


def test_known_incompatible_pairs_are_symmetric_and_or_later_is_fine():
    assert incompatible("Apache-2.0", "GPL-2.0-only")
    assert incompatible("GPL-2.0-only", "Apache-2.0")
    assert incompatible("Apache-2.0", "GPL-3.0-only") is None
    assert incompatible("Apache-2.0", "GPL-2.0-or-later") is None
    assert incompatible("GPL-2.0-only", "GPL-3.0-only")
    assert incompatible("GPL-2.0-only", "GPL-3.0-or-later") is None
    assert incompatible("OpenSSL", "GPL-2.0-or-later")
    assert incompatible("CDDL-1.0", "GPL-2.0-only")
    assert incompatible("MIT", "GPL-2.0-only") is None


def test_the_report_names_copyleft_conflicts_and_gaps():
    bom = {"bomFormat": "CycloneDX", "components": [
        _comp("zlib", "1.3.1", "Zlib"), _comp("busybox", "1.36.1", "GPL-2.0-only"),
        _comp("mbedtls", "3.6.0", "Apache-2.0"), _comp("mystery", "1.0"),
        _comp("dual", "2", expression="GPL-2.0-only OR MIT"),
        _comp("proprietary-hal", "9", "LicenseRef-vendor")]}
    report = check_licenses(bom)
    assert report.counts == {"permissive": 3, "strong": 1, "unknown": 2}
    assert report.copyleft == ["busybox 1.36.1: GPL-2.0-only"]
    assert [(a, b) for a, b, _ in report.possible_conflicts] == [
        ("busybox (GPL-2.0-only)", "mbedtls (Apache-2.0)")]
    assert sorted(report.unlicensed) == ["mystery 1.0", "proprietary-hal 9 (LicenseRef-vendor)"]


def test_prebuilt_binaries_are_listed_apart_from_unlicensed_components():
    bom = {"bomFormat": "CycloneDX", "components": [
        {"type": "file", "name": "vendor/libfoo.a"}, _comp("x", "1", "MIT")]}
    report = check_licenses(bom)
    assert report.unlicensed == [] and report.unlicensed_files == ["vendor/libfoo.a"]
    assert report.counts == {"permissive": 1}


def test_the_command(tmp_path, capsys):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
        _comp("busybox", "1", "GPL-2.0-only"), _comp("mbedtls", "3", "Apache-2.0")]}))
    assert main(["license-check", str(path)]) == 0
    out = capsys.readouterr().out
    assert "possible incompatibilities" in out and "not a legal conclusion" in out
    assert main(["license-check", str(path), "--fail-on", "incompatible"]) == 1
    capsys.readouterr()
    assert main(["license-check", str(path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["copyleft"] == ["busybox 1: GPL-2.0-only"]
    assert data["possibleConflicts"][0]["why"].startswith("Apache-2.0 is not compatible")
    (tmp_path / "x.json").write_text("{}")
    assert main(["license-check", str(tmp_path / "x.json")]) == 2
