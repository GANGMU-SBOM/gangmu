"""``upstream.cpe_aliases`` must reach the SBOM and the vulnerability match.

NVD renamed cJSON's vendor; old CVEs stay under the old name. A rule lists both CPEs,
but the alias used to stop at the rule: nothing copied it to the finding, so a CVE filed
under the old name was never matched.
"""

import json

from gangmu.model import Finding, ScanResult
from gangmu.rules.schema import rule_from_dict
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.sbom.spdx import to_spdx
from gangmu.vuln import candidates_from_cyclonedx, candidates_from_scan, load_database, match
from gangmu.vuln.match import wanted_for

NEW = "cpe:2.3:a:cjson_project:cjson:*:*:*:*:*:*:*:*"
OLD = "cpe:2.3:a:davegamble:cjson:*:*:*:*:*:*:*:*"


def _rule():
    return rule_from_dict({"id": "generic/cjson", "upstream": {
        "name": "cJSON", "purl": "pkg:github/DaveGamble/cJSON", "cpe": NEW, "cpe_aliases": [OLD],
        "source": {"kind": "git", "url": "https://github.com/DaveGamble/cJSON", "ref": "v1.7.18"}},
        "identity": {"anchors": [{"path": "cJSON.h", "sha256": {"1.7.18": "0" * 64}}]}},
        "cjson.yaml")


def _finding():
    rule = _rule()
    return Finding(directory="components/cjson", rule_id=rule.id, upstream_name="cJSON",
                   purl=rule.purl_with_version("1.7.10"), cpe=rule.cpe_with_version("1.7.10"),
                   cpe_aliases=rule.cpe_aliases_with_version("1.7.10"), version="1.7.10",
                   identity_confidence=0.9)


def test_the_rule_splices_the_version_into_each_alias():
    assert _rule().cpe_aliases_with_version("1.7.10") == [
        "cpe:2.3:a:davegamble:cjson:1.7.10:*:*:*:*:*:*:*"]


def test_cyclonedx_carries_the_alias_and_reads_it_back():
    bom = to_cyclonedx(ScanResult(root=".", findings=[_finding()]))
    comp = bom["components"][0]
    assert {"name": "gangmu:cpeAlias",
            "value": "cpe:2.3:a:davegamble:cjson:1.7.10:*:*:*:*:*:*:*"} in comp["properties"]
    assert len(candidates_from_cyclonedx(bom)[0].cpes) == 2


def test_the_scan_result_path_uses_the_alias_too():
    assert len(candidates_from_scan(ScanResult(root=".", findings=[_finding()]))[0].cpes) == 2


def test_spdx_lists_both_cpes():
    text = json.dumps(to_spdx(ScanResult(root=".", findings=[_finding()])))
    assert "davegamble" in text and "cjson_project" in text


def test_a_cve_filed_under_the_old_vendor_name_now_matches(tmp_path):
    nvd = {"cve": {"id": "CVE-2099-0200", "descriptions": [{"lang": "en", "value": "synthetic"}],
                   "configurations": [{"nodes": [{"cpeMatch": [{
                       "vulnerable": True, "criteria": OLD, "versionEndExcluding": "1.7.15"}]}]}]}}
    (tmp_path / "nvd.json").write_text(json.dumps({"vulnerabilities": [nvd]}))
    bom = to_cyclonedx(ScanResult(root=".", findings=[_finding()]))
    cands = candidates_from_cyclonedx(bom)
    found = match(cands, load_database(tmp_path, wanted_for(cands)))
    assert [m.advisory.id for m in found] == ["CVE-2099-0200"]
    assert found[0].channel == "cpe"
