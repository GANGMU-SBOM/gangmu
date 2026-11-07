"""Severity ratings and duplicate vulnerabilities, from real record shapes.

OSV puts a CVSS *vector* in ``severity[].score``, NVD scores some CVEs only in CVSS
v4.0, and one vulnerability is often filed twice (an NVD CVE and the GHSA aliasing
it). Synthetic ids only (CVE-2099-..., GHSA-test-...).
"""

import json
from pathlib import Path

import pytest

from gangmu.vuln.csaf import to_csaf
from gangmu.vuln.cvss import base_score_v3, level, level_for_score, method_for
from gangmu.vuln.match import Candidate, match
from gangmu.vuln.sources import advisory_from_nvd, load_osv
from gangmu.vuln.vex import summary, to_vex

SCHEMAS = Path(__file__).resolve().parent / "fixtures" / "schemas"
V31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
LWIP_CPE = "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*"
LWIP_PURL = "pkg:github/lwip-tcpip/lwip"


def _validator(name):
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(
        json.loads((SCHEMAS / name).read_text(encoding="utf-8")))


def _osv(tmp_path, severity=None, database_specific=None, aliases=("CVE-2099-0001",),
         osv_id="GHSA-test-0001", fixed="2.2.0"):
    record = {"id": osv_id, "summary": "overflow", "aliases": list(aliases),
              "affected": [{"package": {"ecosystem": "GIT", "name": "lwip",
                                        "purl": LWIP_PURL},
                            "ranges": [{"type": "ECOSYSTEM", "events": [
                                {"introduced": "0"}, {"fixed": fixed}]}]}]}
    if severity is not None:
        record["severity"] = severity
    if database_specific is not None:
        record["database_specific"] = database_specific
    path = tmp_path / f"{osv_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return load_osv(path)[0]


def _nvd(metrics=None, cve_id="CVE-2099-0001", end_excluding="2.2.0"):
    return advisory_from_nvd({"cve": {
        "id": cve_id, "metrics": metrics or {},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": LWIP_CPE,
            "versionEndExcluding": end_excluding}]}]}]}})


def _lwip(version="2.1.3"):
    return Candidate(name="lwIP", version=version, directory="components/lwip",
                     cpes=[LWIP_CPE.replace(":*:*:*:*:*:*:*:*", f":{version}:*:*:*:*:*:*:*")],
                     purls=[f"{LWIP_PURL}@{version}"])


# ------------------------------------------------------------------ CVSS

@pytest.mark.parametrize("vector, score", [
    (V31_CRITICAL, 9.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),     # scope changed
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_v3_base_scores_match_the_specification(vector, score):
    assert base_score_v3(vector) == score


@pytest.mark.parametrize("vector", [V4, "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "CVSS:3.1/AV:N/AC:L", "", None])
def test_anything_but_a_complete_v3_vector_is_not_scored(vector):
    assert base_score_v3(vector) is None


def test_methods_and_levels():
    assert method_for(V31_CRITICAL) == "CVSSv31"
    assert method_for("CVSS:3.0/AV:N") == "CVSSv3"
    assert method_for(V4) == "CVSSv4"
    assert method_for("AV:N/AC:L/Au:N/C:P/I:P/A:P") == "CVSSv2"
    assert level("MODERATE") == "medium" and level("High") == "high"
    assert level(V31_CRITICAL) is None
    assert [level_for_score(s) for s in (0.0, 3.9, 4.0, 7.0, 9.0)] == \
        ["none", "low", "medium", "high", "critical"]


# ------------------------------------------------------------------ OSV

def test_an_osv_vector_becomes_a_score_and_a_level_not_a_severity_string(tmp_path):
    adv = _osv(tmp_path, severity=[{"type": "CVSS_V3", "score": V31_CRITICAL}])
    assert (adv.cvss, adv.severity, adv.vector, adv.cvss_method) == \
        (9.8, "critical", V31_CRITICAL, "CVSSv31")


def test_an_osv_v4_vector_keeps_the_ghsa_level_and_no_guessed_score(tmp_path):
    adv = _osv(tmp_path, severity=[{"type": "CVSS_V4", "score": V4}],
               database_specific={"severity": "MODERATE"})
    assert (adv.cvss, adv.severity, adv.vector, adv.cvss_method) == \
        (None, "medium", V4, "CVSSv4")


def test_osv_prefers_v3_when_both_are_given(tmp_path):
    adv = _osv(tmp_path, severity=[{"type": "CVSS_V4", "score": V4},
                                   {"type": "CVSS_V3", "score": V31_CRITICAL}])
    assert adv.cvss == 9.8 and adv.vector == V31_CRITICAL


@pytest.mark.parametrize("severity, database_specific", [
    ([{"type": "CVSS_V3", "score": V31_CRITICAL}], None),
    ([{"type": "CVSS_V4", "score": V4}], {"severity": "HIGH"}),
    ([{"type": "CVSS_V4", "score": V4}], None),
])
def test_vex_from_a_real_osv_record_validates(tmp_path, severity, database_specific):
    adv = _osv(tmp_path, severity=severity, database_specific=database_specific)
    doc = to_vex(match([_lwip()], [adv]))
    errors = [e.message for e in _validator("bom-1.6.schema.json").iter_errors(doc)]
    assert not errors
    rating = doc["vulnerabilities"][0]["ratings"][0]
    assert rating["vector"] == severity[0]["score"]
    assert rating["method"] == ("CVSSv31" if "3.1" in rating["vector"] else "CVSSv4")


# ------------------------------------------------------------------ NVD

def test_an_nvd_cve_scored_only_in_v4_has_a_score_and_level():
    adv = _nvd({"cvssMetricV40": [{"cvssData": {
        "baseScore": 9.3, "baseSeverity": "CRITICAL", "vectorString": V4}}]})
    assert (adv.cvss, adv.severity, adv.vector, adv.cvss_method) == \
        (9.3, "critical", V4, "CVSSv4")


def test_nvd_v2_reads_its_level_from_the_metric_entry():
    adv = _nvd({"cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {
        "baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P"}}]})
    assert (adv.cvss, adv.severity, adv.cvss_method) == (5.0, "medium", "CVSSv2")


def test_nvd_prefers_v31_over_v4():
    adv = _nvd({"cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "vectorString": V4}}],
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                                "vectorString": V31_CRITICAL}}]})
    assert adv.cvss_method == "CVSSv31" and adv.cvss == 9.8


# ------------------------------------------------------------------ duplicates

def test_a_cve_and_the_ghsa_aliasing_it_are_one_finding(tmp_path):
    ghsa = _osv(tmp_path, severity=[{"type": "CVSS_V3", "score": V31_CRITICAL}])
    found = match([_lwip()], [ghsa, _nvd()])
    assert len(found) == 1
    assert found[0].advisory.id == "CVE-2099-0001"           # the CVE record is kept
    assert "GHSA-test-0001" in found[0].advisory.aliases
    assert found[0].advisory.cvss == 9.8                     # NVD had no score; GHSA did
    assert summary(found)["exploitable"] == 1
    assert ghsa.aliases == ["CVE-2099-0001"]                 # shared record left alone


def test_an_osv_record_and_nvd_that_contradict_each_other_leave_it_in_triage(tmp_path):
    ghsa = _osv(tmp_path, fixed="3.0.0")                      # 2.1.3 affected
    nvd = _nvd(end_excluding="2.0.0")                         # 2.1.3 not affected
    for order in ([nvd, ghsa], [ghsa, nvd]):
        found = match([_lwip()], order, include_not_affected=True)
        assert [(m.advisory.id, m.state.value) for m in found] == \
            [("GHSA-test-0001", "in_triage")]
        assert "CVE-2099-0001" in found[0].advisory.aliases
        assert "disagree" in found[0].detail and "NVD CPE range" in found[0].detail
    # the not-affected side counts even when not-affected results are not listed
    assert [m.state.value for m in match([_lwip()], [nvd, ghsa])] == ["in_triage"]


def test_records_that_agree_are_not_a_dispute(tmp_path):
    ghsa = _osv(tmp_path, fixed="3.0.0")
    nvd = _nvd(end_excluding="3.0.0")
    found = match([_lwip()], [nvd, ghsa])
    assert [m.state.value for m in found] == ["exploitable"]


def test_records_without_a_shared_cve_stay_apart(tmp_path):
    other = _osv(tmp_path, aliases=("CVE-2099-0002",), osv_id="GHSA-test-0002")
    assert len(match([_lwip()], [other, _nvd()])) == 2


def test_per_channel_keeps_each_record_and_channel(tmp_path):
    # What `vuln coverage` measures: which channel reaches the vulnerability.
    found = match([_lwip()], [_osv(tmp_path), _nvd()], per_channel=True)
    assert sorted((m.advisory.id, m.channel) for m in found) == \
        [("CVE-2099-0001", "cpe"), ("GHSA-test-0001", "purl")]


def test_csaf_names_an_aliased_cve_once(tmp_path):
    ghsa = _osv(tmp_path, severity=[{"type": "CVSS_V3", "score": V31_CRITICAL}])
    doc = to_csaf(match([_lwip()], [ghsa, _nvd()]), None, publisher="x",
                  publisher_url="https://example.invalid")
    cves = [v.get("cve") for v in doc["vulnerabilities"]]
    assert cves == ["CVE-2099-0001"]


def _osv_commits_only(tmp_path, osv_id="OSV-test-0003"):
    """An OSS-Fuzz-style record: GIT commits, no release tags: it cannot place a version."""
    record = {"id": osv_id, "summary": "overflow", "aliases": ["CVE-2099-0001"],
              "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/lwip-tcpip/lwip",
                                        "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}]}]}]}
    path = tmp_path / f"{osv_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return load_osv(path)[0]


def test_a_verdict_stands_over_a_record_that_cannot_place_the_version(tmp_path):
    undecided = _osv_commits_only(tmp_path)
    for decisive, state in ((_nvd(end_excluding="2.0.0"), "not_affected"),     # 2.1.3 outside
                            (_nvd(end_excluding="3.0.0"), "exploitable")):     # 2.1.3 inside
        for order in ([decisive, undecided], [undecided, decisive]):
            found = match([_lwip()], order, include_not_affected=True)
            assert [m.state.value for m in found] == [state], (order, found)
            assert "OSV-test-0003" in found[0].advisory.aliases or found[0].advisory.id == "OSV-test-0003"


def test_records_that_all_cannot_place_the_version_leave_it_in_triage(tmp_path):
    found = match([_lwip()], [_osv_commits_only(tmp_path)])
    assert [m.state.value for m in found] == ["in_triage"]
    assert "commit only" in found[0].detail


def _osv_tag_list(tmp_path, tags, osv_id="OSV-test-0004"):
    record = {"id": osv_id, "summary": "overflow", "aliases": ["CVE-2099-0001"],
              "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/lwip-tcpip/lwip",
                                        "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}]}],
                            "versions": tags}]}
    path = tmp_path / f"{osv_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return load_osv(path)[0]


def _nvd_unbounded():
    # NVD's lwip CPE with no version bounds: gangmu cannot place a version in it
    return advisory_from_nvd({"cve": {"id": "CVE-2099-0001", "metrics": {},
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": LWIP_CPE}]}]}]}})


def test_a_version_missing_from_an_osv_tag_list_settles_nothing_left_open(tmp_path):
    # OSV lists 2.2.0 and 2.2.1 only; 2.1.3 below them is "not affected" by the list, but
    # the list may just be incomplete, so NVD's open record keeps it in triage.
    osv = _osv_tag_list(tmp_path, ["STABLE-2_2_0_RELEASE", "STABLE-2_2_1_RELEASE"])
    for order in ([osv, _nvd_unbounded()], [_nvd_unbounded(), osv]):
        found = match([_lwip()], order, include_not_affected=True)
        assert [m.state.value for m in found] == ["in_triage"], order
    # alone, the tag list still decides
    assert [m.state.value for m in match([_lwip()], [osv], include_not_affected=True)] == ["not_affected"]


def test_a_release_absent_from_nvds_list_settles_nothing_left_open(tmp_path):
    # NVD names single releases (lwip:2.0.0, lwip:2.2.0): 2.1.3 is not among them, which is
    # no verdict over a record that cannot place it.
    nvd = advisory_from_nvd({"cve": {"id": "CVE-2099-0001", "metrics": {}, "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": LWIP_CPE.replace(":*:*:*:*:*:*:*:*", ":2.0.0:*:*:*:*:*:*:*")},
        {"vulnerable": True, "criteria": LWIP_CPE.replace(":*:*:*:*:*:*:*:*", ":2.2.0:*:*:*:*:*:*:*")}]}]}]}})
    undecided = _osv_commits_only(tmp_path)
    for order in ([nvd, undecided], [undecided, nvd]):
        assert [m.state.value for m in match([_lwip()], order, include_not_affected=True)] == ["in_triage"]
