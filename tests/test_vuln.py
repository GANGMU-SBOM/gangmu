"""Vulnerability matching.

The fixtures are deliberately synthetic (``TEST-...`` identifiers). Shipping a
test database of real CVE records would risk stating something untrue about a
real advisory, and the matcher's logic does not care whose data it is.
"""

import json
from pathlib import Path

import pytest

from gangmu.vuln import (Candidate, candidates_from_cyclonedx, load_database,
                         match, summary, to_vex, unmatched_components)
from gangmu.vuln.match import without_cpe
from gangmu.vuln.model import VexState
from gangmu.vuln.version import compare, in_range, is_orderable

DB = Path(__file__).resolve().parent / "fixtures" / "advisories"


@pytest.fixture(scope="session")
def advisories():
    return load_database(DB)


# ------------------------------------------------------------- versions

def test_version_ordering_handles_what_embedded_actually_uses():
    assert compare("2.2.0", "2.2.2") == -1
    assert compare("1.7.19", "1.7.19") == 0
    assert compare("4.1.1", "4.1") == 1
    assert compare("0.2-265-gad902ca", "0.2") == 1


def test_a_release_candidate_sorts_below_its_release():
    assert compare("v2.6.0-RC1", "2.6.0") == -1


def test_a_commit_identifier_is_not_orderable():
    assert is_orderable("git-2867f6883a12") is False
    assert compare("git-2867f6883a12", "1.0") is None


def test_an_unorderable_version_yields_none_not_false():
    """The whole point: 'cannot tell' must not collapse into 'not affected'."""
    assert in_range("git-abc", introduced="2.0", fixed="2.2.1") is None


# -------------------------------------------------------------- sources

def test_both_database_shapes_load(advisories):
    ids = {a.id for a in advisories}
    assert "TEST-2026-0001" in ids          # NVD 2.0 shape
    assert "TEST-OSV-0001" in ids           # OSV shape
    assert {a.source for a in advisories} == {"nvd", "osv"}


def test_nvd_severity_and_score_survive(advisories):
    first = next(a for a in advisories if a.id == "TEST-2026-0001")
    assert first.severity == "high" and first.cvss == 8.1


def test_a_missing_database_is_an_explicit_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_database(tmp_path / "nope")


# -------------------------------------------------------------- matching

def _lwip(version="2.2.0", fork=False, confidence=0.95):
    return Candidate(name="lwIP", directory="components/lwip/lwip", version=version,
                     cpes=["cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*"],
                     purls=["pkg:generic/lwip"], is_fork=fork,
                     fork_note="Espressif fork", confidence=confidence)


def test_a_version_inside_the_range_is_exploitable(advisories):
    found = match([_lwip()], advisories)
    assert [m.advisory.id for m in found] == ["TEST-2026-0001"]
    assert found[0].state is VexState.EXPLOITABLE


def test_a_version_outside_the_range_is_dropped_by_default(advisories):
    assert match([_lwip("2.5.0")], advisories) == []


def test_not_affected_can_be_asked_for_explicitly(advisories):
    found = match([_lwip("2.5.0")], advisories, include_not_affected=True)
    assert {m.state for m in found} == {VexState.NOT_AFFECTED}


def test_a_vendor_fork_is_never_reported_as_plainly_exploitable(advisories):
    """ESP-IDF's lwIP says 2.2.0, but the fork may already carry the fix."""
    found = match([_lwip(fork=True)], advisories)
    assert found[0].state is VexState.IN_TRIAGE
    assert "vendor fork" in found[0].detail


def test_an_unorderable_version_goes_to_triage_not_silence(advisories):
    found = match([_lwip(version="git-abc1234567")], advisories)
    assert found and all(m.state is VexState.IN_TRIAGE for m in found)
    assert "cannot be ordered" in found[0].detail


def test_component_confidence_travels_with_the_finding(advisories):
    found = match([_lwip(confidence=0.5)], advisories)
    assert found[0].component_confidence == 0.5


def test_the_purl_channel_reaches_a_component_with_no_cpe(advisories):
    littlefs = Candidate(name="littlefs", directory="modules/fs/littlefs",
                         version="2.8.0", cpes=[],
                         purls=["pkg:github/littlefs-project/littlefs"])
    found = match([littlefs], advisories)
    assert [m.advisory.id for m in found] == ["TEST-OSV-0001"]
    assert found[0].channel == "purl"


def test_components_with_no_identifier_at_all_are_named_as_blind_spots():
    mystery = Candidate(name="mystery", directory="d", version=None,
                        cpes=[], purls=[])
    assert [c.name for c in unmatched_components([mystery])] == ["mystery"]


def test_components_the_cpe_channel_cannot_reach_are_counted_separately():
    littlefs = Candidate(name="littlefs", directory="d", version="2.8.0",
                         cpes=[], purls=["pkg:github/littlefs-project/littlefs"])
    assert [c.name for c in without_cpe([littlefs])] == ["littlefs"]
    assert unmatched_components([littlefs]) == []


def test_one_advisory_is_not_reported_twice_on_the_same_component(advisories):
    found = match([_lwip(), _lwip()], advisories)
    assert len(found) == 1


# ------------------------------------------------------------------ VEX

def test_vex_carries_the_reasoning_not_just_the_verdict(advisories):
    found = match([_lwip(fork=True)], advisories)
    doc = to_vex(found, None, timestamp="2026-01-01T00:00:00Z")
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "TEST-2026-0001"
    assert vuln["analysis"]["state"] == "in_triage"
    assert "vendor fork" in vuln["analysis"]["detail"]
    assert vuln["ratings"][0]["score"] == 8.1


def test_vex_records_which_channel_found_it(advisories):
    found = match([_lwip()], advisories)
    props = {p["name"]: p["value"]
             for p in to_vex(found)["vulnerabilities"][0]["properties"]}
    assert props["gangmu:channel"] == "cpe"
    assert props["gangmu:componentConfidence"] == "0.950"


def test_vex_names_the_components_it_could_not_look_up(advisories):
    doc = to_vex([], None, blind_spots=["mystery"])
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["gangmu:notLookedUp"] == "mystery"
    assert "absence of evidence" in props["gangmu:notLookedUpNote"].lower()


def test_vex_merges_into_an_existing_bom(advisories):
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"timestamp": "2026-01-01T00:00:00Z"},
           "components": [{"bom-ref": "c1", "type": "library", "name": "lwIP",
                           "version": "2.2.0",
                           "properties": [{"name": "gangmu:directory",
                                           "value": "components/lwip/lwip"}]}]}
    doc = to_vex(match([_lwip()], advisories), bom)
    assert doc["components"][0]["bom-ref"] == "c1"
    assert doc["vulnerabilities"][0]["affects"][0]["ref"] == "c1"


def test_summary_counts_every_state(advisories):
    counts = summary(match([_lwip(), _lwip(fork=True)], advisories))
    assert counts["exploitable"] + counts["in_triage"] >= 1


def test_candidates_come_out_of_a_real_cyclonedx_document():
    bom = {"components": [{
        "name": "lwIP", "version": "2.2.0",
        "cpe": "cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*",
        "purl": "pkg:generic/lwip@2.2.0",
        "pedigree": {"patches": [{"type": "unofficial"}], "notes": "fork"},
        "properties": [{"name": "gangmu:directory", "value": "d"},
                       {"name": "gangmu:identityConfidence", "value": "0.900"}]}]}
    candidate = candidates_from_cyclonedx(bom)[0]
    assert candidate.is_fork is True
    assert candidate.confidence == 0.9
    assert candidate.directory == "d"


# ------------------------------------------------- link map: not in the image

def _unlinked_lwip():
    c = _lwip()
    c.linked = False
    return c


def test_a_component_the_link_map_dropped_is_not_reported_exploitable(advisories):
    c = _unlinked_lwip()
    found = match([c], advisories)
    assert found
    from gangmu.vuln import apply_linkage
    apply_linkage(found, [c])
    assert all(m.state is VexState.IN_TRIAGE for m in found)
    assert all("not linked" in m.detail for m in found)


def test_unlinked_findings_can_be_recorded_not_affected_on_request(advisories):
    c = _unlinked_lwip()
    found = match([c], advisories)
    from gangmu.vuln import apply_linkage
    changed = apply_linkage(found, [c], mark_not_affected=True)
    assert changed == len(found)
    assert all(m.state is VexState.NOT_AFFECTED and m.justification == "code_not_present"
               for m in found)


def test_no_link_map_means_unknown_not_unlinked(advisories):
    c = _lwip()
    assert c.linked is None
    found = match([c], advisories)
    states = [m.state for m in found]
    from gangmu.vuln import apply_linkage
    assert apply_linkage(found, [c]) == 0
    assert [m.state for m in found] == states


def test_linked_flag_is_read_from_the_cyclonedx_properties():
    bom = {"components": [{"name": "x", "version": "1", "purl": "pkg:generic/x@1",
                           "properties": [{"name": "gangmu:linkedIntoImage", "value": "false"}]},
                          {"name": "y", "version": "1", "purl": "pkg:generic/y@1",
                           "properties": [{"name": "gangmu:linkedIntoImage", "value": "true"}]},
                          {"name": "z", "version": "1", "purl": "pkg:generic/z@1"}]}
    assert [c.linked for c in candidates_from_cyclonedx(bom)] == [False, True, None]
