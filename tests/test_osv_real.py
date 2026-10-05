"""GIT-range matching against records copied from OSV (trimmed, otherwise as published).

tests/test_osv_git.py uses synthetic records written from the schema. These are
real: ``tests/fixtures/osv-real/`` holds libwebsockets CVE-2025-1866, libcoap
CVE-2025-59391, nghttp2 CVE-2023-44487 (its nghttp2 entry only) and OpenThread
OSV-2020-1292, from OSV's GIT-ecosystem dump. The directory is separate from
``advisories/`` so the fixed counts over that one stay put.
"""

from pathlib import Path

import pytest

from gangmu.vuln import Candidate, load_database, match
from gangmu.vuln.model import VexState
from gangmu.vuln.version import normalize_tag

REAL = Path(__file__).resolve().parent / "fixtures" / "osv-real"


@pytest.fixture(scope="module")
def advisories():
    return load_database(REAL)


def _state(advisories, advisory_id, purl, version):
    cand = Candidate(name="c", directory="d", version=version, cpes=[],
                     purls=[purl], confidence=1.0)
    found = [m for m in match([cand], advisories, include_not_affected=True)
             if m.advisory.id == advisory_id]
    assert len(found) == 1
    return found[0].state


LWS = "pkg:github/warmcat/libwebsockets"


def test_all_real_records_load(advisories):
    assert {a.id for a in advisories} == {
        "CVE-2025-1866", "CVE-2025-59391", "CVE-2023-44487", "OSV-2020-1292",
        "CVE-2025-34468"}


@pytest.mark.parametrize("version,state", [
    ("4.3.3", VexState.EXPLOITABLE),      # newest listed tag
    ("4.2.0", VexState.EXPLOITABLE),
    ("4.3.4", VexState.NOT_AFFECTED),     # first release after the fix
    ("4.5.1", VexState.NOT_AFFECTED),
])
def test_libwebsockets_releases_around_the_fix(advisories, version, state):
    # The record lists junk tags next to the releases (master-test-2015-11-19-1,
    # support-chrome-20-firefox-12). They must not stretch the span of tags.
    assert _state(advisories, "CVE-2025-1866", LWS, version) is state


@pytest.mark.parametrize("tag", [
    "master-test-2015-11-19-1", "support-chrome-20-firefox-12",
    "support-protocol-v8-chrome-15-firefox-6", "v1.6.0-chrome48-firefox42",
])
def test_browser_and_date_branch_tags_are_not_releases(tag):
    assert normalize_tag(tag) is None


@pytest.mark.parametrize("tag,expected", [
    ("v4.3.5a", "4.3.5a"), ("4.3.5-NA", "4.3.5"), ("v4.3.5-rc3", "4.3.5-rc3"),
    ("release-0.2", "0.2"), ("v2.1-pre3", "2.1-pre3"), ("v4.3-stable", "4.3"),
    ("jetty-9.4.42.v20210604", "9.4.42"), ("netty-4.0.0.Alpha3", "4.0.0-alpha3"),
])
def test_real_release_tag_spellings_still_normalize(tag, expected):
    assert normalize_tag(tag) == expected


def test_a_commit_only_oss_fuzz_range_cannot_be_ordered_and_says_so(advisories):
    cand = Candidate(name="ot", directory="d", version="1.3.0", cpes=[],
                     purls=["pkg:github/openthread/openthread"], confidence=1.0)
    (found,) = match([cand], advisories)
    assert found.advisory.id == "OSV-2020-1292"
    assert found.state is VexState.IN_TRIAGE
    assert "commit" in found.detail


LC = "pkg:github/obgm/libcoap"


def test_a_tagless_cve_range_falls_back_to_the_record_own_version_bounds(advisories):
    # CVE-2025-34468 lists no tags; database_specific.extracted_events holds
    # introduced 0 / last_affected 4.3.5. Without them every libcoap is "triage".
    for version, state in [("4.3.4", VexState.EXPLOITABLE),
                           ("4.3.5", VexState.EXPLOITABLE),
                           ("4.3.5b", VexState.NOT_AFFECTED),
                           ("4.4.0", VexState.NOT_AFFECTED)]:
        assert _state(advisories, "CVE-2025-34468", LC, version) is state, version


def test_unusable_extracted_bounds_stay_triage():
    from gangmu.vuln.version import in_event_ranges
    assert in_event_ranges("4.3.3", [{"introduced": "0"}, {"fixed": "<4.3.4"}]) is None
    assert in_event_ranges("4.3.3", [{"introduced": "0"}, {"fixed": "release-patches"}]) is None
    assert in_event_ranges("1.0", []) is None


def test_extracted_bounds_with_several_intervals():
    from gangmu.vuln.version import in_event_ranges
    ev = [{"introduced": "4.5.0"}, {"last_affected": "4.5.0"},
          {"introduced": "4.5.2"}, {"last_affected": "4.5.3"}]
    assert in_event_ranges("4.5.0", ev) is True
    assert in_event_ranges("4.5.3", ev) is True
    assert in_event_ranges("4.5.1", ev) is False
    assert in_event_ranges("4.4.9", ev) is False
