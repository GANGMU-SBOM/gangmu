"""OSV records for C projects are mostly ``GIT`` ranges, not purl-addressed.

A record imported from a CVE names the repository and lists the release tags in
range; it carries no ``package.purl``. A matcher that only reads purls reports
GmSSL, Tongsuo, littlefs and every other purl-only component as clean against
the records that actually exist. The shape below follows OSV's schema: no
``package``, ``ranges[].type == "GIT"`` with ``repo`` and commit-hash events,
and the affected tags in ``versions``. The ids and tags are synthetic.
"""

import json

import pytest

from gangmu.vuln import Candidate, load_database, match
from gangmu.vuln.match import wanted_for
from gangmu.vuln.model import VexState
from gangmu.vuln.version import normalize_tag

SHA_A = "a" * 40
SHA_B = "b" * 40


def _record(rid, repo, versions, fixed=SHA_B, extra_events=()):
    events = [{"introduced": SHA_A}, *extra_events]
    if fixed:
        events.append({"fixed": fixed})
    return {"id": rid, "summary": "synthetic",
            "affected": [{"ranges": [{"type": "GIT", "repo": repo,
                                      "events": events}],
                          "versions": versions}]}


def _candidate(version, purl="pkg:github/guanzhi/gmssl", fork=False):
    return Candidate(name="GmSSL", directory="components/crypto_sm",
                     version=version, cpes=[], purls=[purl], confidence=0.9,
                     is_fork=fork)


def _db(tmp_path, *records):
    (tmp_path / "osv.json").write_text(json.dumps(list(records)))
    return load_database(tmp_path)


def test_a_git_record_without_a_purl_is_loaded(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL.git",
                                ["v3.0.0", "v3.1.0"]))
    assert len(adv) == 1
    assert adv[0].osv_ranges, "the GIT range must produce something matchable"


def test_a_version_in_the_listed_tags_is_exploitable(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL",
                                ["v3.0.0", "v3.1.0"]))
    found = match([_candidate("3.1.0")], adv)
    assert [(m.advisory.id, m.state) for m in found] == [
        ("TEST-G-1", VexState.EXPLOITABLE)]
    assert found[0].channel == "purl"


def test_repo_url_forms_all_reach_the_same_component(tmp_path):
    for repo in ("https://github.com/guanzhi/GmSSL", "https://github.com/guanzhi/GmSSL.git",
                 "git://github.com/guanzhi/gmssl", "http://www.github.com/GuanZhi/GmSSL/"):
        adv = _db(tmp_path, _record("TEST-G-1", repo, ["v3.0.0"]))
        assert match([_candidate("3.0.0")], adv), repo


def test_a_fixed_version_is_not_reported(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL",
                                ["v3.0.0", "v3.1.0"]))
    assert match([_candidate("3.2.0")], adv) == []
    shown = match([_candidate("3.2.0")], adv, include_not_affected=True)
    assert shown[0].state is VexState.NOT_AFFECTED


def test_an_older_release_below_the_range_is_not_affected(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL",
                                ["v3.0.0", "v3.1.0"]))
    assert match([_candidate("2.5.4")], adv) == []


def test_an_unfixed_record_covers_newer_releases(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL",
                                ["v3.0.0", "v3.1.0"], fixed=None))
    found = match([_candidate("3.2.0")], adv)
    assert found and found[0].state is VexState.EXPLOITABLE


def test_a_version_between_listed_tags_needs_a_human(tmp_path):
    """Tags 3.0.0 and 3.2.0 listed, 3.1.0 not: a gap, or a fix and a regression.
    The record cannot say which, so neither can the tool."""
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL",
                                ["v3.0.0", "v3.2.0"]))
    found = match([_candidate("3.1.0")], adv)
    assert [m.state for m in found] == [VexState.IN_TRIAGE]


def test_a_commit_pinned_component_needs_a_human(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL",
                                ["v3.0.0"]))
    found = match([_candidate("git-2867f6883a12")], adv)
    assert [m.state for m in found] == [VexState.IN_TRIAGE]


def test_a_vendor_fork_in_range_is_triage_not_exploitable(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/guanzhi/GmSSL",
                                ["v3.0.0"]))
    found = match([_candidate("3.0.0", fork=True)], adv)
    assert [m.state for m in found] == [VexState.IN_TRIAGE]


def test_a_different_repository_does_not_match(tmp_path):
    adv = _db(tmp_path, _record("TEST-G-1", "https://github.com/someone/else",
                                ["v3.0.0"]))
    assert match([_candidate("3.0.0")], adv) == []


def test_selective_loading_keeps_git_records_for_wanted_products(tmp_path):
    rec = _record("TEST-G-1", "https://github.com/guanzhi/GmSSL", ["v3.0.0"])
    other = _record("TEST-G-2", "https://github.com/someone/else", ["v1.0"])
    (tmp_path / "osv.json").write_text(json.dumps([rec, other]))
    adv = load_database(tmp_path, wanted_for([_candidate("3.0.0")]))
    assert [a.id for a in adv] == ["TEST-G-1"]


def test_a_purl_addressed_record_still_works(tmp_path):
    rec = {"id": "TEST-P-1", "affected": [{
        "package": {"purl": "pkg:github/guanzhi/gmssl"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.1.0"}]}]}]}
    found = match([_candidate("3.0.0")], _db(tmp_path, rec))
    assert found and found[0].state is VexState.EXPLOITABLE


@pytest.mark.parametrize("tag,expected", [
    ("v1.7.15", "1.7.15"),
    ("V10.4.1", "10.4.1"),
    ("STABLE-2_2_0_RELEASE", "2.2.0"),
    ("openssl-3.0.1", "3.0.1"),
    ("mbedtls-2.28.0", "2.28.0"),
    ("OpenSSL_1_1_1w", "1.1.1w"),
    ("v2.6.0-RC1", "2.6.0-rc1"),
    ("release", None),
    # GmSSL 3.x and Tongsuo, as upstream spells them
    ("v3.1.0-pr1", "3.1.0-pr1"),
    ("8.3.3", "8.3.3"),
    ("8.4.0-pre1", "8.4.0-pre1"),
])
def test_release_tags_normalize_to_comparable_versions(tag, expected):
    assert normalize_tag(tag) == expected


# Real tag lists of the two Chinese national-crypto upstreams.
GMSSL_TAGS = ["gmbrowser-v0.1", "v3.0.0", "v3.1.0", "v3.1.0-pr1", "v3.1.1",
              "v3.1.1-pr1", "v3.2.0"]
TONGSUO_TAGS = ["8.1.3", "8.2.0", "8.2.1", "8.3.0", "8.3.1", "8.3.2", "8.3.3",
                "8.4.0", "8.4.0-pre1", "8.4.0-pre2", "8.4.0-pre3", "8.5.0",
                "8.5.0-pre1", "8.5.0-pre2"]


def test_a_prerelease_tag_does_not_make_its_release_affected():
    from gangmu.vuln.version import in_tag_set
    # a record that lists only v3.1.0-pr1 says nothing about 3.1.0 itself
    assert in_tag_set("3.1.0", ["v3.1.0-pr1"]) is not True
    assert in_tag_set("3.1.0", ["v3.1.0", "v3.1.0-pr1"]) is True


def test_babassl_era_tongsuo_versions_are_found_in_tongsuo_tag_lists():
    from gangmu.vuln.version import in_tag_set
    for version in ("8.1.3", "8.3.0", "8.3.3", "8.5.0"):
        assert in_tag_set(version, TONGSUO_TAGS) is True
    assert in_tag_set("8.0.0", TONGSUO_TAGS) is False       # below every tag
    assert in_tag_set("8.3.3", ["8.3.0", "8.3.1"], open_ended=False) is False


def test_gmssl_2x_has_no_tags_so_a_tag_range_cannot_cover_it():
    from gangmu.vuln.version import in_tag_set
    # 2.5.4 lies below every GmSSL tag: a GIT-range record cannot affect it
    # by tag, so 2.x advisories have to arrive as ECOSYSTEM or purl ranges.
    assert in_tag_set("2.5.4", GMSSL_TAGS) is not True


def test_gitee_and_the_openharmony_github_mirror_map_to_one_generic_purl():
    """The purl spec has no Gitee type; a Gitee rule uses pkg:generic, and a GIT
    range naming either host of the same OpenHarmony repository must find it."""
    from gangmu.vuln.match import purl_from_repo
    want = "pkg:generic/openharmony/kernel_liteos_a"
    for url in ("https://gitee.com/openharmony/kernel_liteos_a",
                "https://gitee.com/openharmony/kernel_liteos_a.git",
                "https://github.com/openharmony/kernel_liteos_a",
                "https://gitcode.com/openharmony/kernel_liteos_a",
                "https://atomgit.com/openharmony/kernel_liteos_a.git",
                "git@gitee.com:openharmony/kernel_liteos_a.git"):
        assert purl_from_repo(url) == want, url
    # other GitHub owners keep their github purl; unknown hosts still have none
    assert purl_from_repo("https://github.com/lwip-tcpip/lwip") == "pkg:github/lwip-tcpip/lwip"
    assert purl_from_repo("https://example.invalid/o/r") is None

