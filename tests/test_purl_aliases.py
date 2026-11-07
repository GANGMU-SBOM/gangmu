"""``upstream.identifiers``: one upstream known under several purls.

OSV files zlib under its repository (a GIT range) and under Debian; an SBOM from
another tool writes ``pkg:deb/echo/zlib-1.2.11``. Without an alias neither side meets
the other. Ids and tags below are synthetic.
"""

import json

import pytest

from gangmu.rules.schema import RuleError, rule_from_dict
from gangmu.vuln import candidates_from_cyclonedx, load_database, match
from gangmu.vuln.aliases import PurlAliases, keys_for, version_from_name
from gangmu.vuln.match import wanted_for
from gangmu.vuln.model import VexState

SHA_A, SHA_B = "a" * 40, "b" * 40


def _rule(identifiers=None, purl="pkg:github/madler/zlib"):
    upstream = {"name": "zlib", "purl": purl,
                "source": {"kind": "git", "url": "https://github.com/madler/zlib", "ref": "v1.3"}}
    if identifiers is not None:
        upstream["identifiers"] = identifiers
    return rule_from_dict({"id": "generic/zlib", "upstream": upstream,
                           "identity": {"anchors": [{"path": "zlib.h", "sha256": {"1.3": "0" * 64}}]}},
                          "zlib.yaml")


def _aliases():
    return PurlAliases.from_rules([_rule(["pkg:deb/debian/zlib", "pkg:rpm/fedora/zlib",
                                          "pkg:gitlab/madler/zlib"])])


def _bom(purl, version=None):
    comp = {"type": "library", "name": "zlib", "purl": purl}
    if version:
        comp["version"] = version
    return {"bomFormat": "CycloneDX", "components": [comp]}


def test_the_rule_parses_identifiers():
    assert _rule(["pkg:deb/debian/zlib"]).identifiers == ("pkg:deb/debian/zlib",)
    assert _rule().identifiers == ()


@pytest.mark.parametrize("bad", ["zlib", "https://zlib.net", "pkg:deb"])
def test_an_identifier_must_be_a_purl(bad):
    with pytest.raises(RuleError):
        _rule([bad])


def test_identifiers_need_a_primary_purl():
    with pytest.raises(RuleError):
        rule_from_dict({"id": "x/y", "upstream": {
            "name": "y", "identifiers": ["pkg:deb/debian/y"],
            "source": {"kind": "git", "url": "https://example.org/y", "ref": "v1"}}}, "y.yaml")


def test_distribution_purls_compare_without_the_distribution():
    assert "pkg:deb/*/zlib" in keys_for("pkg:deb/echo/zlib-1.2.11")
    assert "pkg:deb/*/zlib" in keys_for("pkg:deb/debian/zlib?arch=source")
    assert keys_for("pkg:github/madler/zlib@1.2.11") == {"pkg:github/madler/zlib"}


def test_a_version_written_into_the_name_is_recovered_only_when_none_is_given():
    assert version_from_name("pkg:deb/echo/zlib-1.2.11") == "1.2.11"
    assert version_from_name("pkg:deb/debian/zlib@1.2.11") is None
    assert version_from_name("pkg:deb/debian/libpng1.6") is None
    assert version_from_name("pkg:github/madler/zlib") is None


def test_expand_reaches_the_whole_class_from_any_member():
    aliases = _aliases()
    from_echo = aliases.expand(["pkg:deb/echo/zlib-1.2.11"])
    assert "pkg:github/madler/zlib" in from_echo
    assert "pkg:deb/debian/zlib" in from_echo
    assert "pkg:deb/echo/zlib" not in from_echo
    assert "pkg:deb/debian/zlib" in aliases.expand(["pkg:github/madler/zlib@1.2.3"])
    assert aliases.expand(["pkg:github/other/thing"]) == []


def test_a_class_needs_two_names():
    assert len(PurlAliases.from_rules([_rule([])])) == 0


def test_the_echo_purl_reaches_a_git_record_filed_under_the_repository(tmp_path):
    record = {"id": "TEST-Z-1", "summary": "synthetic",
              "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/madler/zlib.git",
                                        "events": [{"introduced": SHA_A}, {"fixed": SHA_B}]}],
                            "versions": ["v1.2.11", "v1.2.3"]}]}
    (tmp_path / "osv.json").write_text(json.dumps([record]))
    bom = _bom("pkg:deb/echo/zlib-1.2.11")

    plain = candidates_from_cyclonedx(bom)
    assert match(plain, load_database(tmp_path, wanted_for(plain))) == []

    aliased = candidates_from_cyclonedx(bom, _aliases())
    assert aliased[0].version == "1.2.11"
    found = match(aliased, load_database(tmp_path, wanted_for(aliased)))
    assert [m.advisory.id for m in found] == ["TEST-Z-1"]
    # a Debian-family package: the upstream version cannot say whether it is affected
    assert found[0].state is VexState.IN_TRIAGE
    assert "distribution package" in found[0].detail
    assert found[0].channel == "purl"


def test_a_github_component_stays_exploitable_through_the_same_record(tmp_path):
    record = {"id": "TEST-Z-3", "summary": "synthetic",
              "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/madler/zlib.git",
                                        "events": [{"introduced": SHA_A}, {"fixed": SHA_B}]}],
                            "versions": ["v1.2.11"]}]}
    (tmp_path / "osv.json").write_text(json.dumps([record]))
    cands = candidates_from_cyclonedx(_bom("pkg:github/madler/zlib", "1.2.11"), _aliases())
    found = match(cands, load_database(tmp_path, wanted_for(cands)))
    assert found[0].state is VexState.EXPLOITABLE


def test_a_mirror_purl_reaches_the_same_record(tmp_path):
    record = {"id": "TEST-Z-2", "summary": "synthetic",
              "affected": [{"package": {"ecosystem": "Debian:12", "name": "zlib"},
                            "ranges": [{"type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "1:9.9-1"}]}]}]}
    (tmp_path / "osv.json").write_text(json.dumps([record]))
    cands = candidates_from_cyclonedx(_bom("pkg:github/madler/zlib", "1.2.3"), _aliases())
    found = match(cands, load_database(tmp_path, wanted_for(cands)))
    assert [m.advisory.id for m in found] == ["TEST-Z-2"]


def _debian_record(rid, fixed11, fixed12):
    return {"id": rid, "aliases": ["CVE-2099-0300"], "summary": "synthetic", "affected": [
        {"package": {"ecosystem": "Debian:11", "name": "zlib", "purl": "pkg:deb/debian/zlib?distro=bullseye"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed11}]}]},
        {"package": {"ecosystem": "Debian:12", "name": "zlib", "purl": "pkg:deb/debian/zlib?distro=bookworm"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed12}]}]}]}


def _git_record():
    return {"id": "TEST-Z-9", "aliases": ["CVE-2099-0300"], "summary": "synthetic", "affected": [
        {"ranges": [{"type": "GIT", "repo": "https://github.com/madler/zlib.git",
                     "events": [{"introduced": SHA_A}, {"fixed": SHA_B}]}], "versions": ["v1.2.11"]}]}


def _states(tmp_path, purl, version=None):
    (tmp_path / "osv.json").write_text(json.dumps([
        _debian_record("DEBIAN-CVE-2099-0300", "1:1.2.11.dfsg-2+deb11u2", "1:1.2.11.dfsg-4.1"),
        _git_record()]))
    cands = candidates_from_cyclonedx(_bom(purl, version), _aliases())
    found = match(cands, load_database(tmp_path, wanted_for(cands)), include_not_affected=True)
    return {m.advisory.id: m.state for m in found}, found


def test_a_debian_revision_before_the_fix_is_exploitable(tmp_path):
    states, found = _states(tmp_path, "pkg:deb/debian/zlib@1.2.11.dfsg-2%2Bdeb11u1")
    assert set(states.values()) == {VexState.EXPLOITABLE}
    assert len(found) == 1, "one vulnerability, counted once"


def test_a_debian_revision_with_the_fix_is_not_affected_despite_the_upstream_range(tmp_path):
    states, _ = _states(tmp_path, "pkg:deb/debian/zlib@1:1.2.11.dfsg-4.1")
    assert set(states.values()) == {VexState.NOT_AFFECTED}


def test_the_release_in_the_revision_selects_the_release_range(tmp_path):
    # deb11u2 fixes bullseye; read against bookworm's fix it would look vulnerable
    states, _ = _states(tmp_path, "pkg:deb/debian/zlib@1.2.11.dfsg-2%2Bdeb11u2")
    assert set(states.values()) == {VexState.NOT_AFFECTED}


def test_a_package_without_a_revision_stays_in_triage(tmp_path):
    states, found = _states(tmp_path, "pkg:deb/echo/zlib-1.2.11")
    assert set(states.values()) == {VexState.IN_TRIAGE}
    assert "revision" in found[0].detail


def test_a_match_through_an_alias_says_so(tmp_path):
    record = {"id": "TEST-Z-7", "summary": "synthetic",
              "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/madler/zlib.git",
                                        "events": [{"introduced": SHA_A}, {"fixed": SHA_B}]}],
                            "versions": ["v1.2.11"]}]}
    (tmp_path / "osv.json").write_text(json.dumps([record]))
    via = candidates_from_cyclonedx(_bom("pkg:deb/debian/zlib", "1.2.11"), _aliases())
    found = match(via, load_database(tmp_path, wanted_for(via)))
    assert "upstream.identifiers alias" in found[0].detail
    direct = candidates_from_cyclonedx(_bom("pkg:github/madler/zlib", "1.2.11"), _aliases())
    found = match(direct, load_database(tmp_path, wanted_for(direct)))
    assert "alias" not in found[0].detail


def test_aliases_can_be_switched_off():
    import argparse
    from gangmu.commands.vuln import _purl_aliases
    assert _purl_aliases(argparse.Namespace(no_purl_aliases=True, rules=None)) is None


def test_a_version_in_the_name_is_taken_off_for_the_key():
    from gangmu.vuln.aliases import without_name_version
    assert without_name_version("pkg:deb/echo/zlib-1.2.11") == "pkg:deb/echo/zlib"
    assert without_name_version("pkg:deb/debian/zlib@1.2.11") is None
    assert without_name_version("pkg:github/madler/zlib") is None


def test_a_distribution_record_does_not_decide_an_upstream_component(tmp_path):
    # Debian's range starts at "0" and ends at its own fix: read against an upstream
    # release it would call every older release affected. The GIT record decides.
    debian = _debian_record("DEBIAN-CVE-2099-0300", "1.3-1", "1.3-1")
    (tmp_path / "osv.json").write_text(json.dumps([debian, _git_record()]))
    cands = candidates_from_cyclonedx(_bom("pkg:github/madler/zlib", "1.2.3"), _aliases())
    found = match(cands, load_database(tmp_path, wanted_for(cands)), include_not_affected=True)
    assert [m.state for m in found] == [VexState.NOT_AFFECTED]


def test_a_vulnerability_only_a_distribution_names_stays_in_triage_upstream(tmp_path):
    (tmp_path / "osv.json").write_text(json.dumps([
        _debian_record("DEBIAN-CVE-2099-0300", "1:1.2.11.dfsg-2+deb11u2", "1:1.2.11.dfsg-4.1")]))
    cands = candidates_from_cyclonedx(_bom("pkg:github/madler/zlib", "1.2.3"), _aliases())
    found = match(cands, load_database(tmp_path, wanted_for(cands)))
    assert [m.state for m in found] == [VexState.IN_TRIAGE]
    assert "only Debian's records" in found[0].detail
