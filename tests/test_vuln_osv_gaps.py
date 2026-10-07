"""Ways an OSV-based match used to lose a real finding (synthetic records only)."""

import json

import pytest

from gangmu.vuln import Candidate
from gangmu.vuln.match import match, purl_key
from gangmu.vuln.sources import load_osv
from gangmu.vuln.model import VexState


def _osv(tmp_path, affected, rid="TEST-OSV-GAP-1"):
    path = tmp_path / "osv.json"
    path.write_text(json.dumps([{"id": rid, "summary": "synthetic",
                                 "affected": affected}]), encoding="utf-8")
    return load_osv(path)


def _cand(purl, version):
    return Candidate(name="x", directory="d", version=version, cpes=[], purls=[purl])


def _states(advisories, purl, version, include_not_affected=False):
    return [m.state for m in match([_cand(purl, version)], advisories,
                                   include_not_affected=include_not_affected)]


# 1 ------------------------------------------------ several intervals in one range

def test_every_interval_of_a_range_is_kept(tmp_path):
    adv = _osv(tmp_path, [{"package": {"purl": "pkg:generic/foo"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"},
                                         {"introduced": "2.0"}, {"fixed": "2.5"}]}]}])
    assert _states(adv, "pkg:generic/foo@1.2", "1.2") == [VexState.EXPLOITABLE]
    assert _states(adv, "pkg:generic/foo@2.2", "2.2") == [VexState.EXPLOITABLE]
    assert _states(adv, "pkg:generic/foo@1.7", "1.7") == []
    assert _states(adv, "pkg:generic/foo@3.0", "3.0") == []


# 2 ------------------------------------- one non-matching entry hides a matching one

@pytest.mark.parametrize("flag", [False, True])
def test_a_listed_version_that_matches_is_not_hidden_by_one_that_does_not(tmp_path, flag):
    adv = _osv(tmp_path, [{"package": {"purl": "pkg:generic/foo"},
                           "versions": ["1.0", "1.1", "1.2"]}])
    assert _states(adv, "pkg:generic/foo@1.2", "1.2", flag) == [VexState.EXPLOITABLE]


@pytest.mark.parametrize("flag", [False, True])
def test_a_range_that_matches_is_not_hidden_by_an_earlier_one_that_does_not(tmp_path, flag):
    adv = _osv(tmp_path, [
        {"package": {"purl": "pkg:generic/foo"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]},
        {"package": {"purl": "pkg:generic/foo"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.1"}, {"fixed": "1.9"}]}]}])
    assert _states(adv, "pkg:generic/foo@1.5", "1.5", flag) == [VexState.EXPLOITABLE]


# 5 ------------------------------------------------------------ no purl in record

def test_a_record_with_only_ecosystem_and_name_is_not_dropped(tmp_path):
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
    adv = _osv(tmp_path, [
        {"package": {"ecosystem": "PyPI", "name": "foo-bar"}, "ranges": ranges},
        {"package": {"ecosystem": "npm", "name": "left-pad"}, "ranges": ranges},
        {"package": {"ecosystem": "Maven", "name": "org.example:lib"}, "ranges": ranges},
        {"package": {"ecosystem": "crates.io", "name": "some-crate"}, "ranges": ranges}])
    keys = {purl_key(r["purl"]) for a in adv for r in a.osv_ranges}
    assert keys == {"pkg:pypi/foo-bar", "pkg:npm/left-pad",
                    "pkg:maven/org.example/lib", "pkg:cargo/some-crate"}
    assert _states(adv, "pkg:pypi/foo-bar@1.0", "1.0") == [VexState.EXPLOITABLE]
    assert _states(adv, "pkg:maven/org.example/lib@1.0", "1.0") == [VexState.EXPLOITABLE]


def test_an_unknown_ecosystem_is_skipped_not_guessed(tmp_path):
    adv = _osv(tmp_path, [{"package": {"ecosystem": "Weird", "name": "x"},
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}])
    assert adv[0].osv_ranges == []
