"""Debian, Ubuntu and Alpine packages are read against their own distribution's ranges."""

import json

import pytest

from gangmu.vuln import candidates_from_cyclonedx, load_database, match
from gangmu.vuln.apkver import compare as apk_compare
from gangmu.vuln.distver import FAMILIES, family_of_purl, release_from_purl, verdict
from gangmu.vuln.match import wanted_for
from gangmu.vuln.model import VexState

DEB, UBU, APK = FAMILIES["debian"], FAMILIES["ubuntu"], FAMILIES["alpine"]


@pytest.mark.parametrize("low,high", [
    ("1.2.11-r0", "1.2.11-r3"), ("1.2.11-r3", "1.2.12-r0"), ("1.2.11", "1.2.11-r1"),
    ("2.4_rc1-r0", "2.4-r0"), ("2.4-r0", "2.4_p1-r0"), ("1.0_alpha", "1.0_beta"),
    ("1.0", "1.0a"), ("1.9", "1.10"), ("1.2", "1.2.1"),
])
def test_apk_order(low, high):
    assert apk_compare(low, high) == -1 and apk_compare(high, low) == 1


def test_apk_rejects_what_is_not_an_apk_version():
    assert apk_compare("1:1.2.11.dfsg-2", "1.2.11-r0") is None


DEBIAN = [{"ecosystem": "Debian:11", "introduced": "0", "fixed": "1:1.2.11.dfsg-2+deb11u2"},
          {"ecosystem": "Debian:12", "introduced": "0", "fixed": "1:1.2.11.dfsg-4.1"}]


def test_debian_verdicts():
    assert verdict(DEB, "1.2.11.dfsg-2+deb11u1", DEBIAN) is True      # own release, before its fix
    assert verdict(DEB, "1.2.11.dfsg-2+deb11u2", DEBIAN) is False     # own release, fixed
    assert verdict(DEB, "1.2.11.dfsg-1", DEBIAN) is True              # older than every fix
    assert verdict(DEB, "1.2.13.dfsg-1", DEBIAN) is False             # newer than every fix
    assert verdict(DEB, "1.2.11.dfsg-3", DEBIAN) is None              # between fixes, release unknown
    assert verdict(DEB, "1.2.11", DEBIAN) is None                     # no revision: no answer
    assert verdict(DEB, "1.2.11.dfsg-2+deb10u1", DEBIAN) is None      # a release the advisory omits
    assert verdict(DEB, "1.2.11-1", [{"ecosystem": "npm", "fixed": "9"}]) is None


def test_a_release_picks_its_own_range():
    # 12's fix read against bullseye's package would call a fixed package vulnerable
    assert verdict(DEB, "1.2.11.dfsg-3", DEBIAN, release="11") is False
    assert verdict(DEB, "1.2.11.dfsg-3", DEBIAN, release="12") is True


UBUNTU = [{"ecosystem": "Ubuntu:20.04:LTS", "introduced": "0", "fixed": "1:1.2.11.dfsg-2ubuntu1.5"},
          {"ecosystem": "Ubuntu:22.04:LTS", "introduced": "0", "fixed": "1:1.2.11.dfsg-2ubuntu9.2"},
          {"ecosystem": "Ubuntu:Pro:14.04:LTS", "introduced": "0"}]


def test_ubuntu_reads_ubuntu_ranges_with_the_release_from_the_purl():
    purl = "pkg:deb/ubuntu/zlib@1:1.2.11.dfsg-2ubuntu9.1?distro=jammy"
    assert release_from_purl(purl, "1:1.2.11.dfsg-2ubuntu9.1") == "22.04"
    assert verdict(UBU, "1:1.2.11.dfsg-2ubuntu9.1", UBUNTU, release="22.04") is True
    assert verdict(UBU, "1:1.2.11.dfsg-2ubuntu9.2", UBUNTU, release="22.04") is False
    assert verdict(UBU, "1:1.2.11.dfsg-2ubuntu9.2", UBUNTU, release="14.04") is True   # unfixed there
    assert verdict(DEB, "1:1.2.11.dfsg-2ubuntu9.2", UBUNTU) is None                   # not Debian's records


ALPINE = [{"ecosystem": "Alpine:v3.15", "introduced": "0", "fixed": "1.2.12-r2"},
          {"ecosystem": "Alpine:v3.18", "introduced": "0", "fixed": "1.2.13-r1"}]


def test_alpine_verdicts():
    assert verdict(APK, "1.2.12-r1", ALPINE, release="3.15") is True
    assert verdict(APK, "1.2.12-r2", ALPINE, release="3.15") is False
    assert verdict(APK, "1.2.12-r2", ALPINE) is None                  # between fixes, release unknown
    assert verdict(APK, "1.2.11-r0", ALPINE) is True
    assert verdict(APK, "1.2.12", ALPINE) is None                     # no -rN


def test_release_hints():
    assert release_from_purl("pkg:apk/alpine/zlib@1.2.12-r1?distro=alpine-3.15.4", "1.2.12-r1") == "3.15"
    assert release_from_purl("pkg:deb/debian/zlib@1.2-1?distro=debian-12", "1.2-1") == "12"
    assert release_from_purl("pkg:deb/debian/zlib@1.2-1%2Bdeb11u2", "1.2-1+deb11u2") == "11"
    assert family_of_purl("pkg:deb/echo/zlib") is None


def _record(rid, purl, ranges):
    return {"id": rid, "aliases": ["CVE-2099-0400"], "summary": "synthetic",
            "affected": [{"package": {"ecosystem": eco, "name": "zlib", "purl": purl},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}]}
                         for eco, events in ranges]}


def _states(tmp_path, purl, records):
    (tmp_path / "osv.json").write_text(json.dumps(records))
    bom = {"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "zlib", "purl": purl}]}
    cands = candidates_from_cyclonedx(bom)
    found = match(cands, load_database(tmp_path, wanted_for(cands)), include_not_affected=True)
    return {m.state for m in found}, found


def test_an_alpine_package_end_to_end(tmp_path):
    rec = _record("ALPINE-CVE-2099-0400", "pkg:apk/alpine/zlib?arch=source",
                  [("Alpine:v3.15", [{"introduced": "0"}, {"fixed": "1.2.12-r2"}])])
    assert _states(tmp_path, "pkg:apk/alpine/zlib@1.2.12-r1?distro=alpine-3.15.4", [rec])[0] == {VexState.EXPLOITABLE}
    assert _states(tmp_path, "pkg:apk/alpine/zlib@1.2.12-r2?distro=alpine-3.15.4", [rec])[0] == {VexState.NOT_AFFECTED}


def test_an_ubuntu_package_end_to_end(tmp_path):
    rec = _record("UBUNTU-CVE-2099-0400", "pkg:deb/ubuntu/zlib?arch=source",
                  [("Ubuntu:22.04:LTS", [{"introduced": "0"}, {"fixed": "1:1.2.11.dfsg-2ubuntu9.2"}])])
    base = "pkg:deb/ubuntu/zlib@1:1.2.11.dfsg-2ubuntu9.%s?distro=ubuntu-22.04"
    assert _states(tmp_path, base % "1", [rec])[0] == {VexState.EXPLOITABLE}
    assert _states(tmp_path, base % "2", [rec])[0] == {VexState.NOT_AFFECTED}


def test_another_distributions_records_never_decide_a_package(tmp_path):
    rec = _record("ALPINE-CVE-2099-0400", "pkg:apk/alpine/zlib?arch=source",
                  [("Alpine:v3.15", [{"introduced": "0"}, {"fixed": "9.9-r0"}])])
    states, _ = _states(tmp_path, "pkg:deb/debian/zlib@1:1.0-1", [rec])
    assert states == set()
