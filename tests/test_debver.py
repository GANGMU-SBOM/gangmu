"""dpkg version order (Debian Policy 5.6.12) and a Debian advisory's per-release ranges."""

import pytest

from gangmu.vuln.debver import compare, has_revision, release_of, split_version, verdict


@pytest.mark.parametrize("low,high", [
    ("1.0~rc1", "1.0"), ("1.0", "1.0-1"), ("1.0-9", "1.0-10"), ("1.0", "1.0a"),
    ("1.0", "1.0+b1"), ("1.0~~", "1.0~"), ("1.0-1", "1:0.1"),
    ("1.2.11.dfsg-2+deb11u2", "1:1.2.11.dfsg-4.1"),
    ("2.30-21ubuntu1~18.04.2", "2.30-21ubuntu1~18.04.10"),
])
def test_dpkg_order(low, high):
    assert compare(low, high) == -1 and compare(high, low) == 1 and compare(low, low) == 0


def test_an_sbom_that_dropped_the_epoch_can_be_compared_without_it():
    assert compare("1.2.11.dfsg-4.1", "1:1.2.11.dfsg-4.1") == -1
    assert compare("1.2.11.dfsg-4.1", "1:1.2.11.dfsg-4.1", ignore_epoch=True) == 0


def test_parts():
    assert split_version("1:1.2.11.dfsg-2+deb11u2") == (1, "1.2.11.dfsg", "2+deb11u2", True)
    assert split_version("1.2.3")[1:3] == ("1.2.3", "")
    assert has_revision("1.2.11-1") and not has_revision("1.2.11")
    assert release_of("1.2.11.dfsg-2+deb11u2") == "11" and release_of("1.2-3") is None


R = [{"ecosystem": "Debian:11", "introduced": "0", "fixed": "1:1.2.11.dfsg-2+deb11u2"},
     {"ecosystem": "Debian:12", "introduced": "0", "fixed": "1:1.2.11.dfsg-4.1"}]


def test_verdicts():
    assert verdict("1.2.11.dfsg-2+deb11u1", R) is True      # own release, before its fix
    assert verdict("1.2.11.dfsg-2+deb11u2", R) is False     # own release, fixed
    assert verdict("1.2.11.dfsg-1", R) is True              # older than every release's fix
    assert verdict("1.2.13.dfsg-1", R) is False             # newer than every release's fix
    assert verdict("1.2.11.dfsg-3", R) is None              # between the fixes, release unknown
    assert verdict("1.2.11", R) is None                     # no revision: no answer
    assert verdict("1.2.11.dfsg-2+deb10u1", R) is None      # a release the advisory omits
    assert verdict("1.2.11-1", [{"ecosystem": "npm", "fixed": "9"}]) is None


def test_upstream_version_inside_a_package_version():
    from gangmu.vuln.debver import upstream_version
    assert upstream_version("1:1.2.11.dfsg-2+deb11u1") == "1.2.11"
    assert upstream_version("1.2.13+dfsg-1") == "1.2.13"
    assert upstream_version("7.74.0-1.3+deb11u7") == "7.74.0"
