"""dpkg version order (Debian Policy 5.6.12) and a Debian advisory's per-release ranges."""

import pytest

from gangmu.vuln.debver import compare, has_revision, release_of, split_version


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


def test_upstream_version_inside_a_package_version():
    from gangmu.vuln.debver import upstream_version
    assert upstream_version("1:1.2.11.dfsg-2+deb11u1") == "1.2.11"
    assert upstream_version("1.2.13+dfsg-1") == "1.2.13"
    assert upstream_version("7.74.0-1.3+deb11u7") == "7.74.0"
