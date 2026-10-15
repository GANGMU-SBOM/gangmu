"""dpkg, opkg and apk databases of an unpacked root filesystem."""

from pathlib import Path

from gangmu.declared_rootfs import read_rootfs_packages
from gangmu.rules.loader import load_rules
from gangmu.scan import scan


def _w(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


_DPKG = """Package: zlib1g
Status: install ok installed
Priority: optional
Architecture: arm64
Version: 1:1.2.13.dfsg-1
Description: compression library - runtime
 zlib is a library implementing the deflate compression method.

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0-1

Package: busybox
Status: install ok installed
Version: 1:1.35.0-4+b1
"""

_OPKG = """Package: busybox
Version: 1.36.1-r0
Depends: libc6
Status: install user installed
Architecture: cortexa7t2hf-neon

Package: mytool
Version: 1.0+gitAUTOINC+abc123-r0
Status: install user installed
"""

_APK = """C:Q1abc=
P:musl
V:1.2.4-r2
A:aarch64
L:MIT
U:https://musl.libc.org/
T:the musl c library

C:Q1def=
P:zlib
V:1.3.1-r0
L:Zlib
U:https://zlib.net/
"""


def test_dpkg_reports_installed_packages_only_and_keeps_the_distribution_version(tmp_path):
    _w(tmp_path / "rootfs" / "var" / "lib" / "dpkg" / "status", _DPKG)
    found = {d.name: d for d in read_rootfs_packages(tmp_path)}
    assert set(found) == {"zlib1g", "busybox"}
    assert found["zlib1g"].version == "1:1.2.13.dfsg-1"
    assert not found["zlib1g"].version_is_upstream and found["zlib1g"].cpe is None
    assert found["zlib1g"].purl == "pkg:generic/zlib1g@1:1.2.13.dfsg-1"


def test_opkg_cuts_the_yocto_revision_and_refuses_git_snapshots(tmp_path):
    _w(tmp_path / "usr" / "lib" / "opkg" / "status", _OPKG)
    found = {d.name: d for d in read_rootfs_packages(tmp_path)}
    assert found["busybox"].version == "1.36.1" and found["busybox"].version_is_upstream
    assert found["busybox"].cpe and "busybox" in found["busybox"].cpe
    assert found["mytool"].version is None and found["mytool"].description


def test_apk_fields_are_read(tmp_path):
    _w(tmp_path / "lib" / "apk" / "db" / "installed", _APK)
    found = {d.name: d for d in read_rootfs_packages(tmp_path)}
    assert found["musl"].version == "1.2.4-r2" and found["musl"].license == "MIT"
    assert found["zlib"].upstream_url == "https://zlib.net/"
    assert not found["zlib"].version_is_upstream


def test_a_tree_without_a_package_database_gives_nothing(tmp_path):
    _w(tmp_path / "src" / "main.c", "int main(void){return 0;}\n")
    assert read_rootfs_packages(tmp_path) == []


def test_a_scan_reports_the_installed_packages(tmp_path):
    _w(tmp_path / "var" / "lib" / "opkg" / "status", _OPKG)
    result = scan(tmp_path, load_rules(Path(__file__).parent / "fixtures" / "rules"))
    assert ("declared/opkg/busybox", "1.36.1") in {
        (f.rule_id, f.version) for f in result.findings}
