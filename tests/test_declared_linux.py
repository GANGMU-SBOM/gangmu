"""Buildroot, OpenWrt and Kbuild declarations (Linux-based SDKs)."""

from pathlib import Path

from gangmu.declared_linux import read_buildroot, read_kbuild, read_openwrt
from gangmu.rules.loader import load_rules
from gangmu.scan import scan


def _w(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _buildroot(tmp: Path) -> Path:
    _w(tmp / "Makefile")
    _w(tmp / "package" / "Config.in")
    _w(tmp / "package" / "zlib" / "zlib.mk", "ZLIB_VERSION = 1.3.1\n")
    _w(tmp / "package" / "curl" / "curl.mk", "CURL_VERSION = 8.5.0\n")
    _w(tmp / "package" / "libfoo" / "libfoo.mk", "LIBFOO_VERSION = $(FOO_BASE)\n")
    _w(tmp / "package" / "unused" / "unused.mk", "UNUSED_VERSION = 9.9\n")
    _w(tmp / ".config", "BR2_PACKAGE_ZLIB=y\nBR2_PACKAGE_CURL=y\n"
                        "BR2_PACKAGE_LIBFOO=y\n# BR2_PACKAGE_UNUSED is not set\n")
    return tmp


def test_buildroot_reads_only_selected_packages_with_literal_versions(tmp_path):
    found = {d.name: d.version for d in read_buildroot(_buildroot(tmp_path))}
    assert found == {"zlib": "1.3.1", "curl": "8.5.0"}      # not unused, not libfoo


def test_buildroot_without_a_config_declares_nothing(tmp_path):
    _buildroot(tmp_path)
    (tmp_path / ".config").unlink()
    assert read_buildroot(tmp_path) == []


def test_openwrt_reads_selected_recipes(tmp_path):
    _w(tmp_path / ".config", "CONFIG_PACKAGE_dropbear=y\n# CONFIG_PACKAGE_ppp is not set\n")
    _w(tmp_path / "package" / "network" / "dropbear" / "Makefile",
       "PKG_NAME:=dropbear\nPKG_VERSION:=2022.83\nPKG_RELEASE:=1\n")
    _w(tmp_path / "package" / "network" / "ppp" / "Makefile",
       "PKG_NAME:=ppp\nPKG_VERSION:=2.4.9\n")
    found = {d.name: d.version for d in read_openwrt(tmp_path)}
    assert found == {"dropbear": "2022.83"}


def test_kbuild_reads_kernel_uboot_and_busybox_versions(tmp_path):
    _w(tmp_path / "kernel" / "Makefile", "VERSION = 5\nPATCHLEVEL = 10\nSUBLEVEL = 110\nEXTRAVERSION =\n")
    _w(tmp_path / "kernel" / "init" / "main.c")
    (tmp_path / "kernel" / "kernel" / "sched").mkdir(parents=True)
    _w(tmp_path / "uboot" / "Makefile", "VERSION = 2022\nPATCHLEVEL = 07\nSUBLEVEL =\nEXTRAVERSION = -rc2\n")
    _w(tmp_path / "uboot" / "common" / "main.c")
    (tmp_path / "uboot" / "include" / "configs").mkdir(parents=True)
    _w(tmp_path / "bb" / "Makefile", "VERSION = 1\nPATCHLEVEL = 36\nSUBLEVEL = 1\n")
    _w(tmp_path / "bb" / "applets" / "applets.c")
    (tmp_path / "bb" / "archival").mkdir()
    found = {d.name: d for d in read_kbuild(tmp_path)}
    assert found["linux-kernel"].version == "5.10.110" and found["linux-kernel"].forked
    assert found["u-boot"].version == "2022.07-rc2"
    assert found["busybox"].version == "1.36.1" and not found["busybox"].forked


def test_scan_turns_declarations_into_components(tmp_path, rules_dir):
    _buildroot(tmp_path)
    _w(tmp_path / "linux" / "Makefile", "VERSION = 4\nPATCHLEVEL = 9\nSUBLEVEL = 191\n")
    _w(tmp_path / "linux" / "init" / "main.c")
    (tmp_path / "linux" / "kernel" / "sched").mkdir(parents=True)
    result = scan(tmp_path, load_rules(rules_dir, strict=True))
    by_name = {f.upstream_name: f for f in result.findings}
    assert by_name["Linux kernel"].version == "4.9.191"
    assert by_name["Linux kernel"].vendor_patched
    assert by_name["Linux kernel"].cpe.startswith("cpe:2.3:o:linux:linux_kernel:4.9.191")
    zlib = next(f for f in result.findings if f.directory == "package/zlib")
    assert zlib.version == "1.3.1" and zlib.purl == "pkg:generic/zlib@1.3.1"
    assert zlib.cpe == "cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*"
