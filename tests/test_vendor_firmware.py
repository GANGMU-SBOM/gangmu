"""What vendor firmware without a package database needs: firmware inside a zip or tar,
the kernel release its modules name, and the release strings of dnsmasq, miniupnpd,
iptables, libevent and uClibc as vendor builds keep them."""

import gzip
import io
import struct
import tarfile
import zipfile
from pathlib import Path

from gangmu.binaries import _anchored_versions, _banners, _uclibc_release, kernel_modules
from gangmu.elf import parse_elf
from gangmu.filesystems import archive_members, jobs
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan

HERE = Path(__file__).parent
RULES = HERE / "fixtures" / "rules"
FIRMWARE = HERE / "fixtures" / "squashfs" / "firmware.bin"


def _versions(data: bytes):
    found = _banners(data)
    found += _anchored_versions(data, found)
    return sorted((e.name, e.version) for e in found if e.version)


def test_release_strings_vendor_builds_keep():
    assert _versions(b"\0dnsmasq-2.85\0Dnsmasq version %s  %s\0") == [("dnsmasq", "2.85")]
    assert _versions(b"Server: AirOS/Ubiquiti/v6.3.11 UPnP/1.1 MiniUPnPd/2.0\0") == \
        [("miniupnpd", "2.0")]
    iptables = b"\0This is the IPv4 version of iptables.\0" + b"\x001.4.12.2\0"
    assert _versions(iptables) == [("iptables", "1.4.12.2")]
    multi = b"\0iptables multi-purpose version: unknown subcommand\0\x001.4.7\0"
    assert _versions(multi) == [("iptables", "1.4.7")]
    libevent = b"\0event_get_version_number\0\x002.1.8-stable\0"
    assert _versions(libevent) == [("libevent", "2.1.8")]


def test_a_dnsmasq_name_inside_a_longer_one_is_not_a_release():
    assert _versions(b"\0/etc/dnsmasq-2.85.conf.d\0") == []
    assert _versions(b"\0my-dnsmasq-2.85\0") == []


def test_a_four_part_kernel_release_is_read_whole():
    banner = b"Linux version 2.6.32.71 (root@builder) (gcc version 4.3.3) #1 Tue\0"
    assert ("linux-kernel", "2.6.32.71") in _versions(banner)


def _so(soname: bytes) -> bytes:
    """A 32-bit little-endian shared object with only program headers (as sstrip leaves)."""
    base, ph_at = 0x10000, 52
    dyn_at = ph_at + 64
    strtab = b"\0" + soname + b"\0"
    str_at = dyn_at + 32
    dyn = struct.pack("<8I", 5, base + str_at, 10, len(strtab), 14, 1, 0, 0)
    size = str_at + len(strtab)
    header = (b"\x7fELF\x01\x01\x01" + bytes(9)
              + struct.pack("<HHIIIIIHHHHHH", 3, 8, 1, 0, ph_at, 0, 0, 52, 32, 2, 40, 0, 0))
    phdrs = struct.pack("<8I", 1, 0, base, base, size, size, 5, 0x1000)
    phdrs += struct.pack("<8I", 2, dyn_at, base + dyn_at, base + dyn_at, 32, 32, 6, 4)
    return header + phdrs + dyn + strtab


def test_uclibc_is_named_by_its_loaders_file_name():
    data = _so(b"ld-uClibc.so.0")
    found = _uclibc_release(Path("ld-uClibc-0.9.33.2.so"), parse_elf(data), [])
    assert [(e.name, e.version, e.cpe) for e in found] == [
        ("uclibc", "0.9.33.2", "cpe:2.3:a:uclibc:uclibc:0.9.33.2:*:*:*:*:*:*:*")]
    ng = _uclibc_release(Path("ld-uClibc-1.0.45.so"), parse_elf(data), [])
    assert [(e.name, e.display_name, e.cpe) for e in ng] == [("uclibc-ng", "uClibc-ng", None)]
    assert _uclibc_release(Path("libc-2.31.so"), parse_elf(data), []) == []   # glibc's name


def _module(release: bytes) -> bytes:
    return b"\x7fELF\x01\x01\x01" + bytes(57) + b"license=GPL\0vermagic=" + release \
        + b" SMP preempt mod_unload ARMv7 \0name=x\0"


def test_the_kernel_release_comes_from_the_modules(tmp_path):
    mods = tmp_path / "lib/modules/2.6.36.4brcmarm+/kernel/net"
    mods.mkdir(parents=True)
    for i in range(3):
        (mods / f"m{i}.ko").write_bytes(_module(b"2.6.36.4brcmarm+"))
    (tmp_path / "lib/modules/extra.ko").write_bytes(_module(b"2.6.36.4brcmarm+"))
    (tmp_path / "lib/modules/notelf.ko").write_bytes(b"vermagic=9.9.9 SMP \0")
    found = kernel_modules(tmp_path)
    assert [(k.directory, k.version, k.release, k.modules) for k in found] == [
        ("lib/modules/2.6.36.4brcmarm+", "2.6.36.4", "2.6.36.4brcmarm+", 4)]
    result = scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))
    kernel = [f for f in result.findings if f.upstream_name == "Linux kernel"]
    assert len(kernel) == 1 and kernel[0].version == "2.6.36.4"
    assert kernel[0].cpe == "cpe:2.3:o:linux:linux_kernel:2.6.36.4:*:*:*:*:*:*:*"
    assert "4 kernel module(s)" in kernel[0].evidence[0].summary


# ------------------------------------------------------------ archives

def _zip(members) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in members:
            z.writestr(name, body)
    return buf.getvalue()


def test_firmware_inside_a_zip_is_scanned(tmp_path):
    zipped = _zip([("R7000-V1.0.chk", FIRMWARE.read_bytes()),
                   ("R7000_Release_Notes.html", b"<html>notes</html>" * 300)])
    (tmp_path / "R7000.zip").write_bytes(zipped)
    result = scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))
    assert any(f.upstream_name == "BusyBox" and f.directory.startswith(
        "R7000.zip!zip@0x0/R7000-V1.0.chk!squashfs@0x") for f in result.findings)
    assert any("zip archive, 1 firmware file(s)" in n for n in result.notes)


def test_firmware_inside_a_tar_gz_is_scanned(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        # an OpenWrt sysupgrade tar: its "root" member is the SquashFS itself
        body = (HERE / "fixtures" / "squashfs" / "rootfs-xz.sqfs").read_bytes()
        info = tarfile.TarInfo("sysupgrade-x/root")
        info.size = len(body)
        t.addfile(info, io.BytesIO(body))
    (tmp_path / "update.tar.gz").write_bytes(buf.getvalue())
    result = scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))
    assert any(f.upstream_name == "BusyBox"
               and f.directory.startswith("update.tar.gz!tar@0x0/sysupgrade-x/root!squashfs@0x0/")
               for f in result.findings)


def test_an_archive_of_sources_is_left_alone():
    zipped = _zip([("src/main.c", b"int main(void) { return 0; }\n" * 400),
                   ("docs/manual.pdf", b"%PDF-1.4" + bytes(8000))])
    assert archive_members("project.zip", zipped) == []
    assert jobs("project.zip", zipped, True) == []


def test_an_unsafe_member_path_is_not_written(tmp_path):
    zipped = _zip([("../../escape.bin", FIRMWARE.read_bytes()),
                   ("ok/fw.bin", FIRMWARE.read_bytes())])
    found = jobs("fw.zip", zipped, True)
    got = found[0].extract(tmp_path / "out")
    assert got.files == 1 and (tmp_path / "out/ok/fw.bin").exists()
    assert not list(tmp_path.rglob("escape.bin"))


def test_a_gzipped_image_named_like_one_is_not_an_archive():
    assert jobs("rootfs.cpio.gz", gzip.compress(b"x" * 100), False) == []
