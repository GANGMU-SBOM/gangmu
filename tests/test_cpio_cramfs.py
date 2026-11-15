"""cpio archives (an initramfs, inside a kernel or a ramdisk) and cramfs images."""

import gzip
import importlib.util
import lzma
import struct
from pathlib import Path

import pytest

from gangmu.core import cpio, cramfs
from gangmu.filesystems import jobs
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan

HERE = Path(__file__).parent
RULES = HERE / "fixtures" / "rules"
STATUS = b"Package: busybox\nVersion: 1.36.1-1\nStatus: install user installed\n"
FILES = {
    "usr/lib/opkg/status": STATUS,
    "bin/busybox": b"\x7fELF" + b"BusyBox v1.36.1 (2024-09-23) multi-call binary\0" * 200,
    "etc/deep/er/x.conf": b"x=1\n",
    "empty": b"",
}


def _read(out: Path):
    return {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}


# ------------------------------------------------------------ cpio

def _newc(entries, magic=b"070701"):
    """entries: (name, mode, data, ino, nlink)"""
    out = bytearray()
    for name, mode, data, ino, nlink in entries + [("TRAILER!!!", 0, b"", 0, 1)]:
        raw = name.encode() + b"\0"
        out += magic + b"".join(b"%08X" % v for v in (
            ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(raw), 0))
        out += raw + b"\0" * (-(110 + len(raw)) % 4)
        out += data + b"\0" * (-len(data) % 4)
    return bytes(out)


def _odc(entries):
    out = bytearray()
    for name, mode, data, ino, nlink in entries + [("TRAILER!!!", 0, b"", 0, 1)]:
        raw = name.encode() + b"\0"
        out += b"070707" + b"%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" % (
            0, ino, mode, 0, 0, nlink, 0, 0, len(raw), len(data))
        out += raw + data
    return bytes(out)


def _binary(entries, e="<"):
    out = bytearray()
    for name, mode, data, ino, nlink in entries + [("TRAILER!!!", 0, b"", 0, 1)]:
        raw = name.encode() + b"\0"
        out += struct.pack(e + "13H", 0o070707, 0, ino, mode, 0, 0, nlink, 0, 0, 0, len(raw),
                           len(data) >> 16, len(data) & 0xFFFF)
        out += raw + b"\0" * (len(raw) & 1) + data + b"\0" * (len(data) & 1)
    return bytes(out)


def _entries():
    out, ino = [], 1
    for d in ("usr", "usr/lib", "usr/lib/opkg", "bin", "etc", "etc/deep", "etc/deep/er"):
        out.append((d, 0o040755, b"", ino, 2))
        ino += 1
    for name, data in FILES.items():
        out.append((name, 0o100644, data, ino, 1))
        ino += 1
    out.append(("dev/console", 0o020600, b"", ino, 1))          # a device node: not written
    return out


@pytest.mark.parametrize("build,kind", [
    (lambda e: _newc(e), "newc"), (lambda e: _newc(e, b"070702"), "crc"),
    (_odc, "odc"), (lambda e: _binary(e, "<"), "binary-le"),
    (lambda e: _binary(e, ">"), "binary-be")])
def test_every_cpio_format_reads_back(tmp_path, build, kind):
    data = b"\0" * 64 + build(_entries())
    found = cpio.find(data)
    assert [(a.offset, a.kind) for a in found] == [(64, kind)]
    got = cpio.extract(data, found[0], tmp_path / "out")
    assert got.error is None and _read(tmp_path / "out") == FILES


def test_a_hard_linked_file_gets_its_data_under_every_name(tmp_path):
    body = b"shared body" * 10
    data = _newc([("bin", 0o040755, b"", 1, 2), ("bin/a", 0o100755, b"", 7, 2),
                  ("bin/b", 0o100755, body, 7, 2)])
    cpio.extract(data, cpio.find(data)[0], tmp_path / "out")
    assert (tmp_path / "out/bin/a").read_bytes() == body == (tmp_path / "out/bin/b").read_bytes()


def test_unsafe_cpio_paths_are_skipped(tmp_path):
    data = _newc([("../escape", 0o100644, b"x", 1, 1), ("./ok", 0o100644, b"y", 2, 1),
                  ("/abs/ok2", 0o100644, b"z", 3, 1)])
    cpio.extract(data, cpio.find(data)[0], tmp_path / "out")
    assert _read(tmp_path / "out") == {"ok": b"y", "abs/ok2": b"z"}
    assert not (tmp_path / "escape").exists()


def test_concatenated_archives_are_each_found():
    data = _newc(_entries()) + _newc([("extra", 0o100644, b"e" * 9, 99, 1),
                                      ("more", 0o100644, b"m", 98, 1)])
    assert len(cpio.find(data)) == 2


def test_cpio_magic_in_text_is_not_an_archive():
    text = b"-H newc option\0\0070701\0\0no cpio magic\0TRAILER!!!\0" * 10
    assert cpio.find(text) == []


def _scan(tmp_path):
    return scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))


def test_an_initramfs_compressed_inside_a_kernel_is_scanned(tmp_path):
    # a real initramfs is megabytes; a stream found by its LZMA properties alone must give
    # at least 64 KiB (core.unpack.MIN_LZMA)
    archive = _newc(_entries() + [("lib/libbig.so", 0o100644, bytes(range(256)) * 400, 90, 1)])
    kernel = bytes(range(256)) * 1200 + lzma.compress(archive, format=lzma.FORMAT_ALONE) \
        + bytes(range(256)) * 200
    (tmp_path / "openwrt-initramfs-kernel.bin").write_bytes(kernel)
    result = _scan(tmp_path)
    where = [f.directory for f in result.findings if f.upstream_name == "BusyBox"
             and f.version == "1.36.1-1"]
    assert len(where) == 1 and where[0].startswith("openwrt-initramfs-kernel.bin!lzma@0x")
    assert where[0].endswith("!cpio@0x0/usr/lib/opkg")


def test_a_gzipped_ramdisk_file_is_scanned(tmp_path):
    (tmp_path / "rootfs.cpio.gz").write_bytes(gzip.compress(_newc(_entries()) * 1)
                                              + bytes(300 * 1024))
    result = _scan(tmp_path)
    assert any(f.upstream_name == "BusyBox" and "rootfs.cpio.gz!gzip@0x0!cpio@0x0" in f.directory
               for f in result.findings)


def test_a_kernel_with_only_device_nodes_in_its_initramfs_gives_nothing():
    nodes = _newc([("dev", 0o040755, b"", 1, 2), ("dev/console", 0o020600, b"", 2, 1),
                   ("root", 0o040700, b"", 3, 2)])
    kernel = bytes(range(256)) * 1200 + lzma.compress(nodes, format=lzma.FORMAT_ALONE)
    assert jobs("vmlinux.bin", kernel, True) == []


# ------------------------------------------------------------ cramfs

@pytest.fixture(scope="module")
def expected(tmp_path_factory):
    spec = importlib.util.spec_from_file_location(
        "make_squashfs", HERE / "fixtures" / "squashfs" / "make.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path_factory.mktemp("tree")
    module.tree(root)
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in root.rglob("*") if p.is_file() and not p.is_symlink()}


@pytest.mark.parametrize("order", ["little", "big"])
def test_a_cramfs_image_is_read_back_exactly(tmp_path, expected, order):
    data = gzip.decompress((HERE / "fixtures" / "cramfs" / f"{order}.cramfs.gz").read_bytes())
    found = cramfs.find(data)
    assert len(found) == 1 and found[0].big == (order == "big")
    got = cramfs.extract(data, found[0], tmp_path / "out")
    assert got.error is None and _read(tmp_path / "out") == expected


def test_a_cramfs_inside_a_flash_image_is_scanned(tmp_path):
    data = gzip.decompress((HERE / "fixtures" / "cramfs" / "little.cramfs.gz").read_bytes())
    (tmp_path / "camera.bin").write_bytes(b"\xff" * 0x10000 + data + b"\xff" * 4096)
    result = _scan(tmp_path)
    assert any(f.directory == "camera.bin!cramfs@0x10000/usr/lib/opkg" for f in result.findings)
    assert any("cramfs (little-endian)" in n for n in result.notes)


def test_a_cramfs_signature_alone_is_not_a_file_system():
    assert cramfs.find(b"\0" * 100 + b"E=\xcd(" + bytes(12) + cramfs.SIGNATURE + bytes(80)) == []
