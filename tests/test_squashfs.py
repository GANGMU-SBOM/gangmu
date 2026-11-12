"""SquashFS inside firmware images: the reader, the scan of what it extracts, and the
kernel an OpenWrt image compresses with LZMA and no magic number."""

import hashlib
import lzma
import shutil
import struct
from pathlib import Path

import pytest

from gangmu.binaries import _banners
from gangmu.core import squashfs
from gangmu.core.unpack import expand
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan

FIXTURES = Path(__file__).parent / "fixtures" / "squashfs"
RULES = Path(__file__).parent / "fixtures" / "rules"

TEXT = "".join(f"line {i:05d} of a file that spans several 4 KiB blocks\n" for i in range(400))


def _noise() -> bytes:
    noise, block = b"", b"seed"
    while len(noise) < 6000:
        block = hashlib.sha256(block).digest()
        noise += block
    return noise[:6000]


@pytest.mark.parametrize("comp", ["gzip", "xz"])
def test_every_file_is_read_back_exactly(tmp_path, comp):
    data = (FIXTURES / f"rootfs-{comp}.sqfs").read_bytes()
    found = squashfs.find(data)
    assert [sb.offset for sb in found] == [0] and found[0].compression_name == comp
    got = squashfs.extract(data, found[0], tmp_path / "out")
    assert got.error is None and got.skipped == []
    out = tmp_path / "out"
    assert (out / "usr/share/doc/long.txt").read_text() == TEXT        # blocks and a fragment
    assert (out / "usr/share/doc/noise.bin").read_bytes() == _noise()  # stored uncompressed
    assert (out / "usr/share/doc/zeros.bin").read_bytes() == bytes(3 * 4096)   # sparse
    assert (out / "usr/share/doc/empty").read_bytes() == b""
    assert (out / "etc/deep/er/still/here.conf").read_text() == "x=1\n"
    assert "Package: busybox" in (out / "usr/lib/opkg/status").read_text()
    assert not (out / "lib/libz.so.1").exists()                        # links are not made
    assert got.files == 7


def test_a_file_system_is_found_at_any_offset_in_an_image():
    data = (FIXTURES / "firmware.bin").read_bytes()
    found = squashfs.find(data)
    assert len(found) == 1 and found[0].offset == data.index(b"hsqs")


def test_a_magic_number_alone_is_not_a_file_system():
    assert squashfs.find(b"\0" * 100 + b"hsqs" + b"\x01" * 200) == []


def test_a_truncated_image_stops_reading_without_raising(tmp_path):
    data = (FIXTURES / "rootfs-xz.sqfs").read_bytes()
    sb = squashfs.find(data)[0]
    cut = data[:sb.inode_table + 40]                 # the inode table is cut short
    got = squashfs.extract(cut, sb, tmp_path / "out")
    assert got.error is not None


def test_the_byte_budget_is_kept(tmp_path):
    data = (FIXTURES / "rootfs-gzip.sqfs").read_bytes()
    sb = squashfs.find(data)[0]
    got = squashfs.extract(data, sb, tmp_path / "out", max_bytes=10_000)
    assert got.bytes <= 10_000 and got.skipped


def test_unsafe_names_are_not_written():
    for bad in ("..", ".", "a/b", "a\\b", ""):
        assert not squashfs._safe(bad)
    assert squashfs._safe("busybox")


def test_an_unreadable_compression_is_reported_not_guessed(tmp_path, monkeypatch):
    data = (FIXTURES / "rootfs-gzip.sqfs").read_bytes()
    sb = squashfs.find(data)[0]
    monkeypatch.setattr(squashfs, "decompressor", lambda _: None)
    got = squashfs.extract(data, sb, tmp_path / "out")
    assert got.files == 0 and "optional package" in got.error


def _rules():
    return load_rules(RULES)


def test_a_firmware_image_is_scanned_through_its_file_system(tmp_path):
    shutil.copy(FIXTURES / "firmware.bin", tmp_path / "firmware.bin")
    result = scan(tmp_path, _rules(), options=ScanOptions(unknown=False, loose=False))
    offset = (FIXTURES / "firmware.bin").read_bytes().index(b"hsqs")
    inside = f"firmware.bin!squashfs@{offset:#x}"
    names = {(f.upstream_name, f.version, f.directory) for f in result.findings}
    assert ("BusyBox", "1.36.1-1", f"{inside}/usr/lib/opkg") in names
    assert ("zlib", "1.3.1-1", f"{inside}/usr/lib/opkg") in names
    assert any(b.path == f"{inside}/lib/libz.so.1.3.1" for b in result.binaries)
    assert any("SquashFS (xz)" in n and "7 file(s)" in n for n in result.notes)


def test_a_single_image_file_can_be_scanned(tmp_path):
    shutil.copy(FIXTURES / "firmware.bin", tmp_path / "firmware.bin")
    result = scan(tmp_path / "firmware.bin", _rules(),
                  options=ScanOptions(unknown=False, loose=False))
    assert result.root == str(tmp_path / "firmware.bin")
    assert any(f.upstream_name == "BusyBox" for f in result.findings)
    assert any(b.path == "firmware.bin" for b in result.binaries)


def test_file_systems_can_be_left_alone(tmp_path):
    shutil.copy(FIXTURES / "firmware.bin", tmp_path / "firmware.bin")
    result = scan(tmp_path, _rules(),
                  options=ScanOptions(unknown=False, loose=False, filesystems=False))
    assert not any("!squashfs@" in f.directory for f in result.findings)


def test_a_rootfs_partition_without_a_suffix_is_found_by_its_first_bytes(tmp_path):
    shutil.copy(FIXTURES / "rootfs-gzip.sqfs", tmp_path / "rootfs")
    result = scan(tmp_path, _rules(), options=ScanOptions(unknown=False, loose=False))
    assert any(f.directory == "rootfs!squashfs@0x0/usr/lib/opkg" for f in result.findings)


# ------------------------------------------------------------ the kernel

BANNER = (b"Linux version 5.15.167 (builder@buildhost) (mipsel-openwrt-linux-musl-gcc "
          b"(OpenWrt GCC 12.3.0 r24106-10cc5fcd00) 12.3.0, GNU ld 2.40.0) #0 SMP\n")


def _kernel() -> bytes:
    body, block = bytearray(), b"k"
    while len(body) < 200_000:
        block = hashlib.sha256(block).digest()
        body += block[:8] + b"\0" * 24                  # compressible, but not trivially
    body[100_000:100_000 + len(BANNER)] = BANNER
    return bytes(body)


def _openwrt_lzma(raw: bytes) -> bytes:
    """What OpenWrt's lzma-loader carries: lc=1 lp=2 pb=2 and no 8-byte size field."""
    alone = lzma.compress(raw, format=lzma.FORMAT_ALONE, filters=[
        {"id": lzma.FILTER_LZMA1, "lc": 1, "lp": 2, "pb": 2, "dict_size": 1 << 23}])
    assert alone[0] == 0x6D
    return alone[:5] + alone[13:]


def test_an_openwrt_kernel_is_decompressed_and_its_version_read():
    loader = bytes(range(256)) * 20                   # the loader's own code before it
    image = loader + _openwrt_lzma(_kernel()) + b"\xff" * 512
    layers = expand(image, ".bin")
    assert any(l.label.startswith("lzma@") and BANNER in l.data for l in layers)
    found = [e for l in layers for e in _banners(l.data)]
    assert [(e.name, e.version) for e in found if e.name == "linux-kernel"] == \
        [("linux-kernel", "5.15.167")]


def test_a_standard_lzma_stream_with_its_size_is_read_too():
    raw = _kernel()
    alone = lzma.compress(raw, format=lzma.FORMAT_ALONE)
    assert alone[0] == 0x5D and struct.unpack_from("<Q", alone, 5)[0] in (len(raw), 2**64 - 1)
    layers = expand(b"\0" * 64 + alone, ".bin")
    assert any(BANNER in l.data for l in layers)


def test_the_kernel_banner_needs_a_built_kernel():
    # the source's format string, and prose mentioning a version, are not a kernel
    assert not [e for e in _banners(b"Linux version %s (%s@%s) (%s) %s\n")
                if e.name == "linux-kernel"]
    assert not [e for e in _banners(b"requires Linux version 4.4 or later\0")
                if e.name == "linux-kernel"]


def test_false_zlib_starts_do_not_use_up_the_tries_for_a_later_stream():
    import gzip
    junk = b"\x78\x9c" * 200                          # 200 zlib magic numbers, none real
    payload = b"BusyBox v1.36.1 (2024-09-23 12:34:56 UTC) multi-call binary." * 20
    layers = expand(junk + gzip.compress(payload), ".bin")
    assert any(payload in l.data for l in layers)
