"""SquashFS 2.x/3.x (both byte orders, zlib and the LZMA framings firmware used, vendor
magic numbers), the LZMA framings of vendor SquashFS 4.0, and ipkg databases."""

import hashlib
import lzma
from pathlib import Path

import pytest

from gangmu.core import squashfs, squashfs3
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan
from sq3build import build

RULES = Path(__file__).parent / "fixtures" / "rules"
STATUS = b"Package: busybox\nVersion: 1.11.2-2\nStatus: install user installed\n\n" \
         b"Package: dropbear\nVersion: 0.51-2\nStatus: install user installed\n"
FILES = {
    "usr/lib/opkg/status": STATUS,
    "bin/busybox": b"\x7fELF" + b"BusyBox v1.11.2 (2009-01-21) multi-call binary\0" * 300,
    "etc/deep/er/x.conf": b"x=1\n",
    "lib/noise.bin": b"".join(hashlib.sha256(bytes([i])).digest() for i in range(200)),
    "lib/empty": b"",
}


def _read(out: Path):
    return {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}


@pytest.mark.parametrize("major", [2, 3])
@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("codec", ["zlib", "lzma", "lzma-alone", "lzma-props"])
def test_every_version_byte_order_and_codec_reads_back(tmp_path, major, big, codec):
    image = build(FILES, major=major, big=big, codec=codec)
    found = squashfs3.find(image)
    assert len(found) == 1 and (found[0].major, found[0].big) == (major, big)
    got = squashfs3.extract(image, found[0], tmp_path / "out")
    assert got.error is None and _read(tmp_path / "out") == FILES


def test_sqlzma_images_mixing_zlib_and_lzma_blocks_read_back(tmp_path):
    image = build(FILES, codec="lzma", sqlzma=True)
    got = squashfs3.extract(image, squashfs3.find(image)[0], tmp_path / "out")
    assert got.error is None and _read(tmp_path / "out") == FILES


def test_the_check_byte_after_each_metadata_header_is_skipped(tmp_path):
    image = build(FILES, big=True, codec="lzma", check=True)
    got = squashfs3.extract(image, squashfs3.find(image)[0], tmp_path / "out")
    assert got.error is None and _read(tmp_path / "out") == FILES


@pytest.mark.parametrize("magic", [b"shsq", b"qshs", b"sqlz", b"hsqt", b"tqsh"])
def test_a_vendor_magic_number_is_accepted_when_the_rest_is_consistent(tmp_path, magic):
    image = build(FILES, big=magic in (b"qshs", b"tqsh"), codec="lzma", magic=magic)
    found = squashfs3.find(image)
    assert len(found) == 1 and magic.decode() in found[0].describe
    got = squashfs3.extract(image, found[0], tmp_path / "out")
    assert got.error is None and _read(tmp_path / "out") == FILES


def test_a_magic_number_alone_is_not_a_file_system():
    noise = b"".join(hashlib.sha256(bytes([i, 1])).digest() for i in range(256))
    for magic in squashfs3.MAGICS:
        assert squashfs3.find(noise + magic + noise) == []


def test_a_truncated_image_stops_without_raising(tmp_path):
    image = build(FILES, codec="lzma")
    sb = squashfs3.find(image)[0]
    cut = image[:sb.directory_table + 4]
    sb_cut = squashfs3._parse(image, 0, False)
    got = squashfs3.extract(cut, sb_cut, tmp_path / "out")
    assert got.error is not None


def test_an_old_firmware_image_is_scanned_through_its_file_system(tmp_path):
    fs = build(FILES, big=True, codec="lzma")
    (tmp_path / "openwrt-atheros.bin").write_bytes(b"\x27\x05\x19\x56" + bytes(4092) + fs)
    result = scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))
    found = {(f.upstream_name, f.version) for f in result.findings
             if f.directory == "openwrt-atheros.bin!squashfs@0x1000/usr/lib/opkg"}
    assert ("BusyBox", "1.11.2-2") in found
    assert any("SquashFS 3.0, big-endian" in n for n in result.notes)


def test_an_ipkg_database_is_read_like_opkg(tmp_path):
    fs = build({"usr/lib/ipkg/status": STATUS, "bin/x": b"x" * 10}, major=2, codec="lzma")
    (tmp_path / "wrt54g.trx").write_bytes(fs + b"\xff" * 8192)       # as flashed: padded
    result = scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))
    assert any(f.upstream_name.lower() == "dropbear" and f.version == "0.51-2"
               and f.directory.endswith("usr/lib/ipkg") for f in result.findings)


def test_vendor_squashfs4_lzma_framings_are_all_read():
    raw = b"BusyBox v1.36.1 multi-call binary " * 200
    alone = lzma.compress(raw, format=lzma.FORMAT_ALONE)
    bare = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=[
        {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}])
    decode = squashfs.decompressor(squashfs.LZMA)
    for block in (alone, bare, alone[:5] + bare, alone):
        assert decode(block, 8192) == raw
    with pytest.raises(squashfs.SquashfsError):
        decode(b"\x01\x02\x03 not lzma at all", 8192)
