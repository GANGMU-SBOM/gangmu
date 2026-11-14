"""JFFS2, UBI and UBIFS inside firmware images: the readers, the scan of what they
extract, and the pure-Python LZO they share."""

import gzip
import importlib.util
import os
import random
import struct
from pathlib import Path

import pytest

from gangmu.core import jffs2, lzo, ubi
from gangmu.filesystems import jobs
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures" / "flashfs"
RULES = HERE / "fixtures" / "rules"


def _image(name: str) -> bytes:
    return gzip.decompress((FIXTURES / f"{name}.gz").read_bytes())


@pytest.fixture(scope="module")
def expected(tmp_path_factory):
    """The tree every fixture was built from, as {relative path: bytes}."""
    spec = importlib.util.spec_from_file_location(
        "make_squashfs", HERE / "fixtures" / "squashfs" / "make.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path_factory.mktemp("tree")
    module.tree(root)
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in root.rglob("*") if p.is_file() and not p.is_symlink()}


def _read_back(out: Path):
    return {p.relative_to(out).as_posix(): p.read_bytes()
            for p in out.rglob("*") if p.is_file()}


@pytest.mark.parametrize("name,little", [("le.jffs2", True), ("be.jffs2", False),
                                         ("lzo.jffs2", True)])
def test_a_jffs2_image_is_read_back_exactly(tmp_path, expected, name, little):
    data = _image(name)
    found = jffs2.find(data)
    assert [(f.offset, f.little) for f in found] == [(0, little)]
    got = jffs2.extract(data, found[0], tmp_path / "out")
    assert got.error is None and got.skipped == []
    assert _read_back(tmp_path / "out") == expected


def _dirent(data: bytes, name: bytes):
    for at, total, kind in jffs2._nodes(data, 0, True):
        if kind == jffs2.DIRENT and data[at + 40:at + 40 + len(name)] == name:
            return at, total
    raise AssertionError(name)


def test_the_newest_jffs2_entry_wins_and_a_deletion_removes_the_file(tmp_path):
    data = bytearray(_image("le.jffs2"))
    at, total = _dirent(bytes(data), b"empty")
    node = bytearray(data[at:at + total])
    version, = struct.unpack_from("<I", node, 16)
    struct.pack_into("<II", node, 16, version + 1, 0)            # newer, and inode 0
    struct.pack_into("<I", node, 32, jffs2.crc(bytes(node[:32])))
    data += b"\xff" * (-len(data) % 4) + node
    got = jffs2.extract(bytes(data), jffs2.find(bytes(data))[0], tmp_path / "out")
    assert got.files == 6 and not (tmp_path / "out/usr/share/doc/empty").exists()


def test_a_corrupt_jffs2_node_is_passed_over(tmp_path, expected):
    data = bytearray(_image("le.jffs2"))
    at, _ = _dirent(bytes(data), b"here.conf")
    data[at + 41] ^= 0xFF                                        # break the name's CRC
    jffs2.extract(bytes(data), jffs2.find(bytes(data))[0], tmp_path / "out")
    files = _read_back(tmp_path / "out")
    assert "etc/deep/er/still/here.conf" not in files
    assert files["usr/lib/opkg/status"] == expected["usr/lib/opkg/status"]


@pytest.mark.parametrize("name", ["zlib.ubifs", "lzo.ubifs"])
def test_a_ubifs_image_is_read_back_exactly(tmp_path, expected, name):
    data = _image(name)
    leb = ubi.is_ubifs(data)
    assert leb == 15872
    got = ubi.extract_ubifs(data, leb, tmp_path / "out")
    assert got.error is None and got.skipped == []
    assert _read_back(tmp_path / "out") == expected


def test_ubi_volumes_are_rebuilt_from_their_eraseblocks():
    data = _image("nand.ubi")
    image = ubi.read_ubi(data, ubi.find_ubi(data))
    assert image is not None and image.peb_size == 16384
    names = {v.name: v for v in image.volumes}
    assert set(names) == {"rootfs_data", "rootfs"}
    assert ubi.is_ubifs(names["rootfs_data"].data) == 15872
    assert names["rootfs"].data[:4] == b"hsqs"


def test_a_ubi_image_is_scanned_through_every_volume(tmp_path):
    (tmp_path / "nand.ubi").write_bytes(_image("nand.ubi"))
    (tmp_path / "flash.bin").write_bytes(_image("be.jffs2"))
    result = scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))
    where = {f.directory for f in result.findings if f.upstream_name == "BusyBox"}
    assert where == {"nand.ubi!ubi@0x0/rootfs_data/usr/lib/opkg",
                     "nand.ubi!ubi@0x0/rootfs.bin!squashfs@0x0/usr/lib/opkg",
                     "flash.bin!jffs2@0x0/usr/lib/opkg"}
    assert any("JFFS2 (big-endian)" in n for n in result.notes)
    assert any("UBI image (2 volume(s)" in n for n in result.notes)


def test_a_partition_without_a_suffix_is_found_by_its_first_bytes(tmp_path):
    for name, part in (("le.jffs2", "rootfs_data"), ("zlib.ubifs", "ubifs_part")):
        (tmp_path / part).write_bytes(_image(name))
    result = scan(tmp_path, load_rules(RULES), options=ScanOptions(unknown=False, loose=False))
    dirs = {f.directory for f in result.findings if f.upstream_name == "zlib"}
    assert "rootfs_data!jffs2@0x0/usr/lib/opkg" in dirs
    assert "ubifs_part!ubifs@0x0/usr/lib/opkg" in dirs


def test_no_file_system_is_found_in_code_or_noise():
    rng = random.Random(7)
    noise = bytes(rng.getrandbits(8) for _ in range(1 << 18))
    magics = (b"\x85\x19\x01\xe0" + b"\0" * 60) * 64 + b"UBI#" * 64 + b"hsqs" * 64
    for data in (noise, noise + magics + noise, Path(os.__file__).read_bytes() * 4):
        assert jobs("x.bin", data, True) == []


def test_lzo_refuses_corrupt_input():
    with pytest.raises(lzo.LzoError):
        lzo.decompress(b"\x00\x00\x00\x40\x00\x00", 4096)       # a match before any output
    with pytest.raises(lzo.LzoError):
        lzo.decompress(b"\x15abcd", 4096)                        # literals then nothing
    assert lzo.decompress(b"\x15abcd\x11\x00\x00", 4096) == b"abcd"   # 4 literals, end
