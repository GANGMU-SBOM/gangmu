"""SONAME and file-name releases of shared libraries, and the GNU build-id."""

import struct

import pytest
from pebuild import elf_with_sections

from gangmu.binaries import collect_binaries
from gangmu.elf import SHT_NOTE, build_id, parse_elf, soname
from gangmu.scan import ScanOptions, scan
from gangmu.rules.loader import load_rules

SHT_DYNAMIC = 6


def _dynamic(name, big=False, bits64=True):
    e = ">" if big else "<"
    pool = b"\0" + name.encode() + b"\0"
    pack = (e + "QQ") if bits64 else (e + "II")
    return [(".dynamic", SHT_DYNAMIC, struct.pack(pack, 14, 1) + struct.pack(pack, 0, 0)),
            (".dynstr", 3, pool)]


def _so(soname_text="libz.so.1", extra=(), big=False, bits64=True, etype=3, machine=62):
    sections = [(".text", 1, b"\x90" * 16), *_dynamic(soname_text, big, bits64), *extra]
    return elf_with_sections(sections, machine=machine, etype=etype, bits64=bits64, big=big)


def _note(build, big=False):
    e = ">" if big else "<"
    return struct.pack(e + "III", 4, len(build), 3) + b"GNU\0" + build


@pytest.mark.parametrize("big,bits64", [(False, True), (False, False), (True, True), (True, False)])
def test_soname_is_read_for_every_layout(big, bits64):
    data = _so("libz.so.1", big=big, bits64=bits64)
    assert soname(data, parse_elf(data)) == "libz.so.1"


def test_no_soname_when_the_object_names_none():
    data = elf_with_sections([(".text", 1, b"\x90" * 16)], machine=62, etype=3, bits64=True)
    assert soname(data, parse_elf(data)) is None


def test_a_broken_dynamic_section_is_not_an_error():
    data = elf_with_sections([(".dynamic", SHT_DYNAMIC, b"\x0e" * 7), (".dynstr", 3, b"x")],
                             machine=62, etype=3, bits64=True)
    assert soname(data, parse_elf(data)) is None
    far = elf_with_sections([(".dynamic", SHT_DYNAMIC, struct.pack("<QQQQ", 14, 999, 0, 0)),
                             (".dynstr", 3, b"\0a\0")], machine=62, etype=3, bits64=True)
    assert soname(far, parse_elf(far)) is None


def test_build_id_is_hex_of_the_note():
    ident = bytes(range(20))
    data = _so(extra=[(".note.gnu.build-id", SHT_NOTE, _note(ident))])
    assert build_id(data, parse_elf(data)) == ident.hex()
    assert build_id(_so(), parse_elf(_so())) is None


def test_build_id_ignores_a_note_of_another_kind():
    wrong = struct.pack("<III", 4, 20, 5) + b"GNU\0" + bytes(20)
    data = _so(extra=[(".note.gnu.build-id", SHT_NOTE, wrong)])
    assert build_id(data, parse_elf(data)) is None


def _blobs(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    return {b.path: b for b in collect_binaries(tmp_path)}


def test_a_library_named_by_release_is_credited_with_it(tmp_path):
    blob = _blobs(tmp_path, "libz.so.1.3.1", _so("libz.so.1"))["libz.so.1.3.1"]
    (emb,) = blob.embedded
    assert (emb.name, emb.version, emb.method) == ("zlib", "1.3.1", "file-name")
    assert "SONAME libz.so.1" in emb.banner


def test_zlib_may_be_named_with_two_numbers(tmp_path):
    blob = _blobs(tmp_path, "libz.so.1.3", _so("libz.so.1"))["libz.so.1.3"]
    assert [e.version for e in blob.embedded] == ["1.3"]


@pytest.mark.parametrize("name,own,why", [
    ("libzstd.so.1.5", "libzstd.so.1", "too few numbers for zstd"),
    ("libz.so.1", "libz.so.1", "a major number is not a release"),
    ("libz.so.1.3.1", "libpng.so.16", "renamed: the SONAME disagrees"),
    ("libz.so.1.3.1", None, "no SONAME to confirm it"),
    ("libexpat.so.1.8.10", "libexpat.so.1", "libtool numbers are not releases"),
    ("libfoo.so.1.2.3", "libfoo.so.1", "unknown library"),
])
def test_names_that_do_not_prove_a_release_are_ignored(tmp_path, name, own, why):
    data = _so(own) if own else elf_with_sections(
        [(".text", 1, b"\x90" * 16)], machine=62, etype=3, bits64=True)
    assert _blobs(tmp_path, name, data)[name].embedded == [], why


def test_a_program_is_not_a_library(tmp_path):
    data = _so("libz.so.1", etype=2)
    assert _blobs(tmp_path, "libz.so.1.3.1", data)["libz.so.1.3.1"].embedded == []


def test_a_banner_wins_over_the_file_name(tmp_path):
    data = _so("libz.so.1", extra=[(".rodata", 1, b" inflate 1.2.13 Copyright 1995 Mark Adler ")])
    blob = _blobs(tmp_path, "libz.so.1.3.1", data)["libz.so.1.3.1"]
    assert [(e.version, e.method) for e in blob.embedded] == [("1.2.13", "banner")]


def test_scan_reports_the_release_with_lower_confidence_than_a_banner(tmp_path):
    (tmp_path / "libz.so.1.3.1").write_bytes(_so("libz.so.1"))
    rules = tmp_path / "rules"
    rules.mkdir()
    result = scan(tmp_path, load_rules(rules), None, ScanOptions())
    (found,) = [f for f in result.findings if f.rule_id == "binary/zlib"]
    assert found.version == "1.3.1" and found.version_source == "binary-file-name"
    assert found.version_confidence == pytest.approx(0.55)
    assert found.cpe == "cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*"
    assert "file name" in found.evidence[0].summary


def test_build_id_is_recorded_on_the_binary(tmp_path):
    ident = bytes(range(16, 36))
    data = _so("libfoo.so.1", extra=[(".note.gnu.build-id", SHT_NOTE, _note(ident))])
    blob = _blobs(tmp_path, "libfoo.so.1.2.3", data)["libfoo.so.1.2.3"]
    assert blob.build_id == ident.hex() and blob.to_dict()["build_id"] == ident.hex()
