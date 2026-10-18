"""Programs and libraries of a Linux root file system: found by what they are, not what they
are called, and read for the banners and packaging metadata they carry.

Taken from real Ubuntu 24.04 libraries: libz.so.1.3 and libexpat.so.1 are versioned names
whose suffix is a number, busybox and sshd have none, and libzstd's ELF carries the
distribution's package note.
"""

import json
import os
import random
import struct

import pytest

import thumb_images as fw
from pebuild import elf_blob, elf_with_sections

from gangmu import binaries, disasm
from gangmu.binaries import (Embedded, Binary, _banners, _kind, _looks_unreadable,
                             _package_metadata, _prints_for, collect_binaries, describe_binary)
from gangmu.elf import SHT_NOTE, package_note, parse_elf
from gangmu.scan import ScanOptions, scan
from gangmu.rules.loader import load_rules


def _note(payload, name=b"FDO\0", kind=0xCAFE1A7E, big=False):
    e = ">" if big else "<"
    desc = payload.encode() + b"\0"
    pad = lambda b: b + b"\0" * (-len(b) % 4)
    return struct.pack(e + "III", len(name), len(desc), kind) + pad(name) + pad(desc)


def _packaged(**fields):
    return elf_with_sections([(".text", 1, b"\x90" * 16),
                              (".note.package", SHT_NOTE, _note(json.dumps(fields)))],
                             machine=62, etype=3, bits64=True)


# ------------------------------------------------------------ which files are inventoried

def _tree(tmp_path):
    lib = elf_blob(etype=3, payload=b"inflate-free library " * 100)
    program = elf_with_sections([(".interp", 1, b"/lib64/ld-linux-x86-64.so.2\0"),
                                 (".text", 1, b"BusyBox v1.36.1 (2023-11-07) multi-call\0")],
                                machine=62, etype=3, bits64=True)
    (tmp_path / "lib").mkdir()
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "lib" / "libz.so.1.3").write_bytes(lib)
    (tmp_path / "lib" / "libz.so.1").symlink_to("libz.so.1.3")
    (tmp_path / "lib" / "libz.so").symlink_to("libz.so.1")
    (tmp_path / "lib" / "libfoo.so.2").write_bytes(lib)
    (tmp_path / "usr" / "bin" / "busybox").write_bytes(program)
    (tmp_path / "usr" / "bin" / "python3.12").write_bytes(program)       # a suffix that is a number
    (tmp_path / "usr" / "bin" / "ld.so.cache").write_bytes(b"not an elf" * 50)
    (tmp_path / "usr" / "bin" / "README").write_text("text\n" * 50)
    (tmp_path / "usr" / "bin" / "script").write_text("#!/bin/sh\necho hi\n")
    (tmp_path / "usr" / "bin" / "core").write_bytes(elf_blob(etype=4))   # a core dump
    (tmp_path / "usr" / "bin" / "tool.o").write_bytes(elf_blob(etype=1))
    (tmp_path / "Makefile").write_text("all:\n")
    return tmp_path


def test_versioned_libraries_and_extensionless_programs_are_inventoried(tmp_path):
    found = {b.path: b.kind for b in collect_binaries(_tree(tmp_path))}
    assert found == {"lib/libz.so.1.3": "shared-library", "lib/libfoo.so.2": "shared-library",
                     "usr/bin/busybox": "executable", "usr/bin/python3.12": "executable"}


def test_a_symlink_is_its_target_not_a_second_binary(tmp_path):
    names = [b.path for b in collect_binaries(_tree(tmp_path))]
    assert not any(n in names for n in ("lib/libz.so.1", "lib/libz.so"))


def test_the_kind_of_an_elf_comes_from_its_type(tmp_path):
    exe = elf_with_sections([(".text", 1, b"\0" * 4)], machine=62, etype=2)
    pie = elf_with_sections([(".interp", 1, b"/lib/ld.so\0")], machine=62, etype=3)
    lib = elf_with_sections([(".text", 1, b"\0" * 4)], machine=62, etype=3)
    path = tmp_path / "x"
    assert _kind(path, exe) == "executable" and _kind(path, pie) == "executable"
    assert _kind(path, lib) == "shared-library"
    assert _kind(path, b"not an elf") == "firmware-image"
    assert _kind(tmp_path / "libz.so.1", b"") == "shared-library"


def test_a_tree_of_sources_is_not_slowed_by_the_new_selection(tmp_path):
    for i in range(300):
        (tmp_path / f"file{i}").write_text("x\n")
        (tmp_path / f"v{i}.1").write_text("x\n")
    assert collect_binaries(tmp_path) == []


# ------------------------------------------------------------ banners

@pytest.mark.parametrize("text, name, version", [
    (b" inflate 1.3.1 Copyright 1995-2024 Mark Adler ", "zlib", "1.3.1"),
    (b" deflate 1.3 Copyright 1995-2022 Jean-loup Gailly and Mark Adler ", "zlib", "1.3"),
    (b"deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly", "zlib", "1.2.11"),
    (b"inflate 1.2.11.1 Copyright", "zlib", "1.2.11.1"),
    (b"\0expat_2.6.1\0", "expat", "2.6.1"),
    (b"$LuaVersion: Lua 5.4.6  Copyright (C) 1994-2023 Lua.org, PUC-Rio", "lua", "5.4.6"),
    (b"$Lua: Lua 5.1.5  Copyright (C) 1994-2012 Lua.org", "lua", "5.1.5"),
    (b"libjpeg-turbo version 2.1.5 (build 20240417)", "libjpeg-turbo", "2.1.5"),
    (b"BusyBox v1.36.1 (2023-11-07 18:53:09 UTC) multi-call binary.", "busybox", "1.36.1"),
])
def test_banners_the_real_libraries_carry_name_their_release(text, name, version):
    assert [(e.name, e.version) for e in _banners(b"\0\0" + text + b"\0\0")] == [(name, version)]


@pytest.mark.parametrize("text", [b"myexpat_2.6.1", b"expat_2.6.1.5.7", b"Lua 5.4.6",
                                  b"BusyBox is a tool", b"inflate 1 Copyright", b"libjpeg 2.1.5"])
def test_lookalikes_are_not_banners(text):
    assert _banners(b"\0" + text + b"\0") == []


def test_every_banner_name_has_cpe_data_so_the_vulnerability_step_can_use_it():
    from gangmu.declared_linux import KNOWN
    assert {"expat", "lua", "libjpeg-turbo", "busybox", "zlib"} <= set(KNOWN)


def test_a_program_found_by_its_magic_number_is_read_for_its_banner(tmp_path):
    blobs = {b.path: b for b in collect_binaries(_tree(tmp_path))}
    assert [(e.name, e.version) for e in blobs["usr/bin/busybox"].embedded] == [("busybox", "1.36.1")]


# ------------------------------------------------------------ packaging metadata

def test_the_package_note_is_read_from_its_section():
    data = _packaged(type="deb", os="Ubuntu", name="libzstd", version="1.5.5+dfsg2-2build1.1",
                     architecture="amd64")
    info = parse_elf(data)
    assert package_note(data, info)["name"] == "libzstd"
    (emb,) = _package_metadata(data, info)
    assert (emb.name, emb.version, emb.method) == ("libzstd", "1.5.5+dfsg2-2build1.1", "package-note")
    assert emb.purl == "pkg:deb/ubuntu/libzstd@1.5.5%2Bdfsg2-2build1.1?arch=amd64"
    assert "deb, Ubuntu, amd64" in emb.banner


def test_an_rpm_note_names_its_distribution_by_its_cpe():
    data = _packaged(type="rpm", name="zlib", version="1.2.11-26.fc33", architecture="x86-64",
                     osCpe="cpe:/o:fedoraproject:fedora:33")
    (emb,) = _package_metadata(data, parse_elf(data))
    assert emb.purl == "pkg:rpm/fedora/zlib@1.2.11-26.fc33?arch=x86-64"


@pytest.mark.parametrize("fields", [{}, {"name": "x"}, {"version": "1"}, {"name": "", "version": "1"}])
def test_a_note_without_a_name_and_version_names_nothing(fields):
    data = _packaged(**fields)
    assert _package_metadata(data, parse_elf(data)) == []


@pytest.mark.parametrize("section", [_note("{broken"), _note("[1, 2]"), _note('{"name":"a","version":"1"}', name=b"GNU\0"),
                                     _note('{"name":"a","version":"1"}', kind=1), b"\0" * 8])
def test_a_note_that_is_not_the_packaging_metadata_is_ignored(section):
    data = elf_with_sections([(".note.package", SHT_NOTE, section)], machine=62, etype=3, bits64=True)
    assert package_note(data, parse_elf(data)) is None
    assert _package_metadata(data, parse_elf(data)) == []


def test_a_packaged_library_becomes_a_component_with_the_distribution_purl(tmp_path):
    (tmp_path / "libzstd.so.1").write_bytes(_packaged(
        type="deb", os="Ubuntu", name="libzstd", version="1.5.5+dfsg2-2build1.1",
        architecture="amd64"))
    result = scan(tmp_path, load_rules(os.path.join(os.path.dirname(__file__), "fixtures", "rules")),
                  options=ScanOptions(licenses=False))
    (finding,) = [f for f in result.findings if f.rule_id == "binary/libzstd"]
    assert finding.version == "1.5.5+dfsg2-2build1.1"
    assert finding.purl == "pkg:deb/ubuntu/libzstd@1.5.5%2Bdfsg2-2build1.1?arch=amd64"
    assert finding.cpe is None               # a distribution version is not an upstream release
    assert finding.version_source == "binary-metadata"
    assert "backported" in finding.evidence[0].summary


def test_a_file_that_names_its_own_package_is_described_as_identifying_itself():
    blob = Binary("lib/libzstd.so.1", "0" * 64, 1, "shared-library", embedded=[
        Embedded("libzstd", "libzstd", "1.5.5", "libzstd 1.5.5 (deb)", method="package-note")])
    assert "identifies itself as libzstd 1.5.5" in describe_binary(blob)
    assert "embeds" not in describe_binary(blob)


# ------------------------------------------------------------ function work on a library

class _Prints:
    def __init__(self, arch):
        self.arch = arch


def _arm_library():
    attrs = (b"A" + struct.pack("<I", 4 + 6 + 5 + 10) + b"aeabi\0" + b"\x01"
             + struct.pack("<I", 15) + bytes([6, 10, 7, ord("M"), 8, 0, 9, 2, 18, 4]))
    return elf_with_sections([(".text", 1, b"\0" * 8), (".ARM.attributes", 0x70000003, attrs)],
                             machine=40, etype=3)


def test_function_work_on_a_library_needs_references_for_its_cpu():
    info = parse_elf(_arm_library())
    assert _prints_for(info, [("X", "x", _Prints("thumb"))])
    assert not _prints_for(info, [("X", "x", _Prints("mips32be"))])
    assert not _prints_for(info, [])
    assert not _prints_for(None, [("X", "x", _Prints("thumb"))])


@pytest.mark.skipif(not disasm.available(), reason="capstone not installed")
@pytest.mark.parametrize("arch, runs", [("thumb", True), ("x86-64", False)])
def test_a_library_is_matched_by_function_only_when_a_rule_can_use_it(tmp_path, monkeypatch, arch, runs):
    (tmp_path / "libfoo.so.1").write_bytes(_arm_library())
    called = []
    monkeypatch.setattr(binaries, "_by_functions", lambda *a: called.append(1) or [])
    collect_binaries(tmp_path, None, (), [("Foo", "foo", _Prints(arch))])
    assert bool(called) == runs


# ------------------------------------------------------------ images nothing can read

def _random_bytes(n, seed=11):
    return random.Random(seed).randbytes(n)


def test_a_high_entropy_raw_image_is_called_unreadable():
    assert _looks_unreadable(_random_bytes(200_000))


@pytest.mark.parametrize("data", [
    _random_bytes(8_000),                                  # too small to judge
    b"\x89PNG\r\n\x1a\n" + _random_bytes(100_000),         # a picture
    b"GGUF" + _random_bytes(100_000),                      # a model
    b"\0" * 100_000,
    fw.FLASH_BIN * 80,                                     # code compresses
    b"".join(bytes([i % 251]) * 3 for i in range(40_000)),
])
def test_what_is_not_an_unreadable_image_is_not_called_one(data):
    assert not _looks_unreadable(data)


def test_a_compressed_blob_inside_firmware_does_not_make_the_whole_image_unreadable():
    image = fw.FLASH_BIN * 60 + _random_bytes(20_000) + fw.APP_BIN * 60
    assert not _looks_unreadable(image)


def test_the_scan_says_which_raw_images_could_not_be_read(tmp_path):
    (tmp_path / "update.bin").write_bytes(_random_bytes(100_000))
    (tmp_path / "app.bin").write_bytes(fw.FLASH_BIN * 40)
    result = scan(tmp_path, load_rules(os.path.join(os.path.dirname(__file__), "fixtures", "rules")),
                  options=ScanOptions(licenses=False))
    assert {b.path: b.opaque for b in result.binaries} == {"update.bin": True, "app.bin": False}
    (note,) = [n for n in result.notes if "high-entropy" in n]
    assert "update.bin" in note and "app.bin" not in note
    assert "missing from this SBOM" in note


def test_an_unreadable_image_the_link_map_says_is_not_shipped_is_not_reported():
    blob = Binary("other/update.bin", "0" * 64, 1, "firmware-image", linked=False, opaque=True)
    assert blob.opaque and blob.to_dict()["opaque"] is True
