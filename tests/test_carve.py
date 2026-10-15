"""Native binaries inside other files: found by their headers, sized by their own tables."""

import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest
from pebuild import (build_pe, dotnet_metadata, elf_blob, macho_blob, managed_resource_blob)

from gangmu.binaries import collect_binaries, describe_binary
from gangmu.carve import MIN_SIZE, carve, mask
from gangmu.rules.loader import load_rules
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.sbom.spdx import to_spdx
from gangmu.sbom.spdx3 import to_spdx3
from gangmu.scan import ScanOptions, scan

JUNK = bytes(range(1, 250)) * 4                # no magic numbers, no NULs


def _around(*blobs: bytes, gap: bytes = JUNK) -> bytes:
    return gap + b"".join(b + gap for b in blobs)


# -- finding and sizing ----------------------------------------------------------------------

@pytest.mark.parametrize("blob, kind, arch, suffix", [
    (elf_blob(), "elf", "x86_64", ".elf"),
    (elf_blob(machine=40, bits64=False), "elf", "arm", ".elf"),
    (elf_blob(machine=21, big=True), "elf", "ppc64", ".elf"),
    (elf_blob(machine=183, sections=False), "elf", "aarch64", ".elf"),
    (macho_blob(), "macho", "aarch64", ".dylib"),
    (macho_blob(cputype=0x01000007, filetype=2), "macho", "x86_64", ".dylib"),
    (macho_blob(signature=2048), "macho", "aarch64", ".dylib"),
    (build_pe(dll=True), "pe", "x86_64", ".dll"),
    (build_pe(machine=0x14C), "pe", "x86", ".exe"),
    (build_pe(signed=True), "pe", "x86_64", ".exe"),
], ids=["elf64", "elf32", "elf64-big-endian", "elf64-no-section-headers", "macho-dylib",
        "macho-executable", "macho-code-signature", "pe-dll", "pe-x86-exe", "pe-authenticode"])
def test_each_format_is_found_at_its_offset_with_its_exact_size(blob, kind, arch, suffix):
    data = _around(blob)
    found = carve(data)
    assert [(c.offset, c.size, c.kind, c.arch, c.suffix) for c in found] == [
        (len(JUNK), len(blob), kind, arch, suffix)]
    assert data[found[0].offset:found[0].offset + found[0].size] == blob


def test_several_binaries_in_one_file_are_all_found_in_order():
    blobs = [elf_blob(), macho_blob(), build_pe(dll=True), elf_blob(machine=3)]
    found = carve(_around(*blobs))
    assert [(c.kind, c.size) for c in found] == [(k, len(b)) for k, b in zip(
        ["elf", "macho", "pe", "elf"], blobs)]
    assert [c.offset for c in found] == sorted(c.offset for c in found)


def test_the_file_itself_at_offset_zero_is_not_carved():
    assert carve(elf_blob() + JUNK) == []
    assert carve(build_pe(dll=True)) == []


def test_a_stray_magic_number_is_not_a_binary():
    junk = (b"MZ" + b"\x01" * 200 + b"\x7fELF" + b"\x02" * 200 + b"\xcf\xfa\xed\xfe" + b"\x03" * 200
            + b"MZ\x90\0" + b"\0" * 56 + struct.pack("<I", 0x80) + b"\0" * 300) * 8
    assert carve(_around(junk)) == []


def test_a_header_that_contradicts_itself_is_not_carved():
    pe = bytearray(build_pe(dll=True))
    pe[0x80:0x84] = b"XX\0\0"                              # no PE signature where e_lfanew points
    elf = bytearray(elf_blob())
    elf[16:18] = struct.pack("<H", 1)                      # ET_REL: an object file, not a library
    macho = bytearray(macho_blob())
    macho[12:16] = struct.pack("<I", 1)                    # MH_OBJECT
    assert carve(_around(bytes(pe), bytes(elf), bytes(macho))) == []


def test_a_binary_cut_off_by_the_end_of_the_file_is_not_carved():
    blob = elf_blob()
    assert carve(JUNK + blob[:-100]) == []


def test_something_too_small_to_be_a_library_is_not_carved():
    tiny = elf_blob(payload=b"\x90" * 8)
    assert len(tiny) < MIN_SIZE
    assert carve(_around(tiny)) == []
    assert [c.size for c in carve(_around(tiny), min_size=64)] == [len(tiny)]


def test_only_the_outermost_of_nested_binaries_is_carved():
    inner = build_pe(dll=True)
    outer = elf_blob(payload=JUNK + inner + JUNK)
    found = carve(_around(outer))
    assert [(c.kind, c.size) for c in found] == [("elf", len(outer))]


def test_masking_blanks_only_the_carved_ranges():
    data = _around(elf_blob(), macho_blob())
    found = carve(data)
    masked = mask(data, found)
    assert len(masked) == len(data)
    for c in found:
        assert masked[c.offset:c.offset + c.size] == bytes(c.size)
    assert masked[:len(JUNK)] == JUNK and masked.endswith(JUNK)
    assert mask(data, []) is data


def test_the_number_of_binaries_found_is_capped():
    assert len(carve(_around(*[elf_blob()] * 10), max_blobs=4)) == 4


# -- real binaries ---------------------------------------------------------------------------

def _real_elf():
    for name in ("true", "ls"):
        path = shutil.which(name)
        if path and Path(path).read_bytes()[:4] == b"\x7fELF":
            return Path(path).read_bytes()
    return None


@pytest.mark.skipif(_real_elf() is None, reason="needs a system ELF binary")
def test_a_real_elf_is_carved_byte_for_byte():
    real = _real_elf()
    found = carve(_around(real))
    assert len(found) == 1 and found[0].size == len(real)
    got = _around(real)[found[0].offset:found[0].offset + found[0].size]
    assert hashlib.sha256(got).digest() == hashlib.sha256(real).digest()


def _pip_launcher():
    try:
        import pip
    except ImportError:
        return None
    path = Path(pip.__file__).parent / "_vendor" / "distlib" / "t64.exe"
    return path.read_bytes() if path.is_file() else None


@pytest.mark.skipif(_pip_launcher() is None, reason="pip's vendored launcher is not present")
def test_a_real_msvc_executable_is_carved_byte_for_byte():
    real = _pip_launcher()
    found = carve(_around(real))
    assert len(found) == 1 and found[0].kind == "pe" and found[0].size == len(real)


# -- the inventory ---------------------------------------------------------------------------

def _tree(tmp: Path, files: dict) -> Path:
    for name, data in files.items():
        path = tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return tmp


def test_a_banner_and_a_toolchain_are_credited_to_the_binary_they_are_in(tmp_path):
    lib = elf_blob(payload=b"\x90" * 500 + b"\0libcurl/8.4.0\0GCC: (Acme) 11.4.0\0" + b"\x90" * 2500)
    _tree(tmp_path, {"app.bin": _around(lib)})
    outer, child = collect_binaries(tmp_path)
    assert outer.embedded == [] and outer.toolchain is None      # not the outer file's
    assert [(e.name, e.version) for e in child.embedded] == [("curl", "8.4.0")]
    assert child.toolchain == "Acme 11.4.0"
    assert (child.container, child.offset, child.kind, child.arch) == (
        "app.bin", len(JUNK), "embedded-elf", "x86_64")
    assert child.size == len(lib) and child.sha256 == hashlib.sha256(lib).hexdigest()
    assert outer.embedded_binaries == 1 and child.embedded_binaries == 0
    assert child.path == f"app.bin#{len(JUNK):#x}"


def test_nesting_is_followed_two_levels_deep_and_the_deepest_file_is_read_whole(tmp_path):
    third = elf_blob(payload=b"\0libcurl/1.0.0\0" + b"\x90" * 3000)
    second = elf_blob(payload=JUNK + third + JUNK)
    first = elf_blob(payload=JUNK + second + JUNK)
    _tree(tmp_path, {"outer.bin": _around(first)})
    blobs = collect_binaries(tmp_path)
    # the file, the binary inside it, and the one inside that; the innermost is past the depth
    # limit, so it is not an entry of its own
    assert [b.container for b in blobs] == [None, "outer.bin", blobs[1].path]
    assert [b.embedded_binaries for b in blobs] == [1, 1, 0]
    # nothing is lost at the limit: the deepest analysed file is read whole, so its banner is
    # credited to the closest file that holds it, and the files around it do not claim it
    assert [[e.name for e in b.embedded] for b in blobs] == [[], [], ["curl"]]


def test_an_archive_of_object_files_is_not_carved(tmp_path):
    members = elf_blob(etype=1) + elf_blob(etype=1)
    _tree(tmp_path, {"libx.a": b"!<arch>\n" + members, "liby.a": b"!<arch>\n" + elf_blob() * 2})
    assert [b.path for b in collect_binaries(tmp_path)] == ["libx.a", "liby.a"]


def test_a_native_library_inside_a_pe_is_read_with_its_own_structure(tmp_path):
    dll = build_pe(dll=True, exports=("inner.dll", ["f"]), imports=["ws2_32.dll"],
                   version={"ProductName": "zlib", "ProductVersion": "1.2.13"})
    _tree(tmp_path, {"host.exe": build_pe(extra=[(".blob", JUNK + dll + JUNK)])})
    outer, child = collect_binaries(tmp_path)
    assert outer.imports in (None, []) or "ws2_32.dll" not in outer.imports
    assert child.kind == "embedded-pe" and child.imports == ["ws2_32.dll"]
    assert [(e.name, e.version, e.method) for e in child.embedded] == [
        ("zlib", "1.2.13", "version-info")]


def test_the_outer_file_is_still_read_for_what_is_its_own(tmp_path):
    lib = elf_blob(payload=b"\0libcurl/8.4.0\0" + b"\x90" * 3000)
    outer_text = b"\0OpenSSL 3.0.11\0"
    _tree(tmp_path, {"app.bin": outer_text + _around(lib)})
    outer, child = collect_binaries(tmp_path)
    assert [e.name for e in outer.embedded] == ["openssl"]
    assert [e.name for e in child.embedded] == ["curl"]


def test_dotnet_resources_name_the_binaries_carved_from_them(tmp_path):
    blob, entries = managed_resource_blob([
        ("Pkg.runtime.linux_x64.libx.so", elf_blob()),
        ("Pkg.runtime.win_x64.x.dll", build_pe(dll=True)),
        ("Pkg.notes.txt", b"not a binary" * 20)])
    meta = dotnet_metadata("Pkg", (1, 0, 0, 0), resources=entries)
    _tree(tmp_path, {"Pkg.dll": build_pe(dll=True, clr=meta, clr_resources=blob)})
    outer, *children = collect_binaries(tmp_path)
    assert [c.path for c in children] == ["Pkg.dll!Pkg.runtime.linux_x64.libx.so",
                                          "Pkg.dll!Pkg.runtime.win_x64.x.dll"]
    assert [(c.kind, c.arch) for c in children] == [("embedded-elf", "x86_64"),
                                                    ("embedded-pe", "x86_64")]
    assert outer.runtime == "dotnet" and outer.embedded_binaries == 2


def test_a_resource_name_is_only_used_when_it_points_at_the_binary(tmp_path):
    blob, entries = managed_resource_blob([("Pkg.data", b"\x01" * 100)])
    meta = dotnet_metadata("Pkg", resources=entries)
    # the binary sits somewhere no resource names, so it is called by its offset
    host = build_pe(dll=True, clr=meta, clr_resources=blob, extra=[(".blob", JUNK + elf_blob())])
    _tree(tmp_path, {"Pkg.dll": host})
    _outer, child = collect_binaries(tmp_path)
    assert "#0x" in child.path and "!" not in child.path


PLCTAG_API = ("create_ex destroy read write status shutdown get_size set_raw_bytes get_raw_bytes "
              "get_bit set_bit get_int8 get_uint8 get_int16 get_uint16 get_int32 get_uint32 "
              "get_int64 get_uint64 get_float32 set_float32 get_float64 set_float64 get_string "
              "set_string get_string_length get_string_capacity get_int_attribute "
              "set_int_attribute unlock register_callback unregister_callback "
              "unregister_logger get_byte_array_attribute").split()


def _plctag_lib(*, soname=True, calls=len(PLCTAG_API)):
    names = [f"plc_tag_{n}" for n in PLCTAG_API[:calls]]
    text = b"\0" + b"\0".join(n.encode() for n in names) + b"\0"
    if soname:
        text += b"libplctag.so.2.6\0"
    return elf_blob(payload=text + b"\x90" * 3000)


def test_a_native_library_carved_from_a_dotnet_wrapper_is_named_but_the_wrapper_is_not(tmp_path):
    # the wrapper's own metadata lists every plc_tag_* name it P/Invokes; that says what it
    # calls, not that the library is in it. The carved ELF defines them, and is the library.
    declared = [(f"plc_tag_{n}", 0) for n in PLCTAG_API]
    blob, entries = managed_resource_blob([("Pkg.runtime.linux_x64.libplctag.so", _plctag_lib())])
    meta = dotnet_metadata("Pkg", resources=entries + declared)
    _tree(tmp_path, {"Pkg.dll": build_pe(dll=True, clr=meta, clr_resources=blob)})
    outer, child = collect_binaries(tmp_path)
    assert "libplctag" not in {e.name for e in outer.embedded}
    [lib] = child.embedded
    assert (lib.name, lib.version, lib.method) == ("libplctag", "", "symbols")
    assert "series 2.6" in lib.banner and "34 of 34" in lib.banner


def test_a_few_plc_tag_calls_do_not_make_a_library(tmp_path):
    _tree(tmp_path, {"app.elf": _plctag_lib(calls=10), "lib.elf": _plctag_lib(soname=False)})
    few, full = collect_binaries(tmp_path)
    assert few.embedded == []
    assert [e.name for e in full.embedded] == ["libplctag"] and "series" not in full.embedded[0].banner


def test_the_description_says_what_contains_what(tmp_path):
    _tree(tmp_path, {"app.bin": _around(elf_blob(), macho_blob())})
    outer, first, _second = collect_binaries(tmp_path)
    assert "contains 2 embedded binaries" in describe_binary(outer)
    assert "found inside app.bin" in describe_binary(first)


# -- scan and SBOM output --------------------------------------------------------------------

def test_sboms_say_which_file_a_binary_was_found_in(tmp_path, rules_dir):
    lib = elf_blob(payload=b"\0libcurl/8.4.0\0" + b"\x90" * 3000)
    _tree(tmp_path, {"app.bin": _around(lib)})
    result = scan(tmp_path, load_rules(rules_dir, strict=True), None, ScanOptions())
    assert [b.container for b in result.binaries] == [None, "app.bin"]
    child_path = result.binaries[1].path

    comps = {c["name"]: c for c in to_cyclonedx(result)["components"]}
    props = {(p["name"], p["value"]) for p in comps[child_path]["properties"]}
    assert ("gangmu:containedIn", "app.bin") in props
    assert ("gangmu:offsetInContainer", str(len(JUNK))) in props
    assert ("gangmu:architecture", "x86_64") in props
    assert ("gangmu:embeddedLibrary", "curl 8.4.0") in props
    assert ("gangmu:embeddedBinaries", "1") in {(p["name"], p["value"])
                                                for p in comps["app.bin"]["properties"]}

    spdx = to_spdx(result)
    ids = {p["name"]: p["SPDXID"] for p in spdx["packages"]}
    contains = {(r["spdxElementId"], r["relatedSpdxElement"]) for r in spdx["relationships"]
                if r["relationshipType"] == "CONTAINS"}
    assert (ids["app.bin"], ids[child_path]) in contains          # inside its file
    assert not any(b == ids[child_path] and a != ids["app.bin"] for a, b in contains)

    assert "app.bin#" in json.dumps(to_spdx3(result))

    assert any(f.upstream_name and f.evidence and f.evidence[0].locator == child_path
               for f in result.findings)
