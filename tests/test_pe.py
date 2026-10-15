"""Windows PE files: parsing, and what the binary inventory makes of .exe and .dll."""

import json
from pathlib import Path

import pytest
from pebuild import build_pe

from gangmu.binaries import collect_binaries, describe_binary, embedded_libraries
from gangmu.pe import parse_pe
from gangmu.rules.loader import load_rules
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.sbom.spdx import to_spdx
from gangmu.scan import ScanOptions, scan


def _pip_launchers():
    try:
        import pip
    except ImportError:
        return {}
    root = Path(pip.__file__).parent / "_vendor" / "distlib"
    return {p.name: p for p in root.glob("*.exe")}


# -- the parser on synthetic files ----------------------------------------------------------

def test_what_is_not_a_pe_gives_none():
    assert parse_pe(b"") is None
    assert parse_pe(b"MZ" + b"\0" * 100) is None                  # no PE signature
    assert parse_pe(b"\x7fELF" + b"\0" * 200) is None
    good = build_pe()
    assert parse_pe(good[:0x70]) is None                          # truncated headers
    assert parse_pe(good[:0x90]) is None                          # truncated optional header


def test_machine_bitness_dll_flag_and_linker():
    exe = parse_pe(build_pe())
    assert (exe.machine, exe.bits, exe.is_dll, exe.linker) == ("x86_64", 64, False, "14.38")
    dll = parse_pe(build_pe(dll=True, machine=0xAA64, linker=(2, 43)))
    assert (dll.machine, dll.is_dll, dll.linker) == ("aarch64", True, "2.43")


def test_imports_include_delay_loaded_libraries_and_are_lower_case():
    pe = parse_pe(build_pe(imports=["KERNEL32.dll", "libcurl-4.dll"],
                           delay_imports=["Crypt32.dll", "kernel32.dll"]))
    assert pe.imports == ["kernel32.dll", "libcurl-4.dll", "crypt32.dll"]


def test_exports_and_the_dlls_own_name():
    pe = parse_pe(build_pe(dll=True, exports=("mylib.dll", ["ogg_stream_init", "b"])))
    assert pe.export_name == "mylib.dll"
    assert pe.exports == ["ogg_stream_init", "b"]


def test_the_version_resource_is_read():
    pe = parse_pe(build_pe(version={"ProductName": "OpenSSL", "ProductVersion": "3.0.11",
                                    "CompanyName": "The OpenSSL Project"},
                           file_version=(3, 0, 11, 0)))
    assert pe.version_info == {"ProductName": "OpenSSL", "ProductVersion": "3.0.11",
                               "CompanyName": "The OpenSSL Project"}
    assert pe.file_version == "3.0.11.0" and pe.product_version == "3.0.11.0"


def test_a_file_without_a_resource_section_has_no_version():
    pe = parse_pe(build_pe())
    assert pe.version_info == {} and pe.file_version == ""


def test_the_pdb_path_names_the_build_tree():
    pe = parse_pe(build_pe(pdb=r"C:\src\proj\build\app.pdb"))
    assert pe.pdb == r"C:\src\proj\build\app.pdb"
    assert pe.pdb_guid.startswith("04030201-0605-0807-")


def test_signature_and_dotnet_flags():
    assert parse_pe(build_pe(signed=True)).signed is True
    assert parse_pe(build_pe()).signed is False
    assert parse_pe(build_pe(clr=True)).is_dotnet is True
    assert parse_pe(build_pe()).is_dotnet is False


def test_sections_are_found_by_name():
    data = build_pe(extra=[(".dep-v0", b"payload")])
    pe = parse_pe(data)
    assert pe.section_bytes(data, ".dep-v0") == b"payload"
    assert pe.section_bytes(data, ".nope") == b""


def test_one_corrupt_table_does_not_lose_the_others():
    data = bytearray(build_pe(imports=["a.dll"], pdb="x.pdb"))
    pe = parse_pe(bytes(data))
    assert pe.imports == ["a.dll"] and pe.pdb == "x.pdb"
    # Point the import table at nonsense; the debug record must still be read.
    start = 0x80 + 24 + 112 + 8                                   # directory 1 (imports)
    data[start:start + 4] = (0x7FFFFF00).to_bytes(4, "little")
    broken = parse_pe(bytes(data))
    assert broken is not None and broken.imports == [] and broken.pdb == "x.pdb"


def test_an_unterminated_import_table_is_bounded():
    pe = parse_pe(build_pe(imports=[f"lib{i}.dll" for i in range(50)]))
    assert len(pe.imports) == 50


# -- the parser on real files (pip ships MSVC-built executables) ----------------------------

@pytest.mark.skipif(not _pip_launchers(), reason="pip's vendored launchers are not present")
def test_real_msvc_executables_parse_for_every_architecture():
    launchers = _pip_launchers()
    seen = {}
    for name, path in launchers.items():
        pe = parse_pe(path.read_bytes())
        assert pe is not None, name
        assert pe.is_dll is False and ".text" in [s.name for s in pe.sections]
        assert "kernel32.dll" in pe.imports
        assert pe.pdb.endswith(".pdb") and len(pe.pdb_guid) == 36
        assert "Simple Launcher" in pe.version_info.get("CompanyName", "")
        assert pe.file_version.count(".") == 3
        seen[name] = (pe.machine, pe.bits)
    expected = {"t32.exe": ("x86", 32), "t64.exe": ("x86_64", 64),
                "t64-arm.exe": ("aarch64", 64)}
    for name, want in expected.items():
        if name in seen:
            assert seen[name] == want


# -- the binary inventory --------------------------------------------------------------------

def _tree(tmp: Path, files: dict) -> Path:
    for name, data in files.items():
        path = tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return tmp


def test_exe_and_dll_files_are_inventoried_with_their_kind(tmp_path):
    _tree(tmp_path, {"bin/app.exe": build_pe(), "bin/helper.DLL": build_pe(dll=True),
                     "bin/driver.sys": build_pe(), "bin/notes.txt": b"x"})
    blobs = {b.path: b for b in collect_binaries(tmp_path)}
    assert set(blobs) == {"bin/app.exe", "bin/helper.DLL", "bin/driver.sys"}
    assert blobs["bin/app.exe"].kind == "executable"
    assert blobs["bin/helper.DLL"].kind == "shared-library"
    assert blobs["bin/app.exe"].arch == "x86_64"


def test_a_test_fixture_exe_is_not_inventoried_but_a_fixture_dll_is(tmp_path):
    _tree(tmp_path, {"tests/data/sample.exe": build_pe(), "tests/data/lib.dll": build_pe(dll=True)})
    assert {b.path for b in collect_binaries(tmp_path)} == {"tests/data/lib.dll"}


def test_an_exe_is_a_product_so_a_link_map_does_not_mark_it_unlinked(tmp_path):
    _tree(tmp_path, {"app.exe": build_pe(), "other.exe": build_pe(), "libx.dll": build_pe(dll=True)})
    blobs = {b.path: b for b in collect_binaries(tmp_path, {"/b/libx.dll"}, product_stem="app")}
    assert blobs["app.exe"].linked is True
    assert blobs["other.exe"].linked is False
    assert blobs["libx.dll"].linked is False        # same rule as a .so: parent directory must match


def test_a_banner_inside_an_exe_is_read(tmp_path):
    text = b"\0libcurl/8.4.0\0OpenSSL 3.0.11\0"
    _tree(tmp_path, {"app.exe": build_pe(text=text)})
    found = {(e.name, e.version) for e in collect_binaries(tmp_path)[0].embedded}
    assert found == {("curl", "8.4.0"), ("openssl", "3.0.11")}


def test_the_version_resource_names_a_known_library(tmp_path):
    _tree(tmp_path, {
        "libssl.dll": build_pe(dll=True, version={"ProductName": "OpenSSL",
                                                  "ProductVersion": "3.0.11"}),
        "numeric.dll": build_pe(dll=True, version={"ProductName": "zlib"},
                                file_version=(1, 2, 13, 0)),
        "other.dll": build_pe(dll=True, version={"ProductName": "Acme Widgets",
                                                 "ProductVersion": "9.9.9"}),
    })
    blobs = {b.path: b for b in collect_binaries(tmp_path)}
    ssl = blobs["libssl.dll"].embedded
    assert [(e.name, e.version, e.method) for e in ssl] == [("openssl", "3.0.11", "version-info")]
    assert [(e.name, e.version) for e in blobs["numeric.dll"].embedded] == [("zlib", "1.2.13")]
    assert blobs["other.dll"].embedded == []
    assert blobs["libssl.dll"].product["ProductName"] == "OpenSSL"


def test_a_banner_beats_the_version_resource(tmp_path):
    _tree(tmp_path, {"c.dll": build_pe(dll=True, text=b"\0libcurl/8.4.0\0",
                                       version={"ProductName": "curl", "ProductVersion": "7.0.0"})})
    embedded = collect_binaries(tmp_path)[0].embedded
    assert [(e.name, e.version, e.method) for e in embedded] == [("curl", "8.4.0", "banner")]


def test_an_import_names_a_dependency_but_no_release(tmp_path):
    _tree(tmp_path, {"app.exe": build_pe(imports=["KERNEL32.dll", "libcurl-4.dll",
                                                  "libssl-3-x64.dll", "libcrypto-3-x64.dll"])})
    blob = collect_binaries(tmp_path)[0]
    assert [(e.name, e.version, e.method) for e in blob.embedded] == [
        ("curl", "", "imports"), ("openssl", "", "imports")]
    assert embedded_libraries(blob) == []
    assert "imports curl, OpenSSL" in describe_binary(blob) and "embeds" not in describe_binary(blob)


def test_pe_facts_are_kept_on_the_inventory_entry(tmp_path):
    _tree(tmp_path, {"app.exe": build_pe(pdb=r"D:\b\app.pdb", signed=True, clr=True,
                                         version={"ProductName": "App", "FileVersion": "2.0"})})
    blob = collect_binaries(tmp_path)[0]
    assert (blob.pdb, blob.signed, blob.runtime) == (r"D:\b\app.pdb", True, "dotnet")
    assert blob.toolchain is None                       # a runtime is known: no linker number
    plain = build_pe()
    (tmp_path / "app.exe").write_bytes(plain)
    assert collect_binaries(tmp_path)[0].toolchain == "linker 14.38"
    assert blob.to_dict()["product"]["ProductName"] == "App"


# -- scan and SBOM output --------------------------------------------------------------------

def _scan(tmp, rules_dir):
    return scan(tmp, load_rules(rules_dir, strict=True), None, ScanOptions())


def test_findings_say_what_each_kind_of_evidence_can_and_cannot_show(tmp_path, rules_dir):
    _tree(tmp_path, {
        "ssl.dll": build_pe(dll=True, version={"ProductName": "OpenSSL", "ProductVersion": "3.0.11"}),
        "app.exe": build_pe(imports=["libcurl-4.dll"]),
    })
    result = _scan(tmp_path, rules_dir)
    by_source = {f.version_source: f for f in result.findings if f.rule_id.startswith("binary/")}
    versioned = by_source["binary-version-info"]
    assert versioned.version == "3.0.11"
    assert "version resource" in versioned.evidence[0].summary
    # An import is weak evidence: it goes to the "possible" tier, not the confirmed list.
    imported = next(f for f in result.possible if f.evidence
                    and "needs the library at run time" in f.evidence[0].summary)
    assert imported.version is None and imported.identity_confidence < versioned.identity_confidence
    assert not any(f.version_source == "unknown" and f.rule_id == "binary/curl"
                   for f in result.findings)
    assert "not part of this one" in imported.evidence[0].summary


def test_sboms_do_not_call_an_import_an_embedded_library(tmp_path, rules_dir):
    _tree(tmp_path, {"app.exe": build_pe(imports=["libcurl-4.dll"], pdb="a.pdb", signed=True)})
    result = _scan(tmp_path, rules_dir)
    comp = next(c for c in to_cyclonedx(result)["components"] if c["name"] == "app.exe")
    props = {(p["name"], p["value"]) for p in comp["properties"]}
    assert ("gangmu:importedLibrary", "curl") in props
    assert not any(n == "gangmu:embeddedLibrary" for n, _ in props)
    assert ("gangmu:pdbPath", "a.pdb") in props
    assert ("gangmu:authenticodeSigned", "true") in props
    spdx = json.dumps(to_spdx(result))
    assert "imports curl" in spdx and "embeds curl" not in spdx
