""".NET assemblies and ``.deps.json``: what they say about dependencies, and no more."""

import json
from pathlib import Path

from pebuild import build_pe, dotnet_metadata

from gangmu.binaries import collect_binaries, describe_binary, embedded_libraries
from gangmu.dotnet import is_framework, parse_dotnet, read_deps_json
from gangmu.pe import parse_pe
from gangmu.rules.loader import load_rules
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.scan import ScanOptions, scan

REFS = [("netstandard", (2, 0, 0, 0)), ("System.Memory", (4, 0, 1, 2)),
        ("Newtonsoft.Json", (13, 0, 0, 0)), ("Microsoft.Extensions.Logging", (8, 0, 0, 0))]


def _parse(meta: bytes, dll: bool = True):
    data = build_pe(dll=dll, clr=meta)
    return parse_dotnet(data, parse_pe(data))


# -- the metadata reader ---------------------------------------------------------------------

def test_assembly_identity_and_references_are_read():
    info = _parse(dotnet_metadata("My.Lib", (2, 1, 0, 7), REFS))
    assert (info.name, info.version, info.runtime) == ("My.Lib", "2.1.0.7", "v4.0.30319")
    assert [(r.name, r.version) for r in info.references] == [
        ("netstandard", "2.0.0.0"), ("System.Memory", "4.0.1.2"),
        ("Newtonsoft.Json", "13.0.0.0"), ("Microsoft.Extensions.Logging", "8.0.0.0")]


def test_framework_assemblies_are_not_third_party():
    info = _parse(dotnet_metadata("My.Lib", refs=REFS))
    assert [r.name for r in info.third_party_references()] == [
        "Newtonsoft.Json", "Microsoft.Extensions.Logging"]
    assert is_framework("mscorlib") and is_framework("System.Runtime")
    assert not is_framework("Systemic.Thing") and not is_framework("Serilog")


def test_an_assembly_with_no_references_has_none():
    assert _parse(dotnet_metadata("Solo")).references == []


def test_a_wide_coded_index_moves_the_tables_after_it():
    # 9000 TypeRef rows (6 bytes: 2-byte ResolutionScope, two 2-byte string indexes) make the
    # MemberRefParent index 4 bytes wide (a table >= 2^13 rows), so each of the five MemberRef
    # rows is 4 + 2 (name) + 2 (signature) = 8 bytes. AssemblyRef comes after both.
    wide = {1: (9000, b"\0" * (9000 * 6)), 0x0A: (5, b"\0" * (5 * 8))}
    assert [r.name for r in _parse(dotnet_metadata("A", refs=REFS, extra_tables=wide)).references
            ] == [n for n, _ in REFS]
    # With only 100 TypeRef rows the same MemberRef rows are 2 + 2 + 2 = 6 bytes.
    narrow = {1: (100, b"\0" * 600), 0x0A: (5, b"\0" * (5 * 6))}
    assert [r.name for r in _parse(dotnet_metadata("A", refs=REFS, extra_tables=narrow)).references
            ] == [n for n, _ in REFS]


def test_a_wide_plain_index_moves_the_tables_after_it():
    # 70000 Field rows (2 flags + 2 name + 2 signature = 6 bytes) make a TypeDef's FieldList
    # index 4 bytes: 4 flags + 2 + 2 + 2 (Extends) + 4 (FieldList) + 2 (MethodList) = 16.
    wide = {2: (3, b"\0" * (3 * 16)), 4: (70000, b"\0" * (70000 * 6))}
    info = _parse(dotnet_metadata("Big", (3, 2, 1, 0), REFS, extra_tables=wide))
    assert info.name == "Big" and [r.name for r in info.references] == [n for n, _ in REFS]


def test_four_byte_string_indexes_are_followed():
    info = _parse(dotnet_metadata("Wide.Strings", (1, 2, 3, 4), REFS, wide_strings=True))
    assert info.name == "Wide.Strings" and info.version == "1.2.3.4"
    assert [r.name for r in info.references] == [n for n, _ in REFS]


def test_what_is_not_valid_metadata_gives_none():
    good = dotnet_metadata("X", refs=REFS)
    assert _parse(b"BSJB" + b"\0" * 60) is None
    assert _parse(good.replace(b"BSJB", b"XXXX", 1)) is None
    assert _parse(good[:30]) is None
    plain = build_pe()
    assert parse_dotnet(plain, parse_pe(plain)) is None            # not a managed file at all
    huge = bytearray(good)
    huge[12:16] = (10**6).to_bytes(4, "little")                    # absurd version-string length
    assert _parse(bytes(huge)) is None


# -- deps.json -------------------------------------------------------------------------------

DEPS = {
    "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/win-x64"},
    "libraries": {
        "App/1.0.0": {"type": "project", "serviceable": False},
        "Newtonsoft.Json/13.0.3": {"type": "package", "sha512": "sha512-x"},
        "Serilog/3.1.1": {"type": "package"},
        "runtimepack.Microsoft.NETCore.App.Runtime.win-x64/8.0.1": {"type": "runtimepack"},
        "System.Private.CoreLib/8.0.0": {"type": "reference"},
    },
}


def test_deps_json_lists_packages_and_the_bundled_runtime(tmp_path):
    path = tmp_path / "app.deps.json"
    path.write_text(json.dumps(DEPS))
    got = [(p.name, p.version, p.kind) for p in read_deps_json(path)]
    assert got == [
        ("Newtonsoft.Json", "13.0.3", "package"), ("Serilog", "3.1.1", "package"),
        ("runtimepack.Microsoft.NETCore.App.Runtime.win-x64", "8.0.1", "runtimepack")]


def test_a_broken_or_foreign_deps_json_gives_none(tmp_path):
    for text in ("not json", "[]", '{"libraries": []}', "{}"):
        path = tmp_path / "x.deps.json"
        path.write_text(text)
        assert read_deps_json(path) is None
    assert read_deps_json(tmp_path / "missing.deps.json") is None


def test_a_bom_in_deps_json_is_tolerated(tmp_path):
    path = tmp_path / "app.deps.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(DEPS).encode())
    assert len(read_deps_json(path)) == 3


# -- the inventory ---------------------------------------------------------------------------

def _tree(tmp: Path, files: dict) -> Path:
    for name, data in files.items():
        path = tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    return tmp


def test_packages_from_deps_json_are_exact_and_attached_to_the_executable(tmp_path):
    _tree(tmp_path, {"bin/app.exe": build_pe(clr=dotnet_metadata("App")),
                     "bin/app.dll": build_pe(dll=True, clr=dotnet_metadata("App")),
                     "bin/app.deps.json": DEPS})
    blobs = {b.path: b for b in collect_binaries(tmp_path)}
    exe = {(e.name, e.version, e.purl) for e in blobs["bin/app.exe"].embedded}
    assert ("Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3") in exe
    assert ("Microsoft.NETCore.App.Runtime.win-x64", "8.0.1",
            "pkg:nuget/Microsoft.NETCore.App.Runtime.win-x64@8.0.1") in exe
    assert len(exe) == 3                                   # no project, no reference entries
    assert all(e.method != "deps-json" for e in blobs["bin/app.dll"].embedded)


def test_a_library_alone_gets_its_own_deps_json(tmp_path):
    _tree(tmp_path, {"lib.dll": build_pe(dll=True, clr=dotnet_metadata("Lib")),
                     "lib.deps.json": DEPS})
    assert len([e for e in collect_binaries(tmp_path)[0].embedded if e.method == "deps-json"]) == 3


def test_references_are_dependencies_not_embedded_code(tmp_path):
    _tree(tmp_path, {"app.exe": build_pe(clr=dotnet_metadata("App", refs=REFS))})
    blob = collect_binaries(tmp_path)[0]
    assert [(e.name, e.version, e.method) for e in blob.embedded] == [
        ("Newtonsoft.Json", "", "dotnet-reference"),
        ("Microsoft.Extensions.Logging", "", "dotnet-reference")]
    assert embedded_libraries(blob) == []
    assert "imports Newtonsoft.Json" in describe_binary(blob)
    assert blob.product["AssemblyName"] == "App" and blob.runtime == "dotnet"


def test_a_managed_dll_with_a_package_version_is_a_candidate_only_as_a_library(tmp_path):
    info = {"ProductName": "Json.NET", "ProductVersion": "13.0.3+0a2e291c0d9c0c7675d445703e51750363a549ef"}
    _tree(tmp_path, {"Newtonsoft.Json.dll": build_pe(dll=True, version=info,
                                                     clr=dotnet_metadata("Newtonsoft.Json", (13, 0, 0, 0))),
                     "Tool.exe": build_pe(version=info, clr=dotnet_metadata("Tool", (1, 0, 0, 0)))})
    blobs = {b.path: b for b in collect_binaries(tmp_path)}
    embedded = [(e.name, e.version, e.method, e.purl) for e in blobs["Newtonsoft.Json.dll"].embedded]
    assert embedded == [("Newtonsoft.Json", "13.0.3", "dotnet-assembly",
                         "pkg:nuget/Newtonsoft.Json@13.0.3")]
    assert blobs["Tool.exe"].embedded == []                 # a program is the product, not a package


def test_a_framework_dll_is_not_offered_as_a_package(tmp_path):
    _tree(tmp_path, {"System.Thing.dll": build_pe(
        dll=True, version={"ProductVersion": "8.0.1+abc"},
        clr=dotnet_metadata("System.Thing", (8, 0, 0, 0)))})
    assert collect_binaries(tmp_path)[0].embedded == []


# -- scan and SBOM output --------------------------------------------------------------------

def test_findings_rank_the_three_kinds_of_dotnet_evidence_differently(tmp_path, rules_dir):
    _tree(tmp_path, {
        "app/app.exe": build_pe(clr=dotnet_metadata("App", refs=REFS)),
        "app/app.deps.json": DEPS,
        "lib/Serilog.dll": build_pe(dll=True, version={"ProductVersion": "3.1.1+abc"},
                                    clr=dotnet_metadata("Serilog", (2, 0, 0, 0))),
    })
    result = scan(tmp_path, load_rules(rules_dir, strict=True), None, ScanOptions())
    sidecar = next(f for f in result.findings
                   if f.upstream_name == "Newtonsoft.Json" and f.version == "13.0.3")
    assert (sidecar.version_source, sidecar.identity_confidence) == ("binary-sidecar", 0.85)
    assert sidecar.purl == "pkg:nuget/Newtonsoft.Json@13.0.3"
    assert "separate file" in sidecar.evidence[0].summary
    possible = {(f.upstream_name, f.version, f.purl): f for f in result.possible}
    ref = possible[("Newtonsoft.Json", None, "pkg:nuget/Newtonsoft.Json")]
    assert "assembly version" in ref.evidence[0].summary and ref.identity_confidence == 0.5
    cand = possible[("Serilog", "3.1.1", "pkg:nuget/Serilog@3.1.1")]
    assert "confirm" in cand.evidence[0].summary
    comp = next(c for c in to_cyclonedx(result)["components"] if c["name"] == "app/app.exe")
    props = {(p["name"], p["value"]) for p in comp["properties"]}
    assert ("gangmu:importedLibrary", "Newtonsoft.Json") in props
    # deps.json packages are separate DLLs beside the program: a dependency, not embedded
    assert ("gangmu:declaredDependency", "Newtonsoft.Json 13.0.3") in props
    assert not any(n == "gangmu:embeddedLibrary" for n, _ in props)


def test_a_managed_dll_naming_itself_is_not_said_to_embed_itself(tmp_path, rules_dir):
    info = {"ProductName": "BACnet", "ProductVersion": "4.0.0+abc"}
    _tree(tmp_path, {"BACnet.dll": build_pe(dll=True, version=info,
                                            clr=dotnet_metadata("BACnet", (4, 0, 0, 0)))})
    blob = collect_binaries(tmp_path)[0]
    assert embedded_libraries(blob) == []
    assert "identifies itself as BACnet 4.0.0" in describe_binary(blob)
    assert "embeds" not in describe_binary(blob)
    result = scan(tmp_path, load_rules(rules_dir, strict=True), None, ScanOptions())
    comp = next(c for c in to_cyclonedx(result)["components"] if c["name"] == "BACnet.dll")
    props = {(p["name"], p["value"]) for p in comp["properties"]}
    assert ("gangmu:identifiedAs", "BACnet 4.0.0") in props
    assert not any(n == "gangmu:embeddedLibrary" for n, _ in props)


def test_deps_json_packages_are_listed_as_dependencies_not_as_embedded(tmp_path):
    _tree(tmp_path, {"app.exe": build_pe(clr=dotnet_metadata("App")), "app.deps.json": DEPS})
    blob = collect_binaries(tmp_path)[0]
    assert embedded_libraries(blob) == []
    text = describe_binary(blob)
    assert "lists as dependencies in its deps.json" in text and "Newtonsoft.Json 13.0.3" in text
    assert "embeds" not in text


def test_a_long_dependency_list_is_cut_in_the_description(tmp_path):
    deps = {"libraries": {f"Pkg{i}/1.0.{i}": {"type": "package"} for i in range(20)}}
    _tree(tmp_path, {"app.exe": build_pe(clr=dotnet_metadata("App")), "app.deps.json": deps})
    assert "and 12 more" in describe_binary(collect_binaries(tmp_path)[0])
