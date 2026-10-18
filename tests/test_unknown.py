"""Vendored code no rule names (gangmu.unknown)."""

import json
from pathlib import Path

from gangmu import unknown as u
from gangmu.cli import main
from gangmu.fnsig import FunctionSignature

MIT = """/*
 * Copyright (c) 2019 Jane Doe
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 */
"""
COMPANY = "/* Copyright (c) 2023 Acme Controls Co., Ltd. All rights reserved. */\n"


def _w(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _funcs(prefix: str, n: int, body: str = "return x + 1;") -> str:
    return "\n".join(f"int {prefix}_f{i}(int x)\n{{\n    {body}\n}}\n" for i in range(n))


def _project(root: Path, own_dir: str = "src"):
    """First-party code: main() and two modules that include the project's headers."""
    _w(root, "include/board.h", COMPANY + "#define BOARD_REV 2\n")
    _w(root, "include/app.h", COMPANY + "int app_run(void);\n")
    _w(root, f"{own_dir}/main.c", COMPANY + '#include "board.h"\n#include "app.h"\n#include "motor.h"\n'
                                            "int main(void)\n{\n    return app_run();\n}\n")
    _w(root, f"{own_dir}/motor.h", COMPANY + "int motor_f0(int x);\n")
    _w(root, f"{own_dir}/motor.c", COMPANY + '#include "motor.h"\n#include "board.h"\n#include "app.h"\n'
                                             + _funcs("motor", 4))
    _w(root, "CMakeLists.txt", "project(pmu C)\n")
    _w(root, "README.md", "# pmu\n")


def _lib(root: Path, d: str, prefix: str, header: str = MIT, license_file: bool = True):
    _w(root, f"{d}/{prefix}.h", header + f"#define {prefix.upper()}_VERSION \"1.2.3\"\nint {prefix}_f0(int x);\n")
    _w(root, f"{d}/{prefix}.c", header + f'#include "{prefix}.h"\n' + _funcs(prefix, 5))
    _w(root, f"{d}/{prefix}_util.c", header + f'#include "{prefix}.h"\n' + _funcs(f"{prefix}_util", 3))
    if license_file:
        _w(root, f"{d}/LICENSE", "MIT License\n\nCopyright (c) 2019 Jane Doe\n")


def _discover(root, known=()):
    return u.discover_unknown(root, known)


def test_vendored_directory_found_and_named(tmp_path):
    _project(tmp_path)
    _lib(tmp_path, "third_party/fooz-1.2.3", "fooz")
    c = _discover(tmp_path)
    assert [x.directory for x in c] == ["third_party/fooz-1.2.3"]
    assert c[0].name_hint == "fooz" and c[0].version_hint == "1.2.3"
    assert {"license", "container_child", "foreign_holder"} <= set(c[0].signals)


def test_sources_only_copy_under_neutral_directory(tmp_path):
    """No licence file, no container: holder, namespace and self-containment carry it."""
    _project(tmp_path)
    _lib(tmp_path, "src/fooz", "fooz", license_file=False)
    assert [x.directory for x in _discover(tmp_path)] == ["src/fooz"]


def test_files_dropped_beside_project_code(tmp_path):
    _project(tmp_path)
    _w(tmp_path, "src/barx.h", MIT + "int barx_f0(int x);\n")
    _w(tmp_path, "src/barx.c", MIT + '#include "barx.h"\n' + _funcs("barx", 5))
    c = _discover(tmp_path)
    assert len(c) == 1 and c[0].kind == "files"
    assert c[0].files == ["src/barx.c", "src/barx.h"] and c[0].name_hint == "barx"


def test_project_directory_holding_a_library_is_not_the_library(tmp_path):
    """Core/ = Src/ + Inc/ (first-party) + a library: the library, not Core/."""
    _project(tmp_path, own_dir="Core/Src")
    _lib(tmp_path, "Core/fooz", "fooz", license_file=False)
    assert [x.directory for x in _discover(tmp_path)] == ["Core/fooz"]


def test_first_party_alone_is_not_reported(tmp_path):
    _project(tmp_path)
    _w(tmp_path, "src/util/util.c", COMPANY + _funcs("util", 6))     # self-contained, own prefix
    assert _discover(tmp_path) == []


def test_components_found_are_subtracted(tmp_path):
    _project(tmp_path)
    _lib(tmp_path, "third_party/fooz", "fooz")
    assert _discover(tmp_path, [("third_party/fooz", [], "fooz")]) == []
    # found a level deeper, inside a directory named after it: still that component
    _w(tmp_path, "third_party/fooz/src/fooz_more.c", MIT + _funcs("fooz_more", 3))
    assert _discover(tmp_path, [("third_party/fooz/src", [], "fooz")]) == []


def test_component_found_as_files_leaves_its_neighbours(tmp_path):
    _project(tmp_path)
    _w(tmp_path, "src/mqttx.c", "/* Copyright (c) 2018 Liam B */\n" + _funcs("mqttx", 4))
    _lib(tmp_path, "src/fooz", "fooz", license_file=False)
    c = _discover(tmp_path, [("src", ["src/mqttx.c"], "mqttx")])
    assert [x.directory for x in c] == ["src/fooz"]


def test_holders():
    assert u._holder(b"/* (c) SEGGER Microcontroller GmbH */") == "segger microcontroller"
    assert u._holder(b"/* Copyright (c) 2009-2017 Dave Gamble and cJSON contributors */") == "dave gamble"
    assert u._holder(b"/* Armink, <armink.ztl@gmail.com>\n * Copyright (c) 2015, Armink, "
                     b"<armink.ztl@gmail.com> */") == "armink"
    assert u._holder(b"/* the above copyright notice ...\n SPDX-License-Identifier: MIT */") == "license:mit"


def test_version_hint_prefers_the_codes_own_macro(tmp_path):
    _w(tmp_path, "lib/fastz.h", "#define FASTZ_VERSION_MAJOR 0\n#define FASTZ_VERSION_MINOR 5\n"
                                "#define FASTZ_VERSION_REVISION 0\n")
    _w(tmp_path, "lib/fastz.c", _funcs("fastz", 4))
    for i in range(3):     # a tool beside it, declaring its own version in more files
        _w(tmp_path, f"lib/tool{i}.c", '#define SIXPACK_VERSION_STRING "0.1.0"\n')
    tree = u.read_tree(tmp_path)
    vers = [v for f in tree.files.values() for v in f.versions]
    assert u.pick_version(vers, __import__("collections").Counter({"fastz": 4})) == "0.5.0"
    assert u._versions(b"#define LZX_VERSION_MAJOR 1\n#define LZX_VERSION_MINOR 9\n"
                       b"#define LZX_VERSION_RELEASE 4\n") == [("lzx", "1.9.4")]
    assert u._versions(b"#define LFS_DISK_VERSION_MAJOR (0xffff & (LFS_DISK_VERSION >> 16))\n") == []


def _rules(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    sig = FunctionSignature.build([("1", {12345}, set())])
    (rules / "other.yaml").write_text(f"""id: test/other
component: {{path_globs: ['**/other'], ships_as: other}}
upstream:
  name: other
  cpe_status: 'none-in-nvd: test fixture'
  source: {{kind: git, url: 'https://example.invalid/other', ref: v1}}
identity:
  functions: {{file: other.fnsig, sha256: {sig.write(rules / "other.fnsig")}, count: 1, versions: ['1']}}
""")
    return rules


def test_scan_reports_them_outside_the_sbom(tmp_path):
    tree = tmp_path / "tree"
    _project(tree)
    _lib(tree, "third_party/fooz", "fooz")
    rules = _rules(tmp_path)
    out = tmp_path / "out.json"
    assert main(["scan", str(tree), "--rules", str(rules), "--format", "json", "-o", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["findings"] == []
    assert [(x["directory"], x["name_hint"], x["version_hint"]) for x in data["unknown"]] == [
        ("third_party/fooz", "fooz", "1.2.3")]
    assert main(["scan", str(tree), "--rules", str(rules), "--format", "json", "--no-unknown",
                 "-o", str(out)]) == 0
    assert json.loads(out.read_text())["unknown"] == []
    assert main(["scan", str(tree), "--rules", str(rules), "--format", "cyclonedx", "-o", str(out)]) == 0
    props = json.loads(out.read_text())["metadata"]["properties"]
    assert any(p["name"] == "gangmu:unknownThirdParty" and "fooz" in p["value"] for p in props)


def test_a_second_scan_reads_the_facts_from_the_cache(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    _project(tree)
    _lib(tree, "third_party/fooz", "fooz")
    rules = _rules(tmp_path)
    cache = tmp_path / "cache"
    out = tmp_path / "out.json"
    argv = ["scan", str(tree), "--rules", str(rules), "--format", "json", "--cache-dir", str(cache),
            "-o", str(out)]
    assert main(argv) == 0
    first = json.loads(out.read_text())["unknown"]
    assert first

    def boom(*a, **k):
        raise AssertionError("tokenised again")
    monkeypatch.setattr(u, "extract_functions", boom)
    assert main(argv) == 0
    assert json.loads(out.read_text())["unknown"] == first
