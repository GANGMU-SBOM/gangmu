"""Conditional compilation: which branches the build configuration rules out."""

import json

from gangmu.cli import main
from gangmu.ifdef import Macros, collect_tree_defines, evaluate, find_config_headers, strip_inactive
from gangmu.reach import assess, build_graph


def _macros(**kconfig):
    m = Macros()
    m.add_kconfig(kconfig)
    return m


def test_expressions_are_three_valued():
    m = _macros(A="y", B="n", N="3")
    assert evaluate("defined(CONFIG_A) && !defined(CONFIG_B)", m) == 1
    assert evaluate("CONFIG_B || 0", m) == 0
    assert evaluate("CONFIG_N >= 3 && CONFIG_N < 4", m) == 1
    assert evaluate("IS_ENABLED(CONFIG_A)", m) == 1
    assert evaluate("IS_ENABLED(CONFIG_B)", m) == 0
    # an unknown name keeps the answer unknown unless the other side decides
    assert evaluate("TOOLCHAIN_FLAG", m) is None
    assert evaluate("TOOLCHAIN_FLAG && 0", m) == 0
    assert evaluate("TOOLCHAIN_FLAG || 1", m) == 1
    assert evaluate("__has_include(<x.h>)", m) is None
    assert evaluate("1 +", m) is None


def test_assume_undefined_makes_unknown_names_off():
    m = Macros(assume_undefined=True)
    assert evaluate("defined(MBEDTLS_X)", m) == 0
    assert evaluate("MBEDTLS_X", m) == 0


def test_dead_branches_are_blanked_and_line_numbers_kept():
    src = (b"int a(void){return 1;}\n"
           b"#if 0\nint dead0(void){return 2;}\n#endif\n"
           b"#ifdef CONFIG_B\nint deadb(void){return 3;}\n"
           b"#elif defined(CONFIG_A)\nint livea(void){return 4;}\n"
           b"#else\nint deadelse(void){return 5;}\n#endif\n"
           b"#if UNKNOWN\nint maybe(void){return 6;}\n#else\nint maybe2(void){return 7;}\n#endif\n")
    out, n = strip_inactive(src, _macros(A="y", B="n"))
    text = out.decode()
    assert out.count(b"\n") == src.count(b"\n")
    for kept in ("a(void)", "livea", "maybe(", "maybe2"):
        assert kept in text
    for gone in ("dead0", "deadb", "deadelse"):
        assert gone not in text
    assert n >= 3


def test_nested_and_commented_conditions():
    src = (b"#ifdef CONFIG_B\n#ifdef OTHER\nint x1(void){}\n#else\nint x2(void){}\n#endif\n"
           b"int x3(void){}\n#endif\n"
           b"/*\n#if 1\n#endif\n*/\n"
           b"#if 0 /* off */ \\\n  || 0\nint y1(void){}\n#endif\n"
           b"int z(void){}\n")
    out, _ = strip_inactive(src, _macros(B="n"))
    text = out.decode()
    assert "x1" not in text and "x2" not in text and "x3" not in text and "y1" not in text
    assert "z(void)" in text


def test_only_named_config_headers_make_a_name_defined(tmp_path):
    (tmp_path / "config.h").write_text(
        "#ifndef CONFIG_H\n#define CONFIG_H\n#define FEATURE_ON 1\n"
        "#ifdef SOMETHING\n#define COND_ONLY 1\n#endif\n#endif\n")
    (tmp_path / "alt").mkdir()
    (tmp_path / "alt" / "config-small.h").write_text("#define ALT_ONLY 1\n#undef FEATURE_ON\n")
    m = Macros(assume_undefined=True)
    collect_tree_defines(tmp_path, m, [tmp_path / "config.h"])
    assert m.defined("CONFIG_H") is True
    assert m.defined("COND_ONLY") is None        # defined under an #if: unknown
    assert m.defined("ALT_ONLY") is None         # an alternative config: unknown
    assert m.defined("FEATURE_ON") is None       # #undef-ed elsewhere: unknown
    assert m.defined("NOWHERE") is False         # mentioned nowhere: off
    m = Macros()
    collect_tree_defines(tmp_path, m, [tmp_path / "config.h"])
    assert m.number("FEATURE_ON") is None


def test_config_header_value_and_alias(tmp_path):
    (tmp_path / "sdkconfig.h").write_text("#define CONFIG_A 1\n#define LEVEL CONFIG_A\n")
    m = Macros(assume_undefined=True)
    collect_tree_defines(tmp_path, m, [tmp_path / "sdkconfig.h"])
    assert evaluate("CONFIG_A == 1 && LEVEL", m) == 1


def test_flags_define_and_undefine():
    m = Macros()
    m.add_flags(["-DA", "-D", "B=2", "-UC", "-O2"])
    assert m.number("A") == 1 and m.number("B") == 2 and m.defined("C") is False


def _tree(tmp_path):
    root = tmp_path / "fw"
    (root / "app").mkdir(parents=True)
    (root / "lwip").mkdir()
    (root / "app" / "main.c").write_text(
        "int main(void) { lwip_init(); return 0; }\n")
    (root / "lwip" / "core.c").write_text(
        "int lwip_init(void) { return 0; }\n"
        "#if CONFIG_LWIP_FEATURE\n"
        "int vuln_parse(char *p) { return p[0]; }\n"
        "int caller(void) { return vuln_parse(0); }\n"
        "#endif\n")
    (root / "sdkconfig").write_text("# CONFIG_LWIP_FEATURE is not set\n")
    return root


def test_function_compiled_out_is_absent(tmp_path):
    root = _tree(tmp_path)
    plain = build_graph(root)
    assert assess(plain, "lwip", ["vuln_parse"], "curated").status == "unreachable"
    m = Macros()
    m.add_kconfig({"LWIP_FEATURE": "n"})
    graph = build_graph(root, m)
    got = assess(graph, "lwip", ["vuln_parse"], "advisory text")
    assert got.status == "absent" and "does not compile it" in got.detail
    assert graph.inactive_lines >= 2
    m.define("CONFIG_LWIP_FEATURE", "1")
    assert assess(build_graph(root, m), "lwip", ["vuln_parse"], "curated").status == "unreachable"


def test_vuln_command_reads_sdkconfig_from_source(tmp_path, capsys):
    root = _tree(tmp_path)
    feed = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-0001",
        "descriptions": [{"lang": "en", "value": "overflow in `vuln_parse()`"}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.2.0"}]}]}]}}]}
    db = tmp_path / "db"
    db.mkdir()
    (db / "nvd-2021.json").write_text(json.dumps(feed))
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{"type": "library", "name": "lwip", "version": "2.1.0",
                        "bom-ref": "lwip",
                        "cpe": "cpe:2.3:a:lwip_project:lwip:2.1.0:*:*:*:*:*:*:*",
                        "properties": [{"name": "gangmu:directory", "value": "lwip"}]}]}))
    args = ["vuln", str(sbom), "--db", str(db), "--format", "json", "--source", str(root)]
    assert main(args) == 0
    got = json.loads(capsys.readouterr().out)["matches"][0]
    assert got["reachability"]["status"] == "absent"
    # an explicit -D wins over the sdkconfig's absence of the option
    assert main(args + ["-D", "CONFIG_LWIP_FEATURE=1"]) == 0
    got = json.loads(capsys.readouterr().out)["matches"][0]
    assert got["reachability"]["status"] == "unreachable"


def test_generated_config_headers_are_found_and_used(tmp_path):
    root = _tree(tmp_path)
    (root / "sdkconfig").unlink()
    (root / "build").mkdir()
    (root / "build" / "sdkconfig.h").write_text("#define CONFIG_LWIP_FEATURE 0\n")
    assert [p.name for p in find_config_headers(root)] == ["sdkconfig.h"]
    m = Macros()
    collect_tree_defines(root, m, find_config_headers(root))
    graph = build_graph(root, m)
    assert assess(graph, "lwip", ["vuln_parse"], "curated").status == "absent"


def _db_for(root, entries):
    db = root / "compile_commands.json"
    db.write_text(json.dumps([
        {"directory": str(root), "file": str(root / f), "arguments": ["cc", *args, "-c", f]}
        for f, args in entries]))
    return db


def test_uncompiled_translation_units_and_per_file_flags(tmp_path):
    from gangmu.build.compile_db import load_compile_db
    root = tmp_path / "fw"
    (root / "lwip").mkdir(parents=True)
    (root / "lwip" / "core.c").write_text(
        "int lwip_init(void) { return 0; }\n"
        "#ifdef WITH_DEBUG\nint dbg_dump(void) { return 1; }\n#endif\n")
    (root / "lwip" / "ports.c").write_text("int vuln_port(void) { return 2; }\n")
    (root / "lwip" / "other.c").write_text("int lwip_other(void) { return 3; }\n")
    db = load_compile_db(_db_for(root, [("lwip/core.c", ["-DWITH_DEBUG"]),
                                        ("lwip/other.c", [])]))
    graph = build_graph(root, None, db)
    assert graph.compile_db_used and graph.uncompiled_files == 1
    assert assess(graph, "lwip", ["vuln_port"], "curated").status == "absent"
    assert "dbg_dump" in graph.defined               # -DWITH_DEBUG on core.c
    # without the flag the macro is merely unknown (a header may define it): kept
    db = load_compile_db(_db_for(root, [("lwip/core.c", ["-UWITH_DEBUG"]),
                                        ("lwip/other.c", [])]))
    graph = build_graph(root, None, db)
    assert assess(graph, "lwip", ["dbg_dump"], "curated").status == "absent"


def test_a_compile_database_from_another_machine_is_ignored(tmp_path):
    from gangmu.build.compile_db import CompileDB, CompileEntry
    from pathlib import Path
    root = tmp_path / "fw"
    root.mkdir()
    (root / "a.c").write_text("int fa(void) { return 1; }\n")
    db = CompileDB(entries=[CompileEntry(source=Path("/elsewhere/zzz.c"),
                                         directory=Path("/elsewhere"))])
    graph = build_graph(root, None, db)
    assert not graph.compile_db_used and "fa" in graph.defined
    # the same tree under another prefix still matches by relative path
    db = CompileDB(entries=[CompileEntry(source=Path("/ci/build/fw/a.c"),
                                         directory=Path("/ci/build"))])
    assert build_graph(root, None, db).compile_db_used


def test_vuln_command_with_a_compile_database(tmp_path, capsys):
    root = _tree(tmp_path)
    (root / "sdkconfig").unlink()
    (root / "lwip" / "port.c").write_text("int vuln_port(void) { return 2; }\n")
    cdb = _db_for(root, [("lwip/core.c", ["-DCONFIG_LWIP_FEATURE=1"]), ("app/main.c", [])])
    feed = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-0009",
        "descriptions": [{"lang": "en", "value": "overflow in `vuln_port()`"}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.2.0"}]}]}]}}]}
    db = tmp_path / "db"
    db.mkdir()
    (db / "nvd-2021.json").write_text(json.dumps(feed))
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{"type": "library", "name": "lwip", "version": "2.1.0",
                        "bom-ref": "lwip",
                        "cpe": "cpe:2.3:a:lwip_project:lwip:2.1.0:*:*:*:*:*:*:*",
                        "properties": [{"name": "gangmu:directory", "value": "lwip"}]}]}))
    args = ["vuln", str(sbom), "--db", str(db), "--format", "json", "--source", str(root)]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["matches"][0]["reachability"]["status"] \
        == "unreachable"
    assert main(args + ["--compile-db", str(cdb)]) == 0
    assert json.loads(capsys.readouterr().out)["matches"][0]["reachability"]["status"] \
        == "absent"
