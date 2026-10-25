"""Function-level evidence from the link map and the linked ELF."""

import json
import shutil
import subprocess

import pytest

from gangmu.build.linkmap import parse_function_sections
from gangmu.cli import main
from gangmu.image import ImageFunctions, load_image
from gangmu.reach import apply_image, assess, build_graph

from test_reach import _db, _sbom, _tree

MAP = """\
Archive member included to satisfy reference by file (symbol)

Discarded input sections

 .text.vuln_cb
                0x0000000000000000       0x24 CMakeFiles/fw.dir/lwip/core.c.obj
 .text.helper_a
                0x0000000000000000       0x10 CMakeFiles/fw.dir/lwip/other.c.obj
 .text          0x0000000000000000        0x0 CMakeFiles/fw.dir/lwip/core.c.obj
 .data.vuln_cb  0x0000000000000000        0x4 CMakeFiles/fw.dir/lwip/core.c.obj

Memory Configuration

Linker script and memory map

 .text.helper_a
                0x0000000008000200       0x1c CMakeFiles/fw.dir/lwip/core.c.obj
                0x0000000008000200                helper_a
 .text.main     0x0000000008000300       0x20 esp-idf/app/libapp.a(main.c.obj)
 .text.empty    0x0000000008000400        0x0 CMakeFiles/fw.dir/lwip/core.c.obj
"""


def _map(tmp_path):
    p = tmp_path / "fw.map"
    p.write_text(MAP)
    return p


def test_map_lists_kept_and_discarded_functions(tmp_path):
    got = parse_function_sections(_map(tmp_path))
    assert got.discarded == {"vuln_cb": {"core.c.obj"}, "helper_a": {"other.c.obj"}}
    assert got.kept == {"helper_a": {"core.c.obj"}, "main": {"main.c.obj"}}   # zero size: none


def test_a_map_without_function_sections_says_nothing(tmp_path):
    p = tmp_path / "plain.map"
    p.write_text("Discarded input sections\n\n .text   0x0 0x10 a.o\n\nMemory Configuration\n")
    assert not parse_function_sections(p)
    assert load_image(p).notes and not load_image(p).informative()


def test_two_static_functions_of_one_name_are_told_apart_by_object(tmp_path):
    image = load_image(_map(tmp_path))
    # helper_a: kept from core.c, discarded from other.c
    assert image.state("helper_a", {"core"})[0] == "linked"
    assert image.state("helper_a", {"other"})[0] == "discarded"
    assert image.state("vuln_cb", {"core"})[0] == "discarded"
    assert image.state("never_seen", {"core"})[0] == "unknown"
    # no stem matches anywhere: every copy counts, so a kept one wins
    assert image.state("helper_a", {"elsewhere"})[0] == "linked"


def test_symbols_are_a_weaker_witness_for_absence():
    image = ImageFunctions(symbols={"present"})
    assert image.state("present")[0] == "linked"
    assert image.state("gone")[0] == "absent-from-symbols"


def test_discarded_beats_the_call_graph(tmp_path):
    graph = build_graph(_tree(tmp_path))
    image = load_image(_map(tmp_path))
    reach = assess(graph, "lwip", ["vuln_cb"], "curated")
    assert reach.status == "reachable"                       # a table mentions it
    apply_image(reach, image, graph, "lwip")
    assert reach.status == "discarded" and reach.image == "discarded"
    assert "inlined" in reach.detail

    kept = assess(graph, "lwip", ["vuln_parse"], "curated")   # no map entry
    apply_image(kept, image, graph, "lwip")
    assert kept.status == "unreachable" and kept.image == "unknown"

    both = assess(graph, "lwip", ["vuln_cb", "vuln_parse"], "curated")
    apply_image(both, ImageFunctions(symbols={"vuln_parse"}), graph, "lwip")
    assert both.image == "linked" and both.status == "reachable"


def _run(tmp_path, capsys, *extra):
    db = _db(tmp_path, {"CVE-2021-0002": "bug in `vuln_cb()`"})
    assert main(["vuln", str(_sbom(tmp_path)), "--db", str(db), "--format", "json",
                 "--source", str(_tree(tmp_path)), *extra]) == 0
    return json.loads(capsys.readouterr().out)["matches"][0]


def test_cli_reports_and_only_rules_out_when_told(tmp_path, capsys):
    got = _run(tmp_path, capsys, "--link-map", str(_map(tmp_path)))
    assert got["reachability"]["status"] == "discarded"
    assert got["reachability"]["image"] == "discarded"
    assert got["state"] == "exploitable"

    second = tmp_path / "second"
    second.mkdir()
    got = _run(second, capsys, "--link-map", str(_map(tmp_path)), "--reachability-vex")
    assert got["state"] == "not_affected"


def test_cli_vex_names_code_not_present(tmp_path, capsys):
    db = _db(tmp_path, {"CVE-2021-0002": "bug in `vuln_cb()`"})
    assert main(["vuln", str(_sbom(tmp_path)), "--db", str(db), "--format", "cyclonedx",
                 "--source", str(_tree(tmp_path)), "--link-map", str(_map(tmp_path)),
                 "--reachability-vex"]) == 0
    vuln = json.loads(capsys.readouterr().out)["vulnerabilities"][0]
    assert vuln["analysis"]["justification"] == "code_not_present"
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["gangmu:reachabilityImage"] == "discarded"


def test_image_flags_need_source(tmp_path, capsys):
    db = _db(tmp_path, {"CVE-2021-0002": "bug in `vuln_cb()`"})
    assert main(["vuln", str(_sbom(tmp_path)), "--db", str(db),
                 "--link-map", str(_map(tmp_path))]) == 2
    assert "--source" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
def test_elf_symbol_table_shows_a_function_is_in_the_image(tmp_path):
    src = tmp_path / "a.c"
    src.write_text("int kept_fn(int x){return x*3;}\nint main(void){return kept_fn(2);}\n")
    out = tmp_path / "a.elf"
    subprocess.run(["gcc", "-O0", "-o", str(out), str(src)], check=True)
    image = load_image(elf=out)
    assert image.state("kept_fn")[0] == "linked"
    assert image.state("vuln_cb")[0] == "absent-from-symbols"
    subprocess.run(["strip", str(out)], check=True)
    stripped = load_image(elf=out)
    assert stripped.symbols is None and stripped.notes
