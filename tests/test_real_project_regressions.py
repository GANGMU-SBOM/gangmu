"""Problems found by scanning ST's STM32CubeF1 LwIP echo-server project.

Each test pins one of them: IAR project paths given relative, a ``.cproject``
passed as a file, cross compilers the wrapper did not shim, empty build facts,
and objects that ``--gc-sections`` left with nothing in the image.
"""

import os
import stat
from pathlib import Path

import pytest

from gangmu.build.facts import collect_build_facts
from gangmu.build.linkmap import parse_link_map
from gangmu.build.projects import parse_project
from gangmu.build.wrap import default_compilers
from gangmu.cli import main

EWP = """<?xml version="1.0" encoding="UTF-8"?>
<project>
  <configuration><name>Debug</name></configuration>
  <group><name>User</name>
    <file><name>$PROJ_DIR$\\..\\Src\\main.c</name></file>
    <file><name>$PROJ_DIR$\\..\\..\\lib\\core.c</name></file>
  </group>
</project>
"""


def _iar_tree(tmp_path: Path) -> Path:
    (tmp_path / "app" / "EWARM").mkdir(parents=True)
    (tmp_path / "app" / "Src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "app" / "Src" / "main.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "lib" / "core.c").write_text("int core(void){return 1;}\n")
    ewp = tmp_path / "app" / "EWARM" / "Project.ewp"
    ewp.write_text(EWP)
    return ewp


# ------------------------------------------------ IAR project given relative

def test_iar_project_path_may_be_relative(tmp_path, monkeypatch):
    ewp = _iar_tree(tmp_path)
    monkeypatch.chdir(tmp_path)
    relative = ewp.relative_to(tmp_path)
    parsed = parse_project(relative)
    assert sorted(p.name for p in parsed.sources) == ["core.c", "main.c"]
    assert all(p.is_file() for p in parsed.sources)
    assert parsed.sources == parse_project(ewp).sources


def test_a_project_whose_sources_are_all_missing_is_an_error(tmp_path):
    ewp = _iar_tree(tmp_path)
    (tmp_path / "app" / "Src" / "main.c").unlink()
    (tmp_path / "lib" / "core.c").unlink()
    with pytest.raises(ValueError, match="none of the 2 source files"):
        parse_project(ewp)


def test_a_project_with_some_sources_missing_says_so(tmp_path):
    ewp = _iar_tree(tmp_path)
    (tmp_path / "lib" / "core.c").unlink()
    parsed = parse_project(ewp)
    assert any("1 of 2 source files" in n for n in parsed.notes)


# ------------------------------------------------ .cproject as a file

def test_a_cproject_file_can_be_passed_directly(tmp_path):
    proj = tmp_path / "ide"
    proj.mkdir()
    (proj / "main.c").write_text("int main(void){return 0;}\n")
    (proj / ".cproject").write_text("<cproject></cproject>\n")
    from_file = parse_project(proj / ".cproject")
    from_dir = parse_project(proj)
    assert from_file.kind == "ccs"
    assert [p.name for p in from_file.sources] == ["main.c"]
    assert from_file.sources == from_dir.sources


# ------------------------------------------------ cross compilers

def _fake_bin(tmp_path: Path, *names: str) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in names:
        f = bindir / name
        f.write_text("#!/bin/sh\n")
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    return bindir


def test_default_compilers_include_cross_compilers_on_path(tmp_path):
    bindir = _fake_bin(tmp_path, "arm-none-eabi-gcc", "riscv64-unknown-elf-g++",
                       "arm-none-eabi-objdump", "make")
    names = default_compilers(str(bindir))
    assert names[:5] == ["cc", "gcc", "g++", "clang", "clang++"]
    assert "arm-none-eabi-gcc" in names
    assert "riscv64-unknown-elf-g++" in names
    assert "arm-none-eabi-objdump" not in names
    assert "make" not in names


def test_default_compilers_without_cross_compilers_is_the_plain_list(tmp_path):
    bindir = _fake_bin(tmp_path, "make")
    assert default_compilers(str(bindir)) == ["cc", "gcc", "g++", "clang",
                                              "clang++"]


# ------------------------------------------------ empty build facts

def test_scan_refuses_a_compile_database_with_nothing_under_the_root(
        project_dir, rules_dir, tmp_path, capsys):
    db = tmp_path / "cc.json"
    db.write_text("[]")
    code = main(["scan", str(project_dir), "--rules", str(rules_dir),
                 "--compile-db", str(db)])
    assert code == 2
    assert "lists no source file" in capsys.readouterr().err


# ------------------------------------------------ gc-sections in a GNU map

GNU_GC_MAP = """\
Archive member included to satisfy reference by file (symbol)

/opt/gcc/libgcc.a(_udivsi3.o)
                              b/kept.c.o (__aeabi_uidiv)
/opt/gcc/libc.a(strlen.o)
                              b/collected.c.o (strlen)

Discarded input sections

 .text          0x00000000        0x0 b/collected.c.o
 .text.unused   0x00000000       0x40 b/collected.c.o
 .text.unused   0x00000000       0x20 b/kept.c.o

Memory Configuration

Name             Origin             Length             Attributes
FLASH            0x08000000         0x00040000         xr

Linker script and memory map

LOAD b/kept.c.o
LOAD b/collected.c.o
LOAD b/empty_sections.c.o
LOAD /opt/gcc/libgcc.a

.text           0x08000000      0x100
 .text.main     0x08000000       0x80 b/kept.c.o
 .text.helper
                0x08000080       0x40 b/kept.c.o
 .text.nothing  0x080000c0        0x0 b/empty_sections.c.o

.data           0x20000000       0x10
 .data.x        0x20000000       0x10 b/kept.c.o

.comment        0x00000000       0x27
 .comment       0x00000000       0x27 b/collected.c.o
 .comment       0x00000027       0x27 b/empty_sections.c.o

.ARM.attributes
                0x00000000       0x2d
 .ARM.attributes
                0x00000000       0x2d b/collected.c.o
"""


def test_objects_that_left_nothing_in_the_image_are_not_linked(tmp_path):
    path = tmp_path / "fw.map"
    path.write_text(GNU_GC_MAP)
    lmap = parse_link_map(path)
    assert lmap.objects == {"kept.c.o"}
    assert lmap.discarded_only == {"collected.c.o"}
    assert "collected.c.o" not in lmap.linked_object_names
    assert "empty_sections.c.o" not in lmap.linked_object_names


def test_a_map_without_contributions_keeps_every_named_object(tmp_path):
    path = tmp_path / "fw.map"
    path.write_text("Linker script and memory map\n\nLOAD b/a.o\nLOAD b/b.o\n")
    assert parse_link_map(path).objects == {"a.o", "b.o"}


def test_lto_objects_keep_everything_named(tmp_path):
    path = tmp_path / "fw.map"
    path.write_text(
        "Linker script and memory map\n\n"
        "LOAD b/a.c.o\nLOAD b/b.c.o\n\n"
        ".text           0x08000000      0x100\n"
        " .text          0x08000000      0x100 /tmp/ccXYZ.ltrans0.ltrans.o\n")
    objects = parse_link_map(path).objects
    assert {"a.c.o", "b.c.o"} <= objects


def test_build_facts_drop_the_gc_collected_object(tmp_path):
    root = tmp_path
    for name in ("kept", "collected"):
        (root / f"{name}.c").write_text(f"int {name}(void){{return 1;}}\n")
    import json
    db = [{"directory": str(root), "file": f"{name}.c",
           "output": f"b/{name}.c.o", "arguments": ["gcc", "-c", f"{name}.c"]}
          for name in ("kept", "collected")]
    (root / "cc.json").write_text(json.dumps(db))
    (root / "fw.map").write_text(GNU_GC_MAP)
    facts = collect_build_facts(root, root / "cc.json", root / "fw.map")
    assert {p.name for p in facts.linked} == {"kept.c"}
    assert {p.name for p in facts.dropped} == {"collected.c"}


def test_a_relative_cproject_resolves_linked_resources(tmp_path, monkeypatch):
    sdk = tmp_path / "sdk"
    ide = tmp_path / "app" / "ide"
    sdk.mkdir()
    ide.mkdir(parents=True)
    (sdk / "startup.c").write_text("void start(void){}\n")
    (ide / ".cproject").write_text("<cproject></cproject>\n")
    (ide / ".project").write_text(
        "<projectDescription><linkedResources><link><name>startup.c</name>"
        "<type>1</type><location>PARENT-2-PROJECT_LOC/sdk/startup.c</location>"
        "</link></linkedResources></projectDescription>\n")
    monkeypatch.chdir(tmp_path)
    parsed = parse_project(Path("app/ide/.cproject"))
    assert [p.name for p in parsed.sources] == ["startup.c"]
    assert parsed.sources[0].is_file()
