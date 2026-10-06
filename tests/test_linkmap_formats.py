"""IAR ilink, Arm armlink and lld maps.

The fixtures are written by hand to the layouts the vendors document, not
captured from a real toolchain run; the parsers only rely on the section
headers and the object/module columns shown here.
"""
from pathlib import Path

from gangmu.build.facts import collect_build_facts
from gangmu.build.linkmap import detect_format, parse_link_map
from gangmu.build.projects import parse_project

IAR = """\
###############################################################################
#
# IAR ELF Linker V9.40.1.364/W64 for ARM
#
###############################################################################

*******************************************************************************
*** MODULE SUMMARY
***

    Module            ro code  ro data  rw data
    ------            -------  -------  -------
C:\\proj\\Debug\\Obj: [1]
    app.o                  32
    cJSON.o             4 096      120
    ---------------------------------------------
    Total:              4 128      120

command line/config: [2]
    ---------------------------------------------
    Total:

dl7M_tln.a: [3]
    exit.o                  4
    ---------------------------------------------
    Total:                  4

*******************************************************************************
*** ENTRY LIST
***

Entry                      Address   Size  Type      Object
-----                      -------   ----  ----      ------
main                    0x800'0100   0x20  Code  Gb  app.o [1]
"""

ARMLINK = """\
==============================================================================

Section Cross References

    startup.o(RESET) refers to main.o(.text) for main

==============================================================================

Removing Unused input sections from the image.

    Removing legacy.o(.text), (64 bytes).
    Removing legacy.o(.data), (4 bytes).
    Removing main.o(.data), (4 bytes).

3 unused section(s) (total 72 bytes) removed from the image.

==============================================================================

Image Symbol Table

    Symbol Name                              Value     Ov Type        Size  Object(Section)

    main                                     0x08000100   Thumb Code    20  main.o(.text)

==============================================================================

Memory Map of the image

  Image Entry point : 0x08000000

    Base Addr    Size         Type   Attr      Idx    E Section Name        Object

    0x08000000   0x0000000c   Data   RO            1    RESET               startup.o
    0x0800010c   0x00000014   Code   RO            2    .text               main.o
    0x08000120   0x00000020   Code   RO           10    .text               c_w.l(memcpya.o)

==============================================================================

Image component sizes


      Code (inc. data)   RO Data    RW Data    ZI Data      Debug   Object Name

        20          0          0          0          0        520   main.o
        12          0          0          0          0         88   startup.o

    ----------------------------------------------------------------------
        32          0          0          0          0        608   Object Totals

      Code (inc. data)   RO Data    RW Data    ZI Data      Debug   Library Member Name

        32          0          0          0          0         72   memcpya.o
"""

LLD = """\
             VMA              LMA     Size Align Out     In      Symbol
            1000             1000      40     4 .text
            1000             1000      20     4         /build/CMakeFiles/app.dir/main.c.obj:(.text.main)
            1020             1020      20     4         /build/lib/liblwip.a(init.c.obj):(.text.lwip_init)
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_formats_are_detected_from_the_file(tmp_path):
    assert detect_format(_write(tmp_path, "a.map", IAR)) == "iar"
    assert detect_format(_write(tmp_path, "b.map", ARMLINK)) == "armlink"
    assert detect_format(_write(tmp_path, "c.map", LLD)) == "gnu"


def test_iar_modules_are_grouped_by_the_file_they_came_from(tmp_path):
    lm = parse_link_map(_write(tmp_path, "a.map", IAR))
    assert {"app.o", "cJSON.o"} <= lm.objects
    assert ("dl7M_tln.a", "exit.o") in lm.members
    assert "dl7M_tln.a" in lm.archives
    # the ENTRY LIST section after the summary is not a module list
    assert "main" not in lm.linked_object_names


def test_armlink_keeps_listed_objects_and_notes_removed_sections(tmp_path):
    lm = parse_link_map(_write(tmp_path, "b.map", ARMLINK))
    assert {"main.o", "startup.o"} <= lm.objects
    assert ("c_w.l", "memcpya.o") in lm.members
    # legacy.o lost every section; main.o only lost .data and is still linked
    assert lm.discarded_only == {"legacy.o"}
    assert "legacy.o" not in lm.linked_object_names


def test_lld_maps_use_the_gnu_convention(tmp_path):
    lm = parse_link_map(_write(tmp_path, "c.map", LLD))
    assert ("/build/lib/liblwip.a", "init.c.obj") in lm.members
    assert "main.c.obj" in lm.objects


def test_iar_project_plus_iar_map_drops_the_unlinked_source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for n in ("app.c", "cJSON.c", "legacy.c"):
        (src / n).write_text("int x;\n")
    ewp = tmp_path / "app.ewp"
    ewp.write_text("""<?xml version="1.0"?><project>
<configuration><name>Debug</name></configuration>
<file><name>$PROJ_DIR$/src/app.c</name></file>
<file><name>$PROJ_DIR$/src/cJSON.c</name></file>
<file><name>$PROJ_DIR$/src/legacy.c</name></file>
</project>""")
    db = parse_project(ewp).to_compile_db()
    facts = collect_build_facts(tmp_path, link_map=_write(tmp_path, "a.map", IAR), db=db)
    assert facts.have_link_map
    linked = {p.name for p in facts.linked}
    assert linked == {"app.c", "cJSON.c"}
    assert {p.name for p in facts.dropped} == {"legacy.c"}


def test_gnu_object_names_still_join_to_ide_style_names(tmp_path):
    """init.c.obj in a CMake map and init.o from an IDE project are one stem."""
    src = tmp_path / "init.c"
    src.write_text("int x;\n")
    from gangmu.build.compile_db import CompileDB, CompileEntry
    db = CompileDB(entries=[CompileEntry(source=src.resolve(), directory=tmp_path,
                                         output=Path("init.o"), arguments=[])])
    m = _write(tmp_path, "g.map", "esp-idf/lwip/liblwip.a(init.c.obj)\n")
    facts = collect_build_facts(tmp_path, link_map=m, db=db)
    assert src.resolve() in facts.linked
