from gangmu.build.linkmap import parse_link_map

MAP = """
Archive member included to satisfy reference by file (symbol)

esp-idf/lwip/liblwip.a(init.c.obj)
                              esp-idf/main/libmain.a(app_main.c.obj) (lwip_init)
esp-idf/json/libjson.a(cJSON.c.obj)
                              esp-idf/main/libmain.a(app_main.c.obj) (cJSON_Parse)

Discarded input sections

 .text          0x0000000000000000       0x2a esp-idf/legacy/liblegacy.a(cJSON.c.obj)
 .text          0x0000000000000000       0x10 esp-idf/legacy/liblegacy.a(old.c.obj)

Memory Configuration

Linker script and memory map

 .text.lwip_init
                0x400d1000       0x40 esp-idf/lwip/liblwip.a(init.c.obj)
"""


def write(tmp_path):
    p = tmp_path / "firmware.map"
    p.write_text(MAP)
    return p


def test_kept_members_are_found(tmp_path):
    lm = parse_link_map(write(tmp_path))
    assert ("esp-idf/lwip/liblwip.a", "init.c.obj") in lm.members
    assert ("esp-idf/json/libjson.a", "cJSON.c.obj") in lm.members


def test_discarded_members_are_kept_separate(tmp_path):
    lm = parse_link_map(write(tmp_path))
    assert ("esp-idf/legacy/liblegacy.a", "cJSON.c.obj") in lm.discarded_members
    assert ("esp-idf/legacy/liblegacy.a", "cJSON.c.obj") not in lm.members


def test_shared_path_components_do_not_qualify(tmp_path):
    """esp-idf is common to every archive, so it must not act as a key."""
    lm = parse_link_map(write(tmp_path))
    assert ("esp-idf", "cJSON.c.obj") not in lm.qualified_keys()
    assert ("json", "cJSON.c.obj") in lm.qualified_keys()
    assert ("legacy", "cJSON.c.obj") in lm.discarded_keys()


def test_a_colliding_basename_is_both_kept_and_discarded(tmp_path):
    lm = parse_link_map(write(tmp_path))
    assert "cJSON.c.obj" in lm.linked_object_names
    assert "old.c.obj" in lm.discarded_only


TI_MAP = """\
******************************************************************************
                  TI ARM Linker PC v20.2.5
******************************************************************************
OUTPUT FILE NAME:   <app.out>

SECTION ALLOCATION MAP

 output                                  attributes/
section   page    origin      length       input sections
--------  ----  ----------  ----------   ----------------
.intvecs   0    00000000    000000d8
                  00000000    000000d8     startup_ccs.obj (.intvecs:retain)

.text      0    000000d8    000008e8
                  000000d8    00000250     driverlib.lib : sysctl.obj (.text:SysCtlClockGet)
                  00000328    000000a4     rtsv7M4_T_le_v4SPD16_eabi.lib : memcpy_t2.asm.obj (.text)
                  000003cc    0000009c                                   : copy_decompress_lzss.c.obj (.text:decompress:lzss)
                  00000468    00000088     main.obj (.text)
                  000004f0    00000000     unused.obj (.text)

GLOBAL SYMBOLS: SORTED ALPHABETICALLY BY Name
"""


def test_ti_map_keeps_placed_objects_and_library_members(tmp_path):
    p = tmp_path / "app.map"
    p.write_text(TI_MAP)
    lm = parse_link_map(p)
    assert lm.objects == {"startup_ccs.obj", "main.obj"}
    assert ("driverlib.lib", "sysctl.obj") in lm.members
    assert ("rtsv7M4_T_le_v4SPD16_eabi.lib", "copy_decompress_lzss.c.obj") in lm.members
    assert "unused.obj" not in lm.linked_object_names
    assert lm.archives == {"driverlib.lib", "rtsv7M4_T_le_v4SPD16_eabi.lib"}
