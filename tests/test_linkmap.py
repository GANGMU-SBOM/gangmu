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
                  000004a0    00000034     drivers_cc26x2.aem4f : PINCC26XX.oem4f (.bss:pinSwi)
                  000004d4    00000020                          : PINCC26XX_aux.oem4f (.bss:pinHwi)
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
    assert lm.archives == {"driverlib.lib", "rtsv7M4_T_le_v4SPD16_eabi.lib",
                          "drivers_cc26x2.aem4f"}
    assert ("drivers_cc26x2.aem4f", "PINCC26XX.oem4f") in lm.members
    assert ("drivers_cc26x2.aem4f", "PINCC26XX_aux.oem4f") in lm.members


ARM_MAP = """\
Component: ARM Compiler 5.06 update 6 (build 750) Tool: armlink [4d35ed]

Removing Unused input sections from the image.

    Removing mpu6050.o(i.MPU_Get_Gyroscope), (80 bytes).
    Removing core_cm3.o(.emb_text), (56 bytes).

Memory Map of the image

  Image Entry point : 0x08000131

    Exec Addr    Load Addr    Size         Type   Attr      Idx    E Section Name        Object

    0x08000000   0x08000000   0x00000130   Data   RO         1136    RESET               startup_f10x.o
    0x08000130   0x08000130   0x00000008   Code   RO         2406  * !!!main             c_w.l(__main.o)
    0x08000188   0x08000188   0x00000020   Code   RO           12    i.main              main.o
    0x20000000   0x00000060   Zero   RW         1234    .bss                m_ws.l(libspace.o)

Image component sizes

      Code (inc. data)   RO Data    RW Data    ZI Data      Debug   Object Name

       220         26          0          4          0       1735   main.o
       148         22          0          0          0       5007   mpu6050.o

      Code (inc. data)   RO Data    RW Data    ZI Data      Debug   Library Member Name

         8          0          0          0          0         68   __main.o
         0          0          0          0          0          0   libspace.o

      Code (inc. data)   RO Data    RW Data    ZI Data      Debug   Library Name

     11876        726        438          0        100       6768   Library Totals
"""


def test_armlink_reads_flagged_and_zero_init_rows_and_keeps_members_out_of_objects(tmp_path):
    p = tmp_path / "keil.map"
    p.write_text(ARM_MAP)
    lm = parse_link_map(p)
    assert lm.archives == {"c_w.l", "m_ws.l"}
    assert lm.members == {("c_w.l", "__main.o"), ("m_ws.l", "libspace.o")}
    assert lm.objects == {"startup_f10x.o", "main.o", "mpu6050.o"}   # no bare library members
    assert lm.discarded_only == {"core_cm3.o"}
