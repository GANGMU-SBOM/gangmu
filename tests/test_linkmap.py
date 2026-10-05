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
