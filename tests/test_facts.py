import json

from gangmu.build.facts import collect_build_facts

MAP = """
Archive member included to satisfy reference by file (symbol)

build/json/libjson.a(dup.c.obj)
                              build/main/libmain.a(app.c.obj) (parse)

Discarded input sections

 .text   0x0 0x2a build/legacy/liblegacy.a(dup.c.obj)
 .text   0x0 0x10 build/legacy/liblegacy.a(only_here.c.obj)

Memory Configuration
"""


def _project(tmp_path):
    for comp in ("json", "legacy"):
        (tmp_path / "components" / comp).mkdir(parents=True)
        (tmp_path / "components" / comp / "dup.c").write_text("int dup(void){return 1;}")
    (tmp_path / "components" / "legacy" / "only_here.c").write_text("void x(void){}")
    entries = [
        {"directory": str(tmp_path / "build"),
         "file": str(tmp_path / "components/json/dup.c"),
         "output": str(tmp_path / "build/json/dup.c.obj"),
         "command": "cc -c"},
        {"directory": str(tmp_path / "build"),
         "file": str(tmp_path / "components/legacy/dup.c"),
         "output": str(tmp_path / "build/legacy/dup.c.obj"),
         "command": "cc -c"},
        {"directory": str(tmp_path / "build"),
         "file": str(tmp_path / "components/legacy/only_here.c"),
         "output": str(tmp_path / "build/legacy/only_here.c.obj"),
         "command": "cc -c"},
    ]
    (tmp_path / "build").mkdir(exist_ok=True)
    db = tmp_path / "build" / "compile_commands.json"
    db.write_text(json.dumps(entries))
    mp = tmp_path / "build" / "firmware.map"
    mp.write_text(MAP)
    return db, mp


def test_colliding_object_names_are_split_by_archive(tmp_path):
    db, mp = _project(tmp_path)
    facts = collect_build_facts(tmp_path, db, mp)
    linked = {p.parent.name for p in facts.linked}
    dropped = {p.parent.name for p in facts.dropped}
    assert "json" in linked
    assert "legacy" in dropped
    assert facts.ambiguous_objects == []


def test_without_a_link_map_everything_compiled_counts_as_shipped(tmp_path):
    db, _ = _project(tmp_path)
    facts = collect_build_facts(tmp_path, db, None)
    assert facts.linked == facts.compiled
    assert facts.have_link_map is False


def test_command_string_is_parsed_when_output_is_absent(tmp_path):
    (tmp_path / "a.c").write_text("int a;")
    db = tmp_path / "compile_commands.json"
    db.write_text(json.dumps([{
        "directory": str(tmp_path),
        "file": "a.c",
        "command": f"gcc -c a.c -o build/a.c.o",
    }]))
    facts = collect_build_facts(tmp_path, db, None)
    assert (tmp_path / "a.c").resolve() in facts.compiled
