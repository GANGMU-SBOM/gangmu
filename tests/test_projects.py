"""IDE project files.

Each of these formats answers "which files does this project build", and each
has its own way of saying "not this one in this configuration". Getting that
wrong means over-reporting, which is the failure build facts exist to prevent.
"""

from pathlib import Path

import pytest

from gangmu.build.projects import parse_project

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "projects"


def _names(paths):
    return sorted(p.name for p in paths)


# ------------------------------------------------------------------ IAR

def test_iar_reads_the_file_list():
    parsed = parse_project(FIXTURES / "iar" / "app.ewp")
    assert parsed.kind == "iar"
    assert "main.c" in _names(parsed.sources)
    assert "core.c" in _names(parsed.sources)


def test_iar_defaults_to_the_first_configuration_and_says_so():
    parsed = parse_project(FIXTURES / "iar" / "app.ewp")
    assert parsed.configuration == "Debug"
    assert any("configurations" in n for n in parsed.notes)


def test_iar_honours_per_configuration_exclusions():
    debug = parse_project(FIXTURES / "iar" / "app.ewp", "Debug")
    release = parse_project(FIXTURES / "iar" / "app.ewp", "Release")
    assert "debug_only.c" in _names(debug.sources)
    assert "debug_only.c" not in _names(release.sources)
    assert "debug_only.c" in _names(release.excluded)


def test_iar_drops_a_file_excluded_everywhere():
    for configuration in ("Debug", "Release"):
        parsed = parse_project(FIXTURES / "iar" / "app.ewp", configuration)
        assert "never_built.c" not in _names(parsed.sources)


def test_iar_ignores_unresolvable_toolchain_paths():
    """$TOOLKIT_DIR$ is the IAR install, not the project's source."""
    parsed = parse_project(FIXTURES / "iar" / "app.ewp")
    assert not any("DLib_Config" in p.name for p in parsed.sources)


def test_iar_paths_resolve_relative_to_the_project_file():
    parsed = parse_project(FIXTURES / "iar" / "app.ewp")
    assert all(p.is_absolute() for p in parsed.sources)
    assert all(p.exists() for p in parsed.sources)


# ----------------------------------------------------------------- Keil

def test_keil_reads_the_first_target_by_default():
    parsed = parse_project(FIXTURES / "keil" / "app.uvprojx")
    assert parsed.kind == "keil" and parsed.configuration == "Flash"
    assert "main.c" in _names(parsed.sources)
    assert "core.c" in _names(parsed.sources)


def test_keil_honours_include_in_build_zero():
    parsed = parse_project(FIXTURES / "keil" / "app.uvprojx")
    assert "never_built.c" not in _names(parsed.sources)
    assert "never_built.c" in _names(parsed.excluded)


def test_keil_selects_a_named_target():
    ram = parse_project(FIXTURES / "keil" / "app.uvprojx", "RAM")
    assert _names(ram.sources) == ["debug_only.c"]


def test_keil_ignores_headers_in_the_file_list():
    parsed = parse_project(FIXTURES / "keil" / "app.uvprojx")
    assert not any(p.suffix == ".h" for p in parsed.sources)


def test_keil_backslash_paths_resolve():
    parsed = parse_project(FIXTURES / "keil" / "app.uvprojx")
    assert all(p.exists() for p in parsed.sources)


# ------------------------------------------------------------------ CCS

def test_ccs_walks_the_project_and_its_linked_resources():
    parsed = parse_project(FIXTURES / "ccs")
    names = _names(parsed.sources)
    assert "app.c" in names
    assert "core.c" in names and "buf.c" in names     # via the linked SDK folder


def test_ccs_honours_source_entry_exclusions():
    parsed = parse_project(FIXTURES / "ccs")
    assert "legacy_port.c" not in _names(parsed.sources)
    assert "legacy_port.c" in _names(parsed.excluded)


def test_ccs_reports_the_configuration_it_used():
    assert parse_project(FIXTURES / "ccs").configuration == "Debug"


# --------------------------------------------------------------- general

def test_a_project_converts_to_a_compile_database():
    db = parse_project(FIXTURES / "iar" / "app.ewp").to_compile_db()
    assert db.sources
    assert all(p.is_absolute() for p in db.sources)


def test_an_unsupported_project_file_is_refused_with_a_hint(tmp_path):
    bogus = tmp_path / "thing.sln"
    bogus.write_text("")
    with pytest.raises(ValueError, match="compile_commands.json"):
        parse_project(bogus)


def test_a_directory_with_no_project_is_refused(tmp_path):
    with pytest.raises(ValueError, match="no IAR, Keil or CCS project"):
        parse_project(tmp_path)
