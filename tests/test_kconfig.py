import json
import shutil

from gangmu.build.kconfig import KconfigValues, disabled_by, find_kconfig, parse_kconfig
from gangmu.cli import main

SDKCONFIG = """\
# Automatically generated file
CONFIG_IDF_TARGET="esp32"
CONFIG_MBEDTLS=y
CONFIG_FOO=m
# CONFIG_BT_NIMBLE_ENABLED is not set
CONFIG_ZERO=0
"""


def test_parse_reads_set_and_not_set_lines():
    cfg = parse_kconfig(SDKCONFIG)
    assert cfg.state("CONFIG_MBEDTLS") is True
    assert cfg.state("FOO") is True                      # module counts as on
    assert cfg.state("BT_NIMBLE_ENABLED") is False
    assert cfg.state("ZERO") is False
    assert cfg.state("NEVER_MENTIONED") is None
    assert cfg.values["IDF_TARGET"] == "esp32"


def test_a_component_is_dropped_only_when_the_file_says_it_is_off():
    cfg = parse_kconfig(SDKCONFIG)
    assert disabled_by(["BT_NIMBLE_ENABLED"], cfg) == ["BT_NIMBLE_ENABLED"]
    assert disabled_by(["MBEDTLS"], cfg) is None
    # unknown to this SDK release: keep it
    assert disabled_by(["NEVER_MENTIONED"], cfg) is None
    # any alternative being on keeps it; so does one the file cannot judge
    assert disabled_by(["BT_NIMBLE_ENABLED", "MBEDTLS"], cfg) is None
    assert disabled_by(["BT_NIMBLE_ENABLED", "NEVER_MENTIONED"], cfg) is None
    assert disabled_by([], cfg) is None
    assert disabled_by(["X"], KconfigValues()) is None


def test_find_kconfig_prefers_zephyr_then_sdkconfig(tmp_path):
    assert find_kconfig(tmp_path) is None
    (tmp_path / ".config").write_text("CONFIG_A=y\n")
    (tmp_path / "sdkconfig").write_text("CONFIG_A=y\n")
    assert find_kconfig(tmp_path).name == "sdkconfig"
    (tmp_path / "build/zephyr").mkdir(parents=True)
    (tmp_path / "build/zephyr/.config").write_text("CONFIG_A=y\n")
    assert find_kconfig(tmp_path).parts[-2:] == ("zephyr", ".config")


def _rules_with_symbols(rules_dir, tmp_path, symbols):
    out = tmp_path / "rules"
    shutil.copytree(rules_dir, out)
    path = out / "tinynet.yaml"
    path.write_text(path.read_text().replace(
        "  ships_as: tinynet\n",
        "  ships_as: tinynet\n  config_symbols:\n"
        + "".join(f"  - {s}\n" for s in symbols), 1))
    return out


def _scan(project_dir, rules, tmp_path, *extra):
    out = tmp_path / "scan.json"
    assert main(["scan", str(project_dir), "--rules", str(rules),
                 "--format", "json", "-o", str(out), *extra]) == 0
    return json.loads(out.read_text())


def test_scan_leaves_out_a_component_the_config_turns_off(project_dir, rules_dir, tmp_path):
    rules = _rules_with_symbols(rules_dir, tmp_path, ["TINYNET"])
    cfg = tmp_path / "sdkconfig"
    cfg.write_text("# CONFIG_TINYNET is not set\n")
    data = _scan(project_dir, rules, tmp_path, "--kconfig", str(cfg))
    assert not any(f["upstream_name"] == "tinynet" for f in data["findings"])
    assert [f["upstream_name"] for f in data["notBuilt"]] == ["tinynet"]
    assert data["notBuilt"][0]["config_off"] == ["TINYNET"]
    assert any("switched off" in n for n in data["notes"])


def test_scan_keeps_it_when_the_config_turns_it_on_or_is_silent(project_dir, rules_dir, tmp_path):
    rules = _rules_with_symbols(rules_dir, tmp_path, ["TINYNET"])
    for text in ("CONFIG_TINYNET=y\n", "CONFIG_OTHER=y\n"):
        cfg = tmp_path / "sdkconfig"
        cfg.write_text(text)
        data = _scan(project_dir, rules, tmp_path, "--kconfig", str(cfg))
        assert any(f["upstream_name"] == "tinynet" for f in data["findings"])
        assert data["notBuilt"] == []


def test_no_kconfig_lists_everything(project_dir, rules_dir, tmp_path):
    rules = _rules_with_symbols(rules_dir, tmp_path, ["TINYNET"])
    cfg = tmp_path / "sdkconfig"
    cfg.write_text("# CONFIG_TINYNET is not set\n")
    data = _scan(project_dir, rules, tmp_path, "--kconfig", str(cfg), "--no-kconfig")
    assert any(f["upstream_name"] == "tinynet" for f in data["findings"])


def test_rules_without_symbols_are_never_filtered(project_dir, rules_dir, tmp_path):
    cfg = tmp_path / "sdkconfig"
    cfg.write_text("# CONFIG_TINYNET is not set\n")
    data = _scan(project_dir, rules_dir, tmp_path, "--kconfig", str(cfg))
    assert any(f["upstream_name"] == "tinynet" for f in data["findings"])


def _rules_with_gate(rules_dir, tmp_path, path, symbol):
    out = tmp_path / "rules"
    shutil.copytree(rules_dir, out)
    yml = out / "tinynet.yaml"
    yml.write_text(yml.read_text().replace(
        "  ships_as: tinynet\n",
        f"  ships_as: tinynet\n  config_symbols:\n  - path: '{path}'\n    symbols: [{symbol}]\n", 1))
    return out


def test_a_path_gate_applies_only_to_a_copy_under_that_path(project_dir, rules_dir, tmp_path):
    cfg = tmp_path / "sdkconfig"
    cfg.write_text("# CONFIG_TINYNET is not set\n")
    where = next(p for p in project_dir.rglob("tinynet") if p.is_dir())
    rel = where.relative_to(project_dir).as_posix()
    here = _rules_with_gate(rules_dir, tmp_path / "a", f"**/{rel}", "TINYNET")
    data = _scan(project_dir, here, tmp_path, "--kconfig", str(cfg))
    assert [f["upstream_name"] for f in data["notBuilt"]] == ["tinynet"]
    elsewhere = _rules_with_gate(rules_dir, tmp_path / "b", "**/some/other/place", "TINYNET")
    data = _scan(project_dir, elsewhere, tmp_path, "--kconfig", str(cfg))
    assert any(f["upstream_name"] == "tinynet" for f in data["findings"])
