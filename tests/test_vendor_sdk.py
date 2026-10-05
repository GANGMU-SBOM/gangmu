"""The vendor SDK is named in the SBOM, with its own release."""

from pathlib import Path

from gangmu.declared_sdk import read_vendor_sdks
from gangmu.rules.loader import load_rules
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.scan import ScanOptions, scan


def _w(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _bouffalo(root: Path, version: str = "2.3.36") -> Path:
    _w(root / "VERSION", f'PROJECT_SDK_VERSION "{version}"\n')
    _w(root / "cmake" / "bouffalo_sdk-config.cmake")
    return root


def test_bouffalo_sdk_is_read_from_its_version_file(tmp_path):
    found = read_vendor_sdks(_bouffalo(tmp_path / "bouffalo_sdk"))
    assert [(d.name, d.version) for d in found] == [("Bouffalo SDK", "2.3.36")]
    assert found[0].supplier.startswith("Bouffalo Lab")


def test_a_stray_version_file_is_not_an_sdk(tmp_path):
    _w(tmp_path / "VERSION", 'PROJECT_SDK_VERSION "9.9.9"\n')
    assert read_vendor_sdks(tmp_path) == []


def test_esp8266_version_is_assembled_from_three_defines(tmp_path):
    _w(tmp_path / "components/esp8266/include/esp_idf_version.h",
       "#define ESP_IDF_VERSION_MAJOR   3\n#define ESP_IDF_VERSION_MINOR   4\n"
       "#define ESP_IDF_VERSION_PATCH   0\n")
    _w(tmp_path / "tools" / "idf.py")
    assert [(d.name, d.version) for d in read_vendor_sdks(tmp_path)] == [
        ("ESP8266 RTOS SDK", "3.4.0")]


def test_wm_and_luatos_are_read(tmp_path):
    _w(tmp_path / "wm" / "version", 'config BUILD_VERSION\n    default "2.4-rc"\n')
    (tmp_path / "wm" / "components" / "wm_soc").mkdir(parents=True)
    _w(tmp_path / "luat" / "luat" / "include" / "luat_base.h", '#define LUAT_VERSION "26.04"\n')
    (tmp_path / "luat" / "lua").mkdir()
    found = {d.name: d.version for d in read_vendor_sdks(tmp_path)}
    assert found == {"WM IoT SDK": "2.4-rc", "LuatOS": "26.04"}


def test_the_sdk_is_a_framework_component_with_supplier_and_purl(tmp_path, rules_dir):
    root = _bouffalo(tmp_path)
    result = scan(root, load_rules(rules_dir, strict=True), None,
                  ScanOptions(binaries=False))
    bom = to_cyclonedx(result)
    sdk = next(c for c in bom["components"] if c["name"] == "Bouffalo SDK")
    assert sdk["type"] == "framework" and sdk["version"] == "2.3.36"
    assert sdk["purl"] == "pkg:github/bouffalolab/bouffalo_sdk@2.3.36"
    assert sdk["supplier"]["name"].startswith("Bouffalo Lab")
    assert sdk["licenses"] == [{"license": {"id": "Apache-2.0"}}]


def test_bl_iot_sdk_keeps_the_release_tag_commit_count_and_hash(tmp_path):
    _w(tmp_path / "version.mk",
       'ifeq ("$(CONFIG_CHIP_NAME)", "BL602")\n'
       'EXTRA_CPPFLAGS  += -D BL_SDK_VER=\\"release_bl_iot_sdk_1.6.39-238-gf5ba0a7ee\\"\n'
       'endif\n')
    (tmp_path / "make_scripts_riscv").mkdir()
    (tmp_path / "customer_app").mkdir()
    found = read_vendor_sdks(tmp_path)
    assert [(d.name, d.version) for d in found] == [
        ("Bouffalo IoT SDK (bl_iot_sdk)", "1.6.39-238-gf5ba0a7ee")]
    assert found[0].upstream_url == "https://github.com/bouffalolab/bl_iot_sdk"


def test_alibaba_link_sdk_and_tuya_sdk_are_read(tmp_path):
    _w(tmp_path / "ali" / "src" / "infra" / "infra_defs.h",
       '#define IOTX_SDK_VERSION                "3.0.1"\n')
    (tmp_path / "ali" / "src" / "dev_sign").mkdir()
    _w(tmp_path / "ali" / "makefile")
    _w(tmp_path / "tuya" / "CHANGELOG.md",
       "# 版本更新日志\n\n## 2.3.3 (2021-10-28)\n\n正式发布\n\n## 2.3.2 (2021-05-11)\n")
    _w(tmp_path / "tuya" / "sdk" / "include" / "tuya_iot_com_api.h")
    found = {d.name: d for d in read_vendor_sdks(tmp_path)}
    assert found["Alibaba Cloud Link SDK (iotkit-embedded)"].version == "3.0.1"
    tuya = found["Tuya IoTOS Embedded SDK"]
    assert tuya.version == "2.3.3"                  # the newest heading, not the first number found
    assert tuya.license is None                     # the repository ships no licence file
    assert tuya.supplier == "Tuya Smart"


def test_a_changelog_alone_is_not_a_tuya_sdk(tmp_path):
    _w(tmp_path / "CHANGELOG.md", "## 1.0.0\n")
    assert read_vendor_sdks(tmp_path) == []
