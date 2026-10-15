"""ST Cube packages and CMSIS-Packs."""

from pathlib import Path

from gangmu.declared_packs import read_cmsis_packs, read_stm32cube
from gangmu.scan import scan
from gangmu.rules.loader import load_rules

# Excerpts of the real files in STMicroelectronics/cmsis_device_f4 (V2.6.11),
# cmsis_device_g0 (V1.4.5) and stm32g0xx_hal_driver (V1.4.7).
_F4_HEADER = """/**
  * @brief CMSIS version number V2.6.11
  */
#define __STM32F4xx_CMSIS_VERSION_MAIN   (0x02U) /*!< [31:24] main version */
#define __STM32F4xx_CMSIS_VERSION_SUB1   (0x06U) /*!< [23:16] sub1 version */
#define __STM32F4xx_CMSIS_VERSION_SUB2   (0x0BU) /*!< [15:8]  sub2 version */
#define __STM32F4xx_CMSIS_VERSION_RC     (0x00U) /*!< [7:0]  release candidate */
"""
_G0_HEADER = _F4_HEADER.replace("F4xx", "G0").replace("0x02U", "0x01U") \
    .replace("0x06U", "0x04U").replace("0x0BU", "0x05U")


def _notes(title: str, newest: str, older: str) -> str:
    return (f"<html><head><title>Release Notes for {title}</title></head><body>"
            '<h1 id="purpose">Purpose</h1><h1 id="update-history">Update History</h1>'
            '<div class="collapse"><input type="checkbox" id="collapse-section10" checked '
            f'aria-hidden="true"> <label for="collapse-section10" aria-hidden="true">{newest}'
            "</label><div><h2>Main Changes</h2></div></div>"
            f'<label aria-hidden="true">{older}</label></body></html>')


def _w(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_cmsis_device_version_comes_from_the_header_macros(tmp_path):
    _w(tmp_path / "cmsis_device_f4" / "Include" / "stm32f4xx.h", _F4_HEADER)
    found = read_stm32cube(tmp_path)
    assert [(d.name, d.version, d.supplier) for d in found] == [
        ("stm32f4xx_cmsis_device", "2.6.11", "STMicroelectronics")]


def test_macro_and_title_spellings_of_a_family_are_one_component(tmp_path):
    _w(tmp_path / "dev" / "Include" / "stm32g0xx.h", _G0_HEADER)
    _w(tmp_path / "dev" / "Release_Notes.html",
       _notes("STM32G0xx CMSIS", "V1.4.5 / 30-June-2025", "V1.4.4 / 1-May-2025"))
    found = read_stm32cube(tmp_path)
    assert [(d.name, d.version) for d in found] == [("stm32g0xx_cmsis_device", "1.4.5")]
    assert found[0].source.endswith("stm32g0xx.h")      # the macro, not the notes


def test_hal_version_is_the_newest_entry_of_the_release_notes(tmp_path):
    _w(tmp_path / "hal" / "Release_Notes.html",
       _notes("STM32G0xx HAL Drivers Package", "V1.4.7 / 27-February-2026",
              "V1.4.6 / 10-January-2026"))
    found = read_stm32cube(tmp_path)
    assert [(d.name, d.version) for d in found] == [("stm32g0xx_hal_driver", "1.4.7")]


def test_unrelated_release_notes_are_ignored(tmp_path):
    _w(tmp_path / "x" / "Release_Notes.html",
       "<title>Release Notes for Something Else</title>"
       '<h1 id="update-history"></h1><label>V1.0.0 / today</label>')
    assert read_stm32cube(tmp_path) == []


def test_pdsc_gives_vendor_name_and_newest_release(tmp_path):
    _w(tmp_path / "pack" / "ARM.CMSIS.pdsc", """<?xml version="1.0" encoding="utf-8"?>
<package schemaVersion="1.7.7" xmlns:xs="http://www.w3.org/2001/XMLSchema-instance"
         xs:noNamespaceSchemaLocation="PACK.xsd">
  <vendor>ARM</vendor>
  <name>CMSIS</name>
  <releases>
    <release version="5.9.0" date="2022-06-01">Newest</release>
    <release version="5.8.0" date="2021-06-01">Older</release>
  </releases>
</package>
""")
    found = read_cmsis_packs(tmp_path)
    assert [(d.name, d.version, d.supplier) for d in found] == [("ARM.CMSIS", "5.9.0", "ARM")]


def test_a_broken_pdsc_is_skipped(tmp_path):
    _w(tmp_path / "bad.pdsc", "<package><vendor>x")
    assert read_cmsis_packs(tmp_path) == []


def test_a_scan_reports_the_st_hal(tmp_path):
    _w(tmp_path / "Drivers" / "HAL" / "Release_Notes.html",
       _notes("STM32F4xx HAL Drivers", "V1.8.5 / 23-July-2025", "V1.8.4 / 1-May-2025"))
    result = scan(tmp_path, load_rules(Path(__file__).parent / "fixtures" / "rules"))
    assert ("declared/stm32cube/stm32f4xx_hal_driver", "1.8.5") in {
        (f.rule_id, f.version) for f in result.findings}
