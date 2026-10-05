"""The vendor SDK itself, as a component.

Scanning a Chinese chip vendor's SDK reports the open-source libraries inside it,
but the SBOM never names the SDK. A reviewer's first question is "which SDK, which
release, from whom", and the vendor's own HAL and drivers are the code the customer
cannot get fixed upstream. Each SDK states its own release in a file at a known
place; this reads it, the way the RT-Thread and OpenHarmony declarations are read.

A spec is data: the files that must all be present (so a stray ``VERSION`` file is
not mistaken for an SDK), where the version is written and how to read it. To add an
SDK, add an entry to :data:`SDKS` and a test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from .declared import Declaration
from .declared_linux import _read, _walk

ECOSYSTEM_VENDOR_SDK = "vendor-sdk"
_MAX_DEPTH = 4


@dataclass(frozen=True)
class SdkSpec:
    name: str
    supplier: str
    url: str
    license: str
    markers: Tuple[str, ...]
    version_file: str
    patterns: Dict[str, str]
    template: str


SDKS: Tuple[SdkSpec, ...] = (
    SdkSpec(
        name="Bouffalo SDK", supplier="Bouffalo Lab (Nanjing) Co., Ltd.",
        url="https://github.com/bouffalolab/bouffalo_sdk", license="Apache-2.0",
        markers=("VERSION", "cmake/bouffalo_sdk-config.cmake"),
        version_file="VERSION",
        patterns={"v": r'PROJECT_SDK_VERSION\s+"([^"]+)"'}, template="{v}"),
    SdkSpec(
        name="WM IoT SDK", supplier="WinnerMicro (Beijing Winner Microelectronics)",
        url="https://github.com/winnermicro/wm_iot_sdk", license="Apache-2.0",
        markers=("version", "components/wm_soc"),
        version_file="version",
        patterns={"v": r'default\s+"([^"]+)"'}, template="{v}"),
    SdkSpec(
        name="ESP8266 RTOS SDK", supplier="Espressif Systems",
        url="https://github.com/espressif/ESP8266_RTOS_SDK", license="Apache-2.0",
        markers=("components/esp8266/include/esp_idf_version.h", "tools/idf.py"),
        version_file="components/esp8266/include/esp_idf_version.h",
        patterns={"major": r"ESP_IDF_VERSION_MAJOR\s+(\d+)",
                  "minor": r"ESP_IDF_VERSION_MINOR\s+(\d+)",
                  "patch": r"ESP_IDF_VERSION_PATCH\s+(\d+)"},
        template="{major}.{minor}.{patch}"),
    SdkSpec(
        name="LuatOS", supplier="openLuat (AirM2M)",
        url="https://github.com/openLuat/LuatOS", license="MIT",
        markers=("luat/include/luat_base.h", "lua"),
        version_file="luat/include/luat_base.h",
        patterns={"v": r'#define\s+LUAT_VERSION\s+"([^"]+)"'}, template="{v}"),
    SdkSpec(
        # version.mk sets BL_SDK_VER="release_bl_iot_sdk_1.6.39-238-gf5ba0a7ee" per chip:
        # the tag, the commits since it and the commit, which is what a customer needs.
        name="Bouffalo IoT SDK (bl_iot_sdk)", supplier="Bouffalo Lab (Nanjing) Co., Ltd.",
        url="https://github.com/bouffalolab/bl_iot_sdk", license="Apache-2.0",
        markers=("version.mk", "make_scripts_riscv", "customer_app"),
        version_file="version.mk",
        patterns={"v": r'BL_SDK_VER=\\*"(?:release_bl_iot_sdk_)?([^"\\]+)'}, template="{v}"),
    SdkSpec(
        name="Alibaba Cloud Link SDK (iotkit-embedded)", supplier="Alibaba Cloud",
        url="https://github.com/aliyun/iotkit-embedded", license="Apache-2.0",
        markers=("src/infra/infra_defs.h", "src/dev_sign", "makefile"),
        version_file="src/infra/infra_defs.h",
        patterns={"v": r'#define\s+IOTX_SDK_VERSION\s+"([^"]+)"'}, template="{v}"),
    SdkSpec(
        # The release number is the newest heading of the SDK's CHANGELOG.md.
        # The repository carries no licence file, so none is claimed.
        name="Tuya IoTOS Embedded SDK", supplier="Tuya Smart",
        url="https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n", license="",
        markers=("CHANGELOG.md", "sdk/include/tuya_iot_com_api.h"),
        version_file="CHANGELOG.md",
        patterns={"v": r'(?m)^##\s+v?(\d+\.\d+\.\d+)'}, template="{v}"),
)


def read_vendor_sdks(root: Path) -> List[Declaration]:
    root = Path(root).resolve()
    out: List[Declaration] = []
    for here, _files in _walk(root, _MAX_DEPTH):
        for spec in SDKS:
            if not all((here / m).exists() for m in spec.markers):
                continue
            version = _version(here / spec.version_file, spec)
            if not version:
                continue
            out.append(Declaration(
                ecosystem=ECOSYSTEM_VENDOR_SDK, name=spec.name,
                directory=here, version=version, version_is_upstream=False,
                source=(here / spec.version_file).relative_to(root).as_posix(),
                upstream_url=spec.url, license=spec.license or None, supplier=spec.supplier,
                display_name=spec.name))
    return out


def _version(path: Path, spec: SdkSpec):
    try:
        text = _read(path)
    except OSError:
        return None
    parts = {}
    for key, pattern in spec.patterns.items():
        m = re.search(pattern, text)
        if not m:
            return None
        parts[key] = m.group(1)
    return spec.template.format(**parts)
