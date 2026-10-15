"""Declared components for ST's Cube packages and CMSIS-Packs.

A tree built on STM32Cube carries ST's own HAL and CMSIS device files, copied in
unchanged more often than not, and each states its release: the CMSIS device
header in a version macro, the HAL in the newest entry of its ``Release_Notes.html``.
A CMSIS-Pack (Arm CMSIS, a vendor's device family pack) states its release in the
``<releases>`` of its ``*.pdsc``. Reading them is exact where fingerprinting would
only estimate; ST publishes no CPE for these, so none is claimed. Nothing is
fetched.

STM32 CMSIS device
    ``Include/stm32<family>xx.h``: ``__STM32F4xx_CMSIS_VERSION_MAIN``, ``_SUB1``
    and ``_SUB2``, else the newest entry of the ``Release_Notes.html`` beside it
    (titled "Release Notes for STM32F4xx CMSIS").
STM32 HAL driver
    ``Src/stm32<family>xx_hal.c``: ``__STM32F4xx_HAL_VERSION_MAIN``, ``_SUB1``,
    ``_SUB2`` and ``_RC`` (the macros are in the source file, not the headers),
    else the highest entry of ``Release_Notes.html`` titled "Release Notes for
    STM32F4xx HAL Drivers"; a copy with neither is not reported.
CMSIS-Pack
    ``<vendor>``, ``<name>`` and the first ``<release version=...>`` of a
    ``*.pdsc``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional
from xml.etree import ElementTree

from .declared import Declaration
from .declared_build import _read, _walk

ECOSYSTEM_STM32CUBE = "stm32cube"
ECOSYSTEM_CMSIS_PACK = "cmsis-pack"
SUPPLIER_ST = "STMicroelectronics"

_CMSIS_MACRO = re.compile(
    r"#define\s+__(STM32\w+?)_CMSIS_VERSION_(MAIN|SUB1|SUB2)\s+\(0x([0-9A-Fa-f]+)U?\)")
_NOTES_TITLE = re.compile(
    r"<title>\s*Release Notes for (STM32\w+?)\s+(CMSIS|HAL)\b[^<]*</title>",
    re.IGNORECASE)
_HAL_MACRO = re.compile(
    r"#define\s+__(STM32\w+?)_HAL_VERSION_(MAIN|SUB1|SUB2|RC)\s+\(0x([0-9A-Fa-f]+)U?\)")
# One heading per release, ``V1.2.0 / 26-June-2019``; ST writes the V in either case
# (``v1.3.0`` is the newest entry of the STM32WB HAL notes), so the case is ignored
# and the highest release is taken rather than the first one.
_NOTES_ENTRY = re.compile(r">\s*[Vv](\d+\.\d+\.\d+(?:\.\d+)?)\s*/")


def read_vendor_packages(root: Path) -> List[Declaration]:
    root = Path(root).resolve()
    return read_stm32cube(root) + read_cmsis_packs(root)


def _family(raw: str) -> str:
    """``STM32F4`` (a header macro) and ``STM32F4xx`` (a title) are one family."""
    return re.sub(r"(?i)xx$", "", raw).lower() + "xx"


def _version_key(text: str) -> tuple:
    return tuple(int(n) for n in text.split("."))


def _newest_release(text: str) -> Optional[str]:
    start = text.find('id="update-history"')
    found = _NOTES_ENTRY.findall(text[start:] if start >= 0 else text)
    return max(found, key=_version_key) if found else None


def _st_decl(name: str, version: Optional[str], source: str, where: Path,
             display: str) -> Declaration:
    return Declaration(
        ecosystem=ECOSYSTEM_STM32CUBE, name=name, directory=where, source=source,
        version=version, version_is_upstream=version is not None,
        display_name=display, supplier=SUPPLIER_ST, manifest_only=True)


def read_stm32cube(root: Path) -> List[Declaration]:
    out: Dict[str, Declaration] = {}
    for here, files in _walk(root, 6):
        notes = here / "Release_Notes.html" if "Release_Notes.html" in files else None
        # CMSIS device: the header macros first.
        include = here / "Include"
        if include.is_dir():
            for header in sorted(include.glob("stm32*xx.h")):
                try:
                    text = _read(header)
                except OSError:
                    continue
                parts: Dict[str, int] = {}
                family = None
                for fam, part, value in _CMSIS_MACRO.findall(text):
                    family, parts[part] = fam, int(value, 16)
                if family and {"MAIN", "SUB1", "SUB2"} <= set(parts):
                    version = f"{parts['MAIN']}.{parts['SUB1']}.{parts['SUB2']}"
                    fam = _family(family)
                    name = f"{fam}_cmsis_device"
                    out.setdefault(name, _st_decl(
                        name, version, header.relative_to(root).as_posix(), here,
                        f"{fam.upper().replace('XX', 'xx')} CMSIS device"))
                    break
        # HAL driver: the macros in its Src/stm32*xx_hal.c.
        src = here / "Src"
        if src.is_dir():
            for source in sorted(src.glob("stm32*xx_hal.c")):
                try:
                    text = _read(source)
                except OSError:
                    continue
                parts = {}
                family = None
                for fam, part, value in _HAL_MACRO.findall(text):
                    family, parts[part] = fam, int(value, 16)
                if family and {"MAIN", "SUB1", "SUB2"} <= set(parts):
                    version = f"{parts['MAIN']}.{parts['SUB1']}.{parts['SUB2']}"
                    if parts.get("RC"):
                        version += f"-rc{parts['RC']}"
                    fam = _family(family)
                    name = f"{fam}_hal_driver"
                    out.setdefault(name, _st_decl(
                        name, version, source.relative_to(root).as_posix(), here,
                        f"{fam.upper().replace('XX', 'xx')} HAL driver"))
                    break
        if notes is None:
            continue
        try:
            text = _read(notes)
        except OSError:
            continue
        title = _NOTES_TITLE.search(text[:4000])
        newest = _newest_release(text)
        if not title or not newest:
            continue
        fam, kind = _family(title.group(1)), title.group(2).upper()
        label = fam.upper().replace("XX", "xx")
        version = newest
        if kind == "CMSIS":
            name = f"{fam}_cmsis_device"
            if name in out:
                continue                 # the header's macro already said it
            display = f"{label} CMSIS device"
        else:
            name = f"{fam}_hal_driver"
            display = f"{label} HAL driver"
        out.setdefault(name, _st_decl(name, version,
                                      notes.relative_to(root).as_posix(), here, display))
    return list(out.values())


def read_cmsis_packs(root: Path) -> List[Declaration]:
    out: Dict[str, Declaration] = {}
    for here, files in _walk(root, 4):
        for fname in sorted(f for f in files if f.endswith(".pdsc")):
            try:
                tree = ElementTree.fromstring(_read(here / fname))
            except (ElementTree.ParseError, OSError):
                continue
            vendor = (tree.findtext("vendor") or "").strip()
            name = (tree.findtext("name") or "").strip()
            release = tree.find("releases/release")
            version = release.get("version") if release is not None else None
            if not vendor or not name:
                continue
            ident = f"{vendor}.{name}"
            out.setdefault(ident.lower(), Declaration(
                ecosystem=ECOSYSTEM_CMSIS_PACK, name=ident, directory=here,
                source=(here / fname).relative_to(root).as_posix(),
                version=version, version_is_upstream=version is not None,
                display_name=ident, supplier=vendor, manifest_only=True,
                description=None if version else f"{fname} lists no release"))
    return list(out.values())
