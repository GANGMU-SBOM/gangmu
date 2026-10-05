"""Manifest readers.

Where a vendor already declares what a directory is, believe them -- it is
cheaper and more accurate than any fingerprint.  ESP-IDF is the useful case:
Espressif ships ``idf_component.yml`` and, for the SBOM tool they maintain,
``sbom.yml`` with explicit version, CPE and PURL.  A rule base that ignored
those would be reinventing data the vendor already publishes.

Zephyr modules can do the same: ``zephyr/module.yml`` may carry
``security.external-references``, a list of CPE and PURL strings the module
maintainers vouch for. Zephyr's Mbed TLS, nanopb, hostap and TF-M modules do.

This is also the honest answer to "what if the vendor does it themselves":
their manifest becomes a first-class input.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

import re

MANIFEST_NAMES = ("sbom.yml", "sbom.yaml", "idf_component.yml", "idf_component.yaml")
ZEPHYR_MODULE = "zephyr/module.yml"


@dataclass(frozen=True)
class ManifestFacts:
    source: str                     # file name it came from
    name: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    purl: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None

    def is_empty(self) -> bool:
        return not any((self.name, self.version, self.cpe, self.purl))


def read_manifest(directory: Path) -> Optional[ManifestFacts]:
    for name in MANIFEST_NAMES:
        path = directory / name
        if not path.is_file():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        facts = ManifestFacts(
            source=name,
            name=_first(data, "name", "sbom_name"),
            version=_first(data, "version", "sbom_version"),
            cpe=_first(data, "cpe", "sbom_cpe"),
            purl=_first(data, "purl", "sbom_purl"),
            url=_first(data, "url", "repository", "sbom_url"),
            description=_first(data, "description", "sbom_description"),
        )
        if not facts.is_empty():
            return facts
    return read_zephyr_module(directory)


def read_zephyr_module(directory: Path) -> Optional[ManifestFacts]:
    """CPE and PURL from a Zephyr module's ``security.external-references``.

    The CPE is returned with its version field wildcarded, ready to be used as
    a rule's template; the version is returned separately, so a rule never
    carries a release number in its CPE.
    """
    path = directory / ZEPHYR_MODULE
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return None
    security = data.get("security") if isinstance(data, dict) else None
    refs = security.get("external-references") if isinstance(security, dict) else None
    if not isinstance(refs, list):
        return None
    cpe = purl = version = name = None
    for ref in refs:
        ref = str(ref).strip()
        if ref.startswith("cpe:2.3:") and cpe is None:
            parts = ref.split(":")
            if len(parts) == 13:
                if parts[5] not in ("*", "-", ""):
                    version = version or parts[5]
                parts[5] = "*"
                cpe = ":".join(parts)
        elif ref.startswith("pkg:") and purl is None:
            base, _, ver = ref.split("?", 1)[0].partition("@")
            purl = base
            name = base.rsplit("/", 1)[-1]
            if ver:
                version = version or _strip_v(ver)
    facts = ManifestFacts(source=ZEPHYR_MODULE, name=name, version=version,
                          cpe=cpe, purl=purl)
    return None if facts.is_empty() else facts


def _strip_v(version: str) -> str:
    return version[1:] if re.match(r"^[vV]\d", version) else version


def _first(data: dict, *keys: str) -> Optional[str]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return None
