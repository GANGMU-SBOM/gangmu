"""Declared components in an unpacked Linux root filesystem: dpkg, opkg and apk.

A Linux-class firmware's root filesystem carries the package manager's own
database of what is installed, and that is the most exact statement of what
shipped. This reads it from a tree (an unpacked rootfs or a build's rootfs
staging directory); it does not unpack images.

dpkg
    ``var/lib/dpkg/status``: ``Package`` / ``Version`` stanzas whose ``Status``
    ends in ``installed``.
opkg (OpenWrt, Yocto)
    ``var/lib/opkg/status`` or ``usr/lib/opkg/status``, the same stanza format.
    Yocto's ``PV-PR`` (``1.36.1-r0``) is cut to the upstream release, as the Yocto
    reader does.
apk (Alpine)
    ``lib/apk/db/installed``: ``P:`` name, ``V:`` version, ``L:`` licence, ``U:`` URL.

A dpkg or apk version carries the distribution's own revision (``1.3.1-2+deb12u1``)
and the distribution backports fixes without changing the upstream version, so it
is reported as given, is not treated as an upstream release, and no upstream CPE
is spliced onto it: matching it against NVD ranges would be guessing both ways.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .core.walk import NOT_CONTENT_DIRS
from .declared import Declaration
from .declared_build import _yocto_version
from .declared_linux import _known

ECOSYSTEM_DPKG = "dpkg"
ECOSYSTEM_OPKG = "opkg"
ECOSYSTEM_APK = "apk"

_DATABASES = (
    ("var/lib/dpkg/status", ECOSYSTEM_DPKG),
    ("var/lib/opkg/status", ECOSYSTEM_OPKG),
    ("usr/lib/opkg/status", ECOSYSTEM_OPKG),
    ("lib/apk/db/installed", ECOSYSTEM_APK),
)
_MAX_DEPTH = 6

# Distribution package names that differ from the project's.
_ALIASES = {"zlib1g": "zlib", "libz1": "zlib", "libcurl4": "curl", "libcurl3": "curl",
            "libexpat1": "expat", "libxml2": "libxml2", "libsqlite3-0": "sqlite",
            "libpng16-16": "libpng", "libfreetype6": "freetype", "libssl3": "openssl",
            "libssl1.1": "openssl", "libssl-dev": "openssl", "libgnutls30": "gnutls",
            "liblzma5": "xz", "libzstd1": "zstd", "liblz4-1": "lz4", "libpcre3": "pcre",
            "libssh2-1": "libssh2", "libdbus-1-3": "dbus", "libarchive13": "libarchive"}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _stanzas(text: str) -> Iterator[Dict[str, str]]:
    for block in re.split(r"\n\s*\n", text):
        fields: Dict[str, str] = {}
        for line in block.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue                     # continuation lines are descriptions
            key, value = line.split(":", 1)
            fields.setdefault(key.strip(), value.strip())
        if fields:
            yield fields


def _apk_blocks(text: str) -> Iterator[Dict[str, str]]:
    for block in re.split(r"\n\s*\n", text):
        fields: Dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields.setdefault(line[0], line[2:].strip())
        if fields:
            yield fields


def _find_databases(root: Path) -> List[Tuple[Path, str]]:
    found: List[Tuple[Path, str]] = []
    base = len(root.parts)
    for here, dirs, _files in os.walk(root):
        depth = len(Path(here).parts) - base
        dirs[:] = [d for d in dirs if d not in NOT_CONTENT_DIRS and depth < _MAX_DEPTH]
        for rel, ecosystem in _DATABASES:
            if rel.split("/", 1)[0] not in dirs:
                continue                     # not a rootfs top: skip the stat
            path = Path(here) / rel
            if path.is_file():
                found.append((path, ecosystem))
    return found


def _decl(ecosystem: str, name: str, version: Optional[str], source: str, where: Path,
          upstream: bool, license: Optional[str] = None, url: Optional[str] = None,
          note: Optional[str] = None) -> Declaration:
    alias = _ALIASES.get(name.lower(), name.lower())
    display, cpe = _known(alias) if upstream else (None, None)
    return Declaration(
        ecosystem=ecosystem, name=name, directory=where, source=source,
        version=version, version_is_upstream=upstream and version is not None,
        license=license, upstream_url=url, cpe=cpe, display_name=display,
        description=note, manifest_only=True)


def read_rootfs_packages(root: Path) -> List[Declaration]:
    root = Path(root).resolve()
    out: Dict[Tuple[str, str, str], Declaration] = {}
    for path, ecosystem in _find_databases(root):
        try:
            text = _read(path)
        except OSError:
            continue
        source = path.relative_to(root).as_posix()
        where = path.parent
        if ecosystem == ECOSYSTEM_APK:
            for fields in _apk_blocks(text):
                name, version = fields.get("P"), fields.get("V")
                if not name:
                    continue
                out.setdefault((ecosystem, name, version or ""), _decl(
                    ecosystem, name, version, source, where, upstream=False,
                    license=fields.get("L"), url=fields.get("U"),
                    note="Alpine package version, with the distribution's revision"))
            continue
        for fields in _stanzas(text):
            name = fields.get("Package")
            if not name or not fields.get("Status", "install ok installed").endswith(
                    "installed"):
                continue
            raw = fields.get("Version", "")
            if ecosystem == ECOSYSTEM_OPKG:
                version = _yocto_version(raw)
                out.setdefault((ecosystem, name, version or ""), _decl(
                    ecosystem, name, version, source, where, upstream=True,
                    note=None if version else f"{source} lists {raw!r}, not a release"))
            else:
                out.setdefault((ecosystem, name, raw), _decl(
                    ecosystem, name, raw or None, source, where, upstream=False,
                    note="Debian package version, with the distribution's revision"))
    return list(out.values())
