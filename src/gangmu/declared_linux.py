"""Declared components for Linux-based SDKs: Buildroot, OpenWrt/Tina, Kbuild trees.

Most Chinese application-processor SDKs (Allwinner Tina, Rockchip and Luckfox
Buildroot, HiSilicon, SigmaStar, Ingenic, Fullhan) are not RTOS trees. They are a
Linux kernel, U-Boot, BusyBox and a few hundred packages assembled by Buildroot or
OpenWrt. Like RT-Thread's Env, those build systems already write down what goes
in, so reading it is exact where fingerprinting would only estimate:

Buildroot
    ``.config`` selects ``BR2_PACKAGE_<NAME>=y``; ``package/<name>/<name>.mk``
    holds ``<NAME>_VERSION = x.y.z``.
OpenWrt (and Allwinner Tina, which is OpenWrt)
    ``.config`` selects ``CONFIG_PACKAGE_<name>=y``; the recipe ``Makefile``
    holds ``PKG_NAME:=`` and ``PKG_VERSION:=``.
Kbuild
    The Linux kernel, U-Boot and BusyBox state their release in the top-level
    ``Makefile`` (``VERSION``, ``PATCHLEVEL``, ``SUBLEVEL``).

Only what ``.config`` selects is reported. A recipe tree holds hundreds of
packages and a product ships a few dozen, so listing every recipe would be the
over-reporting this tool exists to prevent. Recipes whose version is computed
(``$(...)``) are skipped rather than guessed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .declared import Declaration

ECOSYSTEM_BUILDROOT = "buildroot"
ECOSYSTEM_OPENWRT = "openwrt"
ECOSYSTEM_KBUILD = "kbuild"

_SKIP = {".git", "node_modules", "__pycache__", "dl", "downloads", "staging_dir",
         "toolchain", "docs", "doc"}
_MAX_DEPTH = 6

# name -> (display name, CPE). Names are the lower-case package names Buildroot and
# OpenWrt use. Each CPE was checked against the NVD on 2026-10-05: it has CVEs
# filed under it. That shows the vendor:product exists, not that every record under
# it is this project's; where two spellings exist (curl is filed under both
# haxx:curl and, since 2023, curl:curl) the one with the most CVEs is listed.
KNOWN: Dict[str, Tuple[str, Optional[str]]] = {
    "zlib": ("zlib", "cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"),
    "libzlib": ("zlib", "cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"),
    "busybox": ("BusyBox", "cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*"),
    "curl": ("curl", "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"),
    "libcurl": ("curl", "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"),
    "dropbear": ("Dropbear", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*"),
    "dnsmasq": ("dnsmasq", "cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*"),
    "libpng": ("libpng", "cpe:2.3:a:libpng:libpng:*:*:*:*:*:*:*:*"),
    "libjpeg-turbo": ("libjpeg-turbo", "cpe:2.3:a:libjpeg-turbo:libjpeg-turbo:*:*:*:*:*:*:*:*"),
    "jpeg-turbo": ("libjpeg-turbo", "cpe:2.3:a:libjpeg-turbo:libjpeg-turbo:*:*:*:*:*:*:*:*"),
    "sqlite": ("SQLite", "cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*"),
    "expat": ("Expat", "cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*"),
    "libexpat": ("Expat", "cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*"),
    "libxml2": ("libxml2", "cpe:2.3:a:xmlsoft:libxml2:*:*:*:*:*:*:*:*"),
    "openssh": ("OpenSSH", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
    "lighttpd": ("lighttpd", "cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*"),
    "mosquitto": ("Eclipse Mosquitto", "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*"),
    "ffmpeg": ("FFmpeg", "cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*"),
    "bluez": ("BlueZ", "cpe:2.3:a:bluez:bluez:*:*:*:*:*:*:*:*"),
    "bluez5_utils": ("BlueZ", "cpe:2.3:a:bluez:bluez:*:*:*:*:*:*:*:*"),
    "glibc": ("glibc", "cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*"),
    "uclibc": ("uClibc-ng", "cpe:2.3:a:uclibc-ng_project:uclibc-ng:*:*:*:*:*:*:*:*"),
    "uclibc-ng": ("uClibc-ng", "cpe:2.3:a:uclibc-ng_project:uclibc-ng:*:*:*:*:*:*:*:*"),
    "musl": ("musl libc", "cpe:2.3:a:musl-libc:musl:*:*:*:*:*:*:*:*"),
    "iptables": ("iptables", "cpe:2.3:a:netfilter:iptables:*:*:*:*:*:*:*:*"),
    "openvpn": ("OpenVPN", "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"),
    "wolfssl": ("wolfSSL", "cpe:2.3:a:wolfssl:wolfssl:*:*:*:*:*:*:*:*"),
    "lua": ("Lua", "cpe:2.3:a:lua:lua:*:*:*:*:*:*:*:*"),
    "libpcap": ("libpcap", "cpe:2.3:a:tcpdump:libpcap:*:*:*:*:*:*:*:*"),
    "tcpdump": ("tcpdump", "cpe:2.3:a:tcpdump:tcpdump:*:*:*:*:*:*:*:*"),
    "xz": ("XZ Utils", "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*"),
    "freetype": ("FreeType", "cpe:2.3:a:freetype:freetype:*:*:*:*:*:*:*:*"),
    "util-linux": ("util-linux", "cpe:2.3:a:kernel:util-linux:*:*:*:*:*:*:*:*"),
    "dbus": ("D-Bus", "cpe:2.3:a:freedesktop:dbus:*:*:*:*:*:*:*:*"),
    "unbound": ("Unbound", "cpe:2.3:a:nlnetlabs:unbound:*:*:*:*:*:*:*:*"),
    "openldap": ("OpenLDAP", "cpe:2.3:a:openldap:openldap:*:*:*:*:*:*:*:*"),
    "bash": ("GNU Bash", "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*"),
    "gnutls": ("GnuTLS", "cpe:2.3:a:gnu:gnutls:*:*:*:*:*:*:*:*"),
    "ntp": ("ntp", "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*"),
    "pcre": ("PCRE", "cpe:2.3:a:pcre:pcre:*:*:*:*:*:*:*:*"),
    "lz4": ("LZ4", "cpe:2.3:a:lz4_project:lz4:*:*:*:*:*:*:*:*"),
    "zstd": ("Zstandard", "cpe:2.3:a:facebook:zstandard:*:*:*:*:*:*:*:*"),
    "protobuf": ("Protocol Buffers", "cpe:2.3:a:google:protobuf:*:*:*:*:*:*:*:*"),
    "bind": ("BIND", "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"),
    "jq": ("jq", "cpe:2.3:a:jqlang:jq:*:*:*:*:*:*:*:*"),
    "nginx": ("nginx", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"),
    "ncurses": ("ncurses", "cpe:2.3:a:invisible-island:ncurses:*:*:*:*:*:*:*:*"),
    "libarchive": ("libarchive", "cpe:2.3:a:libarchive:libarchive:*:*:*:*:*:*:*:*"),
}


def _known(name: str) -> Tuple[Optional[str], Optional[str]]:
    entry = KNOWN.get(name.lower())
    return entry if entry else (None, None)


def read_linux_ecosystems(root: Path) -> List[Declaration]:
    root = Path(root).resolve()
    out: List[Declaration] = []
    out.extend(read_buildroot(root))
    out.extend(read_openwrt(root))
    out.extend(read_kbuild(root))
    return out


# --------------------------------------------------------------------- helpers

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _walk(root: Path, max_depth: int = _MAX_DEPTH):
    root = Path(root)
    base = len(root.parts)
    for here, dirs, files in os.walk(root):
        depth = len(Path(here).parts) - base
        dirs[:] = [d for d in dirs if d not in _SKIP and not d.startswith(".")
                   and depth < max_depth]
        yield Path(here), files


def _configs(root: Path, marker: str) -> List[Path]:
    """``.config`` files (root, ``output/``, ``out/*/``) that select *marker* symbols."""
    found: List[Path] = []
    for candidate in [root / ".config", root / "output" / ".config"] + sorted(
            (root / "out").glob("*/.config") if (root / "out").is_dir() else []):
        if candidate.is_file():
            try:
                if marker in _read(candidate):
                    found.append(candidate)
            except OSError:
                pass
    return found


def _literal(value: str) -> Optional[str]:
    value = value.strip().strip('"').strip("'")
    if not value or "$" in value or "(" in value:
        return None
    return value


# ------------------------------------------------------------------- Buildroot

_BR_SELECTED = re.compile(r"^BR2_PACKAGE_([A-Z0-9_]+)=y\s*$", re.M)
_BR_VERSION = re.compile(r"^([A-Z0-9_]+)_VERSION\s*[:?]?=[ \t]*(.+?)\s*$", re.M)


def read_buildroot(root: Path) -> List[Declaration]:
    out: List[Declaration] = []
    for base in _buildroot_roots(root):
        configs = _configs(base, "BR2_PACKAGE_") or _configs(root, "BR2_PACKAGE_")
        if not configs:
            continue
        selected = set(_BR_SELECTED.findall(_read(configs[0])))
        source = configs[0].relative_to(root).as_posix()
        recipes: Dict[str, Tuple[Path, str]] = {}
        for here, files in _walk(base / "package", 3):
            for name in files:
                if not name.endswith(".mk"):
                    continue
                for symbol, value in _BR_VERSION.findall(_read(here / name)):
                    version = _literal(value)
                    if version and symbol in selected and symbol not in recipes:
                        recipes[symbol] = (here, version)
        for symbol in sorted(recipes):
            here, version = recipes[symbol]
            name = here.name
            built = base / "output" / "build" / f"{name}-{version}"
            display, cpe = _known(name)
            out.append(Declaration(
                ecosystem=ECOSYSTEM_BUILDROOT, name=name,
                directory=(built if built.is_dir() else here).resolve(),
                source=source, version=version, version_is_upstream=True,
                cpe=cpe, display_name=display))
    return out


def _buildroot_roots(root: Path) -> List[Path]:
    roots = []
    for here, files in _walk(root, 3):
        if (here / "package" / "Config.in").is_file() and "Makefile" in files:
            roots.append(here)
    return roots


# --------------------------------------------------------------------- OpenWrt

_OW_SELECTED = re.compile(r"^CONFIG_PACKAGE_([A-Za-z0-9_.+-]+)=y\s*$", re.M)
_OW_NAME = re.compile(r"^PKG_NAME\s*[:?]?=[ \t]*(\S+)", re.M)
_OW_VERSION = re.compile(r"^PKG_VERSION\s*[:?]?=[ \t]*(\S+)", re.M)


def read_openwrt(root: Path) -> List[Declaration]:
    configs = _configs(root, "CONFIG_PACKAGE_")
    if not configs:
        return []
    selected = set(_OW_SELECTED.findall(_read(configs[0])))
    source = configs[0].relative_to(root).as_posix()
    out: List[Declaration] = []
    seen = set()
    for here, files in _walk(root, _MAX_DEPTH):
        parts = here.relative_to(root).parts
        if "Makefile" not in files or not ("package" in parts or "feeds" in parts):
            continue
        text = _read(here / "Makefile")
        name_m, ver_m = _OW_NAME.search(text), _OW_VERSION.search(text)
        if not name_m or not ver_m:
            continue
        name, version = _literal(name_m.group(1)), _literal(ver_m.group(1))
        if not name or not version or name not in selected or name in seen:
            continue
        seen.add(name)
        display, cpe = _known(name)
        out.append(Declaration(
            ecosystem=ECOSYSTEM_OPENWRT, name=name, directory=here.resolve(),
            source=source, version=version, version_is_upstream=True,
            cpe=cpe, display_name=display))
    return out


# ----------------------------------------------------------------------- Kbuild

_KB_FIELD = re.compile(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)[ \t]*=[ \t]*(\S*)", re.M)

_KBUILD_KINDS = (
    # (name, display, marker files all present, CPE, vendor-tree note)
    ("linux-kernel", "Linux kernel", ("init/main.c", "kernel/sched"),
     "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
     "vendor kernel trees carry many backported fixes; the version number alone "
     "does not say which CVEs apply"),
    ("u-boot", "U-Boot", ("common/main.c", "include/configs"),
     "cpe:2.3:a:denx:u-boot:*:*:*:*:*:*:*:*",
     "vendor U-Boot trees are forks; check the fork's history before trusting the version"),
    ("busybox", "BusyBox", ("applets/applets.c", "archival"),
     "cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*", None),
)


def read_kbuild(root: Path) -> List[Declaration]:
    out: List[Declaration] = []
    for here, files in _walk(root, _MAX_DEPTH):
        if "Makefile" not in files:
            continue
        for name, display, markers, cpe, note in _KBUILD_KINDS:
            if not all((here / m).exists() for m in markers):
                continue
            fields = dict(_KB_FIELD.findall(_read(here / "Makefile")[:4000]))
            if not fields.get("VERSION"):
                continue
            version = ".".join(p for p in (fields.get("VERSION"),
                                           fields.get("PATCHLEVEL"),
                                           fields.get("SUBLEVEL")) if p)
            version += fields.get("EXTRAVERSION", "") if fields.get("EXTRAVERSION") else ""
            out.append(Declaration(
                ecosystem=ECOSYSTEM_KBUILD, name=name, display_name=display,
                directory=here.resolve(),
                source=(here / "Makefile").relative_to(root).as_posix() or "Makefile",
                version=version, version_is_upstream=True, cpe=cpe,
                forked=note is not None, fork_note=note))
    return out
