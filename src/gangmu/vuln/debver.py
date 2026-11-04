"""Debian package versions (``[epoch:]upstream[-revision]``) and OSV's Debian ranges.

Debian fixes a vulnerability in a package revision, not in the upstream release: zlib
1.2.11 is fixed in ``1:1.2.11.dfsg-4.1`` (CVE-2022-37434) with no change of upstream
version, so comparing the upstream version with the upstream project's range says nothing
about a Debian package. This implements dpkg's ordering (Debian Policy 5.6.12) and the
reading of an advisory's per-release ranges against one package version.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple


def split_version(version: str) -> Tuple[int, str, str, bool]:
    """(epoch, upstream, revision, had_epoch). The revision is after the last ``-``."""
    text = version.strip()
    epoch, had = 0, False
    head, colon, rest = text.partition(":")
    if colon and head.isdigit():
        epoch, text, had = int(head), rest, True
    upstream, dash, revision = text.rpartition("-")
    if not dash:
        upstream, revision = text, ""
    return epoch, upstream, revision, had


def _order(char: str) -> int:
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ca = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            cb = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ca != cb:
                return -1 if ca < cb else 1
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
        di = dj = ""
        while i < len(a) and a[i].isdigit():
            di += a[i]
            i += 1
        while j < len(b) and b[j].isdigit():
            dj += b[j]
            j += 1
        first = int(di or 0) - int(dj or 0)
        if first:
            return -1 if first < 0 else 1
    return 0


def compare(a: str, b: str, ignore_epoch: bool = False) -> int:
    """-1, 0 or 1 as dpkg orders *a* against *b*. *ignore_epoch* leaves the epoch out
    of both: for an SBOM that wrote ``1.2.11.dfsg-2`` where the package is ``1:1.2.11.dfsg-2``."""
    ea, ua, ra, _ = split_version(a)
    eb, ub, rb, _ = split_version(b)
    if not ignore_epoch and ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)


def has_revision(version: Optional[str]) -> bool:
    return version is not None and bool(split_version(version)[2])


def upstream_version(version: str) -> str:
    """The upstream release inside a package version: ``1:1.2.11.dfsg-2+deb11u1`` -> ``1.2.11``.
    Repackaging markers (``.dfsg``, ``+ds``, ``+really``) are dropped."""
    upstream = split_version(version)[1]
    return re.sub(r"[.+~](?:dfsg|ds|orig|really)\w*.*$", "", upstream)


def release_of(version: str) -> Optional[str]:
    """The Debian release a security-update revision belongs to: ``+deb11u2`` -> ``11``."""
    found = re.search(r"[+~]deb(\d+)u\d+", version)
    return found.group(1) if found else None
