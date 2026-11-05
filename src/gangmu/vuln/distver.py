"""Is a distribution package affected? Read it against that distribution's own records.

A distribution fixes a vulnerability in a package revision of each release, usually
without changing the upstream version (Debian fixed zlib 1.2.11's CVE-2022-37434 in
``1:1.2.11.dfsg-4.1``), so the upstream project's range says nothing about the package.
OSV's records for Debian, Ubuntu and Alpine give one range per release and package;
this reads the ones of the package's own distribution with that distribution's version
order. Debian and Ubuntu order versions alike (dpkg); Alpine has its own (apk).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import unquote

from . import apkver, debver


@dataclass(frozen=True)
class Family:
    name: str                 # "debian" | "ubuntu" | "alpine"
    purl_prefix: str          # the purl key prefix of this distribution's records
    ecosystem: str            # OSV ecosystem prefix, lower-case
    has_revision: Callable[[Optional[str]], bool]


FAMILIES = {
    "debian": Family("debian", "pkg:deb/debian/", "debian", debver.has_revision),
    "ubuntu": Family("ubuntu", "pkg:deb/ubuntu/", "ubuntu", debver.has_revision),
    "alpine": Family("alpine", "pkg:apk/alpine/", "alpine", apkver.has_revision),
    # Echo's hardened images are Debian-based: pkg:deb/echo/<name>, dpkg versions such as
    # 1:1.3.dfsg+really1.3.1-1+e2, one stream (the OSV ecosystem is plain "Echo").
    "echo": Family("echo", "pkg:deb/echo/", "echo", debver.has_revision),
}

_DEBIAN = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
_UBUNTU = {"xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
           "noble": "24.04", "plucky": "25.04", "questing": "25.10"}


def family_of_key(key: Optional[str]) -> Optional[Family]:
    """The distribution a purl key belongs to (``pkg:deb/ubuntu/zlib``), or None."""
    for family in FAMILIES.values():
        if (key or "").startswith(family.purl_prefix):
            return family
    return None


def family_of_purl(purl: str) -> Optional[Family]:
    body = unquote(purl.split("#", 1)[0].split("?", 1)[0]).lower()
    return family_of_key(body)


def _qualifier(purl: str, name: str) -> Optional[str]:
    query = purl.split("#", 1)[0].partition("?")[2]
    for part in query.split("&"):
        key, _, value = part.partition("=")
        if key == name and value:
            return unquote(value)
    return None


def release_from_purl(purl: str, version: Optional[str]) -> Optional[str]:
    """The release a package belongs to, from its purl's ``distro`` qualifier
    (``debian-11``, ``bullseye``, ``ubuntu-22.04``, ``alpine-3.18.4``) or, for Debian,
    from a security revision (``+deb11u2``) and, for Ubuntu, a backport (``~22.04.1``)."""
    family = family_of_purl(purl)
    if family is None:
        return None
    distro = (_qualifier(purl, "distro") or "").lower().split("/")[-1]
    if family.name == "debian":
        if distro in _DEBIAN:
            return _DEBIAN[distro]
        found = re.search(r"(\d+)$", distro)
        if found:
            return found.group(1)
        return debver.release_of(version or "")
    if family.name == "ubuntu":
        if distro in _UBUNTU:
            return _UBUNTU[distro]
        found = re.search(r"(\d\d\.\d\d)", distro) or re.search(r"~(\d\d\.\d\d)", version or "")
        return found.group(1) if found else None
    found = re.search(r"(\d+\.\d+)", distro)           # alpine-3.18.4 -> 3.18
    return found.group(1) if found else None


def _release_of_ecosystem(ecosystem: str) -> Optional[str]:
    found = re.search(r"(\d\d\.\d\d)", ecosystem) or re.search(r"v?(\d+\.\d+)", ecosystem) \
        or re.search(r":(\d+)$", ecosystem)
    return found.group(1) if found else None


def _compare(family: Family, a: str, b: str, ignore_epoch: bool) -> Optional[int]:
    if family.name == "alpine":
        return apkver.compare(a, b)
    return debver.compare(a, b, ignore_epoch)


def _in(family: Family, version: str, rng: Mapping, ignore_epoch: bool) -> Optional[bool]:
    introduced, fixed, last = rng.get("introduced"), rng.get("fixed"), rng.get("last_affected")
    for bound, ok in ((introduced if introduced != "0" else None, lambda c: c >= 0),
                      (fixed, lambda c: c < 0), (last, lambda c: c <= 0)):
        if bound:
            order = _compare(family, version, bound, ignore_epoch)
            if order is None:
                return None
            if not ok(order):
                return False
    return True


def verdict(family: Family, version: str, candidates: Iterable[Mapping],
            release: Optional[str] = None) -> Optional[bool]:
    """Is the package *version* affected, from one vulnerability's records of *family*?

    ``None`` means it cannot be told. Each range names its release (``Debian:12``,
    ``Ubuntu:22.04:LTS``, ``Alpine:v3.18``) and the distribution fixes each separately, so
    a package whose *release* is known is read against that release's ranges only; if
    the advisory lists none for it, nothing can be said. Otherwise the package is affected
    only if every release's range says so, unaffected only if none does. A version without
    a revision is read by its upstream release alone (:func:`_by_upstream`).
    """
    ranges: List[Mapping] = [r for r in candidates
                             if str(r.get("ecosystem") or "").lower().startswith(family.ecosystem)]
    if not ranges:
        return None
    if not family.has_revision(version):
        if release is not None:
            ranges = [r for r in ranges if _release_of_ecosystem(str(r.get("ecosystem"))) == release]
        return _by_upstream(family, version, ranges)
    if release is None and family.name == "debian":
        release = debver.release_of(version)            # +deb11u2 names its own release
    elif release is None and family.name == "ubuntu":
        found = re.search(r"~(\d\d\.\d\d)", version)
        release = found.group(1) if found else None
    if release is not None:
        ranges = [r for r in ranges if _release_of_ecosystem(str(r.get("ecosystem"))) == release]
        if not ranges:
            return None
    ignore_epoch = family.name != "alpine" and not debver.split_version(version)[3]
    verdicts = {_in(family, version, r, ignore_epoch) for r in ranges}
    return verdicts.pop() if len(verdicts) == 1 else None


def _upstream(family: Family, version: str) -> str:
    """The upstream release a package version carries: no epoch, no revision, no
    repackaging marker; ``1.3.dfsg+really1.3.1`` is 1.3.1."""
    if family.name == "alpine":
        return re.sub(r"-r[0-9]+$", "", version.strip())
    upstream = debver.split_version(version)[1]
    if "really" in upstream:
        upstream = upstream.split("really", 1)[1]
    return re.sub(r"[.+~](?:dfsg|ds|orig)\w*.*$", "", upstream)


def _compare_upstream(family: Family, a: str, b: str) -> Optional[int]:
    if family.name == "alpine":
        return apkver.compare(a, b)
    return debver.compare(a, b, ignore_epoch=True)


def _by_upstream(family: Family, version: str, ranges: List[Mapping]) -> Optional[bool]:
    """A verdict from the upstream release alone, for a package written without a revision
    (``pkg:deb/echo/zlib-1.2.11``). A distribution backports a fix into a revision, never
    into an older upstream release, so an upstream below every range's fixed upstream is
    affected and one above every fixed upstream is not; the same upstream as a fix needs
    the revision, and stays undecided."""
    mine = _upstream(family, version)
    verdicts = set()
    for rng in ranges:
        introduced, fixed, last = rng.get("introduced"), rng.get("fixed"), rng.get("last_affected")
        if introduced and introduced != "0":
            order = _compare_upstream(family, mine, _upstream(family, introduced))
            if order is None:
                return None
            if order < 0:
                verdicts.add(False)
                continue
        bound = fixed or last
        if not bound:
            verdicts.add(True)                       # unfixed: every revision is affected
            continue
        order = _compare_upstream(family, mine, _upstream(family, bound))
        if order is None or order == 0:
            return None
        verdicts.add(order < 0)
    return verdicts.pop() if len(verdicts) == 1 else None


__all__: Tuple[str, ...] = ("FAMILIES", "Family", "family_of_key", "family_of_purl",
                            "release_from_purl", "verdict")
