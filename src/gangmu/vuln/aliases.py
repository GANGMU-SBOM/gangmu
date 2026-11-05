"""Purl aliases: one upstream, several names.

OSV files a C library under the repository its fix commit lives in
(``pkg:github/madler/zlib``) and, separately, under each distribution that ships it
(``pkg:deb/debian/zlib``). An SBOM from another tool names the same zlib by whatever
it found: ``pkg:deb/echo/zlib-1.2.11``, a Yocto recipe, an OpenWrt package. A match on
the purl alone sees three unrelated products.

A rule says which names are one product with ``upstream.identifiers``. This module turns
those into a lookup: given the purls of an SBOM component, the other purls of the same
upstream, so the OSV channel can be asked under every one of them.

Only names a rule states are joined. Nothing is guessed from similarity; the one
normalisation is for distribution purls, which are compared without the distribution
namespace (``echo``, ``debian``, ``ubuntu`` ...) and with a ``-<version>`` suffix on the
name removed, because tools write ``zlib-1.2.11`` where the spec says name ``zlib``.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# purl types whose namespace is a distribution, not an owner of the project
DISTRO_TYPES = frozenset({"deb", "rpm", "apk", "alpm", "ebuild", "opkg"})
_VERSION_SUFFIX = re.compile(r"-(?=\d)[0-9][\w.+~:]*$")


def strip_version(purl: str) -> str:
    """``pkg:type/ns/name@1.0?arch=x#sub`` -> ``pkg:type/ns/name`` (case kept)."""
    body = purl.split("#", 1)[0].split("?", 1)[0]
    at = body.find("@", body.rfind("/") + 1)
    return body[:at] if at != -1 else body


def _split(purl: str) -> Optional[Tuple[str, str, str]]:
    """(type, namespace, name) of a purl, lower-cased; None when it is not one."""
    from urllib.parse import unquote
    if not purl or not purl.startswith("pkg:"):
        return None
    body = unquote(strip_version(purl)[4:]).strip("/")
    kind, _, rest = body.partition("/")
    if not kind or not rest:
        return None
    namespace, _, name = rest.rpartition("/")
    return kind.lower(), namespace.lower(), name.lower()


def keys_for(purl: str) -> Set[str]:
    """Every key a purl can be found under: its strict key, and for a distribution
    purl the namespace-free keys of its name with and without a version suffix."""
    parts = _split(purl)
    if parts is None:
        return set()
    kind, namespace, name = parts
    strict = f"pkg:{kind}/{namespace}/{name}" if namespace else f"pkg:{kind}/{name}"
    keys = {strict}
    if kind in DISTRO_TYPES:
        keys.add(f"pkg:{kind}/*/{name}")
        stripped = _VERSION_SUFFIX.sub("", name)
        if stripped and stripped != name:
            keys.add(f"pkg:{kind}/*/{stripped}")
    return keys


def purl_version(purl: str) -> Optional[str]:
    """The ``@version`` of a purl, percent-decoded (``1%3A1.2.11`` -> ``1:1.2.11``)."""
    from urllib.parse import unquote
    body = purl.split("#", 1)[0].split("?", 1)[0]
    at = body.find("@", body.rfind("/") + 1)
    return unquote(body[at + 1:]) or None if at != -1 else None


def without_name_version(purl: str) -> Optional[str]:
    """``pkg:deb/echo/zlib-1.2.11`` -> ``pkg:deb/echo/zlib``: a distribution purl whose
    writer put the version into the name, given the name the distribution uses. ``None``
    when there is nothing to take off."""
    if version_from_name(purl) is None:
        return None
    body = strip_version(purl)
    head, _, name = body.rpartition("/")
    return f"{head}/{_VERSION_SUFFIX.sub('', name)}"


def version_from_name(purl: str) -> Optional[str]:
    """The version a distribution purl wrote into its name (``zlib-1.2.11``), if any
    and if the purl carries no ``@version`` of its own."""
    parts = _split(purl)
    if parts is None or parts[0] not in DISTRO_TYPES:
        return None
    if strip_version(purl) != purl.split("#", 1)[0].split("?", 1)[0]:
        return None
    match = _VERSION_SUFFIX.search(parts[2])
    return match.group(0)[1:] if match else None


class PurlAliases:
    """Equivalence classes of purls, built from rules."""

    def __init__(self) -> None:
        self._classes: List[List[str]] = []
        self._index: Dict[str, List[int]] = {}

    def __len__(self) -> int:
        return len(self._classes)

    def add(self, purls: Iterable[str]) -> None:
        members: List[str] = []
        for purl in purls:
            key = next(iter(sorted(keys_for(purl), key=lambda k: "*" in k)), None)
            if key and key not in members:
                members.append(key)
        if len(members) < 2:
            return
        position = len(self._classes)
        self._classes.append(members)
        for purl in purls:
            for key in keys_for(purl):
                self._index.setdefault(key, []).append(position)

    @classmethod
    def from_rules(cls, rules: Iterable) -> "PurlAliases":
        built = cls()
        for rule in rules:
            identifiers = getattr(rule, "identifiers", ())
            if identifiers and rule.purl:
                built.add([rule.purl, *identifiers])
        return built

    def expand(self, purls: Sequence[str]) -> List[str]:
        """The purls of the same upstream that *purls* do not already name."""
        have: Set[str] = set()
        for purl in purls:
            have |= keys_for(purl)
        extra: List[str] = []
        seen: Set[int] = set()
        for key in sorted(have):
            for position in self._index.get(key, ()):
                if position in seen:
                    continue
                seen.add(position)
                extra.extend(m for m in self._classes[position]
                             if m not in have and m not in extra)
        return extra
