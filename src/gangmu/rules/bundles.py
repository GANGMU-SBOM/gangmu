"""Which rules carry another rule's code, read off the signatures.

A rule built from a whole upstream tree records the libraries that project bundles
(dropbear's libtomcrypt, picotool's littlefs, tcl's zlib). Segmentation then has to
decide whose those functions are. It keeps them the bundled library's when the copy
is a small part of the host (``match.engine.BUNDLE_HOST_SHARE``); where the bundled
library is a large part of a small host, it cannot tell that from a library split out
of another (Mbed Crypto from Mbed TLS), so the functions are nobody's and the bundled
library loses its identity. What fixes that is data: the host's rule excludes the
directory it keeps the copy in, as ``identity.exclude``, and its signature is rebuilt.

``find_bundles`` lists the cases from the signatures alone; ``locate`` finds the
directories in a checkout of the host.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from itertools import chain
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..match.engine import (BUNDLE_HOST_SHARE, BUNDLE_MAX_OWNERS, BUNDLED_MIN_FUNCTIONS,
                            BUNDLED_MIN_OF_LARGEST, BUNDLED_SHARE, _release_counts,
                            _release_sizes, _repeated)


@dataclass
class Bundle:
    host: str
    bundled: str
    release: str             # the bundled rule's release that is (nearly) whole in the host
    inside: int              # of its functions, how many the host's signature holds
    size: int
    host_share: float        # the shared functions as a share of the host's signature
    mutual: bool = False     # each holds a whole release of the other: lineage, not a copy

    @property
    def kept(self) -> bool:
        """Does segmentation already keep the shared code the bundled library's?"""
        return self.host_share <= BUNDLE_HOST_SHARE

    @property
    def state(self) -> str:
        """kept; lineage (a fork or split, whose shared code rightly is nobody's); or lost
        (a copy too large a part of its host, which an ``identity.exclude`` fixes)."""
        return "kept" if self.kept else ("lineage" if self.mutual else "lost")


def find_bundles(rules) -> List[Bundle]:
    """Every (host, bundled) pair where the host's signature holds a whole bundled release."""
    sigs: Dict[str, Tuple[str, Any]] = {}       # sidecar digest -> (rule id, signature)
    family: Dict[str, Optional[str]] = {}
    for rule in rules:
        if rule.functions is None or rule.functions.sha256 in sigs:
            continue
        try:
            sigs[rule.functions.sha256] = (rule.id, rule.functions.load())
        except Exception:                           # noqa: BLE001
            continue
        family[rule.id] = rule.functions.family
    entries = list(sigs.values())
    shared_any = _repeated(chain.from_iterable(sig.hashes for _, sig in entries))
    owners: Dict[int, List[int]] = {}
    for i, (_, sig) in enumerate(entries):
        for h in shared_any.intersection(sig.hashes):
            owners.setdefault(h, []).append(i)
    common: Dict[Tuple[int, int], List[int]] = {}
    for h, held in owners.items():
        if 1 < len(held) <= BUNDLE_MAX_OWNERS:
            for a in held:
                for b in held:
                    if a != b:
                        common.setdefault((a, b), []).append(h)
    out: List[Bundle] = []
    for (a, b), shared in common.items():
        if len(shared) < BUNDLED_SHARE * BUNDLED_MIN_FUNCTIONS:
            continue
        (host, hsig), (bundled, bsig) = entries[a], entries[b]
        if family[host] and family[host] == family[bundled]:
            continue
        sizes = _release_sizes(bsig)
        floor = max(BUNDLED_MIN_FUNCTIONS, BUNDLED_MIN_OF_LARGEST * max(sizes, default=0))
        inside = _release_counts(bsig, shared)
        best = max((v for v, size in enumerate(sizes)
                    if size >= floor and inside[v] >= BUNDLED_SHARE * size),
                   key=lambda v: (inside[v] / sizes[v], v), default=None)
        if best is None:
            continue
        out.append(Bundle(host, bundled, bsig.versions[best], inside[best], sizes[best],
                          len(shared) / len(hsig.hash_set)))
    pairs = {(b.host, b.bundled) for b in out}
    out = [replace(b, mutual=(b.bundled, b.host) in pairs) for b in out]
    order = {"lost": 0, "lineage": 1, "kept": 2}
    out.sort(key=lambda x: (order[x.state], x.host, x.bundled))
    return out


def locate(tree: Path, rulebase, host: str) -> List[Tuple[str, str, Optional[str]]]:
    """(directory, rule id, version) of every other component a scan finds in *tree*."""
    from ..scan import scan

    sidecar = next((r.functions.sha256 for r in rulebase.rules
                    if r.id == host and r.functions is not None), None)
    others = [r for r in rulebase.rules
              if r.id != host and not (sidecar and r.functions is not None
                                       and r.functions.sha256 == sidecar)]
    result = scan(Path(tree), replace(rulebase, rules=others), None)
    return sorted((f.directory, f.rule_id, f.version) for f in result.findings
                  if f.directory not in (".", ""))


def exclude_globs(found: Sequence[Tuple[str, str, Optional[str]]],
                  subdir: str = "") -> List[str]:
    """The ``identity.exclude`` entries for *found*, relative to the rule's own root."""
    prefix = subdir.strip("/") + "/" if subdir and subdir not in (".", "") else ""
    globs: List[str] = []
    seen: Set[str] = set()
    for directory, _, _ in found:
        rel = directory[len(prefix):] if prefix and directory.startswith(prefix) else directory
        if any(rel == s or rel.startswith(s + "/") for s in seen):
            continue                            # inside a directory already excluded
        seen.add(rel)
        globs.append(f"{rel}/**")
    return globs
