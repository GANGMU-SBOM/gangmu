"""Alpine package versions (apk-tools ``version.c``): ``1.2.11-r3``, ``2.4a_rc1-r0``.

``<digits>(.<digits>)*[letter](_suffix[digits])*(-r<digits>)``. The suffixes
``_alpha _beta _pre _rc`` sort before the bare version, ``_cvs _svn _git _hg _p`` after it.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*)"
                      r"(?:-r([0-9]+))?$")
_SUFFIX_RANK = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
_Parsed = Tuple[List[int], str, List[Tuple[int, int]], int]


def parse(version: str) -> Optional[_Parsed]:
    found = _PATTERN.match(version.strip())
    if not found:
        return None
    numbers = [int(n) for n in found.group(1).split(".")]
    suffixes = [(_SUFFIX_RANK[m.group(1)], int(m.group(2) or 0))
                for m in re.finditer(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)([0-9]*)", found.group(3))]
    return numbers, found.group(2), suffixes, int(found.group(4) or 0)


def has_revision(version: Optional[str]) -> bool:
    return version is not None and re.search(r"-r[0-9]+$", version.strip()) is not None


def compare(a: str, b: str) -> Optional[int]:
    """-1, 0, 1 as apk orders *a* against *b*; None when either is not an apk version."""
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    for left, right in ((pa[0], pb[0]), (pa[1], pb[1])):
        if isinstance(left, list):
            size = max(len(left), len(right))          # type: ignore[arg-type]
            left = left + [0] * (size - len(left))     # type: ignore[operator]
            right = right + [0] * (size - len(right))  # type: ignore[operator]
        if left != right:
            return -1 if left < right else 1           # type: ignore[operator]
    size = max(len(pa[2]), len(pb[2]))
    for i in range(size):
        sa = pa[2][i] if i < len(pa[2]) else (0, 0)
        sb = pb[2][i] if i < len(pb[2]) else (0, 0)
        if sa != sb:
            return -1 if sa < sb else 1
    return (pa[3] > pb[3]) - (pa[3] < pb[3])
