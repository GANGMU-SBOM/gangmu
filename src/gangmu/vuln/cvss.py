"""CVSS vectors: the CycloneDX rating method, a v3 base score, the qualitative level.

OSV records carry a vector string (``CVSS:3.1/AV:N/...``) and no number; NVD carries
both. A rating needs a score to sort on and a level from CycloneDX's fixed list, so a
v3 vector is scored here with the specification's base formula. A v4 vector is kept as
it is: its score comes from a lookup over macro vectors, and a guessed one is worse
than none.
"""

from __future__ import annotations

import math
from typing import Dict, Optional

# CycloneDX ``ratings[].severity`` values.
LEVELS = ("critical", "high", "medium", "low", "info", "none", "unknown")
# GHSA's ``database_specific.severity`` says MODERATE where CVSS says medium.
_LEVEL_ALIASES = {"moderate": "medium", "important": "high", "informational": "info"}

_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
          "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def method_for(vector: Optional[str]) -> str:
    """The CycloneDX rating method a vector string is written in."""
    text = (vector or "").upper()
    if text.startswith("CVSS:4"):
        return "CVSSv4"
    if text.startswith("CVSS:3.1"):
        return "CVSSv31"
    if text.startswith("CVSS:3"):
        return "CVSSv3"
    if text.startswith("AV:") or "/AU:" in text:      # v2 vectors have no prefix
        return "CVSSv2"
    return "other"


def level(value: Optional[str]) -> Optional[str]:
    """A severity word as one of :data:`LEVELS`, or ``None`` if it is not one."""
    if not value:
        return None
    word = str(value).strip().lower()
    word = _LEVEL_ALIASES.get(word, word)
    return word if word in LEVELS else None


def level_for_score(score: Optional[float]) -> Optional[str]:
    """The CVSS v3/v4 qualitative rating of a base score."""
    if score is None:
        return None
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number not below *value*."""
    whole = int(round(value * 100000))
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def _metrics(vector: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, sep, value = part.partition(":")
        if sep:
            out[key.upper()] = value.upper()
    return out


def base_score_v3(vector: Optional[str]) -> Optional[float]:
    """The base score of a CVSS v3.0/v3.1 vector, ``None`` for anything else."""
    if method_for(vector) not in ("CVSSv3", "CVSSv31"):
        return None
    m = _metrics(vector or "")
    try:
        scope = m["S"]
        weights = {k: _V3[k][m[k]] for k in _V3}
        pr = _V3_PR[scope][m["PR"]]
    except KeyError:
        return None
    iss = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * weights["AV"] * weights["AC"] * pr * weights["UI"]
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(total, 10.0))
