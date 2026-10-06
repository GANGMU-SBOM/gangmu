"""Near matching of edited function bodies, for patch presence.

An exact body hash answers "is this the vulnerable (or fixed) function". A
vendor who changed one line anywhere in it defeats that, and the function falls
into ``modified``: defined, but neither body. That is where the 1-day literature
spends most of its effort (VULTURE uses TLSH over whole functions; V1SCAN and
MOVERY compare the changed lines). A whole-body similarity cannot answer the
question either: a function that differs from the vulnerable body by a logging
line and from the fixed body by the fix is *equally* close to both.

What separates them is the fix itself. Take the token windows (shingles) of the
vulnerable body and of the fixed body:

    added   = shingles(fixed)      - shingles(vulnerable)    what the fix wrote
    removed = shingles(vulnerable) - shingles(fixed)         what the fix took out

and ask of an edited candidate how much of each it carries. Carrying the added
code and none of the removed code is a fixed variant; carrying the removed code
and none of the added is a vulnerable one; anything between is left alone.
Unrelated edits (a log line, a renamed local) add and remove windows that are in
neither set, so they do not move the answer. This is the chunk comparison of
VULTURE, done on token windows so formatting never matters.

Everything here is deterministic and uses no external library: a window is a
64-bit hash of ``k`` consecutive tokens, a set is sampled by keeping its
smallest hashes (a bottom-k sketch, which keeps fractions and Jaccard estimates
unbiased), and the same seed is used everywhere.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set, Tuple

SHINGLE = 4            # tokens per window
SKETCH = 64            # bottom-k size for whole-body similarity
SAMPLE = 128           # bottom-k size for the added / removed sets
SEED = 0x6E65_6172
MIN_RELATED = 0.5      # below this the candidate is a rewrite, not an edited copy
# Measured on cJSON's history (112 security fixes against 49 releases, 5,145 cases):
# claims are all right from 0.70 and start to be wrong at 0.65, so 0.8 keeps a
# margin from the edge rather than sitting beside it.
FIXED_ADDED = 0.80     # share of the fix's added windows a fixed variant carries
FIXED_REMOVED = 0.25   # ... and the most of the removed ones it may still carry
MIN_SIGNAL = 3         # fewer added/removed windows than this is not evidence
# A fix that only inserts code "removes" the windows that straddle the insertion
# point: SHINGLE - 1 of them. Any vendor edit beside it destroys them, so a removed
# set that small is the seam of an insertion, not code the fix took out.
SEAM = 2 * SHINGLE


def shingles(tokens: Sequence[bytes], k: int = SHINGLE) -> Set[int]:
    """Hashes of every window of *k* consecutive tokens."""
    if len(tokens) < k:
        return {_hash(tokens)} if tokens else set()
    return {_hash(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def _hash(window: Sequence[bytes]) -> int:
    h = hashlib.blake2b(b"\x1f".join(window), digest_size=8,
                        salt=SEED.to_bytes(8, "big"))
    return int.from_bytes(h.digest(), "big")


def bottom(values: Iterable[int], k: int) -> List[int]:
    return sorted(set(values))[:k]


def jaccard(candidate: Set[int], sketch: Sequence[int], k: int = SKETCH) -> float:
    """Estimated Jaccard of *candidate* with the set *sketch* was taken from.

    Exact whenever both sets have at most *k* members.
    """
    ref = set(sketch)
    if not ref or not candidate:
        return 0.0
    mine = set(bottom(candidate, k))
    union = set(bottom(ref | mine, k))
    return len(union & ref & mine) / len(union) if union else 0.0


def share(candidate: Set[int], sample: Sequence[int]) -> Optional[float]:
    """The fraction of *sample* that *candidate* carries; ``None`` if empty."""
    if not sample:
        return None
    return sum(1 for h in sample if h in candidate) / len(sample)


@dataclass(frozen=True)
class NearDiff:
    """What a fix changed in one function, as token windows."""

    added: Tuple[int, ...] = ()
    removed: Tuple[int, ...] = ()
    vulnerable: Tuple[int, ...] = ()      # bottom-k sketch of the vulnerable body
    fixed: Tuple[int, ...] = ()           # ... and of the fixed body

    def __bool__(self) -> bool:
        return bool(self.added or self.removed)

    def to_dict(self) -> dict:
        def hexes(values: Sequence[int]) -> List[str]:
            return [f"{v:016x}" for v in values]
        return {"added": hexes(self.added), "removed": hexes(self.removed),
                "vulnerable": hexes(self.vulnerable), "fixed": hexes(self.fixed)}

    @classmethod
    def from_dict(cls, raw: dict) -> "NearDiff":
        def ints(key: str) -> Tuple[int, ...]:
            return tuple(int(h, 16) for h in raw.get(key, []) or [])
        return cls(ints("added"), ints("removed"), ints("vulnerable"), ints("fixed"))


def diff(vulnerable: Iterable[Set[int]], fixed: Iterable[Set[int]]) -> Optional[NearDiff]:
    """The near diff of a fix from the window sets of its bodies, or ``None``.

    ``None`` when either side is missing (a function the fix added or removed
    outright has no "edited" form to compare) or when the change is too small to
    be evidence: a diff of a window or two would match anything.
    """
    before: Set[int] = set().union(*vulnerable) if vulnerable else set()
    after: Set[int] = set().union(*fixed) if fixed else set()
    if not before or not after:
        return None
    added, removed = after - before, before - after
    if len(added) + len(removed) < MIN_SIGNAL:
        return None
    return NearDiff(added=tuple(bottom(added, SAMPLE)),
                    removed=tuple(bottom(removed, SAMPLE)),
                    vulnerable=tuple(bottom(before, SKETCH)),
                    fixed=tuple(bottom(after, SKETCH)))


@dataclass
class Near:
    label: str                     # "fixed" | "vulnerable" | "unclear" | "unrelated"
    added: Optional[float]         # share of the fix's added windows present
    removed: Optional[float]       # share of the removed windows still present
    related: float                 # closeness to the nearer of the two bodies

    def summary(self) -> str:
        def pct(v: Optional[float]) -> str:
            return "n/a" if v is None else f"{v:.0%}"
        return (f"carries {pct(self.added)} of the fix's added code and "
                f"{pct(self.removed)} of the code it removed")


def classify(candidate: Set[int], diff_: NearDiff) -> Near:
    """Is an edited function closer to the fixed or to the vulnerable body?"""
    related = max(jaccard(candidate, diff_.vulnerable),
                  jaccard(candidate, diff_.fixed))
    added = share(candidate, diff_.added)
    removed = share(candidate, diff_.removed) if len(diff_.removed) >= SEAM else None
    if related < MIN_RELATED:
        return Near("unrelated", added, removed, related)
    # With nothing (informative) removed, a candidate is fixed if it carries the
    # added code, and vulnerable if it lacks it while still resembling the
    # vulnerable body more than the fixed one.
    if added is not None and added >= FIXED_ADDED \
            and (removed is None or removed <= FIXED_REMOVED):
        return Near("fixed", added, removed, related)
    if removed is not None and removed >= FIXED_ADDED \
            and (added is None or added <= FIXED_REMOVED):
        return Near("vulnerable", added, removed, related)
    if removed is None and added is not None and added <= FIXED_REMOVED \
            and jaccard(candidate, diff_.vulnerable) >= jaccard(candidate, diff_.fixed):
        return Near("vulnerable", added, removed, related)
    return Near("unclear", added, removed, related)
