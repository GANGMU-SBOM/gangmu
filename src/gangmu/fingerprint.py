"""Winnowed k-gram fingerprints and bottom-k sketches.

Why this pair
-------------
*Winnowing* (Schleimer, Wilkerson & Aiken, 2003) picks a deterministic subset of
a document's k-grams such that any shared passage longer than the guarantee
threshold is certain to contribute at least one selected fingerprint. That makes
it robust to a vendor inserting or deleting whole blocks of code.

A *bottom-k sketch* (k-minimum values) then compresses the fingerprint set to a
fixed-size summary small enough for a rule file to carry. Comparing two sketches
estimates the Jaccard similarity of the underlying sets, which is exactly the
question "how much of upstream is still in this directory".

k-grams are counted in *tokens*, not bytes, so re-indentation is free.

Why bottom-k and not k-permutation MinHash
------------------------------------------
The usual MinHash takes 128 permutations of every fingerprint: on a 300-file
tree that is 128 x 105,000 modular multiplications, and it measured at 6.0 s out
of a 9.7 s scan -- more than everything else combined. Bottom-k gets an estimator
of the same quality from a single pass (take the 128 smallest distinct hashes),
costs O(n) instead of O(n*128), and stores exactly the same 1 KB. The measured
similarities are unchanged to three decimals; see docs/CALIBRATION.md.

Everything is seeded from constants, so the same input always yields the same
sketch on any machine and any Python build. Rule CI depends on that: it
regenerates each rule's sketch from the declared upstream release and fails the
pull request if the result differs.
"""

from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .normalize import tokenize

# numpy is optional (pip install gangmu-sbom[fast]) and imported on first use,
# so commands that never fingerprint do not pay its import time or memory.
_UNSET = object()
_np = _UNSET


def numpy_module():
    global _np
    if _np is _UNSET:
        try:
            import numpy
            _np = numpy
        except ImportError:             # pragma: no cover - exercised without numpy
            _np = None
    return _np

ALGO = "winnow-bottomk"
DEFAULT_K = 16          # k-gram length, in tokens
DEFAULT_WINDOW = 8      # winnowing window, in k-grams
DEFAULT_SKETCH = 256    # bottom-k sketch size; 128 showed up to 0.04 error near the 0.85 band
SEED = 0x6761_6E67      # "gang"; fixed forever -- changing it invalidates every rule

_MASK = (1 << 64) - 1
_BASE = 0x9E3779B97F4A7C15          # odd, so multiplication mod 2**64 is a bijection
_SEP = b"\x1f"


def _hash64(data: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(data, digest_size=8,
                                          salt=SEED.to_bytes(8, "big")).digest(), "big")


def _mix(x: int) -> int:
    """splitmix64 finaliser.

    A polynomial rolling hash mod 2**64 has poor high bits, and bottom-k selects
    on exactly those. Without this, sketches would be dominated by whichever
    k-grams happen to start with a small token hash.
    """
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9 & _MASK
    x = (x ^ (x >> 27)) * 0x94D049BB133111EB & _MASK
    return x ^ (x >> 31)


_TOKEN_HASHES: Dict[bytes, int] = {}
_TOKEN_HASHES_MAX = 1 << 18


def token_hashes(tokens: Sequence[bytes]) -> List[int]:
    """One 64-bit hash per token, memoised -- C source repeats tokens heavily,
    within a file and across a whole SDK, so the memo outlives the call (and is
    simply dropped if it grows past a quarter of a million tokens)."""
    cache = _TOKEN_HASHES
    if len(cache) > _TOKEN_HASHES_MAX:
        cache.clear()
    out: List[int] = []
    append = out.append
    get = cache.get
    for tok in tokens:
        h = get(tok)
        if h is None:
            h = cache[tok] = _hash64(tok)
        append(h)
    return out


def kgram_hashes(tokens: Sequence[bytes], k: int = DEFAULT_K) -> List[int]:
    """Rolling polynomial hash over token hashes.

    The previous implementation joined k tokens and ran blake2b per position,
    which is O(k) work per k-gram. This is O(1) per position after the first.
    """
    if not tokens:
        return []
    hashes = token_hashes(tokens)
    n = len(hashes)
    if n < k:
        return [_mix(_hash64(_SEP.join(tokens)))]

    power = pow(_BASE, k - 1, 1 << 64)
    acc = 0
    for i in range(k):
        acc = (acc * _BASE + hashes[i]) & _MASK
    out = [_mix(acc)]
    append = out.append
    base, mask = _BASE, _MASK
    # _mix inlined: a function call per k-gram was a quarter of this loop.
    for old, new in zip(hashes, hashes[k:]):
        acc = ((acc - old * power) * base + new) & mask
        x = ((acc ^ (acc >> 30)) * 0xBF58476D1CE4E5B9) & mask
        x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & mask
        append(x ^ (x >> 31))
    return out


def winnow(hashes: Sequence[int], window: int = DEFAULT_WINDOW) -> Set[int]:
    """The set of sliding-window minima.

    Winnowing records the minimum of each window, once per position it occurs
    at; as a *set* of values that is exactly the set of window minima, whichever
    position wins a tie. So the minima are taken with ``min`` over ``window``
    shifted views at once, element-wise in C, rather than with a Python-level
    monotonic deque (which ``tests/test_performance.py`` still checks this
    against).
    """
    n = len(hashes)
    if n == 0:
        return set()
    if n <= window:
        return {min(hashes)}
    span = n - window + 1
    if not isinstance(hashes, list):
        hashes = list(hashes)
    return set(map(min, *(hashes[i:i + span] for i in range(window))))


_VECTOR_MIN_TOKENS = 256      # below this the Python loop is as fast


def sorted_fingerprints(tokens: Sequence[bytes], k: int = DEFAULT_K,
                        window: int = DEFAULT_WINDOW,
                        limit: Optional[int] = None) -> Tuple[List[int], int]:
    """Ascending distinct winnowed fingerprints, at most *limit* of them, and
    how many there were in total.

    Same values as ``sorted(winnow(kgram_hashes(tokens, k), window))``. With
    numpy installed the rolling hash, the splitmix finaliser and the window
    minima run as uint64 vector operations, whose wrap-around arithmetic is
    exactly the mod 2**64 arithmetic of the pure-Python loop; the tests check
    the two paths agree value for value.
    """
    np = numpy_module() if len(tokens) >= _VECTOR_MIN_TOKENS else None
    if np is None or len(tokens) < max(k, 2) + window:
        values = sorted(winnow(kgram_hashes(tokens, k), window))
        return (values if limit is None else values[:limit]), len(values)
    h = np.array(token_hashes(tokens), dtype=np.uint64)
    span = len(h) - k + 1
    with np.errstate(over="ignore"):
        acc = np.zeros(span, dtype=np.uint64)
        for i in range(k):
            acc *= np.uint64(_BASE)
            acc += h[i:i + span]
        x = (acc ^ (acc >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        x = (x ^ (x >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
        x ^= x >> np.uint64(31)
    width = span - window + 1
    minima = x[:width].copy()
    for i in range(1, window):
        np.minimum(minima, x[i:i + width], out=minima)
    unique = np.unique(minima)
    head = unique if limit is None else unique[:limit]
    return head.tolist(), int(unique.size)


def fingerprint_bytes(data: bytes, k: int = DEFAULT_K,
                      window: int = DEFAULT_WINDOW) -> Set[int]:
    return winnow(kgram_hashes(tokenize(data), k), window)


@dataclass(frozen=True)
class Signature:
    """A bottom-k sketch plus the parameters needed to reproduce it."""

    values: List[int]                 # ascending, distinct
    k: int = DEFAULT_K
    window: int = DEFAULT_WINDOW
    size: int = DEFAULT_SKETCH

    def to_hex(self) -> str:
        return "".join(v.to_bytes(8, "big").hex() for v in self.values)

    @classmethod
    def from_hex(cls, blob: str, k: int = DEFAULT_K, window: int = DEFAULT_WINDOW,
                 size: int = DEFAULT_SKETCH) -> "Signature":
        raw = bytes.fromhex("".join(blob.split()))
        if len(raw) % 8:
            raise ValueError(f"sketch is {len(raw)} bytes, not a multiple of 8")
        if len(raw) > size * 8:
            raise ValueError(
                f"sketch holds {len(raw) // 8} values, more than size={size}")
        values = [int.from_bytes(raw[i:i + 8], "big") for i in range(0, len(raw), 8)]
        if values != sorted(values):
            raise ValueError("sketch values must be ascending")
        return cls(values=values, k=k, window=window, size=size)

    def similarity(self, other: "Signature") -> float:
        """k-minimum-values Jaccard estimate.

        Merge both sketches, keep the smallest ``m`` distinct values, and count
        how many of those are in *both* sketches. ``m`` is capped by the shorter
        sketch, so a small component -- which may not have 128 distinct
        fingerprints at all -- is still comparable.
        """
        if (self.k, self.window) != (other.k, other.window):
            raise ValueError("sketches use different parameters and cannot be compared")
        a, b = self.values, other.values
        if not a or not b:
            return 0.0
        m = min(len(a), len(b), self.size, other.size)
        merged = heapq.merge(a, b)
        smallest: List[int] = []
        last = None
        for value in merged:
            if value != last:
                smallest.append(value)
                last = value
                if len(smallest) == m:
                    break
        sa, sb = set(a), set(b)
        both = sum(1 for v in smallest if v in sa and v in sb)
        return both / len(smallest) if smallest else 0.0


def signature_from_fingerprints(fps: Iterable[int], k: int = DEFAULT_K,
                                window: int = DEFAULT_WINDOW,
                                size: int = DEFAULT_SKETCH) -> Signature:
    unique = fps if isinstance(fps, set) else set(fps)
    if not unique:
        return Signature(values=[], k=k, window=window, size=size)
    if len(unique) <= size:
        values = sorted(unique)
    else:
        values = sorted(heapq.nsmallest(size, unique))
    return Signature(values=values, k=k, window=window, size=size)
