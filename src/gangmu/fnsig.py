"""Multi-version function signatures.

One component, several upstream versions, one file. For each function body hash
the signature records **which versions contain it**, which is what makes two
things possible that a single-version fingerprint cannot do:

*Adaptive version ranges* (TIVER, ICSE 2025). A vendor fork typically carries
functions from more than one upstream version at once -- a backport here, a
not-yet-merged fix there. Forcing a single version onto it is the largest source
of false positives in 1-day vulnerability detection. The honest answer is the
range of versions that together explain the functions actually present.

*Version discrimination*. A function present in every release says nothing about
which release this is; a function introduced in 2.2.0 says a great deal. Weighting
by how many versions contain a function is CENTRIS's redundancy elimination seen
from the other side, and it is why function-level separates a fork from a
neighbouring release where a whole-tree sketch cannot. Measured on lwIP:

    upstream 2.2.0 vs Espressif's fork    sketch 0.949   functions 0.887
    upstream 2.2.0 vs upstream 2.1.3      sketch 0.867   functions 0.638

The gap between "a fork of this version" and "a different version" widens from
0.08 to 0.25, which is the difference between a threshold that works and one
that does not.

Format
------
Binary, because a rule carrying a few thousand 64-bit hashes is not something a
human reads. Its sha256 sits in the rule's YAML and CI regenerates it from the
upstream releases the rule names, so it is verified rather than reviewed::

    magic    "GMFN" + format byte
    u16      number of versions, then each as a length-prefixed UTF-8 string
    u32      number of exact function hashes
    per fn:  u64 body hash, u64 version bitmap, u8 flags (bit0 = application code)
    u32      number of abstract hashes (identifiers collapsed; see functions.py)
    per fn:  u64 abstract hash, u64 version bitmap

Versions beyond 64 are folded into the last bit, which only costs precision at
the ends of a very long release history.
"""

from __future__ import annotations

import hashlib
import struct
from array import array
from bisect import bisect_left
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

MAGIC = b"GMFN"
FORMAT = 2
FLAG_APPLICATION = 0x01
MAX_VERSIONS = 64


@dataclass
class FunctionSignature:
    versions: List[str]
    hashes: List[int] = field(default_factory=list)
    bitmaps: List[int] = field(default_factory=list)
    flags: List[int] = field(default_factory=list)
    abstract_hashes: List[int] = field(default_factory=list)
    abstract_bitmaps: List[int] = field(default_factory=list)

    _index: Optional[Dict[int, int]] = field(default=None, repr=False, compare=False)
    _abstract_borrowed: Set[int] = field(default_factory=set, repr=False, compare=False)
    # Derived sets, built once per signature rather than once per directory
    # scanned. Cleared whenever segmentation changes what they would contain.
    _derived: Dict[object, object] = field(default_factory=dict, repr=False,
                                           compare=False)

    def __post_init__(self) -> None:
        # Packed machine words, not lists of Python ints: a list costs about 40
        # bytes per 64-bit hash against 8 here, and a rule base holds one
        # signature per rule, so this is most of what loading the rules weighs.
        self.hashes = _packed("Q", self.hashes)
        self.bitmaps = _packed("Q", self.bitmaps)
        self.flags = _packed("B", self.flags)
        self.abstract_hashes = _packed("Q", self.abstract_hashes)
        self.abstract_bitmaps = _packed("Q", self.abstract_bitmaps)

    # ---------------------------------------------------------------- build

    @classmethod
    def build(cls, per_version: Sequence[Tuple]) -> "FunctionSignature":
        """From [(version, {exact hashes}, {abstract hashes}?)], oldest first."""
        trimmed = list(per_version)[:MAX_VERSIONS]
        versions = [row[0] for row in trimmed]

        def fold(position: int) -> Tuple[List[int], List[int]]:
            bits: Dict[int, int] = {}
            for index, row in enumerate(trimmed):
                if len(row) <= position:
                    continue
                bit = 1 << index
                for h in row[position]:
                    bits[h] = bits.get(h, 0) | bit
            ordered = sorted(bits)
            return ordered, [bits[h] for h in ordered]

        exact, exact_bits = fold(1)
        abstract, abstract_bits = fold(2)
        return cls(versions=versions, hashes=exact, bitmaps=exact_bits,
                   flags=[FLAG_APPLICATION] * len(exact),
                   abstract_hashes=abstract, abstract_bitmaps=abstract_bits)

    # ----------------------------------------------------------------- i/o

    def to_bytes(self) -> bytes:
        out = bytearray(MAGIC)
        out.append(FORMAT)
        out += struct.pack("<H", len(self.versions))
        for version in self.versions:
            raw = version.encode("utf-8")
            out += struct.pack("<H", len(raw)) + raw
        out += struct.pack("<I", len(self.hashes))
        for h, b, f in zip(self.hashes, self.bitmaps, self.flags):
            out += struct.pack("<QQB", h, b, f)
        out += struct.pack("<I", len(self.abstract_hashes))
        for h, b in zip(self.abstract_hashes, self.abstract_bitmaps):
            out += struct.pack("<QQ", h, b)
        return bytes(out)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "FunctionSignature":
        if raw[:4] != MAGIC:
            raise ValueError("not a gangmu function signature")
        if raw[4] != FORMAT:
            raise ValueError(f"function signature format {raw[4]}, expected {FORMAT}")
        pos = 5
        (count,) = struct.unpack_from("<H", raw, pos); pos += 2
        versions: List[str] = []
        for _ in range(count):
            (length,) = struct.unpack_from("<H", raw, pos); pos += 2
            versions.append(raw[pos:pos + length].decode("utf-8")); pos += length
        (n,) = struct.unpack_from("<I", raw, pos); pos += 4
        hashes, bitmaps, flags = array("Q"), array("Q"), array("B")
        for _ in range(n):
            h, b, f = struct.unpack_from("<QQB", raw, pos); pos += 17
            hashes.append(h); bitmaps.append(b); flags.append(f)
        abstract, abstract_bits = array("Q"), array("Q")
        if pos < len(raw):
            (m,) = struct.unpack_from("<I", raw, pos); pos += 4
            for _ in range(m):
                h, b = struct.unpack_from("<QQ", raw, pos); pos += 16
                abstract.append(h); abstract_bits.append(b)
        return cls(versions=versions, hashes=hashes, bitmaps=bitmaps, flags=flags,
                   abstract_hashes=abstract, abstract_bitmaps=abstract_bits)

    def write(self, path: Path) -> str:
        data = self.to_bytes()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def read(cls, path: Path) -> "FunctionSignature":
        return cls.from_bytes(Path(path).read_bytes())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    # ------------------------------------------------------------- queries

    @property
    def index(self) -> Dict[int, int]:
        if self._index is None:
            self._index = {h: i for i, h in enumerate(self.hashes)}
        return self._index

    def _memo(self, key, build):
        value = self._derived.get(key)
        if value is None:
            value = self._derived[key] = build()
        return value

    @property
    def ordered_hashes(self) -> List[int]:
        """Exact hashes ascending. The file stores them sorted, so this is
        normally the list itself and costs nothing."""
        return self._memo("ordered", lambda: _ascending(self.hashes))

    @property
    def ordered_abstract(self) -> List[int]:
        return self._memo("ordered-abstract", lambda: _ascending(self.abstract_hashes))

    @property
    def hash_set(self) -> FrozenSet[int]:
        return self._memo("all", lambda: frozenset(self.hashes))

    @property
    def abstract_set(self) -> FrozenSet[int]:
        return self._memo("abstract", lambda: frozenset(self.abstract_hashes))

    @property
    def application_hashes(self) -> FrozenSet[int]:
        """Functions that identify this component, nested code removed.

        CENTRIS's segmentation: if A vendors B, B's functions must not count
        towards detecting A, or every firmware containing B appears to contain A.
        """
        return self._memo("application", lambda: frozenset(
            h for h, f in zip(self.hashes, self.flags) if f & FLAG_APPLICATION))

    def segment(self, borrowed: Set[int]) -> int:
        """Mark *borrowed* hashes as not-application-code. Returns how many."""
        marked = 0
        for i, h in enumerate(self.hashes):
            if h in borrowed and self.flags[i] & FLAG_APPLICATION:
                self.flags[i] &= ~FLAG_APPLICATION
                marked += 1
        if marked:
            self._derived.clear()
        return marked

    def segment_abstract(self, borrowed: Set[int]) -> int:
        """The same segmentation at the abstract level.

        Without it the renaming fallback quietly undoes the segmentation: two
        rules for an upstream and its fork share thousands of functions, and
        once identifiers are collapsed those shared bodies match again. Not
        persisted -- it depends on which other rules are loaded.
        """
        before = len(self._abstract_borrowed)
        self._abstract_borrowed |= set(self.abstract_hashes) & borrowed
        if len(self._abstract_borrowed) != before:
            self._derived.clear()
        return len(self._abstract_borrowed) - before

    def discriminating(self) -> FrozenSet[int]:
        """Functions that do not appear in every recorded version.

        With a single recorded release nothing can tell versions apart, and
        every function is evidence for that release, so all of them count.
        Otherwise a one-release rule could identify the library but never say
        which version it is, though only one exists.
        """
        if len(self.versions) == 1:
            return self.hash_set
        full = (1 << len(self.versions)) - 1
        return self._memo("discriminating", lambda: frozenset(
            h for h, b in zip(self.hashes, self.bitmaps) if b != full))

    def version_hashes(self, index: int) -> FrozenSet[int]:
        """Every function of one recorded version, reconstructed from bitmaps."""
        bit = 1 << index
        return self._memo(("version", index), lambda: frozenset(
            h for h, b in zip(self.hashes, self.bitmaps) if b & bit))

    def version_discriminating(self, index: int) -> FrozenSet[int]:
        return self._memo(("version-discriminating", index),
                          lambda: self.version_hashes(index) & self.discriminating())

    def version_application_hashes(self, index: int) -> FrozenSet[int]:
        bit = 1 << index
        return self._memo(("application", index), lambda: frozenset(
            h for h, b, f in zip(self.hashes, self.bitmaps, self.flags)
            if b & bit and f & FLAG_APPLICATION))

    def version_abstract_hashes(self, index: int) -> FrozenSet[int]:
        """Same version, identifiers collapsed. The fallback when a vendor has
        renamed symbols, which exact hashing cannot survive."""
        bit = 1 << index
        return self._memo(("abstract", index), lambda: frozenset(
            h for h, b in zip(self.abstract_hashes, self.abstract_bitmaps)
            if b & bit and h not in self._abstract_borrowed))


def _packed(code: str, values: Iterable[int]) -> "array":
    return values if isinstance(values, array) and values.typecode == code \
        else array(code, values)


def _ascending(values: Sequence[int]) -> Sequence[int]:
    if all(a <= b for a, b in zip(values, values[1:])):   # as stored, normally
        return values
    return array("Q", sorted(values))


def intersects(present: Set[int], ordered: Sequence[int]) -> bool:
    """Does *present* share a value with the ascending sequence *ordered*?

    Answered without building a set of *ordered*: a few bisections when the
    directory is small, one C-level membership sweep when the rule is. Holding
    a frozenset per rule instead cost about 70 bytes per recorded function,
    which for a few hundred rules was more memory than the scan itself.
    """
    if not present or not ordered:
        return False
    n = len(ordered)
    if len(present) * 16 < n:
        for h in present:
            i = bisect_left(ordered, h)
            if i < n and ordered[i] == h:
                return True
        return False
    return any(map(present.__contains__, ordered))


@dataclass
class VersionVerdict:
    """What the matched functions say about which version this is."""

    best: Optional[str]
    low: Optional[str]
    high: Optional[str]
    support: float               # share of discriminating functions explained
    multi_version: bool          # functions from more than one version present
    detail: str = ""
    best_index: int = -1
    foreign: int = 0             # matched functions no recorded version explains
    # Recorded functions of the identified release that are absent from the tree:
    # edited (the old body is gone), removed, or never copied. This, not
    # ``foreign`` or ``multi_version``, says the copy differs from the release.
    # Both of those are noisy on pristine trees: ``foreign`` counts every
    # function in files the signature never covered (headers, ports) and
    # ``multi_version`` fires on a handful of bodies shared between releases.
    changed: int = 0

    @property
    def is_range(self) -> bool:
        return bool(self.low and self.high and self.low != self.high)

    @property
    def label(self) -> Optional[str]:
        if not self.best:
            return None
        if self.is_range:
            return f"{self.low}~{self.high}"
        return self.best


def infer_version(signature: FunctionSignature, present: Set[int]) -> VersionVerdict:
    """TIVER-style adaptive version: the range of versions actually present.

    Only *discriminating* functions vote -- one present in every release carries
    no information about which release this is, and letting it vote would make
    every component look like its own first version.
    """
    if not signature.versions:
        return VersionVerdict(None, None, None, 0.0, False, "no versions recorded")

    discriminating = signature.discriminating()
    matched = present & signature.hash_set
    voters = matched & discriminating
    if not voters:
        return VersionVerdict(
            None, None, None, 0.0, False,
            "no version-discriminating function matched: every function present "
            "appears in all recorded versions, so the version cannot be narrowed")

    index = signature.index
    # Score each version by Jaccard over discriminating functions, not by raw
    # coverage. Coverage alone cannot separate a release from its successor: the
    # successor contains everything the release did, so it always ties. Jaccard
    # charges a version for the discriminating functions it has and the tree
    # does not, which is exactly the evidence that says "not that one".
    scores: List[float] = []
    overlaps: List[int] = []
    for v in range(len(signature.versions)):
        own = signature.version_discriminating(v)
        overlap = len(voters & own)
        union = len(voters | own)
        overlaps.append(overlap)
        scores.append(overlap / union if union else 0.0)

    best_score = max(scores)
    best_index = scores.index(best_score)
    # The adaptive range: every version that explains the tree about as well.
    threshold = best_score * 0.95
    explained = [i for i, s in enumerate(scores) if s >= threshold]
    low_index, high_index = min(explained), max(explained)

    best_bit = 1 << best_index
    unexplained = sum(1 for h in voters
                      if not signature.bitmaps[index[h]] & best_bit)
    multi = unexplained > 0
    foreign = len(present) - len(matched)
    changed = len(signature.version_application_hashes(best_index) - present)

    detail = (f"{len(voters)} version-discriminating function(s) matched; "
              f"{overlaps[best_index]} are in {signature.versions[best_index]} "
              f"(agreement {best_score:.2f})")
    if multi and changed:
        detail += (f", and {unexplained} belong to other recorded versions -- "
                   f"this tree mixes releases, which is what a vendor fork "
                   f"looks like ({changed} recorded function(s) of "
                   f"{signature.versions[best_index]} are missing or altered)")
    elif multi:
        detail += (f", and {unexplained} also belong to other recorded versions "
                   f"(this tree mixes releases), but every recorded function of "
                   f"{signature.versions[best_index]} is present, so this is not "
                   f"by itself evidence of modification")
    if foreign:
        detail += (f"; {foreign} function(s) match no recorded version at all "
                   f"(vendor additions, a release not in the signature, or code "
                   f"in files the signature does not cover)")
    return VersionVerdict(
        best=signature.versions[best_index],
        low=signature.versions[low_index],
        high=signature.versions[high_index],
        support=best_score,
        multi_version=multi,
        detail=detail,
        best_index=best_index,
        foreign=foreign,
        changed=changed)


def infer_version_subset(signature: FunctionSignature, present: Set[int]) -> VersionVerdict:
    """Version of a *partial* copy: the releases that contain every function found.

    ``infer_version`` scores by Jaccard against a whole release, which punishes a
    tree for the files it does not hold and so favours the smallest release. For
    a pruned copy the right question is the reverse: which releases have all of
    what is here. Releases tie when the functions present did not change between
    them, and the answer is then the range they span.
    """
    matched = present & signature.hash_set
    if not signature.versions or not matched:
        return VersionVerdict(None, None, None, 0.0, False, "no recorded function matched")
    index = signature.index
    covered = [0] * len(signature.versions)
    for h in matched:
        bitmap = signature.bitmaps[index[h]]
        for v in range(len(covered)):
            if bitmap >> v & 1:
                covered[v] += 1
    best_cover = max(covered)
    tied = [v for v, c in enumerate(covered) if c == best_cover]
    low_index, high_index = min(tied), max(tied)
    best_index = high_index if len(tied) > 1 else tied[0]
    share = best_cover / len(matched)
    detail = (f"{best_cover} of the {len(matched)} recorded function(s) in this "
              f"partial copy are in {signature.versions[best_index]}"
              + (f" and in {len(tied) - 1} other release(s) whose code for these "
                 f"functions is identical" if len(tied) > 1 else "")
              + (f"; {len(matched) - best_cover} belong to other releases only"
                 if best_cover < len(matched) else ""))
    return VersionVerdict(
        best=signature.versions[best_index],
        low=signature.versions[low_index],
        high=signature.versions[high_index],
        support=share,
        multi_version=best_cover < len(matched),
        detail=detail, best_index=best_index,
        foreign=len(present) - len(matched),
        changed=len(matched) - best_cover)
