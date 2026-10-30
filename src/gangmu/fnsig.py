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
import operator
import struct
import sys
from array import array
from bisect import bisect_left
from collections import Counter, OrderedDict
from collections.abc import Mapping
from itertools import islice
from dataclasses import dataclass, field
from pathlib import Path
from typing import (Dict, FrozenSet, Iterable, List, MutableSequence, Optional, Sequence,
                    Set, Tuple)

MAGIC = b"GMFN"
FORMAT = 2
FLAG_APPLICATION = 0x01
MAX_VERSIONS = 64
# Share of the best release's functions that must be missing or altered before an
# oldest or newest match is flagged as possibly lying beyond the recorded releases.
EDGE_ALTERED_SHARE = 0.25


@dataclass
class FunctionSignature:
    versions: List[str]
    hashes: MutableSequence[int] = field(default_factory=list)
    bitmaps: MutableSequence[int] = field(default_factory=list)
    flags: MutableSequence[int] = field(default_factory=list)
    abstract_hashes: MutableSequence[int] = field(default_factory=list)
    abstract_bitmaps: MutableSequence[int] = field(default_factory=list)

    _index: Optional[Mapping[int, int]] = field(default=None, repr=False, compare=False)
    _abstract_borrowed: Set[int] = field(default_factory=set, repr=False, compare=False)
    # Derived sets, built once per signature rather than once per directory
    # scanned. Cleared whenever segmentation changes what they would contain.
    _derived: Dict[object, object] = field(default_factory=dict, repr=False,
                                           compare=False)
    _generation: int = field(default=0, repr=False, compare=False)

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
        """From [(version, {exact hashes}, {abstract hashes}?)], oldest first.

        Beyond ``MAX_VERSIONS`` the newest are kept: they are what firmware ships.
        Keeping the first 64 left 107 rules of the free rule base without the
        release they pin (Varnish recorded 0.9.1 to 6.0.12 and pinned 8.0.0)."""
        trimmed = list(per_version)[-MAX_VERSIONS:]
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
        # Whole tables at once, in C: a record-by-record unpack_from loop was most
        # of the time it took to load a rule base.
        end = pos + 17 * n
        if len(raw) < end:
            raise struct.error("function signature truncated")
        if n:
            h, b, f = zip(*struct.iter_unpack("<QQB", raw[pos:end]))
            hashes, bitmaps, flags = array("Q", h), array("Q", b), array("B", f)
        else:
            hashes, bitmaps, flags = array("Q"), array("Q"), array("B")
        pos = end
        abstract, abstract_bits = array("Q"), array("Q")
        if pos < len(raw):
            (m,) = struct.unpack_from("<I", raw, pos); pos += 4
            end = pos + 16 * m
            if len(raw) < end:
                raise struct.error("function signature truncated")
            if array("Q").itemsize == 8:
                pairs = array("Q")
                pairs.frombytes(raw[pos:end])
                if sys.byteorder != "little":
                    pairs.byteswap()
            else:                                       # pragma: no cover
                pairs = array("Q", (v for (v,) in struct.iter_unpack("<Q", raw[pos:end])))
            abstract, abstract_bits = pairs[0::2], pairs[1::2]
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
    def index(self) -> Mapping[int, int]:
        """Hash -> position. The file stores hashes ascending, so this is a
        binary search over them rather than a dict: a dict per loaded signature
        held 264 MB on ESP-IDF with the free rule base."""
        if self._index is None:
            ordered = self.ordered_hashes
            self._index = (_Positions(self.hashes) if ordered is self.hashes
                           else {h: i for i, h in enumerate(self.hashes)})
        return self._index

    def _memo(self, key, build):
        value = self._derived.get(key)
        if value is None:
            value = self._derived[key] = build()
        return value

    def _lru(self, key, build):
        """A whole-signature set, kept in the shared, bounded _SETS cache."""
        return _SETS.get(self, key, build)

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
        return self._lru("all", lambda: frozenset(self.hashes))

    @property
    def abstract_set(self) -> FrozenSet[int]:
        return self._lru("abstract", lambda: frozenset(self.abstract_hashes))

    @property
    def application_hashes(self) -> FrozenSet[int]:
        """Functions that identify this component, nested code removed.

        CENTRIS's segmentation: if A vendors B, B's functions must not count
        towards detecting A, or every firmware containing B appears to contain A.
        """
        return self._lru(("application", self._generation), lambda: frozenset(
            h for h, f in zip(self.hashes, self.flags) if f & FLAG_APPLICATION))

    def recorded(self, present: Set[int]) -> Set[int]:
        """The members of *present* this signature records. A small directory
        against a large signature is looked up by bisection, which spares
        building (and caching) the signature's whole set for it."""
        hashes = self.hashes
        if len(present) * 32 < len(hashes) and self.ordered_hashes is hashes:
            n, out = len(hashes), set()
            for h in present:
                i = bisect_left(hashes, h)
                if i < n and hashes[i] == h:
                    out.add(h)
            return out
        return present & self.hash_set

    def application_matched(self, present: Set[int]) -> Set[int]:
        """The application functions among *present*, without the whole set."""
        idx, flags = self.index, self.flags
        return {h for h in self.recorded(present) if flags[idx[h]] & FLAG_APPLICATION}

    def borrowed_matched(self, present: Set[int]) -> Set[int]:
        """The functions among *present* segmentation marked as another rule's."""
        idx, flags = self.index, self.flags
        return {h for h in self.recorded(present)
                if not flags[idx[h]] & FLAG_APPLICATION}

    def segment(self, borrowed: Set[int]) -> int:
        """Mark *borrowed* hashes as not-application-code. Returns how many."""
        marked = 0
        for i, h in enumerate(self.hashes):
            if h in borrowed and self.flags[i] & FLAG_APPLICATION:
                self.flags[i] &= ~FLAG_APPLICATION
                marked += 1
        if marked:
            self._derived.clear()
            self._generation += 1
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

    def abstract_view(self) -> "FunctionSignature":
        """The same releases seen through the identifier-abstracted hashes.

        For version inference on a copy whose symbols were renamed: its exact
        bodies no longer match, so the discriminating functions that vote are too
        few and the range widens, while the abstracted bodies still say which
        release each function comes from. Abstract hashes the segmentation marked
        as borrowed from another rule are not application code here either."""
        def build() -> "FunctionSignature":
            borrowed = self._abstract_borrowed
            return FunctionSignature(
                versions=list(self.versions), hashes=self.abstract_hashes,
                bitmaps=self.abstract_bitmaps,
                flags=[0 if h in borrowed else FLAG_APPLICATION
                       for h in self.abstract_hashes])
        return self._memo("abstract-view", build)

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

    def version_counts(self) -> Tuple[List[int], List[int]]:
        """(discriminating, application) functions per recorded version, counted
        from the bitmaps: what scoring needs, without a set per version. Building
        those sets for every version of every rule a scan evaluates held 1.5 GB on
        ESP-IDF with the free rule base (6.7 GB had every version been built)."""
        def build() -> Tuple[List[int], List[int]]:
            n = len(self.versions)
            full = (1 << n) - 1
            disc, app = [0] * n, [0] * n
            # Releases share most bitmaps (a function present from one release
            # on), so walk each distinct (bitmap, flags) pair once.
            for (b, f), count in Counter(zip(self.bitmaps, self.flags)).items():
                d = count if n == 1 or b != full else 0
                a = count if f & FLAG_APPLICATION else 0
                v = 0
                while b:
                    if b & 1:
                        disc[v] += d
                        app[v] += a
                    b >>= 1
                    v += 1
            return disc, app
        return self._memo("version-counts", build)

    def application_presence(self, index: int, present: Set[int]) -> Tuple[int, int]:
        """(held, total): application functions of one version found in *present*,
        and how many it has. The counts behind containment, without the set.
        Index -1 stands for every version together."""
        if index < 0:
            total = self._memo("application-total", lambda: sum(
                1 for f in self.flags if f & FLAG_APPLICATION))
            return len(self.application_matched(present)), total
        bit = 1 << index
        idx = self.index
        bitmaps, flags = self.bitmaps, self.flags
        held = 0
        for h in self.recorded(present):
            i = idx[h]
            if bitmaps[i] & bit and flags[i] & FLAG_APPLICATION:
                held += 1
        return held, self.version_counts()[1][index]

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


class _SetCache:
    """Whole-signature frozensets, most recently used kept, bounded by how many
    hashes they hold together. Memoised on each signature they held 570 MB on
    ESP-IDF with the free rule base, every signature a scan touched at once;
    rebuilding one from its packed array is quick."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.size = 0
        self._sets: "OrderedDict[Tuple[int, object], Tuple[object, FrozenSet[int]]]" = \
            OrderedDict()

    def get(self, owner, key, build) -> FrozenSet[int]:
        slot = (id(owner), key)
        hit = self._sets.get(slot)
        if hit is not None and hit[0] is owner:
            self._sets.move_to_end(slot)
            return hit[1]
        value = build()
        if hit is not None:
            self.size -= len(hit[1])
        self._sets[slot] = (owner, value)
        self.size += len(value)
        while self.size > self.cap and len(self._sets) > 1:
            _, (_, old) = self._sets.popitem(last=False)
            self.size -= len(old)
        return value


_SETS = _SetCache(1_500_000)


class _Positions(Mapping):
    """Read-only hash -> position over an ascending sequence, by bisection."""

    __slots__ = ("_values",)

    def __init__(self, values: Sequence[int]) -> None:
        self._values = values

    def __getitem__(self, h: int) -> int:
        i = bisect_left(self._values, h)
        if i < len(self._values) and self._values[i] == h:
            return i
        raise KeyError(h)

    def __contains__(self, h: object) -> bool:
        try:
            self[h]                                    # type: ignore[index]
        except (KeyError, TypeError):
            return False
        return True

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def _packed(code: str, values: Iterable[int]) -> "array":
    return values if isinstance(values, array) and values.typecode == code \
        else array(code, values)


def _ascending(values: Sequence[int]) -> Sequence[int]:
    if all(map(operator.le, values, islice(values, 1, None))):   # as stored, normally
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
    # "oldest" or "newest" when the best match is the first or last release the
    # signature records and a good part of its code is missing or altered: the tree
    # may then belong to a release the rule does not record, on that side.
    edge: str = ""

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


# A version within the scoring margin of the best is still ruled out when the tree
# holds at least this many of the functions only the best one has, ...
DECISIVE_MIN = 3
# ... these are at least this share of all the functions only the best one has
# (a copy with a fix or two backported is still the older release), and the tree
# holds none of the functions only the other version has.
DECISIVE_SHARE = 0.5


def _takes_sides(signature: FunctionSignature, voters: Set[int], best: int, other: int) -> bool:
    """Does the tree hold most of what *best* has and *other* lacks, and nothing
    *other* has and *best* lacks? Counted from the bitmaps."""
    b_bit, o_bit = 1 << best, 1 << other
    full = (1 << len(signature.versions)) - 1
    only_best = sum(1 for b in signature.bitmaps
                    if b != full and b & b_bit and not b & o_bit)
    held = 0
    index, bitmaps = signature.index, signature.bitmaps
    for h in voters:
        b = bitmaps[index[h]]
        if b & o_bit and not b & b_bit:
            return False
        if b & b_bit and not b & o_bit:
            held += 1
    return held >= DECISIVE_MIN and held >= DECISIVE_SHARE * only_best


def infer_version(signature: FunctionSignature, present: Set[int]) -> VersionVerdict:
    """TIVER-style adaptive version: the range of versions actually present.

    Only *discriminating* functions vote -- one present in every release carries
    no information about which release this is, and letting it vote would make
    every component look like its own first version.
    """
    if not signature.versions:
        return VersionVerdict(None, None, None, 0.0, False, "no versions recorded")

    matched = signature.recorded(present)
    index = signature.index
    n = len(signature.versions)
    full = (1 << n) - 1
    bitmaps = signature.bitmaps
    voters = matched if n == 1 else {h for h in matched if bitmaps[index[h]] != full}
    if not voters:
        return VersionVerdict(
            None, None, None, 0.0, False,
            "no version-discriminating function matched: every function present "
            "appears in all recorded versions, so the version cannot be narrowed")

    # Score each version by Jaccard over discriminating functions, not by raw
    # coverage. Coverage alone cannot separate a release from its successor: the
    # successor contains everything the release did, so it always ties. Jaccard
    # charges a version for the discriminating functions it has and the tree
    # does not, which is exactly the evidence that says "not that one".
    overlaps: List[int] = [0] * n
    for h in voters:
        b, v = bitmaps[index[h]], 0
        while b:
            if b & 1:
                overlaps[v] += 1
            b >>= 1
            v += 1
    sizes = signature.version_counts()[0]
    scores: List[float] = []
    for v in range(n):
        union = len(voters) + sizes[v] - overlaps[v]
        scores.append(overlaps[v] / union if union else 0.0)

    best_score = max(scores)
    best_index = scores.index(best_score)
    # The adaptive range: every version that explains the tree about as well,
    # unless the tree takes sides between it and the best one. Releases a few
    # functions apart score within the margin of each other (DAPLink 0257 and
    # 0258: 14 of 1659), so a tree that holds most of what the best release
    # changed, and nothing the other one has instead, is not the other one.
    threshold = best_score * 0.95
    explained = [i for i, s in enumerate(scores) if s >= threshold
                 and (i == best_index or not _takes_sides(signature, voters, best_index, i))]
    low_index, high_index = min(explained), max(explained)

    best_bit = 1 << best_index
    unexplained = sum(1 for h in voters
                      if not signature.bitmaps[index[h]] & best_bit)
    multi = unexplained > 0
    foreign = len(present) - len(matched)
    held, best_app = signature.application_presence(best_index, present)
    changed = best_app - held
    edge = ""
    if len(signature.versions) > 1 and best_app and changed / best_app >= EDGE_ALTERED_SHARE:
        edge = ("oldest" if best_index == 0 else
                "newest" if best_index == len(signature.versions) - 1 else "")

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
        changed=changed,
        edge=edge)


def infer_version_subset(signature: FunctionSignature, present: Set[int]) -> VersionVerdict:
    """Version of a *partial* copy: the releases that contain every function found.

    ``infer_version`` scores by Jaccard against a whole release, which punishes a
    tree for the files it does not hold and so favours the smallest release. For
    a pruned copy the right question is the reverse: which releases have all of
    what is here. Releases tie when the functions present did not change between
    them, and the answer is then the range they span.
    """
    matched = signature.recorded(present)
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
