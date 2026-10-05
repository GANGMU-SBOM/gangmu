"""Parsing a GNU ld map file.

Compilation is not inclusion.  An embedded build compiles far more than it
ships: ``--gc-sections`` and plain archive semantics drop whole objects at link
time, which is the main reason tools that read only the source tree over-report
(Zephyr's own SBOM is the well-documented case).

The map file is the ground truth for what survived.  ESP-IDF, Zephyr and most
GCC-based embedded builds emit one by default; for others, ``-Wl,-Map=out.map``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set, Tuple

_ARCHIVE_MEMBER = re.compile(r"(?P<archive>[^\s()]+\.a)\((?P<member>[^\s()]+\.ob?j?)\)")
_BARE_OBJECT = re.compile(r"(?<![\w(])(?P<obj>[^\s()]+\.ob?j?)(?![\w)])")

_DISCARD_START = re.compile(r"^Discarded input sections", re.I)
_SECTION_BREAK = re.compile(
    r"^(Memory Configuration|Linker script and memory map|"
    r"Archive member included|Allocating common symbols|"
    r"Cross Reference Table)", re.I)


@dataclass
class LinkMap:
    path: Path
    archives: Set[str] = field(default_factory=set)
    members: Set[Tuple[str, str]] = field(default_factory=set)   # (archive path, member)
    discarded_members: Set[Tuple[str, str]] = field(default_factory=set)
    objects: Set[str] = field(default_factory=set)               # basenames
    discarded_only: Set[str] = field(default_factory=set)

    @property
    def linked_object_names(self) -> Set[str]:
        """Object basenames that reached the image."""
        return {m for _, m in self.members} | self.objects

    def _distinctive_parts(self) -> Set[str]:
        """Archive path components that actually tell archives apart.

        ``esp-idf/json/libjson.a`` and ``esp-idf/legacy/liblegacy.a`` share
        ``esp-idf``, so matching on it would make every object look linked.
        Only components that are *not* common to every archive carry
        information.
        """
        per_archive = [set(Path(a).parent.parts)
                       for a in self.archives | {a for a, _ in self.discarded_members}]
        if not per_archive:
            return set()
        common = set.intersection(*per_archive) if len(per_archive) > 1 else set()
        return {part for parts in per_archive for part in parts
                if part not in common and part not in (".", "/")}

    def qualified_keys(self) -> Set[Tuple[str, str]]:
        """(distinctive path component, object name) pairs that survived."""
        return self._keys(self.members)

    def discarded_keys(self) -> Set[Tuple[str, str]]:
        """The same, for members the linker threw away."""
        return self._keys(self.discarded_members)

    def _keys(self, members: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:
        distinctive = self._distinctive_parts()
        keys: Set[Tuple[str, str]] = set()
        for archive, member in members:
            for part in Path(archive).parent.parts:
                if part in distinctive:
                    keys.add((part, member))
        return keys


def parse_link_map(path: Path) -> LinkMap:
    path = Path(path)
    out = LinkMap(path=path)
    kept: Set[str] = set()
    discarded: Set[str] = set()
    in_discard = False

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if _DISCARD_START.match(line):
                in_discard = True
                continue
            if _SECTION_BREAK.match(line):
                in_discard = False

            sink = discarded if in_discard else kept
            consumed_spans = []
            for m in _ARCHIVE_MEMBER.finditer(line):
                archive = m.group("archive")
                member = Path(m.group("member")).name
                sink.add(member)
                if in_discard:
                    out.discarded_members.add((archive, member))
                else:
                    out.archives.add(archive)
                    out.members.add((archive, member))
                consumed_spans.append(m.span())
            for m in _BARE_OBJECT.finditer(line):
                if any(s <= m.start() < e for s, e in consumed_spans):
                    continue
                name = Path(m.group("obj")).name
                sink.add(name)
                if not in_discard:
                    out.objects.add(name)

    out.discarded_only = discarded - kept
    return out
