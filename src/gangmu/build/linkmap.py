"""Parsing linker map files: GNU ld / lld, IAR ilink and Arm armlink.

Compilation is not inclusion.  An embedded build compiles far more than it
ships: ``--gc-sections`` and plain archive semantics drop whole objects at link
time, which is the main reason tools that read only the source tree over-report
(Zephyr's own SBOM is the well-documented case).

The map file is the ground truth for what survived.  ESP-IDF, Zephyr and most
GCC-based embedded builds emit one by default; for others, ``-Wl,-Map=out.map``.

IAR ilink (``--map``) and Arm Compiler's armlink (``--map`` / ``--list``) write
different layouts, so the format is detected from the file itself and every
parser fills the same :class:`LinkMap`. lld's map reuses GNU ld's
``archive(member)`` convention and goes through the GNU parser. Only formats the
parsers below know are read; anything else falls back to the GNU parser, which
finds nothing in a foreign map rather than guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set, Tuple

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


_IAR_HEADER = re.compile(r"^\*{3}\s+MODULE SUMMARY\b")
_IAR_NEXT_HEADER = re.compile(r"^\*{3}\s+[A-Z]")
_IAR_GROUP = re.compile(r"^(?P<group>\S.*?):\s+\[\d+\]\s*$")
_IAR_MODULE = re.compile(r"^\s+(?P<module>[^\s:]+\.(?:o|obj|r79|r90))(?:\s|$)", re.I)
_ARM_REMOVED = re.compile(r"^\s*Removing\s+(?P<obj>[^\s(]+?)(?:\((?P<member>[^)\s]+)\))?\((?P<section>[^)]*)\)")
_ARM_COMPONENT = re.compile(
    r"^\s+(?:\d+\s+){5}\d+\s+(?P<name>[^\s()]+)(?:\((?P<member>[^()\s]+)\))?\s*$")
_ARM_COMPONENT_HEADER = re.compile(r"^\s*Code \(inc\. data\)\s+RO Data\s+RW Data\s+ZI Data\s+Debug\s+"
                                   r"(Object|Library Member) Name")
_ARM_MEMORY_OBJECT = re.compile(
    r"^\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+\S+\s+\S+\s+\d+\s+\S+\s+"
    r"(?P<name>[^\s()]+)(?:\((?P<member>[^()\s]+)\))?\s*$")


def detect_format(path: Path) -> str:
    """``iar``, ``armlink`` or ``gnu`` from the first part of the file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(256 * 1024)
    if re.search(r"^\*{3}\s+MODULE SUMMARY\b", head, re.M):
        return "iar"
    if (re.search(r"^Image component sizes\b", head, re.M)
            or re.search(r"^Removing Unused input sections from the image", head, re.M)
            or re.search(r"^Memory Map of the image\b", head, re.M)):
        return "armlink"
    return "gnu"


def parse_link_map(path: Path) -> LinkMap:
    path = Path(path)
    kind = detect_format(path)
    if kind == "iar":
        return _parse_iar(path)
    if kind == "armlink":
        return _parse_armlink(path)
    return _parse_gnu(path)


def _parse_iar(path: Path) -> LinkMap:
    """IAR ilink: the ``MODULE SUMMARY`` lists the modules that reached the image.

    Modules are grouped under the file they came from (``dl7M_tln.a: [3]``, or the
    project's object directory), so a group ending in ``.a``/``.lib`` is an
    archive and its modules are archive members; any other group is plain objects.
    ilink does not print a discard list, so ``discarded_*`` stays empty and a
    compiled object missing from the summary is treated as dropped.
    """
    out = LinkMap(path=path)
    in_summary = False
    group: Optional[str] = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if _IAR_HEADER.match(line):
                in_summary, group = True, None
                continue
            if in_summary and _IAR_NEXT_HEADER.match(line):
                in_summary = False
                continue
            if not in_summary:
                continue
            line = line.rstrip("\n")
            head = _IAR_GROUP.match(line)
            if head and not line.startswith(" "):
                group = head.group("group").strip()
                continue
            mod = _IAR_MODULE.match(line)
            if mod is None:
                continue
            name = Path(mod.group("module")).name
            if group and group.lower().endswith((".a", ".lib")):
                out.archives.add(group)
                out.members.add((group, name))
            else:
                out.objects.add(name)
    return out


def _parse_armlink(path: Path) -> LinkMap:
    """Arm armlink ``--map``: kept objects from the size table and memory map,
    dropped sections from ``Removing Unused input sections``.

    Library members print as ``c_w.l(memcpya.o)``. An object is only
    ``discarded_only`` when every section armlink listed for it was removed.
    """
    out = LinkMap(path=path)
    kept: Set[str] = set()
    discarded: Set[str] = set()
    in_removed = False
    in_components = False
    in_memory = False
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if re.match(r"^Removing Unused input sections", line):
                in_removed, in_components, in_memory = True, False, False
                continue
            if re.match(r"^Image component sizes\b", line):
                in_removed, in_components, in_memory = False, True, False
                continue
            if re.match(r"^Memory Map of the image\b", line):
                in_removed, in_components, in_memory = False, False, True
                continue
            if re.match(r"^(Image Symbol Table|Section Cross References|Image Totals|"
                        r"Total RO Size|Total ROM Size)\b", line):
                in_removed = in_components = in_memory = False
                continue
            if in_removed:
                m = _ARM_REMOVED.match(line)
                if m is None:
                    continue
                name = Path(m.group("member") or m.group("obj")).name
                discarded.add(name)
                if m.group("member"):
                    out.discarded_members.add((m.group("obj"), name))
                continue
            m = (_ARM_COMPONENT.match(line) if in_components
                 else _ARM_MEMORY_OBJECT.match(line) if in_memory else None)
            if m is None:
                continue
            raw = m.group("name")
            member = m.group("member")
            if member:                                  # lib.l(member.o)
                out.archives.add(raw)
                out.members.add((raw, Path(member).name))
                kept.add(Path(member).name)
            elif raw.lower().endswith((".o", ".obj")):
                out.objects.add(Path(raw).name)
                kept.add(Path(raw).name)
    out.discarded_only = discarded - kept
    return out


def _parse_gnu(path: Path) -> LinkMap:
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
