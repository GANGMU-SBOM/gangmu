"""Parsing linker map files: GNU ld / lld, IAR ilink, Arm armlink and TI armlnk/lnk2000.

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
# ``0x08000130  0x08000130  0x00000008  Code  RO  2406  * !!!main  c_w.l(__main.o)``; zero-init
# lines carry no load address, and a ``*`` marks an entry-point section
_ARM_MEMORY_OBJECT = re.compile(
    r"^\s+0x[0-9a-fA-F]+\s+(?:0x[0-9a-fA-F]+\s+)?0x[0-9a-fA-F]+\s+\S+\s+\S+\s+\d+\s+"
    r"(?:\*\s+)?\S+\s+(?P<name>[^\s()]+)(?:\((?P<member>[^()\s]+)\))?\s*$")


_TI_ALLOCATION = re.compile(r"^SECTION ALLOCATION MAP\b")
_TI_NEXT = re.compile(r"^(GLOBAL SYMBOLS|LINKER GENERATED COPY TABLES|"
                      r"SEGMENT ALLOCATION MAP|MODULE SUMMARY|GLOBAL SYMBOLS:)", re.I)
# ``  000000d8  00000250  driverlib.lib : sysctl.obj (.text:SysCtlClockGet)``; the library
# column is blank on the continuation lines that follow (``  ...  : memcpy.obj (.text)``)
_TI_ENTRY = re.compile(
    r"^\s+[0-9a-fA-F]{4,}\s+(?P<size>[0-9a-fA-F]+)\s+"
    r"(?:(?P<lib>[^\s:()]+)\s+)?(?::\s+)?(?P<obj>[^\s:()]+\.(?:obj|o\w*))\s+\(")


def detect_format(path: Path) -> str:
    """``iar``, ``armlink``, ``ti`` or ``gnu`` from the first part of the file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(256 * 1024)
    if re.search(r"^\*{3}\s+MODULE SUMMARY\b", head, re.M):
        return "iar"
    if re.search(r"^SECTION ALLOCATION MAP\b", head, re.M):
        return "ti"
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
    if kind == "ti":
        return _parse_ti(path)
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


def _parse_ti(path: Path) -> LinkMap:
    """TI ``armlnk`` / ``lnk2000`` (Code Composer Studio) ``-m`` map.

    ``SECTION ALLOCATION MAP`` lists every input section that was placed, as
    ``lib.lib : member.obj (.text)`` or ``main.obj (.text)``. Sections removed by
    ``--unused_section_elimination`` are not placed, so an object appears only if it
    kept at least one byte. The linker prints no discard list, like ilink, so
    ``discarded_*`` stays empty and a compiled object missing here counts as dropped.
    """
    out = LinkMap(path=path)
    in_alloc = False
    lib: Optional[str] = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if _TI_ALLOCATION.match(line):
                in_alloc = True
                continue
            if in_alloc and _TI_NEXT.match(line):
                break
            if not in_alloc:
                continue
            m = _TI_ENTRY.match(line)
            if m is None:
                if line[:1] not in (" ", "\t"):
                    lib = None                         # a new output section
                continue
            if m.group("lib"):
                lib = m.group("lib")
            elif ":" not in line.split("(")[0]:
                lib = None                             # a plain object, not a continuation
            if int(m.group("size"), 16) == 0:
                continue
            name = Path(m.group("obj")).name
            if lib:
                out.archives.add(lib)
                out.members.add((lib, name))
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
    lib_table = False
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
            if in_components:
                header = _ARM_COMPONENT_HEADER.match(line)
                if header:
                    # library members are listed bare here; the memory map names their library
                    lib_table = header.group(1) == "Library Member"
                    continue
            m = (_ARM_COMPONENT.match(line) if in_components
                 else _ARM_MEMORY_OBJECT.match(line) if in_memory else None)
            if m is None:
                continue
            raw = m.group("name")
            member = m.group("member")
            if in_components and lib_table and not member:
                continue
            if member:                                  # lib.l(member.o)
                out.archives.add(raw)
                out.members.add((raw, Path(member).name))
                kept.add(Path(member).name)
            elif raw.lower().endswith((".o", ".obj")):
                out.objects.add(Path(raw).name)
                kept.add(Path(raw).name)
    out.discarded_only = discarded - kept
    return out


_GNU_MAP_START = re.compile(r"^Linker script and memory map", re.I)
_GNU_CONTRIB = re.compile(
    r"^\s+(?:\S+\s+)?0x[0-9a-fA-F]+\s+(?P<size>0x[0-9a-fA-F]+)\s+(?P<file>\S.*?)\s*$")
# Output sections that carry no code or data of the image.
_NON_IMAGE_SECTIONS = (".comment", ".ARM.attributes", ".riscv.attributes",
                       ".debug", ".stab", ".note", ".mdebug", ".pdr")


def _parse_gnu(path: Path) -> LinkMap:
    """GNU ld (and lld, which writes the same ``archive(member)`` form).

    A bare object counts as kept only when it contributes bytes to an image
    section in ``Linker script and memory map``. Naming it on a ``LOAD`` line or
    as the referrer in ``Archive member included`` does not: with
    ``--gc-sections`` an object can be on the command line and still leave
    nothing behind. If the map cannot show contributions (none found, or LTO,
    where the objects in the map are temporary ltrans files) every named object
    is kept, which overstates rather than loses a component.
    """
    out = LinkMap(path=path)
    kept: Set[str] = set()
    discarded: Set[str] = set()
    named: Set[str] = set()          # bare objects named anywhere outside the discard list
    contributing: Set[str] = set()   # bare objects with bytes in the image
    lto = False
    in_discard = False
    in_map = False
    section = ""

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if _DISCARD_START.match(line):
                in_discard = True
                continue
            if _SECTION_BREAK.match(line):
                in_discard = False
                in_map = bool(_GNU_MAP_START.match(line))
                section = ""
            if in_map and line[:1] not in (" ", "\t", "\n", "\r"):
                head = line.split(None, 1)[0] if line.strip() else ""
                if head.startswith("."):
                    section = head

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
                if in_discard:
                    discarded.add(name)
                    continue
                named.add(name)
                if "ltrans" in name:
                    lto = True
            if in_map and not in_discard and section \
                    and not section.startswith(_NON_IMAGE_SECTIONS):
                c = _GNU_CONTRIB.match(line)
                if c and int(c.group("size"), 16) > 0 and "(" not in c.group("file"):
                    f = Path(c.group("file")).name
                    if re.search(r"\.ob?j?$", f, re.I):
                        contributing.add(f)

    objects = named if (lto or not contributing) else contributing
    out.objects = set(objects)
    kept |= objects
    out.discarded_only = discarded - kept
    return out
