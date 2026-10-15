"""What a .NET assembly and its ``.deps.json`` say about dependencies.

Two sources, with very different strength:

* ``<app>.deps.json`` is written by the .NET SDK next to the program and lists every NuGet
  package the build restored, with its exact version. It is the best statement of a .NET
  program's dependencies, and it is a separate file, so it can be stale or edited: it says
  what the build resolved, not what a user copied next to the executable afterwards.
* The assembly's own metadata (ECMA-335, the ``Assembly`` and ``AssemblyRef`` tables) names
  the assemblies it references. An ``AssemblyRef`` carries the *assembly* version, which is
  not the NuGet package version (two package releases often share one assembly version), so
  it identifies a dependency but never a release.

Everything is read from bytes with a bounded walk and returns ``None`` for what is not
well-formed. Only the tables up to ``AssemblyRef`` are needed, but a table's position depends
on the width of every table before it, so their row layouts are listed in full.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pe import PeInfo

MAX_REFS = 2048
MAX_DEPS_JSON = 16 * 1024 * 1024
MAX_PACKAGES = 20000
ASSEMBLY, ASSEMBLY_REF, MANIFEST_RESOURCE = 0x20, 0x23, 0x28
MAX_RESOURCES = 4096

# Assemblies that ship with the runtime or SDK: referencing one says nothing about a
# third-party dependency.
FRAMEWORK_PREFIXES = ("System.", "Microsoft.CSharp", "Microsoft.VisualBasic", "Microsoft.Win32.",
                      "Windows.", "PresentationFramework", "PresentationCore", "WindowsBase",
                      "Accessibility", "UIAutomation")
FRAMEWORK_NAMES = {"mscorlib", "netstandard", "System", "WindowsBase", "Accessibility",
                   "Microsoft.CSharp", "Microsoft.VisualBasic"}

# Coded indexes: (tag bits, tables the tag selects among).
_CODED = {
    "TypeDefOrRef": (2, (2, 1, 27)),
    "HasConstant": (2, (4, 8, 23)),
    "HasCustomAttribute": (5, (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35,
                               38, 39, 40, 42, 44, 43)),
    "HasFieldMarshal": (1, (4, 8)),
    "HasDeclSecurity": (2, (2, 6, 32)),
    "MemberRefParent": (3, (2, 1, 26, 6, 27)),
    "HasSemantics": (1, (20, 23)),
    "MethodDefOrRef": (1, (6, 10)),
    "MemberForwarded": (1, (4, 6)),
    "Implementation": (2, (38, 35, 39)),
    "CustomAttributeType": (3, (6, 10)),
    "ResolutionScope": (2, (0, 26, 35, 1)),
}
# Column types: a number is a fixed width in bytes; "S", "G", "B" are string, GUID and blob
# heap indexes; "T<n>" a plain index into table n; anything else a coded index above.
_TABLES = {
    0x00: (2, "S", "G", "G", "G"),
    0x01: ("ResolutionScope", "S", "S"),
    0x02: (4, "S", "S", "TypeDefOrRef", "T4", "T6"),
    0x03: ("T4",),
    0x04: (2, "S", "B"),
    0x05: ("T6",),
    0x06: (4, 2, 2, "S", "B", "T8"),
    0x07: ("T8",),
    0x08: (2, 2, "S"),
    0x09: ("T2", "TypeDefOrRef"),
    0x0A: ("MemberRefParent", "S", "B"),
    0x0B: (2, "HasConstant", "B"),
    0x0C: ("HasCustomAttribute", "CustomAttributeType", "B"),
    0x0D: ("HasFieldMarshal", "B"),
    0x0E: (2, "HasDeclSecurity", "B"),
    0x0F: (2, 4, "T2"),
    0x10: (4, "T4"),
    0x11: ("B",),
    0x12: ("T2", "T20"),
    0x13: ("T20",),
    0x14: (2, "S", "TypeDefOrRef"),
    0x15: ("T2", "T23"),
    0x16: ("T23",),
    0x17: (2, "S", "B"),
    0x18: (2, "T6", "HasSemantics"),
    0x19: ("T2", "MethodDefOrRef", "MethodDefOrRef"),
    0x1A: ("S",),
    0x1B: ("B",),
    0x1C: (2, "MemberForwarded", "S", "T26"),
    0x1D: (4, "T4"),
    0x1E: (4, 4),
    0x1F: (4,),
    0x20: (4, 2, 2, 2, 2, 4, "B", "S", "S"),
    0x21: (4,),
    0x22: (4, 4, 4),
    0x23: (2, 2, 2, 2, 4, "B", "S", "S", "B"),
    0x24: (4, "T23"),
    0x25: (4, 4, 4, "T23"),
    0x26: (4, "S", "B"),
    0x27: (4, 4, "S", "S", "Implementation"),
    0x28: (4, 4, "S", "Implementation"),
}


@dataclass
class AssemblyRef:
    name: str
    version: str                      # the assembly version, not a package version


@dataclass
class DotnetInfo:
    name: str = ""
    version: str = ""
    runtime: str = ""                 # the metadata version string, e.g. "v4.0.30319"
    references: List[AssemblyRef] = field(default_factory=list)

    def third_party_references(self) -> List[AssemblyRef]:
        return [r for r in self.references if not is_framework(r.name)]


def is_framework(name: str) -> bool:
    return name in FRAMEWORK_NAMES or name.startswith(FRAMEWORK_PREFIXES)


def parse_dotnet(data: bytes, pe: PeInfo) -> Optional[DotnetInfo]:
    """The assembly identity and references of a managed PE, or None."""
    if not pe.is_dotnet:
        return None
    try:
        return _parse(data, pe)
    except (struct.error, IndexError, ValueError):
        return None


class _Metadata:
    """An opened metadata root: where every table starts and how wide its columns are."""

    def __init__(self, data: bytes, pe: PeInfo):
        self.ok = False
        self.runtime = ""
        self.cor = pe.rva_to_offset(pe.clr_rva)
        if self.cor is None or self.cor + 16 > len(data):
            return
        meta_rva = struct.unpack_from("<I", data, self.cor + 8)[0]
        root = pe.rva_to_offset(meta_rva)
        if root is None or root + 16 > len(data) or data[root:root + 4] != b"BSJB":
            return
        vlen = struct.unpack_from("<I", data, root + 12)[0]
        if vlen > 255:
            return
        self.runtime = data[root + 16:root + 16 + vlen].split(b"\0")[0].decode("latin-1")
        at = root + 16 + vlen
        nstreams = struct.unpack_from("<H", data, at + 2)[0]
        at += 4
        streams: Dict[str, Tuple[int, int]] = {}
        for _ in range(min(nstreams, 16)):
            off, size = struct.unpack_from("<II", data, at)
            end = data.index(b"\0", at + 8)
            streams[data[at + 8:end].decode("latin-1")] = (root + off, size)
            at = (end + 4) & ~3
        tables = streams.get("#~") or streams.get("#-")
        strings = streams.get("#Strings")
        if not tables or not strings:
            return
        self.heap_start, self.heap_size = strings
        t = tables[0]
        heap_sizes = data[t + 6]
        valid = struct.unpack_from("<Q", data, t + 8)[0]
        pos = t + 24
        self.rows: Dict[int, int] = {}
        for table in range(64):
            if valid >> table & 1:
                self.rows[table] = struct.unpack_from("<I", data, pos)[0]
                pos += 4
        if heap_sizes & 0x40:
            pos += 4
        self.widths = _column_widths(self.rows, heap_sizes)
        self.start: Dict[int, int] = {}
        for table in range(MANIFEST_RESOURCE + 1):
            count = self.rows.get(table, 0)
            if table not in _TABLES and count:
                return                             # a table we cannot size: do not guess
            self.start[table] = pos
            pos += count * sum(self.widths.get(table, ()))
        self.data = data
        self.ok = True

    def text(self, index: int) -> str:
        if index >= self.heap_size:
            return ""
        end = self.data.find(b"\0", self.heap_start + index, self.heap_start + self.heap_size)
        return self.data[self.heap_start + index:end if end >= 0 else
                         self.heap_start + self.heap_size].decode("utf-8", "replace")

    def read(self, table: int, row: int, column: int) -> int:
        widths = self.widths[table]
        at = self.start[table] + row * sum(widths) + sum(widths[:column])
        return int.from_bytes(self.data[at:at + widths[column]], "little")


def _parse(data: bytes, pe: PeInfo) -> Optional[DotnetInfo]:
    meta = _Metadata(data, pe)
    if not meta.ok:
        return None
    info = DotnetInfo(runtime=meta.runtime)
    if meta.rows.get(ASSEMBLY):                   # HashAlgId, Major, Minor, Build, Revision,
        info.version = ".".join(str(meta.read(ASSEMBLY, 0, i)) for i in (1, 2, 3, 4))
        info.name = meta.text(meta.read(ASSEMBLY, 0, 7))      # Flags, PublicKey, Name
    for i in range(min(meta.rows.get(ASSEMBLY_REF, 0), MAX_REFS)):   # Major..Revision, Flags,
        info.references.append(AssemblyRef(                         # PublicKeyOrToken, Name
            meta.text(meta.read(ASSEMBLY_REF, i, 6)),
            ".".join(str(meta.read(ASSEMBLY_REF, i, c)) for c in range(4))))
    return info


def managed_resources(data: bytes, pe: PeInfo) -> Dict[int, str]:
    """File offset of each embedded managed resource's data -> its name.

    Native libraries shipped as resources (a .NET assembly carrying one per platform) are
    named here by their author, which says more than an offset does."""
    if not pe.is_dotnet:
        return {}
    try:
        meta = _Metadata(data, pe)
        if not meta.ok or meta.cor is None:
            return {}
        res_rva = struct.unpack_from("<I", data, meta.cor + 24)[0]
        base = pe.rva_to_offset(res_rva)
        if base is None:
            return {}
        out: Dict[int, str] = {}
        for i in range(min(meta.rows.get(MANIFEST_RESOURCE, 0), MAX_RESOURCES)):
            if meta.read(MANIFEST_RESOURCE, i, 3) != 0:
                continue                           # Implementation set: not in this file
            at = base + meta.read(MANIFEST_RESOURCE, i, 0)
            if at + 4 <= len(data):
                out[at + 4] = meta.text(meta.read(MANIFEST_RESOURCE, i, 2))
        return out
    except (struct.error, IndexError, ValueError):
        return {}


def _column_widths(rows: Dict[int, int], heap_sizes: int) -> Dict[int, List[int]]:
    string = 4 if heap_sizes & 1 else 2
    guid = 4 if heap_sizes & 2 else 2
    blob = 4 if heap_sizes & 4 else 2

    def simple(table: int) -> int:
        return 4 if rows.get(table, 0) >= 1 << 16 else 2

    def coded(name: str) -> int:
        bits, tables = _CODED[name]
        biggest = max((rows.get(t, 0) for t in tables), default=0)
        return 4 if biggest >= 1 << (16 - bits) else 2

    out: Dict[int, List[int]] = {}
    for table, columns in _TABLES.items():
        widths = []
        for col in columns:
            if isinstance(col, int):
                widths.append(col)
            elif col == "S":
                widths.append(string)
            elif col == "G":
                widths.append(guid)
            elif col == "B":
                widths.append(blob)
            elif col[0] == "T" and col[1:].isdigit():
                widths.append(simple(int(col[1:])))
            else:
                widths.append(coded(col))
        out[table] = widths
    return out


# -- deps.json ------------------------------------------------------------------------------

@dataclass
class DepsPackage:
    name: str
    version: str
    kind: str                         # "package" | "runtimepack"


def read_deps_json(path: Path) -> Optional[List[DepsPackage]]:
    """NuGet packages (and a bundled runtime) listed in a ``.deps.json``, or None."""
    try:
        if path.stat().st_size > MAX_DEPS_JSON:
            return None
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    libraries = doc.get("libraries") if isinstance(doc, dict) else None
    if not isinstance(libraries, dict):
        return None
    out: List[DepsPackage] = []
    for key, entry in list(libraries.items())[:MAX_PACKAGES]:
        kind = entry.get("type") if isinstance(entry, dict) else None
        name, _, version = str(key).rpartition("/")
        if kind not in ("package", "runtimepack") or not name or not version:
            continue                               # "project" and "reference" are not packages
        out.append(DepsPackage(name, version, kind))
    return out
