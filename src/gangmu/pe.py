"""A small, dependency-free reader for Windows PE files (``.exe``, ``.dll``, ``.sys``).

Like ``elf.py``, only what the binary inventory needs, and bounded: a file that is not a
well-formed PE gives ``None`` rather than an exception, every table walk has a cap, and no
offset is trusted before it is checked against the file. What is read:

* the machine, bitness, DLL flag, linker version, timestamp and whether an Authenticode
  signature is attached;
* the import table (library names only; delay-load imports included) and the export table;
* the ``VS_VERSIONINFO`` resource, which is the one place a Windows binary states its
  product name and version in a structured way (``ProductName``, ``ProductVersion``...);
* the CodeView debug record (PDB path, GUID, age), which names the build tree;
* whether there is a CLR header (a .NET assembly) and the sections by name, so a caller can
  look for toolchain metadata (Go's build info, Rust's ``.dep-v0``).

None of this is a function-level analysis and none of it proves a library is unmodified.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0x1C4: "armnt",
            0xAA64: "aarch64", 0x5064: "riscv64", 0x200: "ia64"}
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_SECURITY, DIR_DEBUG = 0, 1, 2, 4, 6
DIR_DELAY_IMPORT, DIR_CLR = 13, 14
RT_VERSION = 16
IMAGE_FILE_DLL = 0x2000
MAX_SECTIONS = 96
MAX_IMPORTS = 2048
MAX_EXPORTS = 65536
MAX_RESOURCE_ENTRIES = 512
MAX_STRING = 4096
MAX_VERSION_DEPTH = 6


@dataclass
class PeSection:
    name: str
    vaddr: int
    vsize: int
    offset: int
    size: int


@dataclass
class PeInfo:
    machine: str
    bits: int
    is_dll: bool = False
    timestamp: int = 0
    linker: str = ""                                  # "14.38": the linker that made it
    signed: bool = False                              # an Authenticode blob is attached
    is_dotnet: bool = False
    sections: List[PeSection] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)  # library names, lower case, unique
    exports: List[str] = field(default_factory=list)  # exported function names
    export_name: str = ""                             # the DLL's own name for itself
    version_info: Dict[str, str] = field(default_factory=dict)   # StringFileInfo strings
    file_version: str = ""                            # numeric VS_FIXEDFILEINFO file version
    product_version: str = ""                         # numeric VS_FIXEDFILEINFO product version
    pdb: str = ""                                     # CodeView PDB path
    pdb_guid: str = ""
    clr_rva: int = 0
    clr_size: int = 0

    def section(self, name: str) -> Optional[PeSection]:
        return next((s for s in self.sections if s.name == name), None)

    def section_bytes(self, data: bytes, name: str) -> bytes:
        sec = self.section(name)
        if sec is None or sec.offset > len(data):
            return b""
        # SizeOfRawData is rounded up to the file alignment; the data is VirtualSize bytes.
        size = min(sec.size, sec.vsize) if sec.vsize else sec.size
        return data[sec.offset:sec.offset + size]

    def rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.size):
                off = s.offset + (rva - s.vaddr)
                return off if rva - s.vaddr < max(s.size, 0) else None
        if self.sections and rva < min(s.vaddr for s in self.sections):
            return rva                                 # in the headers
        return None


def parse_pe(data: bytes) -> Optional[PeInfo]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if pe < 0x40 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
            return None
        machine, nsec, stamp, _sym, _nsym, optsize, chars = struct.unpack_from(
            "<HHIIIHH", data, pe + 4)
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B) or nsec > MAX_SECTIONS or nsec == 0:
            return None
        bits = 32 if magic == 0x10B else 64
        major, minor = data[opt + 2], data[opt + 3]
        dirs_at = opt + (96 if bits == 32 else 112)
        ndirs = struct.unpack_from("<I", data, dirs_at - 4)[0]
        dirs: List[Tuple[int, int]] = []
        for i in range(min(ndirs, 16)):
            if dirs_at + 8 * i + 8 > min(len(data), opt + optsize):
                break
            dirs.append(struct.unpack_from("<II", data, dirs_at + 8 * i))
        info = PeInfo(MACHINES.get(machine, f"0x{machine:x}"), bits,
                      is_dll=bool(chars & IMAGE_FILE_DLL), timestamp=stamp,
                      linker=f"{major}.{minor}")
        table = opt + optsize
        for i in range(nsec):
            raw = data[table + 40 * i:table + 40 * i + 40]
            if len(raw) < 40:
                return None
            name, vsize, vaddr, rsize, roff = struct.unpack_from("<8sIIII", raw, 0)
            info.sections.append(PeSection(name.rstrip(b"\0").decode("latin-1"),
                                           vaddr, vsize, roff, rsize))
    except struct.error:
        return None

    def directory(index: int) -> Tuple[int, int]:
        return dirs[index] if index < len(dirs) else (0, 0)

    sec_off, sec_size = directory(DIR_SECURITY)         # a file offset, not an RVA
    info.signed = bool(sec_off and sec_size and sec_off < len(data))
    info.clr_rva, info.clr_size = directory(DIR_CLR)
    info.is_dotnet = bool(info.clr_rva and info.clr_size)
    for reader, index in ((_read_imports, DIR_IMPORT), (_read_delay_imports, DIR_DELAY_IMPORT),
                          (_read_exports, DIR_EXPORT), (_read_debug, DIR_DEBUG),
                          (_read_version, DIR_RESOURCE)):
        rva, size = directory(index)
        if rva:
            try:
                reader(data, info, rva, size)
            except (struct.error, IndexError, ValueError):
                continue                                # one bad table does not lose the rest
    return info


def _cstring(data: bytes, off: Optional[int], limit: int = 512) -> str:
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, off + limit)
    return data[off:end if end >= 0 else off + limit].decode("latin-1")


def _read_imports(data: bytes, info: PeInfo, rva: int, size: int) -> None:
    base = info.rva_to_offset(rva)
    if base is None:
        return
    for i in range(MAX_IMPORTS):
        at = base + 20 * i
        if at + 20 > len(data):
            return
        name_rva = struct.unpack_from("<I", data, at + 12)[0]
        if name_rva == 0:
            return
        _add_import(info, _cstring(data, info.rva_to_offset(name_rva)))


def _read_delay_imports(data: bytes, info: PeInfo, rva: int, size: int) -> None:
    base = info.rva_to_offset(rva)
    if base is None:
        return
    for i in range(MAX_IMPORTS):
        at = base + 32 * i
        if at + 32 > len(data):
            return
        attrs, name_rva = struct.unpack_from("<II", data, at)
        if name_rva == 0:
            return
        # attribute bit 0 set: the fields are RVAs (always, in modern linkers)
        _add_import(info, _cstring(data, info.rva_to_offset(name_rva)))


def _add_import(info: PeInfo, name: str) -> None:
    name = name.lower()
    if name and name not in info.imports:
        info.imports.append(name)


def _read_exports(data: bytes, info: PeInfo, rva: int, size: int) -> None:
    base = info.rva_to_offset(rva)
    if base is None or base + 40 > len(data):
        return
    name_rva, _ordbase, nfuncs, nnames, _funcs, names_rva = struct.unpack_from(
        "<IIIIII", data, base + 12)
    info.export_name = _cstring(data, info.rva_to_offset(name_rva))
    arr = info.rva_to_offset(names_rva)
    if arr is None:
        return
    for i in range(min(nnames, MAX_EXPORTS)):
        if arr + 4 * i + 4 > len(data):
            return
        label = _cstring(data, info.rva_to_offset(struct.unpack_from("<I", data, arr + 4 * i)[0]))
        if label:
            info.exports.append(label)


def _read_debug(data: bytes, info: PeInfo, rva: int, size: int) -> None:
    base = info.rva_to_offset(rva)
    if base is None:
        return
    for i in range(min(max(size // 28, 1), 16)):
        at = base + 28 * i
        if at + 28 > len(data):
            return
        kind, dsize, _addr, ptr = struct.unpack_from("<IIII", data, at + 12)
        if kind != 2 or ptr + 24 > len(data) or data[ptr:ptr + 4] != b"RSDS":
            continue                                    # 2 = CodeView; RSDS is the PDB 7.0 form
        g = data[ptr + 4:ptr + 20]
        a, b, c = struct.unpack("<IHH", g[:8])
        info.pdb_guid = f"{a:08X}-{b:04X}-{c:04X}-{g[8:10].hex().upper()}-{g[10:16].hex().upper()}"
        info.pdb = _cstring(data, ptr + 24, MAX_STRING)
        return


def _read_version(data: bytes, info: PeInfo, rva: int, size: int) -> None:
    root = info.rva_to_offset(rva)
    if root is None:
        return
    entry = _resource_entry(data, root, root, RT_VERSION)     # the RT_VERSION subtree
    if entry is None:
        return
    for _ in range(2):                                        # name level, then language level
        entry = _first_entry(data, root, entry)
        if entry is None:
            return
    if entry & 0x80000000 or root + entry + 16 > len(data):
        return
    data_rva, dsize = struct.unpack_from("<II", data, root + entry)
    start = info.rva_to_offset(data_rva)
    if start is None or dsize < 6:
        return
    _parse_version_block(data[start:start + min(dsize, 65536)], info)


def _resource_entry(data: bytes, root: int, directory: int, wanted: int) -> Optional[int]:
    """Offset (from *root*, high bit marks a subdirectory) of the entry whose id is *wanted*."""
    if directory + 16 > len(data):
        return None
    named, ids = struct.unpack_from("<HH", data, directory + 12)
    for i in range(min(named + ids, MAX_RESOURCE_ENTRIES)):
        at = directory + 16 + 8 * i
        if at + 8 > len(data):
            return None
        ident, target = struct.unpack_from("<II", data, at)
        if not ident & 0x80000000 and ident == wanted:
            return target
    return None


def _first_entry(data: bytes, root: int, entry: int) -> Optional[int]:
    if not entry & 0x80000000:
        return None
    directory = root + (entry & 0x7FFFFFFF)
    if directory + 24 > len(data):
        return None
    if struct.unpack_from("<HH", data, directory + 12) == (0, 0):
        return None
    return struct.unpack_from("<I", data, directory + 20)[0]


def _wstring(block: bytes, off: int) -> Tuple[str, int]:
    """A NUL-terminated UTF-16LE string at *off*, and the offset just past it."""
    end = off
    while end + 1 < len(block) and block[end:end + 2] != b"\0\0" and end - off < MAX_STRING:
        end += 2
    return block[off:end].decode("utf-16-le", "replace"), end + 2


def _block(data: bytes, off: int) -> Optional[Tuple[int, int, int, str, int]]:
    """One version block: (end, value length, type, key, offset of the value)."""
    if off + 6 > len(data):
        return None
    length, vlen, typ = struct.unpack_from("<HHH", data, off)
    if length < 6:
        return None
    key, after = _wstring(data, off + 6)
    return min(off + length, len(data)), vlen, typ, key, (after + 3) & ~3


def _parse_version_block(block: bytes, info: PeInfo) -> None:
    top = _block(block, 0)
    if top is None or top[3] != "VS_VERSION_INFO":
        return
    end, vlen, _typ, _key, value = top
    if vlen >= 52 and value + 52 <= len(block):
        sig, _ver, fms, fls, pms, pls = struct.unpack_from("<IIIIII", block, value)
        if sig == 0xFEEF04BD:
            info.file_version = f"{fms >> 16}.{fms & 0xFFFF}.{fls >> 16}.{fls & 0xFFFF}"
            info.product_version = f"{pms >> 16}.{pms & 0xFFFF}.{pls >> 16}.{pls & 0xFFFF}"
    child = (value + vlen + 3) & ~3
    while child + 6 <= end:
        one = _block(block, child)
        if one is None:
            return
        cend, _v, _t, key, body = one
        if key == "StringFileInfo":
            _read_string_tables(block, body, cend, info)
        child = (cend + 3) & ~3
        if cend <= child - 4 and child >= end:
            return


def _read_string_tables(block: bytes, at: int, end: int, info: PeInfo) -> None:
    while at + 6 <= end:
        table = _block(block, at)
        if table is None:
            return
        tend, _v, _t, _lang, body = table
        if not info.version_info:                        # the first language is enough
            cur = body
            while cur + 6 <= tend:
                one = _block(block, cur)
                if one is None:
                    break
                send, vlen, typ, key, vbody = one
                if typ == 1 and key:
                    text = block[vbody:vbody + 2 * vlen].decode("utf-16-le", "replace")
                    info.version_info[key] = text.rstrip("\0")
                cur = (send + 3) & ~3
                if send <= cur - 4 and cur >= tend:
                    break
        at = (tend + 3) & ~3
