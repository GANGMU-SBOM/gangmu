"""A small, dependency-free reader for Mach-O files (macOS and iOS executables and dylibs).

Like ``elf.py`` and ``pe.py``, only what function fingerprints need, and bounded: bytes that
are not a well-formed Mach-O give ``None``, every table has a cap and no offset is trusted
before it is checked against the file. What is read:

* the CPU, file type and the entry point (``LC_MAIN``);
* the segments' sections with their addresses, file offsets and types;
* ``LC_FUNCTION_STARTS``, a list of every function's start address that the linker writes
  even into a stripped binary (the Mach-O counterpart of the x64 PE ``.pdata`` table);
* the symbol table, when there is one.

A fat (universal) file holds several thin images; the one for the CPU in *prefer* is chosen,
else the first that has a decoder here. Big-endian images (PowerPC) are not read.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

MH_MAGIC, MH_MAGIC_64 = 0xFEEDFACE, 0xFEEDFACF
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB, LC_FUNCTION_STARTS, LC_MAIN = 0x1, 0x19, 0x2, 0x26, 0x80000028
S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL = 0x1, 0xC, 0x12
S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS = 0x80000000, 0x400

CPUS = {7: "x86", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "aarch64"}
MAX_COMMANDS, MAX_SECTIONS, MAX_SYMBOLS, MAX_STARTS = 4096, 512, 2_000_000, 1_000_000


@dataclass
class MachoSection:
    segment: str
    name: str
    addr: int
    size: int
    offset: int
    flags: int

    @property
    def zerofill(self) -> bool:
        return self.flags & 0xFF in (S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL)

    @property
    def executable(self) -> bool:
        return bool(self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))


@dataclass
class MachoInfo:
    cpu: str
    bits: int
    filetype: int
    offset: int = 0                       # where this image starts in a fat file
    size: int = 0
    entry: int = 0
    text_base: int = 0                    # vmaddr of ``__TEXT``: the base of the function-start deltas
    sections: List[MachoSection] = field(default_factory=list)
    starts: List[int] = field(default_factory=list)                 # LC_FUNCTION_STARTS
    functions: List[Tuple[int, str]] = field(default_factory=list)  # (address, name) of symbols
    stripped: bool = True

    def image(self, data: bytes) -> bytes:
        """The bytes of this image (the file itself unless it is a slice of a fat file)."""
        return data[self.offset:self.offset + self.size] if self.size else data


def _uleb(buf: bytes) -> List[int]:
    out, value, shift = [], 0, 0
    for b in buf:
        value |= (b & 0x7F) << shift
        if b & 0x80:
            shift += 7
            if shift > 63:
                break
            continue
        out.append(value)
        value, shift = 0, 0
    return out


def _fat_slices(data: bytes) -> List[Tuple[int, int, int]]:
    """(cputype, offset, size) of each image of a fat file; fat headers are big-endian."""
    magic, count = struct.unpack_from(">II", data, 0)
    wide = magic == FAT_MAGIC_64
    size = 32 if wide else 20
    out = []
    for i in range(min(count, 32)):
        base = 8 + i * size
        if wide:
            cpu, _sub, off, length = struct.unpack_from(">iiQQ", data, base)
        else:
            cpu, _sub, off, length = struct.unpack_from(">iiII", data, base)
        if off + length <= len(data) and length >= 28:
            out.append((cpu & 0xFFFFFFFF, off, length))
    return out


def parse_macho(data: bytes, prefer: Sequence[str] = ("aarch64", "x86_64")) -> Optional[MachoInfo]:
    if len(data) < 28:
        return None
    try:
        magic, = struct.unpack_from(">I", data, 0)
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            slices = _fat_slices(data)
            ranked = sorted(slices, key=lambda s: prefer.index(CPUS[s[0]])
                            if CPUS.get(s[0]) in prefer else len(prefer))
            for cpu, off, length in ranked:
                if CPUS.get(cpu):
                    info = _parse_thin(data[off:off + length])
                    if info is not None:
                        info.offset, info.size = off, length
                        return info
            return None
        return _parse_thin(data)
    except struct.error:
        return None


def _parse_thin(data: bytes) -> Optional[MachoInfo]:
    magic, = struct.unpack_from("<I", data, 0)
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        return None                       # includes the byte-swapped (big-endian) magics
    bits = 64 if magic == MH_MAGIC_64 else 32
    cputype, _sub, filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from("<iiIIII", data, 4)
    cpu = CPUS.get(cputype & 0xFFFFFFFF)
    if cpu is None or ncmds > MAX_COMMANDS:
        return None
    info = MachoInfo(cpu, bits, filetype)
    pos = 32 if bits == 64 else 28
    symtab = funcstarts = None
    entryoff = None
    for _ in range(ncmds):
        if pos + 8 > len(data):
            return info
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8 or pos + size > len(data):
            break
        if cmd == LC_SEGMENT_64 and size >= 72:
            segname = data[pos + 8:pos + 24].split(b"\0")[0].decode("ascii", "replace")
            vmaddr, _vmsize, _fileoff, _filesize, _mp, _ip, nsects, _f = struct.unpack_from(
                "<QQQQiiII", data, pos + 24)
            if segname == "__TEXT" and not info.text_base:
                info.text_base = vmaddr
            at = pos + 72
            for _s in range(min(nsects, MAX_SECTIONS)):
                if at + 80 > pos + size:
                    break
                sect = data[at:at + 16].split(b"\0")[0].decode("ascii", "replace")
                seg = data[at + 16:at + 32].split(b"\0")[0].decode("ascii", "replace")
                addr, ssize, off, _al, _ro, _nr, flags = struct.unpack_from("<QQIIIII", data, at + 32)
                info.sections.append(MachoSection(seg, sect, addr, ssize, off, flags))
                at += 80
        elif cmd == LC_SEGMENT and size >= 56:
            segname = data[pos + 8:pos + 24].split(b"\0")[0].decode("ascii", "replace")
            vmaddr, _vmsize, _fileoff, _filesize, _mp, _ip, nsects, _f = struct.unpack_from(
                "<IIIIiiII", data, pos + 24)
            if segname == "__TEXT" and not info.text_base:
                info.text_base = vmaddr
            at = pos + 56
            for _s in range(min(nsects, MAX_SECTIONS)):
                if at + 68 > pos + size:
                    break
                sect = data[at:at + 16].split(b"\0")[0].decode("ascii", "replace")
                seg = data[at + 16:at + 32].split(b"\0")[0].decode("ascii", "replace")
                addr, ssize, off, _al, _ro, _nr, flags = struct.unpack_from("<IIIIIII", data, at + 32)
                info.sections.append(MachoSection(seg, sect, addr, ssize, off, flags))
                at += 68
        elif cmd == LC_SYMTAB and size >= 24:
            symtab = struct.unpack_from("<IIII", data, pos + 8)         # symoff nsyms stroff strsize
        elif cmd == LC_FUNCTION_STARTS and size >= 16:
            funcstarts = struct.unpack_from("<II", data, pos + 8)       # dataoff datasize
        elif cmd == LC_MAIN and size >= 24:
            entryoff, = struct.unpack_from("<Q", data, pos + 8)
        pos += size
    if entryoff is not None:
        info.entry = info.text_base + entryoff
    if funcstarts is not None and funcstarts[0] + funcstarts[1] <= len(data):
        addr = info.text_base
        for delta in _uleb(data[funcstarts[0]:funcstarts[0] + funcstarts[1]])[:MAX_STARTS]:
            if delta == 0:
                break                 # the list ends with a zero byte, then padding
            addr += delta
            info.starts.append(addr)
    if symtab is not None:
        _read_symbols(data, info, *symtab)
    return info


def _read_symbols(data: bytes, info: MachoInfo, symoff: int, nsyms: int, stroff: int,
                  strsize: int) -> None:
    width = 16 if info.bits == 64 else 12
    if nsyms > MAX_SYMBOLS or symoff + nsyms * width > len(data):
        return
    strings = data[stroff:stroff + strsize]
    for i in range(nsyms):
        at = symoff + i * width
        if info.bits == 64:
            strx, ntype, nsect, _desc, value = struct.unpack_from("<IBBHQ", data, at)
        else:
            strx, ntype, nsect, _desc, value = struct.unpack_from("<IBBHI", data, at)
        if ntype & 0xE0 or ntype & 0x0E != 0x0E or not 1 <= nsect <= len(info.sections):
            continue                      # a debugger (stab) entry, or not defined in a section
        info.stripped = False
        if info.sections[nsect - 1].executable and strx < len(strings):
            end = strings.find(b"\0", strx)
            name = strings[strx:end if end >= 0 else len(strings)].decode("ascii", "replace")
            info.functions.append((value, name))
