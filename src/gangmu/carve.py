"""Native binaries that sit inside another file, found by their headers.

A file can carry whole executables or libraries as data: a .NET assembly with the native
libraries for every platform as managed resources, an installer or self-extractor with its payload
appended, firmware with an embedded ELF, a Go or Rust program that embeds a helper. Reading the
outer file for banners sees the bytes but cannot say which binary they belong to, and none of the
structural readers (symbol tables, imports, version resources, dependency lists) can run on a
binary that is not at offset zero.

This module finds such binaries and works out where each one ends. It is deliberately strict: a
magic number alone is not enough (``MZ`` and ``\\x7fELF`` turn up inside ordinary code and data),
so a candidate must have a header that is consistent with itself, and its size comes from the
format's own tables, not from a guess. Anything that fails a check is left alone. Searching is
bounded in count and size, and nothing here executes or decompresses anything.

Handled: ELF executables and shared objects (not relocatable objects, which is what the members of
a static archive are), PE images, and little-endian Mach-O. Fat Mach-O is not: its magic is also
the magic of a Java class file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

MIN_SIZE = 2048                  # smaller than this is a header-shaped coincidence, not a library
MAX_BLOBS = 64
MAX_CANDIDATES = 200_000         # "MZ" is two ordinary bytes; stop looking after this many

_ELF_MACHINES = {3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 62: "x86_64",
                 94: "xtensa", 183: "aarch64", 243: "riscv", 247: "bpf"}
_PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0x1C4: "armnt",
                0xAA64: "aarch64", 0x5064: "riscv64", 0x200: "ia64"}
_MACHO_CPUS = {7: "x86", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "aarch64"}


@dataclass
class Carved:
    offset: int
    size: int
    kind: str                 # elf | pe | macho
    arch: str
    suffix: str               # what to treat it as: .elf, .dll or .exe, .dylib


def carve(data: bytes, min_size: int = MIN_SIZE, max_blobs: int = MAX_BLOBS) -> List[Carved]:
    """Binaries embedded in *data* (never the file itself, which starts at offset 0)."""
    hits: List[Carved] = []
    for offset, kind in _candidates(data):
        found = _VALIDATORS[kind](data, offset)
        if found is None or found.size < min_size or offset + found.size > len(data):
            continue
        hits.append(found)
    hits.sort(key=lambda c: (c.offset, -c.size))
    out: List[Carved] = []
    end = 0
    for c in hits:                    # keep the outermost; a binary inside one is found when
        if c.offset >= end:           # that one is analysed in turn
            out.append(c)
            end = c.offset + c.size
        if len(out) >= max_blobs:
            break
    return out


def _candidates(data: bytes):
    for magic, kind in ((b"\x7fELF", "elf"), (b"\xcf\xfa\xed\xfe", "macho"),
                        (b"\xce\xfa\xed\xfe", "macho"), (b"MZ", "pe")):
        at = data.find(magic, 1)             # offset 0 is the outer file itself
        seen = 0
        while at >= 0 and seen < MAX_CANDIDATES:
            yield at, kind
            seen += 1
            at = data.find(magic, at + 1)


def mask(data: bytes, carved: List[Carved]) -> bytes:
    """*data* with each carved binary blanked, so the outer file is scanned for what is its own."""
    if not carved:
        return data
    out = bytearray(data)
    for c in carved:
        out[c.offset:c.offset + c.size] = bytes(c.size)
    return bytes(out)


def _u(data: bytes, fmt: str, at: int) -> Optional[tuple]:
    try:
        return struct.unpack_from(fmt, data, at)
    except struct.error:
        return None


def _elf(data: bytes, off: int) -> Optional[Carved]:
    head = data[off:off + 64]
    if len(head) < 52 or head[4] not in (1, 2) or head[5] not in (1, 2) or head[6] != 1:
        return None
    e = "<" if head[5] == 1 else ">"
    bits64 = head[4] == 2
    etype, machine = struct.unpack_from(e + "HH", head, 16)
    if etype not in (2, 3):                    # executable or shared object, not an .o
        return None
    if bits64:
        if len(head) < 64:
            return None
        phoff, shoff = struct.unpack_from(e + "QQ", head, 0x20)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", head, 0x36)
    else:
        phoff, shoff = struct.unpack_from(e + "II", head, 0x1C)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", head, 0x2A)
    if phnum > 256 or shnum > 4096 or (phnum and phentsize < (56 if bits64 else 32)) \
            or (shnum and shentsize < (64 if bits64 else 40)):
        return None
    end = 0
    for i in range(phnum):                     # program headers: p_offset + p_filesz
        row = _u(data, e + ("IIQQQQ" if bits64 else "IIIIII"), off + phoff + i * phentsize)
        if row is None:
            return None
        end = max(end, row[2] + row[5] if bits64 else row[1] + row[4])
    if phnum:
        end = max(end, phoff + phnum * phentsize)
    for i in range(shnum):                     # section headers: sh_offset + sh_size, unless NOBITS
        at = off + shoff + i * shentsize
        row = _u(data, e + ("IIQQQQ" if bits64 else "IIIIII"), at)
        if row is None:
            return None
        if row[1] != 8:
            end = max(end, row[4] + row[5])               # sh_offset + sh_size
    if shnum:
        end = max(end, shoff + shnum * shentsize)
    if end <= 0:
        return None
    return Carved(off, end, "elf", _ELF_MACHINES.get(machine, f"machine {machine}"), ".elf")


def _pe(data: bytes, off: int) -> Optional[Carved]:
    got = _u(data, "<I", off + 0x3C)
    if got is None or not 0x40 <= got[0] <= 0x1000:
        return None
    pe = off + got[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return None
    coff = _u(data, "<HHIIIHH", pe + 4)
    if coff is None:
        return None
    machine, nsec, _stamp, _sym, _nsym, optsize, chars = coff
    if machine not in _PE_MACHINES or not 1 <= nsec <= 96 or optsize < 96:
        return None
    opt = pe + 24
    magic = _u(data, "<H", opt)
    if magic is None or magic[0] not in (0x10B, 0x20B):
        return None
    headers = _u(data, "<I", opt + 60)           # SizeOfHeaders
    end = headers[0] if headers else 0
    for i in range(nsec):
        row = _u(data, "<IIII", opt + optsize + 40 * i + 8)   # VirtualSize.. skip name, take raw
        if row is None:
            return None
        end = max(end, row[3] + row[2])          # PointerToRawData + SizeOfRawData
    cert = _u(data, "<II", opt + (96 if magic[0] == 0x10B else 112) + 8 * 4)
    if cert and cert[0] and cert[1]:
        end = max(end, cert[0] + cert[1])        # an Authenticode blob is appended past the sections
    if end <= 0:
        return None
    suffix = ".dll" if chars & 0x2000 else ".exe"
    return Carved(off, end, "pe", _PE_MACHINES[machine], suffix)


def _macho(data: bytes, off: int) -> Optional[Carved]:
    head = _u(data, "<IiiIIIII", off)
    if head is None:
        return None
    magic, cputype, _sub, filetype, ncmds, sizeofcmds, _flags, _res = head
    bits64 = magic == 0xFEEDFACF
    if magic not in (0xFEEDFACF, 0xFEEDFACE) or filetype not in (2, 6, 8) \
            or not 1 <= ncmds <= 1000 or sizeofcmds > 1 << 20:
        return None
    at = off + (32 if bits64 else 28)
    end = 0
    for _ in range(ncmds):
        row = _u(data, "<II", at)
        if row is None or row[1] < 8:
            return None
        cmd, size = row
        if cmd == 0x19 and bits64:                # LC_SEGMENT_64: fileoff, filesize
            seg = _u(data, "<QQ", at + 40)
            if seg is None:
                return None
            end = max(end, seg[0] + seg[1])
        elif cmd == 0x1 and not bits64:           # LC_SEGMENT
            seg = _u(data, "<II", at + 32)
            if seg is None:
                return None
            end = max(end, seg[0] + seg[1])
        elif cmd == 0x1D:                         # LC_CODE_SIGNATURE: dataoff, datasize
            sig = _u(data, "<II", at + 8)
            if sig is None:
                return None
            end = max(end, sig[0] + sig[1])
        at += size
    if end <= 0:
        return None
    return Carved(off, end, "macho", _MACHO_CPUS.get(cputype, f"cpu {cputype}"), ".dylib")


_VALIDATORS = {"elf": _elf, "pe": _pe, "macho": _macho}
