"""A small, dependency-free ELF reader: defined symbols, ``.comment`` and strippedness.

Only what the binary inventory needs. Bytes that are not a well-formed ELF file give
``None`` rather than an exception, so a ``.bin`` image or a truncated file falls back to
the plain byte scan.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

SHT_SYMTAB, SHT_DYNSYM = 2, 11
STT_OBJECT, STT_FUNC = 1, 2
SHF_EXECINSTR, SHT_PROGBITS = 4, 1
EM_386, EM_ARM, EM_X86_64, EM_RISCV = 3, 40, 62, 243
MAX_SECTIONS = 4096
PT_LOAD, PT_DYNAMIC, DT_PLTGOT = 1, 2, 3
SHT_NOBITS = 8


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int


@dataclass
class ElfInfo:
    machine: int
    bits: int
    entry: int = 0
    little: bool = True
    sections: List[Section] = field(default_factory=list)
    functions: List[Tuple[int, int, str]] = field(default_factory=list)  # (addr, size, name)
    defined: Set[str] = field(default_factory=set)      # named FUNC/OBJECT symbols with a section
    comments: List[str] = field(default_factory=list)   # NUL-separated strings of ``.comment``
    stripped: bool = True                               # no ``.symtab``
    relocatable: bool = False                           # an object file: sections have no address yet
    flags: int = 0                                      # e_flags
    got: int = 0                                        # DT_PLTGOT (MIPS: _gp is this + 0x7ff0)


def parse_elf(data: bytes) -> Optional[ElfInfo]:
    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    bits = 32 if data[4] == 1 else 64
    e = "<" if data[5] == 1 else ">"
    try:
        machine = struct.unpack_from(e + "H", data, 18)[0]
        relocatable = struct.unpack_from(e + "H", data, 16)[0] == 1
        flags, = struct.unpack_from(e + "I", data, 0x30 if bits == 64 else 0x24)
        if bits == 64:
            entry, = struct.unpack_from(e + "Q", data, 0x18)
            shoff, = struct.unpack_from(e + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
        else:
            entry, = struct.unpack_from(e + "I", data, 0x18)
            shoff, = struct.unpack_from(e + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
        if not shoff or shnum == 0 or shnum > MAX_SECTIONS or shentsize < 40:
            return _from_segments(data, ElfInfo(machine, bits, entry, e == "<",
                                                relocatable=relocatable, flags=flags))
        secs = []
        for i in range(shnum):
            o = shoff + i * shentsize
            if bits == 64:
                name, typ, flg, addr, off, size, link = struct.unpack_from(e + "IIQQQQI", data, o)
            else:
                name, typ, flg, addr, off, size, link = struct.unpack_from(e + "IIIIIII", data, o)
            secs.append((name, typ, off, size, link, flg, addr))
    except struct.error:
        return None

    def blob(sec) -> bytes:
        return data[sec[2]:sec[2] + sec[3]]

    def cstr(table: bytes, at: int) -> str:
        end = table.find(b"\0", at)
        return table[at:end if end >= 0 else len(table)].decode("ascii", "replace")

    info = ElfInfo(machine, bits, entry, e == "<", relocatable=relocatable, flags=flags)
    shstr = blob(secs[shstrndx]) if shstrndx < len(secs) else b""
    for sec in secs:
        info.sections.append(Section(cstr(shstr, sec[0]), sec[1], sec[5], sec[6], sec[2], sec[3]))
        if cstr(shstr, sec[0]) == ".comment":
            info.comments = [s.decode("ascii", "replace") for s in blob(sec).split(b"\0") if s]
        if sec[1] not in (SHT_SYMTAB, SHT_DYNSYM) or sec[4] >= len(secs):
            continue
        if sec[1] == SHT_SYMTAB:
            info.stripped = False
        strtab = blob(secs[sec[4]])
        raw = blob(sec)
        size = 24 if bits == 64 else 16
        for o in range(0, len(raw) - size + 1, size):
            if bits == 64:
                name, st_info, _o, shndx, value, ssize = struct.unpack_from(e + "IBBHQQ", raw, o)
            else:
                name, value, ssize, st_info, _o, shndx = struct.unpack_from(e + "IIIBBH", raw, o)
            if name and shndx != 0 and st_info & 0xF in (STT_OBJECT, STT_FUNC):
                label = cstr(strtab, name)
                info.defined.add(label)
                if st_info & 0xF == STT_FUNC and value:
                    info.functions.append((value, ssize, label))   # Thumb: bit 0 is the mode
    return info


def _from_segments(data: bytes, info: ElfInfo) -> ElfInfo:
    """Sections for a file with no section table (sstrip, or a packed image).

    A loader needs only the program headers, so the loadable segments stand in: each gives
    an allocated section (executable when the segment is) and, where it is larger in memory
    than in the file, a zero-filled one for the rest. ``DT_PLTGOT`` is read from the
    dynamic segment because MIPS code is addressed relative to it."""
    e = "<" if info.little else ">"
    try:
        if info.bits == 64:
            phoff, = struct.unpack_from(e + "Q", data, 0x20)
            phentsize, phnum = struct.unpack_from(e + "HH", data, 0x36)
        else:
            phoff, = struct.unpack_from(e + "I", data, 0x1C)
            phentsize, phnum = struct.unpack_from(e + "HH", data, 0x2A)
        if not phoff or phentsize < 32 or phnum > 64:
            return info
        dynamic = None
        for i in range(phnum):
            o = phoff + i * phentsize
            if info.bits == 64:
                typ, flg, off, vaddr, _p, filesz, memsz = struct.unpack_from(e + "IIQQQQQ", data, o)
            else:
                typ, off, vaddr, _p, filesz, memsz, flg = struct.unpack_from(e + "IIIIIII", data, o)
            if typ == PT_DYNAMIC:
                dynamic = (off, filesz)
            if typ != PT_LOAD or not memsz:
                continue
            shf = 2 | (SHF_EXECINSTR if flg & 1 else 0) | (1 if flg & 2 else 0)
            filesz = min(filesz, max(0, len(data) - off))
            info.sections.append(Section(f".load{i}", SHT_PROGBITS, shf, vaddr, off, filesz))
            if memsz > filesz:
                info.sections.append(Section(f".load{i}.bss", SHT_NOBITS, shf,
                                             vaddr + filesz, 0, memsz - filesz))
        if dynamic is not None:
            width = 8 if info.bits == 64 else 4
            blob = data[dynamic[0]:dynamic[0] + dynamic[1]]
            for o in range(0, len(blob) - 2 * width + 1, 2 * width):
                tag, val = struct.unpack_from(e + ("QQ" if width == 8 else "II"), blob, o)
                if tag == 0:
                    break
                if tag == DT_PLTGOT:
                    info.got = val
    except struct.error:
        pass
    return info
