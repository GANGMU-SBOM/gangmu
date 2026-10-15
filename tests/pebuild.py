"""Build small, valid PE32+ files for tests, byte by byte from the specification.

Real binaries are used where they are available (see ``test_pe.py``), but they cannot be
committed. Every section here starts at a multiple of 0x1000 with file alignment equal to
section alignment, so an RVA equals its file offset. That keeps the builder short; the parser
still goes through its section table to translate addresses.
"""

import struct
import zlib
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

PAGE = 0x1000
GO_MAGIC = b"\xff Go buildinf:"
GO_SENTINEL = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"


def _pad(data: bytes, to: int = 4) -> bytes:
    return data + b"\0" * (-len(data) % to)


def _w(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\0\0"


def _vblock(key: str, value: bytes = b"", children: bytes = b"", vlen: int = 0,
            kind: int = 0) -> bytes:
    """One VS_VERSIONINFO node: header, key, padded value, then its children."""
    head = struct.pack("<HHH", 0, vlen, kind) + _w(key)
    body = _pad(head) + value
    if children:
        body = _pad(body) + children
    return struct.pack("<H", len(body)) + body[2:]


def version_resource(strings: Dict[str, str], file_version=(1, 2, 3, 4),
                     product_version=(1, 2, 3, 4)) -> bytes:
    fixed = struct.pack("<IIIIIIIIIIIII", 0xFEEF04BD, 0x10000,
                        (file_version[0] << 16) | file_version[1],
                        (file_version[2] << 16) | file_version[3],
                        (product_version[0] << 16) | product_version[1],
                        (product_version[2] << 16) | product_version[3], 0, 0, 0, 0, 0, 0, 0)
    entries = b""
    for key, value in strings.items():
        text = _w(value)
        entries += _pad(_vblock(key, text, vlen=len(text) // 2, kind=1))
    table = _vblock("040904B0", children=entries, kind=1)
    info = _vblock("StringFileInfo", children=_pad(table), kind=1)
    return _vblock("VS_VERSION_INFO", fixed, _pad(info), vlen=52)


def go_buildinfo_blob(version: str, modinfo: str, flags: int = 2, ptr: int = 8) -> bytes:
    """The inline (Go 1.18+) layout; ``flags=0`` gives the older pointer layout header."""
    def varint(n: int) -> bytes:
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out
    head = GO_MAGIC + bytes([ptr, flags]) + b"\0" * 16
    wrapped = GO_SENTINEL + modinfo.encode() + GO_SENTINEL
    return (head + varint(len(version)) + version.encode()
            + varint(len(wrapped)) + wrapped)


def cargo_blob(packages: Sequence[dict]) -> bytes:
    import json
    return zlib.compress(json.dumps({"packages": list(packages), "format": 1}).encode())


class _Section:
    def __init__(self, name: str, data: bytes):
        self.name, self.data = name, data


def build_pe(*, machine: int = 0x8664, dll: bool = False, imports: Iterable[str] = (),
             delay_imports: Iterable[str] = (), exports: Optional[Tuple[str, List[str]]] = None,
             version: Optional[Dict[str, str]] = None, file_version=(1, 2, 3, 4),
             pdb: Optional[str] = None, clr: bool = False, signed: bool = False,
             extra: Sequence[Tuple[str, bytes]] = (), linker=(14, 38),
             text: bytes = b"") -> bytes:
    rdata = bytearray()
    base = 2 * PAGE                                     # .rdata starts at RVA 0x2000

    def alloc(raw: bytes) -> int:
        while len(rdata) % 4:
            rdata.append(0)
        at = base + len(rdata)
        rdata.extend(raw)
        return at

    dirs = {i: (0, 0) for i in range(16)}
    imports, delay_imports = list(imports), list(delay_imports)
    if imports:
        names = [alloc(n.encode() + b"\0") for n in imports]
        table = b"".join(struct.pack("<IIIII", 0, 0, 0, rva, 0) for rva in names) + b"\0" * 20
        dirs[1] = (alloc(table), len(table))
    if delay_imports:
        names = [alloc(n.encode() + b"\0") for n in delay_imports]
        table = b"".join(struct.pack("<IIIIIIII", 1, rva, 0, 0, 0, 0, 0, 0)
                         for rva in names) + b"\0" * 32
        dirs[13] = (alloc(table), len(table))
    if exports:
        dll_name, funcs = exports
        name_rva = alloc(dll_name.encode() + b"\0")
        rvas = [alloc(f.encode() + b"\0") for f in funcs]
        array = alloc(b"".join(struct.pack("<I", r) for r in rvas))
        head = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, name_rva, 1, len(funcs), len(funcs),
                           array, array, array)
        dirs[0] = (alloc(head), len(head))
    if pdb is not None:
        cv = (b"RSDS" + bytes(range(1, 17)) + struct.pack("<I", 1) + pdb.encode() + b"\0")
        cv_rva = alloc(cv)
        entry = struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(cv), cv_rva, cv_rva)
        dirs[6] = (alloc(entry), len(entry))
    if clr:
        dirs[14] = (alloc(b"\x48\0\0\0" + b"\0" * 68), 72)

    sections: List[_Section] = [_Section(".text", text or b"\xc3"),
                                _Section(".rdata", bytes(rdata) or b"\0")]
    if version is not None:
        res_at = (2 + 1) * PAGE
        blob = version_resource(version, file_version, file_version)
        leaf = res_at + 88
        tree = (struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 16, 0x80000018)
                + struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 1, 0x80000030)
                + struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 0x409, 72)
                + struct.pack("<IIII", leaf, len(blob), 0, 0))
        sections.append(_Section(".rsrc", tree + blob))
        dirs[2] = (res_at, len(tree) + len(blob))
    for name, data in extra:
        sections.append(_Section(name, data))

    sec_table = b""
    body = b""
    rva = PAGE
    for sec in sections:
        size = len(sec.data)
        padded = size + (-size % PAGE or (PAGE if size == 0 else 0))
        sec_table += struct.pack("<8sIIIIIIHHI", sec.name.encode(), size, rva, padded, rva,
                                 0, 0, 0, 0, 0x40000040)
        body += sec.data + b"\0" * (padded - size)
        rva += padded
    sec_end = rva
    ddirs = b"".join(struct.pack("<II", *dirs[i]) for i in range(16))
    sec_off = 0
    if signed:
        sec_off = PAGE + len(body)
        body += b"\x08\0\0\0" + b"\0" * 12
        dirs[4] = (sec_off, 16)
        ddirs = b"".join(struct.pack("<II", *dirs[i]) for i in range(16))
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, linker[0], linker[1], 0, 0, 0, 0,
                      PAGE, 0x140000000, PAGE, PAGE, 6, 0, 0, 0, 6, 0, 0, sec_end, PAGE, 0, 3,
                      0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + ddirs
    chars = 0x22 | (0x2000 if dll else 0)
    coff = struct.pack("<HHIIIHH", machine, len(sections), 0x65000000, 0, 0, len(opt), chars)
    header = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80)
    header += b"\0" * (0x80 - len(header)) + b"PE\0\0" + coff + opt + sec_table
    return header + b"\0" * (PAGE - len(header)) + body
