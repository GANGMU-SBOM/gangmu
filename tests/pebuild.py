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
             pdb: Optional[str] = None, clr=False, clr_resources: bytes = b"", signed: bool = False,
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
        meta_rva = alloc(clr if isinstance(clr, bytes) else b"BSJB" + b"\0" * 60)
        res_rva = alloc(clr_resources) if clr_resources else 0
        cor = struct.pack("<IHHIIIIII", 0x48, 2, 5, meta_rva,
                          len(clr) if isinstance(clr, bytes) else 64, 1, 0, res_rva,
                          len(clr_resources)) + b"\0" * 40
        dirs[14] = (alloc(cor), 72)

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


def managed_resource_blob(items: Sequence[Tuple[str, bytes]]):
    """The resources area of an assembly (each entry a 4-byte length then the data), and the
    ``(name, offset of its length prefix)`` pairs that the ManifestResource table needs."""
    blob, entries = b"", []
    for name, data in items:
        entries.append((name, len(blob)))
        blob += struct.pack("<I", len(data)) + data
    return blob, entries


def dotnet_metadata(name: str, version=(1, 0, 0, 0), refs: Sequence[Tuple[str, tuple]] = (),
                    extra_tables: Optional[Dict[int, Tuple[int, bytes]]] = None,
                    wide_strings: bool = False,
                    resources: Sequence[Tuple[str, int]] = ()) -> bytes:
    """The metadata root of an assembly: Module, Assembly and AssemblyRef tables.

    Written from ECMA-335 II.22 without calling the parser, so a width the parser gets wrong
    is not repeated here. ``extra_tables`` maps a table number to ``(row count, raw bytes)``
    that the caller worked out by hand; those tables sit before ``AssemblyRef`` and push it
    along, which is how a wrong index width shows up. ``wide_strings`` makes the #Strings
    heap larger than 64 KiB, so every string index is 4 bytes.
    """
    heap = b"\0"
    seen: Dict[str, int] = {}

    def add(text: str) -> int:
        nonlocal heap
        if text not in seen:
            seen[text] = len(heap)
            heap += text.encode() + b"\0"
        return seen[text]

    sw = 4 if wide_strings else 2                     # string index width; GUID/blob stay 2
    ref_rows = [struct.pack("<HHHHI", *v, 0) + (0).to_bytes(2, "little")
                + add(n).to_bytes(sw, "little") + (0).to_bytes(sw, "little")
                + (0).to_bytes(2, "little") for n, v in refs]
    module = (0).to_bytes(2, "little") + add("module.dll").to_bytes(sw, "little") + b"\0" * 6
    assembly = (struct.pack("<IHHHHI", 0x8004, *version, 0) + (0).to_bytes(2, "little")
                + add(name).to_bytes(sw, "little") + (0).to_bytes(sw, "little"))
    if wide_strings:
        heap += b"\0" * 70000
    tables = {0x00: (1, module), 0x20: (1, assembly)}
    tables.update(extra_tables or {})
    if refs:
        tables[0x23] = (len(refs), b"".join(ref_rows))
    if resources:                    # ManifestResource: Offset, Flags, Name, Implementation (0)
        tables[0x28] = (len(resources), b"".join(
            struct.pack("<II", off, 1) + add(n).to_bytes(sw, "little") + (0).to_bytes(2, "little")
            for n, off in resources))
    valid = sum(1 << t for t in tables)
    body = b"".join(raw for _t, (_n, raw) in sorted(tables.items()))
    stream = (struct.pack("<IBBBBQQ", 0, 2, 0, 1 if wide_strings else 0, 1, valid, 0)
              + b"".join(struct.pack("<I", n) for _t, (n, _r) in sorted(tables.items())) + body)
    streams = [("#~", stream), ("#Strings", heap)]
    version_str = b"v4.0.30319\0\0"
    head_len = 16 + len(version_str) + 4 + sum(8 + len(n) + 1 + (-(len(n) + 1) % 4)
                                              for n, _ in streams)
    directory, blobs, at = b"", b"", head_len
    for n, data in streams:
        data += b"\0" * (-len(data) % 4)
        directory += struct.pack("<II", at, len(data)) + n.encode() + b"\0"
        directory += b"\0" * (-(len(n) + 1) % 4)
        blobs += data
        at += len(data)
    return (b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version_str)) + version_str
            + struct.pack("<HH", 0, len(streams)) + directory + blobs)


def elf_blob(machine: int = 62, etype: int = 3, payload: bytes = b"", sections: bool = True,
             bits64: bool = True, big: bool = False) -> bytes:
    """A small ELF whose size is fixed by its tables: ``sections`` puts the section header
    table last (the usual layout); without it only a PT_LOAD program header says how long it is."""
    payload = payload or b"\x90" * 3000
    e = ">" if big else "<"
    ident = b"\x7fELF" + bytes([2 if bits64 else 1, 2 if big else 1, 1]) + b"\0" * 9
    ehsize = 64 if bits64 else 52
    body_at = ehsize + (56 if bits64 else 32)         # one program header follows the header
    names = b"\0.text\0.shstrtab\0"
    total = body_at + len(payload)
    if sections:
        shoff = total + len(names)
        shnum, shentsize = 3, (64 if bits64 else 40)
        total = shoff + shnum * shentsize
    else:
        shoff, shnum, shentsize = 0, 0, (64 if bits64 else 40)
    if bits64:
        head = ident + struct.pack(e + "HHIQQQIHHHHHH", etype, machine, 1, 0, ehsize, shoff, 0,
                                   ehsize, 56, 1, shentsize, shnum, 2)
        phdr = struct.pack(e + "IIQQQQQQ", 1, 5, 0, 0, 0, total if not sections else body_at
                           + len(payload), total, 0x1000)
    else:
        head = ident + struct.pack(e + "HHIIIIIHHHHHH", etype, machine, 1, 0, ehsize, shoff, 0,
                                   ehsize, 32, 1, shentsize, shnum, 2)
        phdr = struct.pack(e + "IIIIIIII", 1, 0, 0, 0, total if not sections else body_at
                           + len(payload), total, 5, 0x1000)
    out = head + phdr + payload
    if sections:
        out += names
        if bits64:
            row = lambda n, t, off, sz: struct.pack(e + "IIQQQQIIQQ", n, t, 0, 0, off, sz, 0, 0, 1, 0)
        else:
            row = lambda n, t, off, sz: struct.pack(e + "IIIIIIIIII", n, t, 0, 0, off, sz, 0, 0, 1, 0)
        out += (row(0, 0, 0, 0) + row(1, 1, body_at, len(payload))
                + row(7, 3, body_at + len(payload), len(names)))
    assert len(out) == total or not sections
    return out if sections else out + b"\0" * (total - len(out))


def macho_blob(cputype: int = 0x0100000C, filetype: int = 6, text: int = 4096,
               linkedit: int = 1024, signature: int = 0) -> bytes:
    """A 64-bit little-endian Mach-O: __TEXT then __LINKEDIT, optionally a code signature."""
    def segment(name: bytes, fileoff: int, size: int) -> bytes:
        return struct.pack("<II16sQQQQiiII", 0x19, 72, name, fileoff, size, fileoff, size, 7, 5,
                           0, 0)
    cmds = segment(b"__TEXT", 0, text) + segment(b"__LINKEDIT", text, linkedit)
    ncmds = 2
    if signature:
        cmds += struct.pack("<IIII", 0x1D, 16, text + linkedit, signature)
        ncmds = 3
    head = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 3, filetype, ncmds, len(cmds), 0, 0)
    out = head + cmds
    return out + b"\0" * (text + linkedit + signature - len(out))
