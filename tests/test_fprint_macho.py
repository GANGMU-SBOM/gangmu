"""Function fingerprints of Mach-O images (LC_FUNCTION_STARTS gives the boundaries)."""

import struct

import pytest

from gangmu import disasm
from gangmu.fprint import _hash, image_features, memory_from_macho
from gangmu.macho import parse_macho

pytestmark = pytest.mark.skipif(not disasm.available(), reason="capstone not installed")

TEXT_VM = 0x100000000
F1 = (b"\x53" + b"\x48\x83\xec\x20" + b"\xb8" + struct.pack("<I", 0x12345678)
      + b"\x48\x83\xc4\x20" + b"\x5b\xc3")
F2 = b"\x48\xb8" + struct.pack("<Q", 0x1122334455667788) + b"\xc3"


def _uleb(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _name(s):
    return s.encode().ljust(16, b"\0")


def macho(cpu=0x01000007, starts=True, symbols=(), fat=False, cstring=b"a literal in __cstring\0"):
    """A thin 64-bit little-endian image: __TEXT with __text and __cstring, plus LINKEDIT data.

    *symbols*: (name, offset into __text) pairs, written as defined symbols of section 1."""
    text = F1.ljust(0x20, b"\xcc") + F2 + b"\xcc" * 5
    text_off, cstr_off = 0x1000, 0x1000 + len(text)
    cstr_addr = TEXT_VM + cstr_off
    seg_size = 72 + 2 * 80
    fs = b"".join(_uleb(d) for d in (0x1000, 0x20)) if starts else b""
    fs = fs.ljust((len(fs) + 7) // 8 * 8, b"\0")
    nl = b"".join(struct.pack("<IBBHQ", 1 + sum(len(s[0]) + 1 for s in symbols[:i]), 0x0F, 1, 0,
                              TEXT_VM + text_off + off) for i, (_, off) in enumerate(symbols))
    strtab = b"\0" + b"".join(s.encode() + b"\0" for s, _ in symbols)
    link_off = cstr_off + len(cstring)
    cmds = struct.pack("<II16sQQQQiiII", 0x19, seg_size, _name("__TEXT"), TEXT_VM, 0x4000, 0,
                       link_off, 7, 5, 2, 0)
    cmds += struct.pack("<16s16sQQIIIIIIII", _name("__text"), _name("__TEXT"), TEXT_VM + text_off,
                        len(text), text_off, 4, 0, 0, 0x80000400, 0, 0, 0)
    cmds += struct.pack("<16s16sQQIIIIIIII", _name("__cstring"), _name("__TEXT"), cstr_addr,
                        len(cstring), cstr_off, 0, 0, 0, 0x2, 0, 0, 0)
    ncmds = 1
    if starts:
        cmds += struct.pack("<IIII", 0x26, 16, link_off, len(fs))
        ncmds += 1
    sym_off = link_off + len(fs)
    if symbols:
        cmds += struct.pack("<IIIIII", 0x2, 24, sym_off, len(symbols), sym_off + len(nl), len(strtab))
        ncmds += 1
    body = bytearray(link_off + len(fs) + len(nl) + len(strtab))
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, 3, 6, ncmds, len(cmds), 0, 0)
    body[:len(header) + len(cmds)] = header + cmds
    body[text_off:text_off + len(text)] = text
    body[cstr_off:cstr_off + len(cstring)] = cstring
    body[link_off:link_off + len(fs)] = fs
    body[sym_off:sym_off + len(nl)] = nl
    body[sym_off + len(nl):] = strtab
    image = bytes(body)
    if not fat:
        return image
    head = struct.pack(">II", 0xCAFEBABE, 2)
    head += struct.pack(">iiIII", 0x01000007, 3, 0x4000, len(image), 14)           # x86_64 slice
    head += struct.pack(">iiIII", 0x0100000C, 0, 0x4000 + len(image), len(image), 14)
    return head.ljust(0x4000, b"\0") + image + image


def test_sections_entry_points_and_function_starts_are_read():
    info = parse_macho(macho())
    assert info.cpu == "x86_64" and info.text_base == TEXT_VM
    assert [s.name for s in info.sections] == ["__text", "__cstring"]
    assert info.sections[0].executable and not info.sections[1].executable
    assert info.starts == [TEXT_VM + 0x1000, TEXT_VM + 0x1020]


def test_functions_come_from_the_function_starts_list_with_exact_sizes():
    data = macho()
    rec = disasm.recover_macho(data, parse_macho(data))
    assert rec.arch == "x86-64"
    assert {f.address: f.size for f in rec.functions} == {
        TEXT_VM + 0x1000: 0x20, TEXT_VM + 0x1020: len(F2) + 5}


def test_symbols_name_functions_when_there_are_no_function_starts():
    data = macho(starts=False, symbols=[("_first", 0), ("_second", 0x20)])
    info = parse_macho(data)
    assert not info.stripped and not info.starts
    rec = disasm.recover_macho(data, info)
    assert {f.name for f in rec.functions} >= {"_first", "_second"}


def test_features_are_the_constants_and_the_memory_maps_the_sections():
    data = macho()
    feats, arch = image_features(data, min_features=1)
    assert arch == "x86-64"
    assert {_hash(b"c", (0x12345678).to_bytes(8, "big"))} in feats
    mem = memory_from_macho(data, parse_macho(data))
    assert mem.read(TEXT_VM + 0x1000, 1) == b"\x53"


def test_a_fat_file_gives_the_preferred_slice():
    data = macho(fat=True)
    info = parse_macho(data, prefer=("x86_64",))
    assert info.cpu == "x86_64" and info.offset == 0x4000
    feats, arch = image_features(data, min_features=1)
    assert feats and arch in ("x86-64", "aarch64")


def test_an_unsupported_cpu_is_reported_and_garbage_is_not_a_macho():
    data = macho(cpu=12)                                   # 32-bit ARM
    rec = disasm.recover_macho(data, parse_macho(data))
    assert rec.arch == "unsupported" and not rec.functions
    assert parse_macho(b"\xcf\xfa\xed\xfe" + b"\0" * 8) is None
    assert parse_macho(b"MZ" + b"\0" * 100) is None
