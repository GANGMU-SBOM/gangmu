"""Function fingerprints of Windows PE images (the exception table gives the boundaries)."""

import struct

import pytest
from pebuild import build_pe

from gangmu import disasm
from gangmu.fprint import _hash, image_features, memory_from_pe
from gangmu.pe import parse_pe

pytestmark = pytest.mark.skipif(not disasm.available(), reason="capstone not installed")

TEXT, BASE = 0x1000, 0x140000000


def _x64_image(pdata_entries=True):
    f1 = (b"\x53" + b"\x48\x83\xec\x20" + b"\xb8" + struct.pack("<I", 0x12345678)
          + b"\xe8" + struct.pack("<i", 0x20 - 15) + b"\x48\x83\xc4\x20" + b"\x5b\xc3")
    f2 = b"\x48\xb8" + struct.pack("<Q", 0x1122334455667788) + b"\xc3"
    text = f1.ljust(0x20, b"\xcc") + f2
    assert len(f1) == 0x15 and len(f2) == 0xB
    chain = TEXT + 0x30
    entries = [(TEXT, TEXT + len(f1), 0x2000), (TEXT + 0x20, TEXT + 0x20 + len(f2), 0x2000),
               (chain, chain + 8, 0x2010)]               # the last is a UNW_FLAG_CHAININFO piece
    pdata = b"".join(struct.pack("<III", *e) for e in entries) if pdata_entries else b""
    head = b"\x01\0\0\0".ljust(0x10, b"\0") + b"\x21\0\0\0"
    return build_pe(text=text.ljust(0x40, b"\xcc"), code=True, pdata=pdata, rdata_head=head)


def test_the_parser_reads_base_entry_and_exception_table():
    info = parse_pe(_x64_image())
    assert info.image_base == BASE
    assert info.exception_size == 36
    assert info.sections[0].flags & 0x20000000                 # .text is executable


def test_x64_functions_come_from_the_unwind_table_without_chained_pieces():
    data = _x64_image()
    rec = disasm.recover_pe(data, parse_pe(data))
    assert rec.arch == "x86-64"
    unwind = {f.address: f.size for f in rec.functions if f.source == "unwind"}
    assert unwind == {BASE + TEXT: 0x15, BASE + TEXT + 0x20: 0xB}


def test_functions_without_an_exception_table_are_swept():
    data = _x64_image(pdata_entries=False)
    rec = disasm.recover_pe(data, parse_pe(data))
    assert BASE + TEXT + 0x20 in {f.address for f in rec.functions}    # the call target


def test_features_are_the_distinctive_constants_of_each_function():
    data = _x64_image()
    features, arch = image_features(data, min_features=1)
    assert arch == "x86-64"
    c1 = _hash(b"c", (0x12345678).to_bytes(8, "big"))
    c2 = _hash(b"c", (0x1122334455667788).to_bytes(8, "big"))
    assert {c1} in features and {c2} in features


def test_memory_maps_sections_at_their_load_address():
    data = _x64_image()
    mem = memory_from_pe(data, parse_pe(data))
    assert mem.read(BASE + TEXT, 1) == b"\x53"


def test_an_unsupported_machine_is_reported_not_guessed():
    data = build_pe(machine=0x200, text=b"\x00" * 16, code=True)
    rec = disasm.recover_pe(data, parse_pe(data))
    assert rec.arch == "unsupported" and not rec.functions


# Windows CE: the same PE container around ARM code, a different exception table, subsystem 9.
CE_BASE = 0x10000
CE_CODE = bytes.fromhex("10402de9780605e3340241e3030000eb1080bde8"      # f1 at +0x00
                        "00f020e300f020e300f020e3"                      # padding nops
                        "ef1e0be3fe1a4ce31eff2fe1")                    # f2 at +0x20


def _ce_image(pdata=True):
    table = b"".join(struct.pack("<IIIII", CE_BASE + TEXT + off, CE_BASE + TEXT + off + n, 0, 0, 0)
                     for off, n in ((0, 0x14), (0x20, 0xC))) if pdata else b""
    return build_pe(machine=0x1C0, text=CE_CODE, code=True, pdata=table, subsystem=9,
                    image_base=CE_BASE)


def test_a_windows_ce_image_is_recognised_and_its_arm_functions_recovered():
    data = _ce_image()
    info = parse_pe(data)
    assert info.is_windows_ce and info.machine == "arm"
    rec = disasm.recover_pe(data, info)
    assert rec.arch == "arm"
    unwind = {f.address: f.size for f in rec.functions if f.source == "unwind"}
    assert unwind == {CE_BASE + TEXT: 0x14, CE_BASE + TEXT + 0x20: 0xC}
    features, arch = image_features(data, min_features=1)
    assert arch == "arm"
    assert {_hash(b"c", (0x12345678).to_bytes(8, "big"))} in features
    assert {_hash(b"c", (0xCAFEBEEF).to_bytes(8, "big"))} in features


def test_arm_functions_are_swept_when_the_ce_image_has_no_exception_table():
    data = _ce_image(pdata=False)
    rec = disasm.recover_pe(data, parse_pe(data))
    assert CE_BASE + TEXT + 0x20 in {f.address for f in rec.functions}


def test_windows_ce_on_a_cpu_with_no_decoder_says_so():
    data = build_pe(machine=0x1A6, text=b"\0" * 16, code=True, subsystem=9)    # SH-4
    rec = disasm.recover_pe(data, parse_pe(data))
    assert not rec.functions and "sh4" in rec.note and "Windows CE" in rec.note


def test_arm64_functions_come_from_packed_and_xdata_unwind_records():
    ins = [0xA9BF7BFD, 0x52800000, 0xA8C17BFD, 0xD65F03C0]                # stp ; mov w0,#0 ; ldp ; ret
    f1 = b"".join(struct.pack("<I", w) for w in ins)                      # 4 words, packed
    f2 = b"".join(struct.pack("<I", w) for w in (0x52800020, 0x52800040, 0xD65F03C0))   # 3 words, .xdata
    text = f1 + f2
    pdata = struct.pack("<II", TEXT, (4 << 2) | 1) + struct.pack("<II", TEXT + 16, 0x2000)
    data = build_pe(machine=0xAA64, text=text.ljust(0x40, b"\0"), code=True, pdata=pdata,
                    rdata_head=struct.pack("<I", 3))                       # xdata: length 3 words
    rec = disasm.recover_pe(data, parse_pe(data))
    assert rec.arch == "aarch64"
    unwind = {f.address: f.size for f in rec.functions if f.source == "unwind"}
    assert unwind == {BASE + TEXT: 16, BASE + TEXT + 16: 12}
