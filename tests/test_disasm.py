"""Function boundaries recovered by disassembly, checked against ground truth."""

import shutil
import struct
import subprocess

import pytest

from gangmu import disasm
from gangmu.binaries import collect_binaries
from gangmu.elf import parse_elf

pytestmark = pytest.mark.skipif(not disasm.available(), reason="capstone not installed")


def _thumb_bl(here: int, target: int) -> bytes:
    off = (target - (here + 4)) >> 1
    assert 0 <= off < 2048
    return struct.pack("<HH", 0xF000, 0xF800 | off)


def _cortex_m_image():
    """Reset handler -> f1 -> f2, laid out after a 64-byte vector table."""
    base = 0x08000000
    reset, f1, f2 = 0x40, 0x50, 0x68
    img = bytearray(0x80)
    words = [0x20001000] + [(base + reset) | 1] * 15
    struct.pack_into("<16I", img, 0, *words)
    code = {
        reset: struct.pack("<H", 0xB500) + _thumb_bl(reset + 2, f1) + struct.pack("<H", 0xBD00),
        f1: struct.pack("<HH", 0xB510, 0x2001) + _thumb_bl(f1 + 4, f2) + struct.pack("<H", 0xBD10),
        f2: struct.pack("<HHH", 0xB580, 0xBF00, 0xBD80),
    }
    for at, body in code.items():
        img[at:at + len(body)] = body
    return bytes(img), base, (reset, f1, f2)


def test_a_cortex_m_bin_is_based_from_its_vector_table():
    image, base, _ = _cortex_m_image()
    assert disasm.cortex_m_base(image) == base
    assert disasm.cortex_m_base(b"\x00" * 128) is None


def test_thumb_functions_are_found_by_calls_and_prologues():
    image, base, (reset, f1, f2) = _cortex_m_image()
    rec = disasm.recover_raw(image)
    assert rec.arch == "thumb"
    assert {f.address for f in rec.functions} >= {base + reset, base + f1, base + f2}
    sizes = {f.address: f.size for f in rec.functions}
    assert sizes[base + f1] == f2 - f1                  # up to where the next one starts


def _jal(rd, here, target):
    off = target - here
    imm = (((off >> 20) & 1) << 31 | ((off >> 1) & 0x3FF) << 21 | ((off >> 11) & 1) << 20
           | ((off >> 12) & 0xFF) << 12)
    return struct.pack("<I", imm | rd << 7 | 0x6F)


def test_riscv_functions_are_found_by_calls_and_prologues():
    base = 0x80000000
    prologue = struct.pack("<II", 0xFF010113, 0x00112623)       # addi sp,sp,-16 ; sw ra,12(sp)
    epilogue = struct.pack("<III", 0x00C12083, 0x01010113, 0x00008067)
    a, b = 0x00, 0x20
    img = bytearray(0x40)
    body_a = prologue + _jal(1, a + 8, b) + epilogue
    body_b = prologue + struct.pack("<I", 0x00000013) + epilogue  # nop
    img[a:a + len(body_a)] = body_a
    img[b:b + len(body_b)] = body_b
    rec = disasm.recover_raw(bytes(img), "riscv32", base)
    assert {f.address for f in rec.functions} == {base + a, base + b}


def test_a_raw_image_that_is_not_cortex_m_needs_an_architecture():
    rec = disasm.recover_raw(b"\x00" * 256)
    assert rec.functions == [] and "--arch" in rec.note


@pytest.fixture(scope="module")
def x86_pair(tmp_path_factory):
    if not shutil.which("gcc"):
        pytest.skip("no gcc")
    tmp = tmp_path_factory.mktemp("x86")
    src = ("int g(int x) { return x + 1; }\n"
           + "".join(f"int f{i}(int x) {{ return g(x) * {i + 3} + (x > {i} ? g(x + {i}) : x); }}\n"
                     for i in range(40))
           + "int main(void) { return f0(3) + f9(2); }\n")
    (tmp / "a.c").write_text(src)
    for name, extra in (("sym", []), ("stripped", ["-s"])):
        subprocess.run(["gcc", "-O1", "-o", str(tmp / name), str(tmp / "a.c")] + extra,
                       check=True)
    return tmp


def test_a_stripped_native_binary_recovers_every_function_the_symbols_had(x86_pair):
    truth = {a for a, _s, n in parse_elf((x86_pair / "sym").read_bytes()).functions
             if n == "main" or n == "g" or n.startswith("f")}
    stripped = (x86_pair / "stripped").read_bytes()
    rec = disasm.recover_elf(stripped, parse_elf(stripped))
    found = {f.address for f in rec.functions}
    assert truth <= found                                       # full recall
    assert len(found - truth) <= 10                             # plus a few CRT/PLT stubs
    assert rec.from_symbols == 0


def test_symbols_are_kept_exactly_when_the_file_has_them(x86_pair):
    data = (x86_pair / "sym").read_bytes()
    rec = disasm.recover_elf(data, parse_elf(data))
    named = {f.name: f for f in rec.functions if f.source == "symbol"}
    assert "main" in named and named["main"].size > 0


def test_the_inventory_reports_recovered_functions(x86_pair):
    (x86_pair / "fw.elf").write_bytes((x86_pair / "stripped").read_bytes())
    blob = next(b for b in collect_binaries(x86_pair) if b.path == "fw.elf")
    assert blob.arch == "x86-64" and blob.functions >= 40
    assert blob.function_source == "disassembly"


def test_a_cortex_m_bin_in_the_inventory_gets_its_functions(tmp_path):
    image, _base, _ = _cortex_m_image()
    (tmp_path / "app.bin").write_bytes(image)
    blob = collect_binaries(tmp_path)[0]
    assert (blob.arch, blob.function_source) == ("thumb", "disassembly") and blob.functions >= 3


def test_the_inventory_works_without_capstone(tmp_path, monkeypatch):
    image, _base, _ = _cortex_m_image()
    (tmp_path / "app.bin").write_bytes(image)
    monkeypatch.setattr(disasm, "capstone", None)
    blob = collect_binaries(tmp_path)[0]
    assert blob.functions is None and blob.arch is None


# ---------------------------------------------------------------- MIPS (both byte orders)

def _mips_words(order, base=0x80000000):
    def i(op, rs, rt, imm):
        return op << 26 | rs << 21 | rt << 16 | imm & 0xFFFF
    sp, ra, a0, v0 = 29, 31, 4, 2
    f2 = base + 0x40
    f1 = [i(9, sp, sp, -24), i(0x2B, sp, ra, 20), i(0xF, 0, a0, 0x1234), i(0xD, a0, a0, 0x5678),
          3 << 26 | (f2 >> 2) & 0x3FFFFFF, 0,             # jal f2 ; nop (delay slot)
          i(0x23, sp, ra, 20), ra << 21 | 8,              # lw ra ; jr ra
          i(9, sp, sp, 24)]                               # addiu sp (delay slot)
    leaf = [i(0xF, 0, v0, 0x9E37), i(0xD, v0, v0, 0x79B1), ra << 21 | 8, 0]
    words = f1 + [0] * (16 - len(f1)) + leaf
    image = b"".join(struct.pack(order + "I", w) for w in words)
    return base, image, f2


@pytest.mark.parametrize("arch,order", [("mips32", "<"), ("mips32be", ">")])
def test_mips_functions_are_found_by_calls_and_prologues_and_the_delay_slot_stays(arch, order):
    base, image, f2 = _mips_words(order)
    rec = disasm.recover_raw(image, arch, base)
    assert rec.arch == arch
    starts = {f.address for f in rec.functions}
    assert {base, f2} <= starts
    # the instruction after "jr ra" belongs to the function; it is not a start of its own
    assert base + 8 * 4 not in starts


@pytest.mark.parametrize("arch,order", [("mips32", "<"), ("mips32be", ">")])
def test_mips_constants_and_string_addresses_are_rebuilt_from_lui_pairs(arch, order):
    from gangmu.fprint import Memory, _hash, function_features
    base, image, f2 = _mips_words(order)
    text = b"mips string literal\0"
    mem = Memory([(base, image), (0x12340000 + 0x5678, text)])
    feats = function_features(mem, arch, base, 36)
    assert _hash(b"s", text[:-1]) in feats                     # lui+ori formed 0x12345678
    leaf = function_features(mem, arch, f2, 16)
    assert _hash(b"c", (0x9E3779B1).to_bytes(8, "big")) in leaf


def test_position_independent_mips_finds_strings_through_the_got_and_ignores_gp_disp():
    from gangmu.fprint import Memory, _hash, function_features
    base, gp = 0x80100000, 0x80108120

    def i(op, rs, rt, imm):
        return op << 26 | rs << 21 | rt << 16 | imm & 0xFFFF
    code = [i(0xF, 0, 2, 1),                        # lui   v0, 1
            i(9, 2, 2, gp - base - 0x10000),         # addiu v0, v0, _gp_disp - 0x10000
            2 << 21 | 25 << 16 | 17 << 11 | 0x21,    # addu  s1, v0, t9
            i(0x23, 17, 1, -0x7FE8),                 # lw    at, got_entry(s1)
            i(9, 1, 4, 0x100),                       # addiu a0, at, %lo(string)
            31 << 21 | 8, 0]                         # jr ra ; nop
    text = b"a string reached through the global offset table\0"
    mem = Memory([(base, b"".join(struct.pack("<I", w) for w in code)),
                  (gp - 0x7FE8, struct.pack("<I", base + 0x100)), (base + 0x200, text)])
    mem.gp = gp
    feats = function_features(mem, "mips32", base, len(code) * 4)
    assert set(feats) == {_hash(b"s", text[:-1])}      # the string, and no _gp_disp constant


def test_an_elf_without_a_section_table_is_read_from_its_program_headers():
    """OpenWrt strips shared libraries down to their segments, and a shared object is
    linked at address 0, so the code starts there."""
    from gangmu.fprint import _hash, image_features
    base = 0x100
    _, code, f2 = _mips_words(">", base)
    text = b"a string that sits in the same segment\0"
    image = bytearray(0x300)
    image[base:base + len(code)] = code
    image[0x200:0x200 + len(text)] = text
    # lui+ori in f1 build 0x12345678; point the function at the string instead
    struct.pack_into(">II", image, base + 8, 0x3C040000 | 0, 0x34840200)       # lui a0,0 ; ori a0,a0,0x200
    dyn = 0x280
    struct.pack_into(">II", image, dyn, 3, 0x2F000)                            # DT_PLTGOT
    ehdr = b"\x7fELF" + bytes([1, 2, 1, 0]) + bytes(8)
    ehdr += struct.pack(">HHIIIIIHHHHHH", 3, 8, 1, 0, 52, 0, 0x70001005, 52, 32, 2, 0, 0, 0)
    phdrs = struct.pack(">8I", 1, 0, 0, 0, len(image), len(image), 5, 0x10000)  # PT_LOAD R+X
    phdrs += struct.pack(">8I", 2, dyn, dyn, dyn, 16, 16, 4, 4)                 # PT_DYNAMIC
    image[:len(ehdr) + len(phdrs)] = ehdr + phdrs
    info = parse_elf(bytes(image))
    assert info is not None and info.sections and not info.sections[0].name.startswith(".text")
    assert info.sections[0].addr == 0 and info.got == 0x2F000
    feats, arch = image_features(bytes(image), min_features=1)
    assert arch == "mips32be"
    assert any(_hash(b"s", text[:-1]) in f for f in feats)


def test_mips16_code_is_reported_as_unsupported_not_decoded_as_mips32():
    """OpenWrt builds most libraries as MIPS16e; decoding those words as MIPS32 gives noise."""
    image = bytearray(0x100)
    image[:4] = b"\x7fELF"
    image[4:6] = bytes([1, 2])
    struct.pack_into(">HHIIIIIHHHHHH", image, 16, 3, 8, 1, 0, 52, 0, 0x74001005, 52, 32, 0, 0, 0, 0)
    info = parse_elf(bytes(image))
    rec = disasm.recover_elf(bytes(image), info)
    assert rec.arch == "unsupported" and "MIPS16" in rec.note
