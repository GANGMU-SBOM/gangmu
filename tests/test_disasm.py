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
