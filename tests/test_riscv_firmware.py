"""Function boundaries on real RV32 code, against the symbols of the same build.

Compiles a small firmware with riscv64-unknown-elf-gcc when one is installed (the newlib
headers are not needed here) and skips otherwise. The code has what hand-written streams
lack: leaf functions with no prologue, early returns laid out after the epilogue, calls the
linker shortened to ``c.jal``, and a function-pointer table.
"""

import shutil
import subprocess

import pytest

from gangmu import disasm
from gangmu.elf import parse_elf

pytestmark = [pytest.mark.skipif(not disasm.available(), reason="capstone not installed"),
              pytest.mark.skipif(not shutil.which("riscv64-unknown-elf-gcc"),
                                 reason="no riscv64-unknown-elf-gcc")]

LD = """MEMORY { FLASH (rx) : ORIGIN = 0x20000000, LENGTH = 16M
         RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 16M }
ENTRY(_start)
SECTIONS {
  .text : { *(.text.start) *(.text*) . = ALIGN(4); } > FLASH
  .rodata : { *(.rodata*) *(.srodata*) . = ALIGN(4); } > FLASH
  .data : { *(.data*) *(.sdata*) } > RAM
  .bss : { *(.sbss*) *(.bss*) *(COMMON) } > RAM
}
"""


def _app() -> str:
    body = ["typedef int (*op_t)(int);", "volatile int sink; int table[64];"]
    for i in range(20):                       # a leaf, an early return, a loop and a switch
        body.append(f"""__attribute__((noinline)) int leaf{i}(int x) {{ return x * {i + 3}; }}
__attribute__((noinline)) int op{i}(int x) {{
  if (x < 0) return -{i + 1};
  int s = leaf{i}(x);
  for (int k = 0; k < x; k++) s ^= table[(k + {i}) & 63] + k;
  switch (x & 7) {{ case 0: s += {i}; break; case 3: s -= 5; break; case 5: s *= 3; break; }}
  return s;
}}""")
    body.append("op_t const ops[] = {" + ",".join(f"op{i}" for i in range(0, 20, 2)) + "};")
    body.append("int helper(int x) { int s = 0; " + " ".join(f"s += op{i}(x + {i});"
                                                           for i in range(1, 20, 2)) + " return s; }")
    body.append("int main(void) { int s = helper(sink); for (int i = 0; i < 10; i++) "
                "s += ops[i](s); return s; }")
    return "\n".join(body)


@pytest.fixture(scope="module")
def firmware(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("rv")
    (tmp / "fw.ld").write_text(LD)
    (tmp / "app.c").write_text(_app())
    (tmp / "start.c").write_text('__attribute__((section(".text.start"), naked)) void _start(void)'
                                 '{ __asm__ volatile("la sp, 0x81000000\\n call main\\n 1: j 1b"); }\n')
    out = {}
    for name, opt in (("os", "-Os"), ("o2", "-O2")):
        elf = tmp / f"fw-{name}.elf"
        subprocess.run(["riscv64-unknown-elf-gcc", "-march=rv32imac", "-mabi=ilp32", opt,
                        "-nostartfiles", "-nostdlib", "-T", str(tmp / "fw.ld"), "-o", str(elf),
                        str(tmp / "app.c"), str(tmp / "start.c")], check=True)
        stripped, binary = tmp / f"s-{name}.elf", tmp / f"fw-{name}.bin"
        subprocess.run(["riscv64-unknown-elf-strip", "-s", "-o", str(stripped), str(elf)], check=True)
        subprocess.run(["riscv64-unknown-elf-objcopy", "-O", "binary", "-j", ".text",
                        str(elf), str(binary)], check=True)
        out[name] = (elf.read_bytes(), stripped.read_bytes(), binary.read_bytes())
    return out


def _truth(full):
    return {a for a, size, name in parse_elf(full).functions
            if size and name not in ("_start", "main")}


@pytest.mark.parametrize("opt", ["os", "o2"])
def test_stripped_elf_recovers_the_functions_the_symbols_name(firmware, opt):
    full, stripped, _ = firmware[opt]
    rec = disasm.recover_elf(stripped, parse_elf(stripped))
    assert rec.arch == "riscv32"
    found = {f.address for f in rec.functions}
    truth = _truth(full)
    assert len(truth & found) / len(truth) >= 0.95
    assert len(truth & found) / len(found) >= 0.8


@pytest.mark.parametrize("opt", ["os", "o2"])
def test_a_raw_bin_with_its_code_size_gives_the_same_functions(firmware, opt):
    full, _, binary = firmware[opt]
    rec = disasm.recover_raw(binary, "riscv32", 0x20000000, code_size=len(binary))
    found = {f.address for f in rec.functions}
    truth = _truth(full)
    assert len(truth & found) / len(truth) >= 0.95 and len(truth & found) / len(found) >= 0.8


def test_c_jal_and_branch_targets_are_decoded_from_the_encoding():
    import struct

    class Insn:                                    # what _riscv_call/_riscv_flow read
        def __init__(self, raw, address):
            self.bytes, self.address, self.size = raw, address, len(raw)

    # c.jal +0x20 at 0x1000, c.j -0x10, beq x0,x0,+0x40, c.beqz a0,+0x8, ret, c.jr ra
    assert disasm._riscv_call(Insn(struct.pack("<H", 0x2005), 0x1000)) is not None
    cj = Insn(struct.pack("<H", 0xB7DD), 0x2000)
    assert disasm._riscv_flow(cj) == ("jump", 0x2000 + disasm._cj_offset(0xB7DD))
    assert disasm._riscv_flow(Insn(struct.pack("<I", 0x00008067), 0)) == ("ret", None)
    assert disasm._riscv_flow(Insn(struct.pack("<H", 0x8082), 0)) == ("ret", None)
    assert disasm._riscv_flow(Insn(struct.pack("<I", 0x02000463), 0x100)) == ("cond", 0x100 + 0x28)
