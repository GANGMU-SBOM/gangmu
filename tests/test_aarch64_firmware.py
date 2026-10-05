"""Function boundaries on real AArch64 code, against the symbols of the same build.

Compiles a small freestanding firmware with aarch64-linux-gnu-gcc when one is installed and
skips otherwise. The code has leaf functions with no prologue, early returns laid out after
the epilogue, rotated loops (an unconditional jump to the test, the body after it), a switch
and a function-pointer table.
"""

import shutil
import subprocess

import pytest

from gangmu import disasm
from gangmu.elf import parse_elf

pytestmark = [pytest.mark.skipif(not disasm.available(), reason="capstone not installed"),
              pytest.mark.skipif(not shutil.which("aarch64-linux-gnu-gcc"),
                                 reason="no aarch64-linux-gnu-gcc")]

LD = """MEMORY { FLASH (rx) : ORIGIN = 0x80000, LENGTH = 16M
         RAM (rwx) : ORIGIN = 0x10000000, LENGTH = 16M }
ENTRY(_start)
SECTIONS {
  .text : { *(.text.start) *(.text*) . = ALIGN(4); } > FLASH
  .rodata : { *(.rodata*) . = ALIGN(8); } > FLASH
  .data : { *(.data*) } > RAM
  .bss : { *(.bss*) *(COMMON) } > RAM
}
"""


def _app() -> str:
    body = ["typedef int (*op_t)(int);", "volatile int sink; int table[64];"]
    for i in range(20):
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
    tmp = tmp_path_factory.mktemp("a64")
    (tmp / "fw.ld").write_text(LD)
    (tmp / "app.c").write_text(_app())
    (tmp / "start.c").write_text('__attribute__((section(".text.start"), naked)) void _start(void)'
                                 '{ __asm__ volatile("ldr x0, =0x11000000\\n mov sp, x0\\n bl main\\n'
                                 ' 1: b 1b"); }\n')
    out = {}
    for name, opt in (("os", "-Os"), ("o2", "-O2")):
        elf = tmp / f"fw-{name}.elf"
        subprocess.run(["aarch64-linux-gnu-gcc", "-march=armv8-a", "-ffreestanding", "-fno-pic",
                        "-fno-pie", "-fno-asynchronous-unwind-tables", opt, "-static", "-no-pie",
                        "-nostartfiles", "-nostdlib", "-T", str(tmp / "fw.ld"), "-o", str(elf),
                        str(tmp / "app.c"), str(tmp / "start.c")], check=True)
        stripped = tmp / f"s-{name}.elf"
        subprocess.run(["aarch64-linux-gnu-strip", "-s", "-o", str(stripped), str(elf)], check=True)
        out[name] = (elf.read_bytes(), stripped.read_bytes())
    return out


@pytest.mark.parametrize("opt", ["os", "o2"])
def test_stripped_elf_recovers_the_functions_the_symbols_name(firmware, opt):
    full, stripped = firmware[opt]
    rec = disasm.recover_elf(stripped, parse_elf(stripped))
    assert rec.arch == "aarch64"
    found = {f.address for f in rec.functions}
    truth = {a for a, size, name in parse_elf(full).functions if size and name != "_start"}
    assert len(truth & found) / len(truth) >= 0.95
    assert len(truth & found) / len(found) >= 0.8


def test_branches_are_decoded_from_the_encoding():
    import struct

    class Insn:
        def __init__(self, word, address):
            self.bytes, self.address, self.size = struct.pack("<I", word), address, 4

    assert disasm._a64_flow(Insn(0xD65F03C0, 0)) == ("ret", None)               # ret
    assert disasm._a64_flow(Insn(0x14000004, 0x100)) == ("jump", 0x110)         # b .+16
    assert disasm._a64_flow(Insn(0x17FFFFFF, 0x100)) == ("jump", 0xFC)          # b .-4
    assert disasm._a64_flow(Insn(0x54000080, 0x100)) == ("cond", 0x110)         # b.eq .+16
    assert disasm._a64_flow(Insn(0xB4000080, 0x100)) == ("cond", 0x110)         # cbz x0, .+16
    assert disasm._a64_flow(Insn(0x36000080, 0x100)) == ("cond", 0x110)         # tbz w0, #0, .+16
    assert disasm._a64_flow(Insn(0x94000004, 0x100)) is None                    # bl is a call
