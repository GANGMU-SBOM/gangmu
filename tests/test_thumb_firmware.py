"""Function boundaries on real Cortex-M code, against the symbols of the same build.

Hand-encoded instruction streams (test_disasm.py) cannot show what a real compiler does
to Thumb code: literal pools in the middle of the text, loads scheduled ahead of the
push, shrink-wrapped prologues, functions reached only through a pointer table. This
compiles a small firmware with arm-none-eabi-gcc when one is installed and skips otherwise.
"""

import shutil
import subprocess

import pytest

from gangmu import disasm
from gangmu.elf import parse_elf

pytestmark = [pytest.mark.skipif(not disasm.available(), reason="capstone not installed"),
              pytest.mark.skipif(not shutil.which("arm-none-eabi-gcc"),
                                 reason="no arm-none-eabi-gcc")]

LD = """MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1M
         RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 128K }
ENTRY(Reset_Handler)
SECTIONS {
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
  .text : { *(.text*) *(.rodata*) *(.ARM.exidx*) . = ALIGN(4); _etext = .; } > FLASH
  .data : AT(_etext) { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > RAM
  .bss : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
"""

START = """extern int main(void);
extern unsigned _estack, _sdata, _edata, _etext, _sbss, _ebss;
void Reset_Handler(void) {
  unsigned *s = &_etext, *d = &_sdata;
  while (d < &_edata) *d++ = *s++;
  for (d = &_sbss; d < &_ebss; ) *d++ = 0;
  main();
  for (;;) ;
}
void Default_Handler(void) { for (;;) ; }
__attribute__((section(".isr_vector"), used)) void (*const vectors[16])(void) = {
  (void (*)(void))&_estack, Reset_Handler, Default_Handler, Default_Handler, Default_Handler,
  Default_Handler, Default_Handler, 0, 0, 0, 0, Default_Handler, Default_Handler, 0,
  Default_Handler, Default_Handler };
"""


def _app() -> str:
    body = ["typedef int (*op_t)(int);",
            "volatile int sink; int table[64]; static const char *names[] = {"
            + ",".join(f'"operation number {i} of the dispatch table"' for i in range(8)) + "};"]
    for i in range(24):
        body.append(f"__attribute__((noinline)) static int op{i}(int x) {{ "
                    f"int s = x * 0x{0x9E3779B1 + i * 7919:X}u; "
                    f"if (x > {i}) {{ for (int k = 0; k < x; k++) s ^= table[(k + {i}) & 63] + k; }} "
                    f"sink = (int)names[{i} & 7]; return s + {i}; }}")
    body.append("static const op_t ops[] = {" + ",".join(f"op{i}" for i in range(0, 24, 2)) + "};")
    body.append("int helper(int x) { int s = 0; "
                + " ".join(f"s += op{i}(x + {i});" for i in range(1, 24, 2)) + " return s; }")
    body.append("int main(void) { int s = helper(sink); for (unsigned i = 0; i < 12; i++) "
                "s += ops[i](s); return s; }")
    return "\n".join(body)


@pytest.fixture(scope="module")
def firmware(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("thumb")
    (tmp / "fw.ld").write_text(LD)
    (tmp / "start.c").write_text(START)
    (tmp / "app.c").write_text(_app())
    out = {}
    for name, opt in (("os", "-Os"), ("o2", "-O2")):
        elf = tmp / f"fw-{name}.elf"
        subprocess.run(["arm-none-eabi-gcc", "-mcpu=cortex-m3", "-mthumb", opt,
                        "-ffunction-sections", "-fdata-sections", "-fno-tree-loop-distribute-patterns",
                        "-nostartfiles", "-nostdlib",
                        "-T", str(tmp / "fw.ld"), "-Wl,--gc-sections", "-o", str(elf),
                        str(tmp / "app.c"), str(tmp / "start.c")], check=True)
        stripped, binary = tmp / f"s-{name}.elf", tmp / f"fw-{name}.bin"
        subprocess.run(["arm-none-eabi-strip", "-s", "-o", str(stripped), str(elf)], check=True)
        subprocess.run(["arm-none-eabi-objcopy", "-O", "binary", str(elf), str(binary)], check=True)
        out[name] = (elf.read_bytes(), stripped.read_bytes(), binary.read_bytes())
    return out


def _score(truth, found):
    hit = len(truth & found)
    return hit / len(truth), hit / len(found)


@pytest.mark.parametrize("opt", ["os", "o2"])
def test_stripped_elf_and_raw_bin_recover_the_functions_the_symbols_name(firmware, opt):
    full, stripped, binary = firmware[opt]
    truth = {a & ~1 for a, size, _ in parse_elf(full).functions if size}
    for image, rec in ((stripped, disasm.recover_elf(stripped, parse_elf(stripped))),
                       (binary, disasm.recover_raw(binary))):
        assert rec.arch == "thumb"
        recall, precision = _score(truth, {f.address for f in rec.functions})
        assert recall >= 0.9 and precision >= 0.85, (opt, recall, precision)


def test_the_raw_bin_is_based_and_seeded_from_its_vector_table(firmware):
    binary = firmware["os"][2]
    assert disasm.cortex_m_base(binary) == 0x08000000
    rec = disasm.recover_raw(binary)
    assert any(f.source == "vector-table" for f in rec.functions)
