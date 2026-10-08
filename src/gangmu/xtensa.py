"""Just enough Xtensa (ESP32, ESP8266) to fingerprint functions: no general disassembler.

Capstone has no Xtensa decoder. Two things are enough for ``fprint``, and both are simple:

* where a function starts: the windowed ABI opens every function with ``entry a1, N``
  (bytes ``36 x1 ..``), on a 4-byte boundary;
* what it refers to: strings and constants are never immediates, the compiler loads them
  with ``l32r`` from a literal pool, so the value is the word at a computed address.

Instructions are 3 bytes, or 2 for the density option (op0 >= 8), so a linear walk keeps
in step. The literal pool before a function decodes as junk when walked, which only adds
stray features: matching is by containment and tolerates them.
"""

from __future__ import annotations

from typing import Callable, Iterator, List, Optional

MACHINE = 94                      # EM_XTENSA


def starts(code: bytes, base: int) -> List[int]:
    """Addresses of the ``entry a1, N`` instructions, 4-byte aligned, ascending."""
    first = (-base) % 4
    return [base + off for off in range(first, len(code) - 2, 4)
            if code[off] == 0x36 and code[off + 1] & 0x0F == 1]


def l32r_targets(code: bytes, base: int) -> Iterator[int]:
    """The address each ``l32r`` in *code* loads from (a walk from the first byte)."""
    off, end = 0, len(code)
    while off < end:
        op0 = code[off] & 0x0F
        if op0 >= 8:
            off += 2                              # density option: 16 bits
            continue
        if off + 3 > end:
            return
        if op0 == 1:                              # l32r at, label
            imm16 = (code[off + 1] | code[off + 2] << 8)
            yield ((base + off + 3) & ~3) + (imm16 - 0x10000) * 4
        off += 3


def features(code: bytes, base: int, read: Callable[[int, int], Optional[bytes]],
             emit: Callable[[int], None]) -> None:
    """Call *emit* with the 32-bit value behind every ``l32r`` in the function."""
    for target in l32r_targets(code, base):
        word = read(target, 4)
        if word is not None:
            emit(int.from_bytes(word, "little"))
