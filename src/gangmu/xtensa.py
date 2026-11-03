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

from typing import Callable, Iterator, List, Optional, Tuple

MACHINE = 94                      # EM_XTENSA


def starts(code: bytes, base: int) -> List[int]:
    """Addresses of the ``entry a1, N`` instructions, 4-byte aligned, ascending."""
    first = (-base) % 4
    return [base + off for off in range(first, len(code) - 2, 4)
            if code[off] == 0x36 and code[off + 1] & 0x0F == 1]


def _ends_flow(code: bytes, off: int, size: int) -> bool:
    """``j``, ``jx``, ``ret``, ``retw`` or their narrow forms: nothing falls through."""
    b0 = code[off]
    if size == 2:
        return code[off + 1] == 0xF0 and b0 in (0x0D, 0x1D)          # ret.n, retw.n
    if b0 & 0x3F == 0x06:                                            # j
        return True
    return code[off + 2] == 0 and (b0 in (0x80, 0x90)                # ret, retw
                                    and code[off + 1] == 0 or b0 == 0xA0 and not code[off + 1] & 0x0F)


def _walk(code: bytes) -> Iterator[Tuple[int, int]]:
    """(offset, size) of each instruction, from the first byte.

    The assembler pads with zero bytes after a jump or a return so that the next branch
    target does not straddle a 4-byte fetch; read as a 3-byte instruction, the padding
    swallowed the first byte of the next one and the rest of the function was decoded out
    of step (in zstd at -Os, a third of the ``l32r`` found were not instructions at all)."""
    off, end = 0, len(code)
    while off < end:
        size = 2 if code[off] & 0x0F >= 8 else 3        # density option: 16 bits
        if off + size > end:
            return
        yield off, size
        flow_ends = _ends_flow(code, off, size)
        off += size
        if flow_ends:
            skipped = 0
            while off < end and code[off] == 0 and skipped < 3:
                off, skipped = off + 1, skipped + 1


def l32r_targets(code: bytes, base: int) -> Iterator[int]:
    """The address each ``l32r`` in *code* loads from (a walk from the first byte)."""
    for off, size in _walk(code):
        if size == 3 and code[off] & 0x0F == 1:          # l32r at, label
            imm16 = (code[off + 1] | code[off + 2] << 8)
            yield ((base + off + 3) & ~3) + (imm16 - 0x10000) * 4


def features(code: bytes, base: int, read: Callable[[int, int], Optional[bytes]],
             emit: Callable[[int], None]) -> None:
    """Call *emit* with the 32-bit value behind every ``l32r`` in the function."""
    for target in l32r_targets(code, base):
        word = read(target, 4)
        if word is not None:
            emit(int.from_bytes(word, "little"))


def calls(code: bytes, base: int, read: Callable[[int, int], Optional[bytes]]) -> List[int]:
    """Where the function may call: ``call0/4/8/12`` targets, and every word an ``l32r``
    loads (a long call loads its target into a register first); the caller keeps the ones
    that are function starts."""
    out: List[int] = []
    for off, size in _walk(code):
        if size != 3:
            continue
        op0 = code[off] & 0x0F
        word = code[off] | code[off + 1] << 8 | code[off + 2] << 16
        if op0 == 5:                              # CALLn: offset in bits 6..23, signed
            offset = word >> 6
            if offset & (1 << 17):
                offset -= 1 << 18
            out.append((((base + off) >> 2) + offset + 1) << 2)
        elif op0 == 1:
            target = ((base + off + 3) & ~3) + ((word >> 8) - 0x10000) * 4
            value = read(target, 4)
            if value is not None:
                out.append(int.from_bytes(value, "little"))
    return out
