"""Function boundaries recovered by disassembly, for code that has no symbols.

A stripped image names no functions, but the code still marks where they are: a call
instruction names its target, and a function begins with a recognisable prologue after
the previous one has returned. This module sweeps the code with Capstone, collects those
two kinds of evidence, and hands back ``(address, size)`` pairs. When the file *does*
carry a symbol table the symbols are used as they are and the sweep only fills gaps.

It recovers boundaries and nothing else: no control-flow graph, no types, no names. The
boundaries are what a later per-function fingerprint needs.

Capstone is an optional dependency (``pip install gangmu-sbom[disasm]``). Without it
``available()`` is false and nothing here is called. Supported: ARM Thumb (Cortex-M),
ARM, AArch64, RISC-V (32/64, including compressed), x86 and x86-64. **Xtensa (ESP32 and
ESP8266) is not supported**: Capstone has no Xtensa decoder, so those images are
reported as unsupported instead of being guessed at.

Sizes are upper bounds: a function is taken to end where the next one starts, so a
literal pool after it (Thumb, ARM) is counted with it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from .elf import EM_386, EM_ARM, EM_RISCV, EM_X86_64, SHF_EXECINSTR, SHT_PROGBITS, ElfInfo

try:                                      # an optional dependency
    import capstone
except ImportError:                       # pragma: no cover - exercised by the extra
    capstone = None

MAX_CODE = 32 * 1024 * 1024               # bytes of code swept per image
TABLE_RUN = 3                             # consecutive code pointers that make a function table
EXTENT = 0x400                            # a function this far past the last called one still counts
_PADDING = frozenset(("nop", "c.nop", "unimp", "c.unimp", "udf"))
JUMP_REACH = 512                          # a forward jump this close stays inside the function
EM_AARCH64 = 183
EM_XTENSA = 94
ARCHES = ("thumb", "arm", "aarch64", "riscv32", "riscv64", "x86", "x86-64")


def available() -> bool:
    return capstone is not None


@dataclass
class Function:
    address: int
    size: int
    name: str = ""
    source: str = "disassembly"           # symbol | disassembly | entry | vector-table


@dataclass
class Recovery:
    arch: str
    functions: List[Function] = field(default_factory=list)
    note: str = ""

    @property
    def from_symbols(self) -> int:
        return sum(1 for f in self.functions if f.source == "symbol")


# ----------------------------------------------------------------------- arches

def _x86_start(prev, insn) -> bool:
    if insn.mnemonic == "endbr64" or insn.mnemonic == "endbr32":
        return True
    return insn.mnemonic == "push" and insn.op_str in ("rbp", "ebp") and prev in ("end", "gap")


def _thumb_start(prev, insn) -> bool:
    # "prev" is "end" once a return has been seen since the last start, however many stray
    # instructions a literal pool in between decoded as: -Os also pushes lr in the middle
    # of a function (shrink-wrapping), before any return, and that is not a new function.
    return insn.mnemonic.startswith("push") and "lr" in insn.op_str and prev in ("end", "gap")


def _arm_start(prev, insn) -> bool:
    return insn.mnemonic.startswith("push") and "lr" in insn.op_str and prev in ("end", "gap") \
        or (insn.mnemonic.startswith("stmdb") and "lr" in insn.op_str and prev in ("end", "gap"))


def _a64_start(prev, insn) -> bool:
    return (insn.mnemonic in ("stp", "sub", "str") and prev in ("end", "gap")
            and ("x30" in insn.op_str or insn.op_str.startswith("sp, sp")))


def _riscv_start(prev, insn) -> bool:
    return insn.mnemonic in ("addi", "c.addi", "c.addi16sp") and prev in ("end", "gap") \
        and insn.op_str.replace(" ", "").startswith("sp,sp,-")


def _imm(op_str: str) -> Optional[int]:
    text = op_str.strip().lstrip("#")
    try:
        return int(text, 0)
    except ValueError:
        return None


def _x86_call(insn) -> Optional[int]:
    return _imm(insn.op_str) if insn.mnemonic == "call" else None


def _thumb_call(insn) -> Optional[int]:
    return _imm(insn.op_str) if insn.mnemonic in ("bl", "blx") else None


def _a64_call(insn) -> Optional[int]:
    return _imm(insn.op_str) if insn.mnemonic == "bl" else None


def _cj_offset(half: int) -> int:
    """Offset of a compressed ``c.j`` / ``c.jal``."""
    off = (((half >> 12) & 1) << 11 | ((half >> 11) & 1) << 4 | ((half >> 9) & 3) << 8
           | ((half >> 8) & 1) << 10 | ((half >> 7) & 1) << 6 | ((half >> 6) & 1) << 7
           | ((half >> 3) & 7) << 1 | ((half >> 2) & 1) << 5)
    return off - (1 << 12) if off & (1 << 11) else off


def _riscv_flow(insn):
    """How an instruction moves control, from its encoding: ``("cond", target)`` for a
    conditional branch, ``("jump", target)`` for an unconditional jump, ``("ret", None)``
    for a return, else None. Indirect jumps (a switch's ``jr``) are not returns."""
    raw = bytes(insn.bytes)
    at = insn.address
    if len(raw) == 2:
        half = struct.unpack("<H", raw)[0]
        quad, f3 = half & 3, half >> 13
        if quad == 1 and f3 == 5:                                  # c.j
            return "jump", at + _cj_offset(half)
        if quad == 1 and f3 in (6, 7):                             # c.beqz / c.bnez
            off = (((half >> 12) & 1) << 8 | ((half >> 10) & 3) << 3 | ((half >> 5) & 3) << 6
                   | ((half >> 3) & 3) << 1 | ((half >> 2) & 1) << 5)
            return "cond", at + (off - (1 << 9) if off & (1 << 8) else off)
        if quad == 2 and f3 == 4 and not (half >> 12) & 1 and (half >> 2) & 0x1F == 0 \
                and (half >> 7) & 0x1F == 1:                       # c.jr ra
            return "ret", None
        return None
    if len(raw) != 4:
        return None
    word = struct.unpack("<I", raw)[0]
    opcode = word & 0x7F
    if opcode == 0x63:                                             # beq bne blt bge bltu bgeu
        off = (((word >> 31) & 1) << 12 | ((word >> 7) & 1) << 11 | ((word >> 25) & 0x3F) << 5
               | ((word >> 8) & 0xF) << 1)
        return "cond", at + (off - (1 << 13) if off & (1 << 12) else off)
    if opcode == 0x6F and (word >> 7) & 0x1F == 0:                 # jal x0 = j
        off = (((word >> 31) & 1) << 20 | ((word >> 12) & 0xFF) << 12
               | ((word >> 20) & 1) << 11 | ((word >> 21) & 0x3FF) << 1)
        return "jump", at + (off - (1 << 21) if off & (1 << 20) else off)
    if opcode == 0x67 and (word >> 7) & 0x1F == 0 and (word >> 15) & 0x1F == 1 \
            and word >> 20 == 0:                                   # jalr x0, 0(ra) = ret
        return "ret", None
    return None


def _riscv_call(insn) -> Optional[int]:
    """Target of ``jal ra, off`` or ``c.jal off``, decoded from the encoding: Capstone
    prints the offset, not the address, and prints it differently between releases.
    Far calls (``auipc`` + ``jalr``) are not followed."""
    raw = bytes(insn.bytes)
    if len(raw) == 2:
        half = struct.unpack("<H", raw)[0]
        if half & 3 != 1 or half >> 13 != 1:                      # c.jal (RV32C only)
            return None
        return insn.address + _cj_offset(half)
    if len(raw) != 4:
        return None
    word = struct.unpack("<I", raw)[0]
    if word & 0x7F != 0x6F or (word >> 7) & 0x1F != 1:        # jal, rd = ra
        return None
    off = (((word >> 31) & 1) << 20 | ((word >> 12) & 0xFF) << 12
           | ((word >> 20) & 1) << 11 | ((word >> 21) & 0x3FF) << 1)
    if off & (1 << 20):
        off -= 1 << 21
    return insn.address + off


def _x86_end(insn) -> bool:
    return insn.mnemonic in ("ret", "retf", "jmp", "ud2", "hlt")


def _thumb_end(insn) -> bool:
    m, ops = insn.mnemonic, insn.op_str
    return (m.startswith("pop") and "pc" in ops) or (m == "bx" and ops == "lr") \
        or m in ("b", "b.w") or (m.startswith("ldr") and ops.startswith("pc"))


def _a64_flow(insn):
    """Branches and returns of an AArch64 instruction, from its encoding (see
    ``_riscv_flow``): ``b``, ``b.cond``, ``cbz``/``cbnz``, ``tbz``/``tbnz`` and ``ret``."""
    raw = bytes(insn.bytes)
    if len(raw) != 4:
        return None
    word = struct.unpack("<I", raw)[0]
    at = insn.address

    def signed(value: int, bits: int) -> int:
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    if word & 0xFC000000 == 0x14000000:                            # b
        return "jump", at + 4 * signed(word & 0x3FFFFFF, 26)
    if word & 0xFF000010 == 0x54000000:                            # b.cond
        return "cond", at + 4 * signed((word >> 5) & 0x7FFFF, 19)
    if word & 0x7E000000 == 0x34000000:                            # cbz / cbnz
        return "cond", at + 4 * signed((word >> 5) & 0x7FFFF, 19)
    if word & 0x7E000000 == 0x36000000:                            # tbz / tbnz
        return "cond", at + 4 * signed((word >> 5) & 0x3FFF, 14)
    if word & 0xFFFFFC1F == 0xD65F0000:                            # ret xN
        return "ret", None
    return None


def _a64_end(insn) -> bool:
    return insn.mnemonic in ("ret", "b", "br", "eret")


def _riscv_end(insn) -> bool:
    m, ops = insn.mnemonic, insn.op_str.replace(" ", "")
    return m in ("ret", "c.j", "j", "mret", "sret") or (m in ("jr", "c.jr"))\
        or (m == "jalr" and ops.startswith("zero,"))


@dataclass
class _Arch:
    cs_arch: int
    cs_mode: int
    start: Callable
    call: Callable
    end: Callable
    align: int
    flow: Optional[Callable] = None     # branch and return decoder; enables the closure rule


def _arch(name: str) -> Optional[_Arch]:
    if capstone is None:
        return None
    c = capstone
    table = {
        "thumb": _Arch(c.CS_ARCH_ARM, c.CS_MODE_THUMB | c.CS_MODE_MCLASS, _thumb_start,
                       _thumb_call, _thumb_end, 2),
        "arm": _Arch(c.CS_ARCH_ARM, c.CS_MODE_ARM, _arm_start, _thumb_call, _thumb_end, 4),
        "aarch64": _Arch(c.CS_ARCH_ARM64, c.CS_MODE_ARM, _a64_start, _a64_call, _a64_end, 4,
                         _a64_flow),
        "riscv32": _Arch(c.CS_ARCH_RISCV, c.CS_MODE_RISCV32 | c.CS_MODE_RISCVC,
                         _riscv_start, _riscv_call, _riscv_end, 2, _riscv_flow),
        "riscv64": _Arch(c.CS_ARCH_RISCV, c.CS_MODE_RISCV64 | c.CS_MODE_RISCVC,
                         _riscv_start, _riscv_call, _riscv_end, 2, _riscv_flow),
        "x86": _Arch(c.CS_ARCH_X86, c.CS_MODE_32, _x86_start, _x86_call, _x86_end, 1),
        "x86-64": _Arch(c.CS_ARCH_X86, c.CS_MODE_64, _x86_start, _x86_call, _x86_end, 1),
    }
    return table.get(name)


def arch_of_elf(info: ElfInfo) -> Optional[str]:
    """The Capstone architecture for an ELF, or None when it has no decoder here."""
    if info.machine == EM_ARM:
        return "thumb" if info.entry & 1 else "arm"
    return {EM_AARCH64: "aarch64", EM_X86_64: "x86-64", EM_386: "x86",
            EM_RISCV: "riscv64" if info.bits == 64 else "riscv32"}.get(info.machine)


# ----------------------------------------------------------------------- sweep

def _decode(spec, code: bytes, base: int):
    md = capstone.Cs(spec.cs_arch, spec.cs_mode)
    md.skipdata = True
    md.skipdata_setup = ("db", None, None)
    return md.disasm(code[:MAX_CODE], base)


def _scan(spec, code: bytes, base: int, inside: bool = False):
    """(instruction boundaries, direct call targets, prologue starts) of one block.

    *inside*: the block starts at a known function start, so a prologue before the first
    return is the same function's (gcc schedules loads ahead of the push)."""
    end_addr = base + len(code)
    boundaries: Set[int] = set()
    calls: Set[int] = set()
    prologues: Set[int] = set()
    prev = "gap"
    ended = not inside            # else the block begins where something ended
    expected = base
    pending = 0                   # farthest forward target of a conditional branch
    closed = False                # a return or jump ended the function and nothing jumps past it
    for insn in _decode(spec, code, base):
        if insn.mnemonic == "db":
            prev = "gap"
            expected = insn.address + insn.size
            continue
        if closed and insn.mnemonic not in _PADDING:
            # Leaf functions have no prologue to recognise. What follows the end of a
            # function, once no branch reaches past it, is the next function.
            prologues.add(insn.address)
            ended, closed, pending = False, False, 0
        boundaries.add(insn.address)
        if insn.address != expected:
            prev = "gap"
        target = spec.call(insn)
        if target is not None and base <= target < end_addr and target % spec.align == 0:
            calls.add(target)
        if spec.start(prev if prev == "gap" else ("end" if ended else "code"), insn) \
                and not (spec.flow is not None and pending >= insn.address):
            # (a branch that lands here or beyond means this is inside the function)
            prologues.add(insn.address)
            ended, pending = False, 0
        if spec.end(insn):
            ended = True
        if spec.flow is not None:
            flow = spec.flow(insn)
            if flow is not None:
                kind, where = flow
                if kind == "cond" and where > insn.address:
                    pending = max(pending, where)
                if kind == "jump" and insn.address < where <= insn.address + JUMP_REACH:
                    pending = max(pending, where)      # a rotated loop's jump to its test
                if kind in ("ret", "jump") and pending < insn.address + insn.size:
                    closed = True
        prev = "end" if spec.end(insn) else "code"
        expected = insn.address + insn.size
    return boundaries, calls, prologues


def sweep(code: bytes, base: int, arch: str, seeds: Sequence[int] = (),
          pools: Sequence[bytes] = ()) -> List[int]:
    """Start addresses of the functions in one block of code, ascending.

    Pass 1 decodes the block in one go and collects what is reliable: seeds, direct call
    targets and, on Thumb, code pointers found in *pools*. A literal pool in the middle
    of the code decodes as stray instructions and can leave the rest of a linear sweep
    half a word out of step, so pass 2 decodes again from each reliable start and takes
    the prologues from those aligned streams.

    Thumb code pointers: the vector table, literal pools and function-pointer tables hold
    the address of every function that is reached indirectly, with bit 0 set. A word
    counts if it is an odd address that is an instruction boundary, lies within the code
    already seen, and is a prologue, a vector, part of a run of three or more code pointers
    (a function table), or pointed at more than once. That
    screens out the odd words that fill constant tables and ``.rodata``.
    """
    spec = _arch(arch)
    if spec is None or not code:
        return []
    end_addr = base + len(code)
    reliable: Set[int] = {s for s in seeds if base <= s < end_addr}
    boundaries, calls, prologues = _scan(spec, code, base)
    reliable |= calls
    if arch == "thumb":
        extent = max(reliable | {base}) + EXTENT
        refs: Dict[int, int] = {}
        tables: Set[int] = set()
        for blob in list(pools) + [code]:
            run: List[int] = []
            for off in range(0, len(blob) - 3, 4):
                word = struct.unpack_from("<I", blob, off)[0]
                if word & 1 and (word & ~1) in boundaries and (word & ~1) <= extent:
                    refs[word & ~1] = refs.get(word & ~1, 0) + 1
                    run.append(word & ~1)
                    continue
                if len(run) >= TABLE_RUN:
                    tables.update(run)
                run = []
            if len(run) >= TABLE_RUN:
                tables.update(run)
        vectors = {w for w in seeds}
        for target, count in refs.items():
            if target in prologues or target in vectors or target in tables or count >= 2:
                reliable.add(target)
    starts: Set[int] = set(reliable)
    ordered = sorted(reliable | {base})
    for i, lo in enumerate(ordered):
        hi = ordered[i + 1] if i + 1 < len(ordered) else end_addr
        _, more_calls, more_prologues = _scan(spec, code[lo - base:hi - base], lo,
                                              inside=lo in reliable)
        starts |= {c for c in more_calls}
        starts |= {a for a in more_prologues if a != lo or lo in reliable or lo in prologues}
    # A Thumb image has constant tables after its code (CRC tables, string pools) whose
    # words decode as plausible prologues. Code ends a little past the last function that
    # anything calls or points to. (Other architectures here are handled as ELF with
    # separate executable sections, where this does not arise.)
    limit = max(reliable | {base}) + EXTENT if arch == "thumb" else end_addr
    return sorted(a for a in starts if base <= a < min(end_addr, limit))


def _sized(starts: Sequence[int], limit: int) -> List[Tuple[int, int]]:
    ordered = sorted(set(starts))
    out = []
    for i, a in enumerate(ordered):
        end = ordered[i + 1] if i + 1 < len(ordered) else limit
        out.append((a, max(end - a, 0)))
    return out


# ----------------------------------------------------------------------- entry points

def recover_elf(data: bytes, info: ElfInfo) -> Optional[Recovery]:
    """Functions of an ELF: its symbols, plus whatever the sweep finds between them."""
    arch = arch_of_elf(info)
    if arch is None:
        return Recovery("unsupported",
                        note="no decoder for this architecture (Xtensa is not supported "
                             "by Capstone)" if info.machine == EM_XTENSA else
                             f"no decoder for ELF machine {info.machine}")
    if capstone is None:
        return None
    mask = ~1 if arch == "thumb" else ~0          # a Thumb symbol's bit 0 is not an address
    entry = info.entry & mask
    found: Dict[int, Function] = {a & mask: Function(a & mask, s, n, "symbol")
                                  for a, s, n in info.functions if s}
    code_sections = [s for s in info.sections
                     if s.flags & SHF_EXECINSTR and s.type == SHT_PROGBITS and s.size]
    pools = [data[s.offset:s.offset + s.size] for s in info.sections
             if s.flags & 2 and not s.flags & SHF_EXECINSTR and s.type == SHT_PROGBITS and s.size]
    for sec in code_sections:
        blob = data[sec.offset:sec.offset + sec.size]
        seeds = [entry] + list(found)
        starts = sweep(blob, sec.addr, arch, seeds, pools)
        for a, size in _sized(starts, sec.addr + len(blob)):
            if a not in found:
                found[a] = Function(a, size, "", "entry" if a == entry
                                    else "disassembly")
    functions = sorted(found.values(), key=lambda f: f.address)
    # symbol sizes are exact; a swept size is only the gap to the next start
    return Recovery(arch, functions)


def cortex_m_base(image: bytes) -> Optional[int]:
    """Load address of a raw Cortex-M image, from its vector table, or None.

    Word 0 is the initial stack pointer (RAM), words 1.. are handlers with the Thumb bit
    set. The right base is the one that puts most of them inside the image.
    """
    if len(image) < 64:
        return None
    words = struct.unpack_from("<16I", image, 0)
    handlers = [w for w in words[1:] if w & 1 and w > 0x100]
    if len(handlers) < 4 or not 0x1000_0000 <= words[0] <= 0x7000_0000 and words[0] >> 28 not in (1, 2):
        return None
    best, best_hits = None, 0
    for base in sorted({h & ~0xFFFFF for h in handlers} | {0}):
        hits = sum(1 for h in handlers if base <= (h & ~1) < base + len(image))
        if hits > best_hits:
            best, best_hits = base, hits
    return best if best is not None and best_hits >= max(4, len(handlers) * 3 // 4) else None


def recover_raw(image: bytes, arch: Optional[str] = None,
                base: Optional[int] = None, code_size: Optional[int] = None
                ) -> Optional[Recovery]:
    """Functions of a bare image. Cortex-M is recognised from its vector table; any other
    architecture and load address have to be given.

    A bare image has no section table, so constant tables after the code decode as code.
    *code_size* (from a map file or the linker script) cuts the image there; without it,
    RISC-V precision on table-heavy libraries drops to about 0.4 (docs/BINARY-VALIDATION.md)."""
    if capstone is None:
        return None
    if code_size is not None:
        image = image[:code_size]
    seeds: List[int] = []
    if arch is None or base is None:
        guessed = cortex_m_base(image)
        if guessed is None:
            return Recovery("unknown", note="a raw image needs --arch and --base unless it "
                                            "starts with a Cortex-M vector table")
        arch, base = arch or "thumb", guessed if base is None else base
        seeds = [w & ~1 for w in struct.unpack_from("<16I", image, 0)[1:] if w & 1]
    starts = sweep(image, base, arch, seeds)
    sized = _sized(starts, base + len(image))
    seed_set = set(seeds)
    return Recovery(arch, [Function(a, s, "", "vector-table" if a in seed_set else "disassembly")
                           for a, s in sized])
