"""Per-function fingerprints that survive compilation.

Source-level function hashes (``functions.py``) need tokens, and instruction bytes
change with the compiler, the optimisation level and the architecture. What a function
*refers to* mostly does not: the string literals it prints and the distinctive numeric
constants it uses (a CRC polynomial, a SHA round constant, a protocol magic number). A
function's fingerprint here is the set of those, resolved out of its machine code.

Resolving them takes more than reading operands, because a 32-bit constant is rarely one
instruction: Thumb builds it from ``movw``/``movt`` or loads it from a literal pool,
RISC-V from ``lui`` + ``addi``, x86 puts it in an immediate and reaches a string with a
RIP-relative ``lea``. Each is folded back into the value the source wrote.

What real code showed (docs/BINARY-VALIDATION.md): a constant the source wrote
survives, but a compiler also *derives* constants -- reciprocal multipliers for ``% 65521``,
a four-character literal packed into one 32-bit store -- and those differ between
architectures and compilers. Built from the same toolchain family, references recognise
the library at every optimisation level; built on x86-64 and matched against a Thumb
image, they matched nothing. Build the references for the architecture you ship.

A reference function matches an image function when most of the reference's features
appear in the image's (*containment*, not Jaccard: the image side also holds addresses
and peripheral constants that no reference has). Matched functions then vote for a
release the way ``fnsig`` does, by Jaccard over each release's functions, so a function
present in one release only is what separates it from its neighbour.

Limits, stated because they matter: a function with fewer than ``MIN_FEATURES`` features
(a getter, a wrapper) has no fingerprint; code that keeps no strings or constants is
invisible; and function sizes from the sweep include any literal pool after the function,
whose words decode as stray instructions on the image side. Containment tolerates that.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import disasm, xtensa
from .binsig import MIN_LEN, _wanted
from .elf import ElfInfo

MIN_FEATURES = 2          # fewer than this is not a fingerprint (3 left half of zlib out)
MAX_FEATURES = 64         # per reference function
MIN_CONTAINMENT = 0.7     # share of a reference function's features the image must hold
MIN_MATCHES = 5           # matched functions before a library is claimed
MIN_COVERAGE = 0.12       # share of the best release's fingerprintable functions matched (0.08 let one
#                         unrelated library through in 1920 negative pairs on RISC-V)
TIE_SHARE = 0.85         # releases scoring within this share of the best are reported as a span
#                         (0.95 asserted a wrong release in 3 of 48 real builds, 0.85 in none)
UNKNOWN_STRINGS = 0xFFFF  # a sidecar made before features told strings from constants
MAX_DF = 40               # a feature in more reference functions than this says nothing
MAX_STRING = 512
MAGIC = b"GMFP"
FORMAT = 3               # 3 records the architecture and which features are strings; 2 appends the
#                          author's self-test (calibration) as JSON; 1 and 2 are still read
_SALT = (0x6D66_7072).to_bytes(8, "big")
_BRANCHES = ("b", "bl", "blx", "bx", "cbz", "cbnz", "call", "jmp", "j", "jal", "jalr",
             "tbb", "tbh", "it")


def _hash(kind: bytes, value: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(kind + value, digest_size=8, salt=_SALT).digest(),
                          "big")


# ------------------------------------------------------------------ address space

@dataclass
class Memory:
    """The bytes of an image by address, enough to follow a pointer to a string."""

    regions: List[Tuple[int, bytes]] = field(default_factory=list)
    ranges: List[Tuple[int, int]] = field(default_factory=list)   # allocated, no bytes (.bss)

    def is_address(self, value: int) -> bool:
        """Inside the image or its zero-initialised data: a pointer, not a constant."""
        return self.contains(value) or any(lo <= value < hi for lo, hi in self.ranges)

    def read(self, addr: int, n: int) -> Optional[bytes]:
        for start, blob in self.regions:
            if start <= addr and addr + n <= start + len(blob):
                return blob[addr - start:addr - start + n]
        return None

    def contains(self, addr: int) -> bool:
        return any(start <= addr < start + len(blob) for start, blob in self.regions)

    def cstring(self, addr: int) -> Optional[bytes]:
        for start, blob in self.regions:
            if start <= addr < start + len(blob):
                end = blob.find(b"\0", addr - start, addr - start + MAX_STRING)
                if end < 0:
                    return None
                text = blob[addr - start:end]
                if len(text) >= MIN_LEN and all(32 <= c < 127 or c in (9, 10, 13) for c in text) \
                        and _wanted(text):
                    return text
                return None
        return None


def memory_from_elf(data: bytes, info: ElfInfo) -> Memory:
    regions = [(s.addr, data[s.offset:s.offset + s.size]) for s in info.sections
               if s.flags & 2 and s.type == 1 and s.addr and s.size]      # SHF_ALLOC, PROGBITS
    bss = [(s.addr, s.addr + s.size) for s in info.sections
           if s.flags & 2 and s.type == 8 and s.addr and s.size]          # SHT_NOBITS
    return Memory(regions, bss)


# ------------------------------------------------------------------ features

SMALL_NEGATIVE = 0x1000   # a value this close below 2**bits is a small negative number

_SIMPLE = {0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x7FFFFFFFFFFFFFFF}


def _distinctive(v: int) -> bool:
    if v < 0x1000 or v in _SIMPLE:
        return False
    if v & (v - 1) == 0 or (v + 1) & v == 0:               # 2**n, 2**n - 1
        return False
    return True


def _unsigned(v: int, bits: int) -> int:
    if v >= 0:
        return v
    return v + (1 << 32) if v >= -(1 << 31) else v + (1 << 64)


class FeatureSet(set):
    """A function's features. ``strings`` is the part that came from string literals.

    Strings are what the programmer wrote and survive a change of architecture; constants
    include ones the compiler derived (reciprocal multipliers, packed literals), which do not."""

    strings: Set[int]

    def __init__(self, items=(), strings=()):
        super().__init__(items)
        self.strings = set(strings)


def function_features(mem: Memory, arch: str, address: int, size: int) -> "FeatureSet":
    """Strings referenced and distinctive constants used by one function."""
    spec = disasm._arch(arch)
    code = mem.read(address, size) if size else None
    if (spec is None and arch != "xtensa") or not code:
        return FeatureSet()
    bits = 64 if arch in ("aarch64", "riscv64", "x86-64") else 32
    out = FeatureSet()

    def emit(v: int) -> None:
        v = _unsigned(v, bits)
        if v >= (1 << bits) - SMALL_NEGATIVE or (
                arch == "x86-64" and (1 << 32) - SMALL_NEGATIVE <= v < (1 << 32)):
            return          # -36 is a frame offset or a step, not a constant (x86-64's
            #                 32-bit ``mov`` zero-extends, so there it reads 0xFFFFFFDC)
        if mem.is_address(v):
            s = mem.cstring(v)
            if s:
                h = _hash(b"s", s)
                out.add(h)
                out.strings.add(h)
        elif _distinctive(v):
            out.add(_hash(b"c", v.to_bytes(8, "big")))

    if arch == "xtensa":
        xtensa.features(code, address, mem.read, emit)
        return out
    md = disasm.capstone.Cs(spec.cs_arch, spec.cs_mode)
    md.detail = True
    md.skipdata = True
    md.skipdata_setup = ("db", None, None)
    building: Dict[int, int] = {}         # AArch64: register -> constant being built
    low: Dict[int, int] = {}              # ARM: register -> movw half
    regs: Dict[int, int] = {}             # RISC-V: register -> known value
    cs = disasm.capstone
    for insn in md.disasm(code, address):
        m = insn.mnemonic
        if m == "db":
            continue
        ops = insn.operands
        if arch in ("thumb", "arm"):
            if m.startswith("movw") and len(ops) == 2 and ops[1].type == cs.CS_OP_IMM:
                low[ops[0].reg] = ops[1].imm & 0xFFFF
                continue
            if m.startswith("movt") and len(ops) == 2 and ops[0].reg in low:
                emit((ops[1].imm & 0xFFFF) << 16 | low.pop(ops[0].reg))
                continue
            if m.startswith("ldr") and len(ops) == 2 and ops[1].type == cs.CS_OP_MEM \
                    and ops[1].mem.base and insn.reg_name(ops[1].mem.base) == "pc":
                pc = (insn.address + 4) & ~3 if arch == "thumb" else insn.address + 8
                word = mem.read(pc + ops[1].mem.disp, 4)
                if word:
                    emit(struct.unpack("<I", word)[0])
                continue
            if m.split(".")[0] in _BRANCHES:
                continue
            for op in ops:
                if op.type == cs.CS_OP_IMM:
                    emit(op.imm)
        elif arch in ("riscv32", "riscv64"):
            names = [(o.type, o.reg if o.type == cs.CS_OP_REG else o.imm) for o in ops]
            if m in ("lui", "c.lui") and len(ops) == 2:
                regs[ops[0].reg] = ((ops[1].imm << 12) & 0xFFFFFFFF)
                if regs[ops[0].reg] & 0x80000000 and arch == "riscv64":
                    regs[ops[0].reg] -= 1 << 32
            elif m == "auipc" and len(ops) == 2:
                regs[ops[0].reg] = insn.address + (ops[1].imm << 12)
            elif m in ("addi", "c.addi") and len(ops) == 3 and ops[2].type == cs.CS_OP_IMM:
                src = ops[1].reg if m == "addi" else ops[0].reg
                if src in regs:
                    value = regs[src] + ops[2].imm
                    emit(value)
                    regs[ops[0].reg] = value
                else:
                    emit(ops[2].imm)
                    regs.pop(ops[0].reg, None)
            elif m in ("jal", "jalr", "c.jal", "c.j", "j", "beq", "bne", "blt", "bge",
                       "bltu", "bgeu"):
                continue
            elif names and ops[0].type == cs.CS_OP_REG:
                regs.pop(ops[0].reg, None)
        elif arch == "aarch64":
            # A constant is built from movz/movk (flushed once the run of movk ends) and an
            # address from adrp + add or an adrp-relative load.
            if m == "movk" and len(ops) == 2 and ops[0].reg in building:
                shift = ops[1].shift.value if ops[1].shift.type else 0
                building[ops[0].reg] = ((building[ops[0].reg] & ~(0xFFFF << shift))
                                        | (ops[1].imm & 0xFFFF) << shift)
                continue
            for reg, value in building.items():
                emit(value)
            building.clear()
            if m == "adrp" and len(ops) == 2:
                regs[ops[0].reg] = ops[1].imm
                continue
            if m in ("movz", "mov") and len(ops) == 2 and ops[1].type == cs.CS_OP_IMM:
                shift = ops[1].shift.value if m == "movz" and ops[1].shift.type else 0
                building[ops[0].reg] = (ops[1].imm << shift) if m == "movz" else ops[1].imm
                continue
            if m.startswith(("b", "cb", "tb")) or m == "ret":
                continue
            if m == "add" and len(ops) == 3 and ops[2].type == cs.CS_OP_IMM \
                    and ops[1].reg in regs:
                value = regs[ops[1].reg] + ops[2].imm
                emit(value)
                regs[ops[0].reg] = value
                continue
            for op in ops:
                if op.type == cs.CS_OP_IMM:
                    emit(op.imm)
                elif op.type == cs.CS_OP_MEM and op.mem.base in regs:
                    emit(regs[op.mem.base] + op.mem.disp)
        else:                             # x86: immediates and RIP-relative
            if m.split(".")[0] in _BRANCHES or m.startswith("j"):
                continue
            for op in ops:
                if op.type == cs.CS_OP_IMM:
                    emit(op.imm)
                elif op.type == cs.CS_OP_MEM:
                    base = insn.reg_name(op.mem.base) if op.mem.base else ""
                    if base == "rip":
                        emit(insn.address + insn.size + op.mem.disp)
                    elif op.mem.disp and (not op.mem.base and not op.mem.index
                                          or abs(op.mem.disp) >= 0x10000):
                        # an absolute address, or a constant folded into an address
                        # calculation: gcc turns ``x + K`` into ``lea K(%reg)``
                        emit(op.mem.disp)
    for value in building.values():
        emit(value)
    return out


def image_features(data: bytes, arch: Optional[str] = None, base: Optional[int] = None,
                   min_features: Optional[int] = None, ignore_symbols: bool = False
                   ) -> Tuple[List[Set[int]], Optional[str]]:
    """Feature sets of the fingerprintable functions of an ELF or a Cortex-M ``.bin``, and
    the architecture they were decoded as (None if nothing could be decoded).

    *min_features*: functions with fewer are left out (default ``MIN_FEATURES``); the
    benchmark passes 1 and applies its own threshold, so one extraction serves every one.
    *ignore_symbols*: recover boundaries as if the ELF were stripped (for a self-test)."""
    if not disasm.available():
        return [], None
    from .elf import parse_elf
    info = parse_elf(data)
    if info is not None:
        if ignore_symbols:
            info.functions = []
        rec = disasm.recover_elf(data, info)
        mem = memory_from_elf(data, info)
    else:
        rec = disasm.recover_raw(data, arch, base)
        start = base if base is not None else disasm.cortex_m_base(data)
        mem = Memory([(start, data)] if start is not None else [])
    if rec is None or not rec.functions or not mem.regions:
        return [], None
    found = []
    for f in rec.functions:
        feats = function_features(mem, rec.arch, f.address, f.size)
        if len(feats) >= (MIN_FEATURES if min_features is None else min_features):
            found.append(feats)
    return found, rec.arch


def image_function_features(data: bytes, arch: Optional[str] = None,
                            base: Optional[int] = None,
                            min_features: Optional[int] = None,
                            ignore_symbols: bool = False) -> List[Set[int]]:
    """:func:`image_features` without the architecture."""
    return image_features(data, arch, base, min_features, ignore_symbols)[0]


# ------------------------------------------------------------------ reference prints

@dataclass
class FunctionPrints:
    versions: List[str]
    functions: List[Tuple[int, Tuple[int, ...]]] = field(default_factory=list)  # bitmap, features
    meta: Dict[str, object] = field(default_factory=dict)   # the author's self-test, see calibrate.py
    arch: str = ""            # what the references were built for ("" = not recorded)
    strings: List[int] = field(default_factory=list)  # per function: how many leading features are
    #                         string literals (UNKNOWN_STRINGS: not recorded)
    _index: Optional[Dict[int, List[int]]] = field(default=None, repr=False, compare=False)
    _string_index: Optional[Dict[int, List[int]]] = field(default=None, repr=False,
                                                          compare=False)

    @classmethod
    def build(cls, per_version: Sequence[Tuple[str, Iterable[Set[int]]]],
              min_features: Optional[int] = None, arch: str = "") -> "FunctionPrints":
        """*arch*: what the references were built for. With it (and features that know which
        of them are strings) the prints can be used on other architectures by strings alone."""
        floor = MIN_FEATURES if min_features is None else min_features
        versions = [label for label, _ in per_version][:64]
        merged: Dict[Tuple[Tuple[int, ...], int], int] = {}
        for bit, (_, sets) in enumerate(per_version[:64]):
            for feats in sets:
                if isinstance(feats, FeatureSet):
                    strs = sorted(feats.strings)
                    key = tuple(strs + sorted(feats - feats.strings))[:MAX_FEATURES]
                    known = min(len(strs), len(key))
                else:
                    key, known = tuple(sorted(feats)[:MAX_FEATURES]), UNKNOWN_STRINGS
                if len(key) >= floor:
                    merged[(key, known)] = merged.get((key, known), 0) | (1 << bit)
        ordered = sorted(merged.items())
        return cls(versions, [(bits, key) for (key, _), bits in ordered], arch=arch,
                   strings=[known for (_, known), _ in ordered])

    def to_bytes(self) -> bytes:
        out = bytearray(MAGIC + bytes([FORMAT]) + struct.pack("<H", len(self.versions)))
        for v in self.versions:
            raw = v.encode("utf-8")
            out += struct.pack("<H", len(raw)) + raw
        arch = self.arch.encode("utf-8")
        out += struct.pack("<H", len(arch)) + arch
        out += struct.pack("<I", len(self.functions))
        known = self.strings or [UNKNOWN_STRINGS] * len(self.functions)
        for (bits, feats), n in zip(self.functions, known):
            out += struct.pack("<QHH", bits, len(feats), n) + struct.pack(f"<{len(feats)}Q", *feats)
        meta = json.dumps(self.meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
        out += struct.pack("<I", len(meta)) + meta
        return bytes(out)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "FunctionPrints":
        if raw[:4] != MAGIC or raw[4] not in (1, 2, FORMAT):
            raise ValueError("not a function-print sidecar")
        pos = 5
        (n,) = struct.unpack_from("<H", raw, pos)
        pos += 2
        versions = []
        for _ in range(n):
            (ln,) = struct.unpack_from("<H", raw, pos)
            versions.append(raw[pos + 2:pos + 2 + ln].decode("utf-8"))
            pos += 2 + ln
        arch = ""
        if raw[4] >= 3:
            (ln,) = struct.unpack_from("<H", raw, pos)
            arch = raw[pos + 2:pos + 2 + ln].decode("utf-8")
            pos += 2 + ln
        (count,) = struct.unpack_from("<I", raw, pos)
        pos += 4
        functions, strings = [], []
        for _ in range(count):
            if raw[4] >= 3:
                bits, k, n = struct.unpack_from("<QHH", raw, pos)
                pos += 12
            else:
                bits, k = struct.unpack_from("<QH", raw, pos)
                n = UNKNOWN_STRINGS
                pos += 10
            functions.append((bits, struct.unpack_from(f"<{k}Q", raw, pos)))
            strings.append(n)
            pos += 8 * k
        meta: Dict[str, object] = {}
        if raw[4] >= 2:
            (size,) = struct.unpack_from("<I", raw, pos)
            meta = json.loads(raw[pos + 4:pos + 4 + size].decode("utf-8")) if size else {}
        return cls(versions, functions, meta, arch, strings)

    def write(self, path) -> str:
        raw = self.to_bytes()
        with open(path, "wb") as fh:
            fh.write(raw)
        return hashlib.sha256(raw).hexdigest()

    def index(self, strings_only: bool = False) -> Dict[int, List[int]]:
        if strings_only:
            if self._string_index is None:
                inverted: Dict[int, List[int]] = {}
                for i, (_, feats) in enumerate(self.functions):
                    for f in feats[:self.strings[i]]:
                        inverted.setdefault(f, []).append(i)
                self._string_index = {f: ids for f, ids in inverted.items()
                                      if len(ids) <= MAX_DF}
            return self._string_index
        if self._index is None:
            inverted = {}
            for i, (_, feats) in enumerate(self.functions):
                for f in feats:
                    inverted.setdefault(f, []).append(i)
            self._index = {f: ids for f, ids in inverted.items() if len(ids) <= MAX_DF}
        return self._index

    def knows_strings(self) -> bool:
        """Whether each function records which of its features are string literals."""
        return bool(self.functions) and len(self.strings) == len(self.functions) \
            and UNKNOWN_STRINGS not in self.strings

    def match(self, image: Sequence[Set[int]], min_features: Optional[int] = None,
              tie_share: Optional[float] = None, arch: Optional[str] = None
              ) -> Optional[Tuple[str, int, int, float, str]]:
        """(best version, matched, of, coverage, tied range or ""), or None.

        *arch*: what the image was decoded as. When it differs from what the references were
        built for, only string literals are compared: the constants a compiler derives
        differ between architectures, and on a Cortex-M3 reference against rv32imac and
        AArch64 images they were the source of every wrong release
        (docs/BINARY-VALIDATION.md). Fewer functions are recognised, none wrongly."""
        floor = MIN_FEATURES if min_features is None else min_features
        share = TIE_SHARE if tie_share is None else tie_share
        by_string = bool(arch and self.arch and arch != self.arch and self.knows_strings())
        index = self.index(by_string)
        matched: Set[int] = set()
        for feats in image:
            if by_string:
                feats = getattr(feats, "strings", None) or ()
                if len(feats) < floor:
                    continue
            votes: Dict[int, int] = {}
            for f in feats:
                for i in index.get(f, ()):
                    votes[i] = votes.get(i, 0) + 1
            for i, hits in votes.items():
                size = self.strings[i] if by_string else len(self.functions[i][1])
                if hits >= min(floor, size) and hits >= MIN_CONTAINMENT * size:
                    matched.add(i)
        if len(matched) < MIN_MATCHES:
            return None
        scores, owns = [], []
        for v in range(len(self.versions)):
            own = {i for i, (bits, _) in enumerate(self.functions)
                   if bits >> v & 1 and (not by_string or self.strings[i] >= floor)}
            owns.append(own)
            union = len(own | matched)
            scores.append(len(own & matched) / union if union else 0.0)
        best = max(scores)
        index_best = scores.index(best)
        own = owns[index_best]
        coverage = len(own & matched) / len(own) if own else 0.0
        if coverage < MIN_COVERAGE:
            return None
        tied = [i for i, s in enumerate(scores) if s >= best * share]
        low, high = self.versions[min(tied)], self.versions[max(tied)]
        return (self.versions[index_best], len(own & matched), len(own), coverage,
                "" if low == high else f"{low}~{high}")
