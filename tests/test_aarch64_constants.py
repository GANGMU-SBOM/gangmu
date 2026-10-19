"""AArch64 constants built by mov/movk with unrelated instructions scheduled in between."""
import pytest

from gangmu import disasm, fprint

pytestmark = pytest.mark.skipif(not disasm.available(), reason="capstone not installed")


def _features(words):
    code = b"".join(w.to_bytes(4, "little") for w in words)
    return fprint.function_features(fprint.Memory([(0x1000, code)]), "aarch64", 0x1000, len(code))


MOV_X2_3800 = 0xD2870002       # mov  x2, #0x3800
MOV_W3_F = 0x528001E3          # mov  w3, #0xf
MOVK_X2_4002 = 0xF2A80042      # movk x2, #0x4002, lsl #16
STR_W3_X0 = 0xB9000003         # str  w3, [x0]
LDR_W3_X2_8 = 0xB9400843       # ldr  w3, [x2, #8]
RET = 0xD65F03C0


def test_interleaved_movk_builds_the_whole_constant():
    interleaved = _features([MOV_X2_3800, MOV_W3_F, MOVK_X2_4002, STR_W3_X0, LDR_W3_X2_8, RET])
    contiguous = _features([MOV_X2_3800, MOVK_X2_4002, MOV_W3_F, STR_W3_X0, LDR_W3_X2_8, RET])
    assert interleaved == contiguous
    assert fprint._hash(b"c", (0x40023800).to_bytes(8, "big")) in interleaved
    assert fprint._hash(b"c", (0x3800).to_bytes(8, "big")) not in interleaved


def test_a_register_read_before_its_movk_ends_the_constant():
    # x2 is used as 0x3800 before the movk, so 0x3800 is a constant of its own
    feats = _features([MOV_X2_3800, LDR_W3_X2_8, MOVK_X2_4002, RET])
    assert fprint._hash(b"c", (0x3800).to_bytes(8, "big")) in feats
