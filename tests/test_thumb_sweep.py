"""Thumb function-start recovery: pointer words in data must not invent functions."""

import struct

import pytest

from gangmu import disasm

pytestmark = pytest.mark.skipif(not disasm.available(), reason="needs capstone")

BASE = 0x08000000
PUSH, POP, NOP, MOVS = 0xB510, 0xBD10, 0xBF00, 0x2000


def _function(body: int) -> bytes:
    return struct.pack("<%dH" % (body + 3), PUSH, MOVS, *([NOP] * body), POP)


def _code():
    """Two 16-byte functions, then a call-free third one."""
    first = _function(5)                       # 16 bytes
    second = _function(5)
    third = _function(5)
    return first + second + third, [BASE, BASE + 16, BASE + 32]


def _words(values):
    return b"".join(struct.pack("<I", v) for v in values)


def _starts(pools):
    code, funcs = _code()
    return funcs, disasm.sweep(code, BASE, "thumb", [BASE], pools)


def test_repeated_data_words_in_rodata_do_not_count_as_two_references():
    stray = [BASE + 5, 0x12345678, BASE + 5, 0x9ABCDEF0, BASE + 7, 0x11111111, BASE + 7]
    funcs, got = _starts([_words(stray)])
    assert got == funcs


def test_function_pointer_table_still_finds_functions():
    code, funcs = _code()
    table = _words([BASE + 1, BASE + 17, BASE + 33])
    assert disasm.sweep(code, BASE, "thumb", [], [table]) == funcs


def test_vector_table_with_a_repeated_default_handler_still_seeds_it():
    code, funcs = _code()
    vectors = _words([0x20001000, BASE + 17, BASE + 33, BASE + 33, BASE + 33, BASE + 33])
    assert BASE + 32 in disasm.sweep(code, BASE, "thumb", [], [vectors])


def test_table_targets_that_push_late_are_still_functions():
    # gcc schedules loads ahead of the push, so a function pointer names the instruction
    # before the prologue the scan recognises; the table, not the prologue, says it starts here
    def late(body):
        return struct.pack("<%dH" % (body + 5), NOP, NOP, PUSH, MOVS, *([NOP] * body), POP)
    code = late(3) + late(3) + late(3)             # three functions of 16 bytes
    table = _words([BASE + 1, BASE + 17, BASE + 33])
    got = disasm.sweep(code, BASE, "thumb", [], [table])
    assert {BASE, BASE + 16, BASE + 32} <= set(got)
