"""What lets more images be recognised without claiming unrelated ones: a gate that fits
small libraries, closures over direct calls, and no matches inside giant functions."""

from gangmu import fprint, xtensa
from gangmu.fprint import FeatureSet, FunctionPrints, closures_of


def _feats(tag, n):
    return {hash((tag, k)) & 0xFFFFFFFF for k in range(n)}


def _small_library():
    # four fingerprintable functions in each of two releases, one of them changed
    shared = [_feats(f"s{i}", 4) for i in range(3)]
    return FunctionPrints.build([("1.0", shared + [_feats("a", 4)]),
                                 ("1.1", shared + [_feats("b", 4)])], min_features=2), shared


def test_a_small_library_is_claimed_when_most_of_it_is_there():
    prints, shared = _small_library()
    got = prints.match(shared + [_feats("b", 4)])
    assert got is not None and got[0] == "1.1" and got[1] == 4


def test_three_matches_are_not_enough_for_a_large_library():
    funcs = [_feats(f"f{i}", 4) for i in range(40)]
    prints = FunctionPrints.build([("1.0", funcs), ("1.1", funcs + [_feats("x", 4)])],
                                  min_features=2)
    assert prints.match(funcs[:3]) is None                  # 3 of 40: under half
    assert prints.match(funcs[:5]) is not None              # 5 of 40, 12% or more: as before


def test_two_matches_never_claim_a_library():
    prints, shared = _small_library()
    assert prints.match(shared[:2]) is None


def test_a_closure_joins_a_function_with_what_it_calls():
    caller = FeatureSet({1, 2}, strings={1}, calls={0x200})
    callee = FeatureSet({3, 4}, strings={3})
    leaf = FeatureSet({5, 6})
    got = closures_of({0x100: caller, 0x200: callee, 0x300: leaf})
    assert len(got) == 1 and got[0] == {1, 2, 3, 4} and got[0].strings == {1, 3}


def test_a_closure_finds_a_print_the_compiler_inlined_elsewhere():
    # The reference was built with the callee inlined: one function, both halves. The
    # image keeps them apart, so only its closure holds the whole print.
    inlined = [_feats(f"i{i}", 3) | _feats(f"j{i}", 3) for i in range(6)]
    prints = FunctionPrints.build([("1.0", inlined), ("1.1", inlined + [_feats("z", 4)])],
                                  min_features=2)
    apart = {}
    for i in range(6):
        apart[0x1000 + 0x100 * i] = FeatureSet(_feats(f"i{i}", 3), calls={0x8000 + 0x100 * i})
        apart[0x8000 + 0x100 * i] = FeatureSet(_feats(f"j{i}", 3))
    plain = list(apart.values())
    assert prints.match(plain) is None
    assert prints.match(plain + closures_of(apart)) is not None


def test_a_dispatcher_gets_no_closure():
    many = {0x100 * (i + 2): FeatureSet({100 + i, 200 + i}) for i in range(fprint.MAX_CALLEES + 1)}
    many[0x100] = FeatureSet({1, 2}, calls=set(many))
    assert all(len(c) < 10 for c in closures_of(many))      # only the callees, none of 0x100


def test_a_print_is_not_found_inside_a_constant_table():
    # An error-string switch holds hundreds of constants: small prints of any library sit
    # in it by chance.
    small = [_feats(f"c{i}", 3) for i in range(8)]
    prints = FunctionPrints.build([("1.0", small), ("1.1", small + [_feats("y", 3)])],
                                  min_features=2)
    table = set().union(*small) | set(range(1, 3 * fprint.MAGNET_RATIO * 3))
    assert prints.match([table]) is None
    assert prints.match(small) is not None


def test_xtensa_calls_are_read_from_call_instructions_and_literal_pools():
    base = 0x40080000
    # call8 to base + 4 + 4 * 3: op0 = 5, n = 2, offset 3 (target = ((pc >> 2) + 3 + 1) << 2)
    word = 5 | 2 << 4 | 3 << 6
    code = bytes([word & 0xFF, word >> 8 & 0xFF, word >> 16 & 0xFF])
    assert xtensa.calls(code, base, lambda a, n: None) == [base + 16]
    # l32r from the word before the function: imm16 = 0xFFFF, (pc + 3) & ~3 - 4
    code = bytes([0x01, 0xFF, 0xFF])
    pool = {base - 4 + 0: (0x400D1234).to_bytes(4, "little")}
    assert xtensa.calls(code, base, lambda a, n: pool.get(a)) == [0x400D1234]
