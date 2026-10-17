"""A signature holds packed machine words, not lists of Python ints."""

from array import array

from gangmu.fnsig import FunctionSignature, intersects

from community import REPO_RULES, needs_rules


def _sig():
    return FunctionSignature.build([
        ("1.0", {5, 3, 9}, {1, 2}),
        ("2.0", {3, 9, 11}, {2, 4}),
    ])


def test_fields_are_packed_arrays():
    sig = _sig()
    assert isinstance(sig.hashes, array) and sig.hashes.typecode == "Q"
    assert isinstance(sig.bitmaps, array) and isinstance(sig.flags, array)
    assert isinstance(sig.abstract_hashes, array)
    assert list(sig.hashes) == [3, 5, 9, 11]


def test_roundtrip_and_lists_are_accepted():
    sig = _sig()
    again = FunctionSignature.from_bytes(sig.to_bytes())
    assert list(again.hashes) == list(sig.hashes)
    assert again.sha256 == sig.sha256
    from_lists = FunctionSignature(versions=["1"], hashes=[1 << 63, 2],
                                   bitmaps=[1, 1], flags=[1, 1])
    assert isinstance(from_lists.hashes, array)
    assert list(from_lists.ordered_hashes) == [2, 1 << 63]


def test_intersects_on_packed_hashes():
    sig = _sig()
    assert intersects({9}, sig.ordered_hashes)
    assert not intersects({4}, sig.ordered_hashes)


def test_single_release_signature_reports_its_version():
    from gangmu.fnsig import infer_version
    sig = FunctionSignature.build([("1.0.1", {3, 5, 9}, {1})])
    verdict = infer_version(sig, {3, 5, 9, 100})
    assert verdict.best == "1.0.1"
    assert infer_version(sig, {100}).best is None


def _segmented(families):
    """Segment two rules whose signatures share most functions."""
    from types import SimpleNamespace
    from gangmu.match.engine import MatchEngine

    shared = set(range(100, 160))
    rules = []
    for i, family in enumerate(families):
        sig = FunctionSignature.build([("1.0", shared | {i}, set())])
        spec = SimpleNamespace(family=family, sha256=f"sig{i}", load=lambda s=sig: s)
        rules.append(SimpleNamespace(functions=spec))
    engine = object.__new__(MatchEngine)
    engine.rulebase = rules
    engine._segmented = False
    engine.segment_rule_base()
    return [r.functions.load() for r in rules]


def test_shared_functions_are_dropped_between_unrelated_rules():
    for sig in _segmented(["", ""]):
        assert len(sig.application_hashes) == 1


def test_sibling_rules_of_one_family_keep_their_shared_functions():
    for sig in _segmented(["gd32", "gd32"]):
        assert len(sig.application_hashes) == 61
    first, other = _segmented(["gd32", "other"])
    assert len(first.application_hashes) == 1


def _derivative(own, present):
    from types import SimpleNamespace
    from gangmu.match.engine import MatchEngine

    sig = FunctionSignature.build([("1.0", set(own), set()), ("2.0", set(own) | {1}, set())])
    engine = object.__new__(MatchEngine)
    rule = SimpleNamespace(upstream_name="hostap")
    evidence = []
    return engine._by_derivative(sig, set(present), rule, "d", evidence), evidence


def test_derivative_reports_weak_identity_without_a_version():
    own = range(1000, 1400)
    found, evidence = _derivative(own, set(own) | set(range(5000, 5600)))
    identity, label, verdict = found
    assert identity == 0.5 and label is None
    assert verdict.foreign > 0                       # so the finding is vendor_patched
    assert evidence and "modified derivative" in evidence[0].summary


def test_derivative_needs_enough_identical_functions_and_share():
    own = range(1000, 1400)
    assert _derivative(range(1000, 1100), set(range(1000, 1100)))[0] is None
    assert _derivative(own, set(own) | set(range(5000, 9000)))[0] is None


def _decode_reference(raw):
    """The record-by-record decoder the table-at-once one replaced."""
    import struct
    pos = 5
    (count,) = struct.unpack_from("<H", raw, pos); pos += 2
    versions = []
    for _ in range(count):
        (length,) = struct.unpack_from("<H", raw, pos); pos += 2
        versions.append(raw[pos:pos + length].decode("utf-8")); pos += length
    (n,) = struct.unpack_from("<I", raw, pos); pos += 4
    rows = []
    for _ in range(n):
        rows.append(struct.unpack_from("<QQB", raw, pos)); pos += 17
    abstract = []
    if pos < len(raw):
        (m,) = struct.unpack_from("<I", raw, pos); pos += 4
        for _ in range(m):
            abstract.append(struct.unpack_from("<QQ", raw, pos)); pos += 16
    return versions, rows, abstract


def _as_reference(sig):
    return (list(sig.versions), list(zip(sig.hashes, sig.bitmaps, sig.flags)),
            list(zip(sig.abstract_hashes, sig.abstract_bitmaps)))


def test_decoding_matches_the_record_by_record_reference():
    import random
    rng = random.Random(9)
    releases = [(f"{i}.0", {rng.getrandbits(64) for _ in range(300)},
                 {rng.getrandbits(64) for _ in range(200)}) for i in range(5)]
    sig = FunctionSignature.build(releases)
    raw = sig.to_bytes()
    assert _as_reference(FunctionSignature.from_bytes(raw)) == _decode_reference(raw)
    empty = FunctionSignature.build([("1.0", set(), set())]).to_bytes()
    assert _as_reference(FunctionSignature.from_bytes(empty)) == _decode_reference(empty)


def test_a_truncated_signature_is_an_error_not_a_short_one():
    import struct
    import pytest
    raw = _sig().to_bytes()
    with pytest.raises(struct.error):
        FunctionSignature.from_bytes(raw[:-5])


@needs_rules
def test_every_installed_sidecar_decodes_as_the_reference_does():
    from pathlib import Path
    from gangmu.rules.loader import load_rules
    seen = 0
    for rule in load_rules(REPO_RULES):
        spec = rule.functions
        if spec is None or spec.format == "fnprint":
            continue
        raw = (Path(spec.base_dir or ".") / spec.file).read_bytes()
        assert _as_reference(FunctionSignature.from_bytes(raw)) == _decode_reference(raw), spec.file
        seen += 1
    assert seen > 10
