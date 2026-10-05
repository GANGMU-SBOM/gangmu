"""A signature holds packed machine words, not lists of Python ints."""

from array import array

from gangmu.fnsig import FunctionSignature, intersects


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
