"""Release scoring of per-function fingerprints: contradiction, not share explained."""

from gangmu.fprint import FunctionPrints


def _feats(tag, n):
    return {hash((tag, k)) & 0xFFFFFFFF for k in range(n)}


def _prints():
    # A function is a set of features; each release is a list of functions.
    stable = [_feats(f"s{i}", 5) for i in range(6)]
    only_a = [_feats(f"a{i}", 5) for i in range(3)]
    only_b = [_feats(f"b{i}", 5) for i in range(3)]
    only_c = [_feats(f"c{i}", 5) for i in range(3)]
    prints = FunctionPrints.build([("1.0", stable + only_a),
                                   ("1.1", stable + only_b),
                                   ("1.2", stable + only_c)], min_features=2)
    return prints, stable, only_a, only_b, only_c


def test_a_release_specific_function_names_the_release():
    prints, stable, _, only_b, _ = _prints()
    got = prints.match(stable + only_b)
    assert got is not None and got[0] == "1.1" and got[4] == ""


def test_two_version_specific_functions_are_not_yet_enough_to_exclude_a_neighbour():
    prints, stable, _, only_b, _ = _prints()
    got = prints.match(stable + only_b[:2])
    assert got[0] == "1.1" and got[4] == "1.0~1.2"


def test_contradicting_evidence_excludes_a_release_even_when_most_is_shared():
    prints, stable, only_a, _, _ = _prints()
    got = prints.match(stable + only_a)
    assert got[0] == "1.0" and got[4] == ""


def test_with_nothing_version_specific_the_span_covers_every_release():
    prints, stable, *_ = _prints()
    got = prints.match(stable)
    assert got is not None and got[4] == "1.0~1.2"


def test_one_contradiction_does_not_split_a_pair_but_three_do():
    prints, stable, only_a, only_b, _ = _prints()
    one = prints.match(stable + only_b[:3] + only_a[:1])      # a vendor mix: 1 stray
    assert one[0] == "1.1" and one[4] == "1.0~1.1"
    mix = prints.match(stable + only_b[:3] + only_a[:3])
    assert mix[4] != ""                                       # no clean answer: a span


def test_a_two_feature_print_counts_for_less_than_a_full_one():
    # Two-feature prints are subsets of many unrelated functions, so a stray match of
    # one costs a third of a full contradiction; a stray full print costs one.
    stable = [_feats(f"s{i}", 5) for i in range(6)]
    big_b = [_feats(f"b{i}", 5) for i in range(3)]
    weak_a = [_feats("weak", 2)]
    strong_a = [_feats("strong", 5)]
    prints = FunctionPrints.build([("1.0", stable + weak_a + strong_a),
                                   ("1.1", stable + big_b)], min_features=2)
    # 1.0 trails 1.1 by the three big_b prints; the stray costs 1.1 a third or a whole.
    weak = prints.match(stable + big_b + weak_a)
    strong = prints.match(stable + big_b + strong_a)
    assert weak[0] == "1.1" and weak[4] == ""
    assert strong[0] == "1.1" and strong[4] == "1.0~1.1"


def test_the_older_share_score_is_still_available():
    prints, stable, _, only_b, _ = _prints()
    got = prints.match(stable + only_b, tie_share=0.85)
    assert got is not None and got[0] == "1.1"
