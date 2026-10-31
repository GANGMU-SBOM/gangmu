"""The binary-identification benchmark scores what it says it scores."""

import json
import random

import pytest

from gangmu.eval import binary as ev

# A library of 40 functions per release; release n adds 6 functions and keeps the rest, so
# adjacent releases differ little. Every function has 3 features of its own.
_rng = random.Random(7)


def _library(name: str, releases: int, base: int = 40, added: int = 6):
    pool = [{_rng.getrandbits(62) for _ in range(3)} for _ in range(base + added * releases)]
    return {f"{name}{r}": pool[:base + added * r] for r in range(releases)}


def _corpus(*names: str, opts=("A", "B")) -> ev.Corpus:
    corpus = ev.Corpus()
    for name in names:
        by_tag = _library(name, 3)
        corpus.releases[name] = list(by_tag)
        corpus.builds[name] = {tag: {opt: ev.Build(list(map(set, feats)), list(map(set, feats)))
                                     for opt in opts}
                               for tag, feats in by_tag.items()}
    return corpus


def test_a_clean_corpus_is_identified_exactly_and_unrelated_libraries_do_not_match():
    report = ev.evaluate(_corpus("p", "q"), min_features=2, tie_share=0.85)
    assert report.counts()["wrong"] == 0 and report.counts()["none"] == 0
    assert report.counts()["exact"] + report.counts()["range"] == len(report.cells)
    assert report.negative_total > 0 and report.negatives == []


def test_every_reference_optimisation_is_tried_against_every_image_optimisation():
    report = ev.evaluate(_corpus("p"), 2, 0.85)
    assert {(c.ref_opt, c.img_opt) for c in report.cells} == {("A", "A"), ("A", "B"),
                                                              ("B", "A"), ("B", "B")}
    cross = report.counts(cross_opt_only=True)
    assert sum(cross.values()) == sum(1 for c in report.cells if c.ref_opt != c.img_opt) == 6


def test_outcome_classification():
    tags = ["1", "2", "3"]
    assert ev._classify(("2", 5, 5, 1.0, ""), tags, "2") == ("exact", "2")
    assert ev._classify(("1", 5, 5, 1.0, ""), tags, "2") == ("wrong", "1")
    assert ev._classify(("2", 5, 5, 1.0, "2~3"), tags, "3") == ("range", "2~3")
    assert ev._classify(("1", 5, 5, 1.0, "1~2"), tags, "3") == ("wrong", "1~2")
    assert ev._classify(None, tags, "1") == ("none", "")


def test_a_shared_feature_set_across_libraries_is_reported_as_a_false_positive():
    corpus = _corpus("p", "q")
    # make q's builds contain p's functions: p's fingerprints now match q's images
    p_feats = corpus.builds["p"]["p2"]["A"].img
    for per_opt in corpus.builds["q"].values():
        for build in per_opt.values():
            build.img = build.img + [set(s) for s in p_feats]
    report = ev.evaluate(corpus, 2, 0.85)
    assert report.negatives and report.false_positives("p") > 0


def test_leave_one_library_out_scores_only_the_library_left_out():
    corpus = _corpus("p", "q", "r")
    folds = ev.leave_one_library_out(corpus)
    assert [f.held_out for f in folds] == ["p", "q", "r"]
    for f in folds:
        assert sum(f.held.values()) > 0
        assert f.chosen in ev.GRID
    assert "held out" in ev.format_folds(folds)


def test_the_selection_prefers_fewer_wrong_answers_to_more_exact_ones():
    corpus = _corpus("p", "q")
    reports = {p: ev.evaluate(corpus, *p) for p in ev.GRID}
    libs = ["p", "q"]
    best = min(ev.GRID, key=lambda p: (ev._score(reports[p], libs), ev.GRID.index(p)))
    wrong_fp = lambda p: ev._score(reports[p], libs)[0]
    assert wrong_fp(best) == min(wrong_fp(p) for p in ev.GRID)


def test_the_corpus_loader_reads_the_manifest_and_caches_features(tmp_path, monkeypatch):
    import gangmu.fprint as fp
    calls = []
    monkeypatch.setattr(fp, "image_features",
                        lambda data, *a, **k: (calls.append(data) or [{1, 2, 3}], "thumb"))
    for tag in ("v1", "v2"):
        for opt in ("Os",):
            d = tmp_path / "lib" / tag
            d.mkdir(parents=True)
            (d / f"{opt}.elf").write_bytes(b"ref" + tag.encode())
            (d / f"{opt}.strip.elf").write_bytes(b"img" + tag.encode())
    (tmp_path / "corpus.json").write_text(json.dumps(
        {"lib": [{"tag": "v1", "opts": ["Os"]}, {"tag": "v2", "opts": ["Os"]}]}))
    corpus = ev.load_corpus(tmp_path)
    assert corpus.releases == {"lib": ["v1", "v2"]} and len(calls) == 4
    ev.load_corpus(tmp_path)
    assert len(calls) == 4                                     # second load came from the cache


def test_the_feature_cache_is_json_and_a_pickle_left_behind_is_never_loaded(tmp_path, monkeypatch):
    # A corpus can come from someone else; unpickling its cache would run their code.
    import pickle

    import gangmu.fprint as fp
    calls = []
    monkeypatch.setattr(fp, "image_features",
                        lambda data, *a, **k: (calls.append(data) or [{3, 1, 2}], "thumb"))
    d = tmp_path / "lib" / "v1"
    d.mkdir(parents=True)
    (d / "Os.elf").write_bytes(b"ref")
    (d / "Os.strip.elf").write_bytes(b"img")
    (tmp_path / "corpus.json").write_text(json.dumps({"lib": [{"tag": "v1", "opts": ["Os"]}]}))

    class Boom:
        def __reduce__(self):
            return (pytest.fail, ("the pickle cache was unpickled",))
    (tmp_path / ".features.pickle").write_bytes(pickle.dumps(Boom()))

    first = ev.load_corpus(tmp_path)
    cache = json.loads((tmp_path / ev.FEATURES_CACHE).read_text(encoding="utf-8"))
    assert cache["lib/v1/Os.elf"][2] == [[1, 2, 3]]
    second = ev.load_corpus(tmp_path)
    assert len(calls) == 2                                     # the second load hit the cache
    assert second.builds["lib"]["v1"]["Os"].ref == first.builds["lib"]["v1"]["Os"].ref == [{1, 2, 3}]


def test_a_corrupt_feature_cache_is_a_miss(tmp_path, monkeypatch):
    import gangmu.fprint as fp
    monkeypatch.setattr(fp, "image_features", lambda data, *a, **k: ([{1}], "thumb"))
    d = tmp_path / "lib" / "v1"
    d.mkdir(parents=True)
    (d / "Os.elf").write_bytes(b"ref")
    (d / "Os.strip.elf").write_bytes(b"img")
    (tmp_path / "corpus.json").write_text(json.dumps({"lib": [{"tag": "v1", "opts": ["Os"]}]}))
    (tmp_path / ev.FEATURES_CACHE).write_text('{"lib/v1/Os.elf": [1]}')
    assert ev.load_corpus(tmp_path).builds["lib"]["v1"]["Os"].ref == [{1}]


def test_a_library_and_its_fuller_build_are_one_component():
    from gangmu.eval.binary import _same_component
    assert _same_component("mbedtls", "mbedtls-full")
    assert _same_component("mbedtls-full", "mbedtls")
    assert not _same_component("lz4", "zstd")
    assert not _same_component("libpng", "png")


def _prints(*funcs, arch="thumb"):
    from gangmu.fprint import FunctionPrints
    return FunctionPrints(["1.0", "2.0"], [(3, tuple(f)) for f in funcs], arch=arch,
                          strings=[0] * len(funcs))


def test_a_function_two_libraries_share_counts_for_neither():
    from gangmu.fprint import segment_prints
    shared = (1, 2, 3, 4)
    lz4 = _prints(shared, (10, 11, 12), (13, 14, 15), (16, 17, 18))
    zstd = _prints(shared, (20, 21, 22), (23, 24, 25), (26, 27, 28))
    a, b = segment_prints([("lz4", lz4), ("zstd", zstd)])
    assert shared not in [f for _, f in a.functions] and len(a.functions) == 3
    assert shared not in [f for _, f in b.functions] and len(b.functions) == 3


def test_a_library_bundled_whole_keeps_its_functions_and_the_host_gives_them_up():
    from gangmu.fprint import segment_prints
    xx = [(1, 2, 3), (4, 5, 6), (7, 8, 9)]
    xxhash = _prints(*xx)
    zstd = _prints(*xx, (20, 21, 22), (23, 24, 25), (26, 27, 28), (29, 30, 31))
    kept_xxhash, kept_zstd = segment_prints([("xxhash", xxhash), ("zstd", zstd)])
    assert len(kept_xxhash.functions) == 3
    assert [f for _, f in kept_zstd.functions] == [(20, 21, 22), (23, 24, 25),
                                                   (26, 27, 28), (29, 30, 31)]


def test_one_components_prints_and_other_architectures_are_not_compared():
    from gangmu.fprint import segment_prints
    shared = (1, 2, 3, 4)
    one, two = _prints(shared, (5, 6, 7)), _prints(shared, (8, 9, 10))
    assert [len(p.functions) for p in segment_prints([("m", one), ("m", two)])] == [2, 2]
    other = _prints(shared, (8, 9, 10), arch="riscv32")
    assert [len(p.functions) for p in segment_prints([("a", one), ("b", other)])] == [2, 2]
