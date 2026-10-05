"""The binary-identification benchmark scores what it says it scores."""

import json
import random

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
    monkeypatch.setattr(fp, "image_function_features",
                        lambda data, *a, **k: calls.append(data) or [{1, 2, 3}])
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
