"""The 0.6 fast paths give the same answers as the slow ones.

Every optimisation here changes *how* an answer is computed -- once per file
instead of once per directory and rule, from a cache instead of from source,
with numpy instead of a Python loop, with rules skipped that cannot fire -- and
none of them is allowed to change *what* the answer is. These tests pin that,
and pin the work counters the CI performance check relies on.
"""

import os
import shutil
import time
from pathlib import Path

import pytest

from gangmu import fingerprint
from gangmu.analysis import AnalysisStore, TreeIndex, analyse_bytes
from gangmu.dirprint import print_directory, print_from_store
from gangmu.eval.perf import check, scaled_rulebase, synthetic_tree
from gangmu.match.engine import MatchEngine, PrintCache
from gangmu.normalize import _COMMENT_GROUPS, _TOKEN, _strip_numeric_suffix, tokenize
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan

from community import REPO_RULES, needs_rules

pytestmark = needs_rules
INCLUDE = ["src/**/*.c", "include/**/*.h"]


def _tokenize_reference(data: bytes):
    """The finditer tokenizer 0.5 shipped, kept as the definition."""
    out = []
    for m in _TOKEN.finditer(data):
        if m.lastgroup in _COMMENT_GROUPS:
            continue
        tok = m.group(0)
        out.append(_strip_numeric_suffix(tok) if m.lastgroup == "num" else tok)
    return out


def _sample_sources():
    tree = Path(__file__).resolve().parent / "fixtures"
    texts = [p.read_bytes() for p in sorted(tree.rglob("*.[ch]"))]
    texts.append(b"x = 0xFFu + 1.5e-3f + .25L + 10UL; /* c */ y = a...b; // tail\n"
                 b"z = 'a' + \"s\\\"t\" / 2; /* unterminated")
    return texts


def test_tokenizer_matches_the_reference_definition():
    for data in _sample_sources():
        assert tokenize(data) == _tokenize_reference(data)


def test_vector_fingerprints_equal_the_python_loop(monkeypatch):
    if fingerprint.numpy_module() is None:
        pytest.skip("numpy not installed; the pure path is the only path")
    monkeypatch.setattr(fingerprint, "_VECTOR_MIN_TOKENS", 0)
    for data in _sample_sources():
        tokens = tokenize(data)
        fast = fingerprint.sorted_fingerprints(tokens, 16, 8, 256)
        with monkeypatch.context() as m:
            m.setattr(fingerprint, "_np", None)
            slow = fingerprint.sorted_fingerprints(tokens, 16, 8, 256)
        assert fast == slow
        reference = sorted(fingerprint.winnow(fingerprint.kgram_hashes(tokens, 16), 8))
        assert slow == (reference[:256], len(reference))


def test_per_file_bottoms_give_the_exact_directory_sketch(upstream_dir):
    """The union of per-file bottom-k sets contains the directory's bottom-k."""
    slow = print_directory(upstream_dir, INCLUDE)
    with AnalysisStore(upstream_dir.parent, 16, 8, cap=4) as store:   # tiny cap
        fast = print_from_store(store, upstream_dir, INCLUDE)
        for size in (1, 3, 4):
            assert fast.signature(size=size).values == slow.signature(size=size).values
        assert fast.file_hashes == slow.file_hashes
        assert fast.fileset_sha256 == slow.fileset_sha256
        assert fast.functions == slow.functions
        assert fast.abstract_functions == slow.abstract_functions


def test_tree_index_slices_directories_on_a_path_boundary(tmp_path):
    for rel in ("a/b/x.c", "a/bc/y.c", "a/b.c", "a/b/c/z.c", ".git/k.c"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n")
    index = TreeIndex(tmp_path)
    assert index.under("a/b") == ["a/b/c/z.c", "a/b/x.c"]
    assert ".git/k.c" not in index.under(".")


def test_nested_components_are_tokenised_once(tmp_path, upstream_dir):
    outer = tmp_path / "components" / "outer"
    shutil.copytree(upstream_dir, outer)
    shutil.copytree(upstream_dir, outer / "third_party" / "inner")
    stats = {}
    scan(tmp_path, load_rules(REPO_RULES), options=ScanOptions(stats=stats))
    # Two copies of four sources: identical content, so four analyses in all.
    assert stats["files_tokenised"] == 4
    assert stats["files_hashed"] == 8


def test_incremental_cache_reanalyses_only_what_changed(tmp_path, upstream_dir):
    tree = tmp_path / "tree"
    shutil.copytree(upstream_dir, tree / "components" / "tinynet")
    cache = tmp_path / "cache"
    old = time.time() - 60
    for path in tree.rglob("*"):
        os.utime(path, (old, old))       # older than the racy-mtime window

    def run():
        stats = {}
        result = scan(tree, load_rules(REPO_RULES),
                      options=ScanOptions(cache_dir=cache, stats=stats))
        return result, stats

    first, cold = run()
    second, warm = run()
    assert cold["files_tokenised"] == 4
    assert warm["files_tokenised"] == 0 and warm["files_hashed"] == 0
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]

    edited = tree / "components" / "tinynet" / "src" / "buf.c"
    edited.write_text(edited.read_text() + "\nint vendor_extra(void) { return 42; }\n")
    os.utime(edited, (old + 1, old + 1))
    _, again = run()
    assert again["files_tokenised"] == 1 and again["files_hashed"] == 1


def test_prefilter_changes_nothing_but_the_work(project_dir, rules_dir):
    rules = load_rules(rules_dir)
    root = project_dir.resolve()
    with AnalysisStore(root, 16, 8) as store:
        plain = MatchEngine(rulebase=rules, cache=PrintCache(store=store),
                            prefilter=False)
        quick = MatchEngine(rulebase=rules, cache=PrintCache(store=store))
        for directory in sorted(p for p in root.rglob("*") if p.is_dir()):
            a = [f.to_dict() for f in plain.identify_directory(root, directory)]
            b = [f.to_dict() for f in quick.identify_directory(root, directory)]
            assert a == b, directory


def test_replicated_rules_are_skipped_not_evaluated(tmp_path):
    synthetic_tree(tmp_path / "sdk", components=6, files_per_component=6)
    base = load_rules(REPO_RULES)
    stats = {}
    scan(tmp_path / "sdk", scaled_rulebase(base, 4), options=ScanOptions(stats=stats))
    assert stats["rule_checks"] == 0
    assert stats["rule_checks_skipped"] == 4 * len(base) * stats["candidate_directories"]


def test_synthetic_tree_is_deterministic(tmp_path):
    a = synthetic_tree(tmp_path / "a", seed=3, components=5, files_per_component=4)
    b = synthetic_tree(tmp_path / "b", seed=3, components=5, files_per_component=4)
    assert a == b
    files_a = sorted(p.relative_to(tmp_path / "a") for p in (tmp_path / "a").rglob("*.c"))
    files_b = sorted(p.relative_to(tmp_path / "b") for p in (tmp_path / "b").rglob("*.c"))
    assert files_a == files_b
    assert all((tmp_path / "a" / f).read_bytes() == (tmp_path / "b" / f).read_bytes()
               for f in files_a)


def test_perf_check_flags_a_counter_regression():
    base = {"numpy": True, "runs": [{"mode": "cold", "scale": 1, "findings": ["x"],
                                     "files_tokenised": 100, "rule_checks": 5,
                                     "scan_units": 10.0, "peak_rss_mb": 50.0}]}
    same = {"numpy": True, "runs": [dict(base["runs"][0])]}
    assert check(same, base) == []
    worse = {"numpy": True, "runs": [dict(base["runs"][0], files_tokenised=200)]}
    assert any("files_tokenised" in p for p in check(worse, base))
    slower = {"numpy": True, "runs": [dict(base["runs"][0], scan_units=30.0)]}
    assert any("calibration units" in p for p in check(slower, base))
    other_numpy = dict(slower, numpy=False)
    assert check(other_numpy, base) == []      # times not comparable, counters are


def test_analysis_blob_round_trips():
    a = analyse_bytes(b"int f(int x) { return x + 1; } int g(void) { return f(2) * 3; }",
                      16, 8)
    from gangmu.analysis import FileAnalysis
    assert FileAnalysis.from_blob(a.to_blob()) == a


def _perf_run(mode, memory):
    return {"mode": mode, "scale": 1, "scan_units": 10.0, "peak_rss_mb": memory,
            "findings": []}


def test_warm_memory_gets_more_room_than_cold_memory():
    baseline = {"numpy": True, "runs": [_perf_run("cold", 100.0), _perf_run("warm", 100.0)]}

    def problems(mode, memory):
        return check({"numpy": True, "runs": [_perf_run(mode, memory)]}, baseline)

    assert not problems("cold", 130.0) and not problems("warm", 150.0)
    assert problems("cold", 140.0)      # past 1.35x
    assert not problems("warm", 155.0)  # still inside 1.6x
    assert problems("warm", 170.0)      # past 1.6x
