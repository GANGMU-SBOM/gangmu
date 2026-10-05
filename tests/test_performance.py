"""Guards for the fast paths.

These are correctness tests for optimisations, not timings: a benchmark that
fails on a loaded CI box teaches nobody anything, but an optimisation that
quietly changes the answer is exactly the bug worth catching.
"""

import random
from typing import List, Sequence, Set

from gangmu.dirprint import SketchCache, print_directory
from gangmu.fingerprint import (DEFAULT_SKETCH, kgram_hashes, signature_from_fingerprints,
                                token_hashes, winnow)
from gangmu.normalize import tokenize


def _winnow_naive(hashes: Sequence[int], window: int) -> Set[int]:
    """The O(n*window) definition the deque version replaced."""
    if not hashes:
        return set()
    if len(hashes) <= window:
        return {min(hashes)}
    selected, prev = set(), -1
    for start in range(len(hashes) - window + 1):
        best_index, best = start, hashes[start]
        for off in range(1, window):
            if hashes[start + off] <= best:
                best, best_index = hashes[start + off], start + off
        if best_index != prev:
            selected.add(best)
            prev = best_index
    return selected


def test_deque_winnowing_matches_the_definition():
    rng = random.Random(7)
    for n in (0, 1, 7, 8, 9, 50, 500):
        for window in (2, 8, 13):
            hashes = [rng.randrange(1 << 32) for _ in range(n)]
            assert winnow(hashes, window) == _winnow_naive(hashes, window), (n, window)


def test_winnowing_survives_heavy_ties():
    """All-equal input is the worst case for a monotonic deque."""
    assert winnow([5] * 100, 8) == _winnow_naive([5] * 100, 8)


def test_rolling_kgram_count_is_right():
    tokens = tokenize(b"int a; int b; int c; int d; int e; int f;")
    for k in (2, 4, 8):
        expected = max(1, len(tokens) - k + 1) if len(tokens) >= k else 1
        assert len(kgram_hashes(tokens, k)) == expected


def test_rolling_hash_is_deterministic_and_order_sensitive():
    a = tokenize(b"int f(void) { return 1; }")
    b = tokenize(b"int g(void) { return 1; }")
    assert kgram_hashes(a, 4) == kgram_hashes(a, 4)
    assert kgram_hashes(a, 4) != kgram_hashes(b, 4)


def test_token_hashes_are_memoised_consistently():
    tokens = [b"int", b"a", b"int", b"a"]
    hashes = token_hashes(tokens)
    assert hashes[0] == hashes[2] and hashes[1] == hashes[3]
    assert hashes[0] != hashes[1]


def _jaccard(a: Set[int], b: Set[int]) -> float:
    return len(a & b) / len(a | b)


def test_bottom_k_tracks_the_true_jaccard():
    rng = random.Random(11)
    universe = [rng.randrange(1 << 63) for _ in range(20000)]
    base = set(universe[:10000])
    for overlap in (10000, 9000, 7000, 3000, 0):
        other = set(universe[:overlap]) | set(universe[10000:10000 + (10000 - overlap)])
        exact = _jaccard(base, other)
        got = signature_from_fingerprints(base).similarity(
            signature_from_fingerprints(other))
        assert abs(got - exact) < 0.06, (overlap, exact, got)


def test_small_sets_compare_without_a_full_sketch():
    a = signature_from_fingerprints({1, 2, 3, 4})
    b = signature_from_fingerprints({1, 2, 3, 99})
    assert len(a.values) == 4 < DEFAULT_SKETCH
    assert 0.3 < a.similarity(b) < 0.9


def test_pass_two_is_not_run_when_only_hashes_are_needed(upstream_dir):
    """The exact-copy short circuit is the main performance claim."""
    dp = print_directory(upstream_dir, ["src/**/*.c"])
    assert dp.file_hashes and dp.fileset_sha256
    assert dp._fingerprints is None          # untouched
    assert dp.fingerprints                   # ...until asked
    assert dp._fingerprints is not None


def test_sketch_cache_round_trips_and_is_keyed_by_content(upstream_dir, tmp_path):
    cache = SketchCache(tmp_path)
    first = print_directory(upstream_dir, ["src/**/*.c"], cache=cache)
    sig = first.signature()
    second = print_directory(upstream_dir, ["src/**/*.c"], cache=cache)
    assert cache.get(second.fileset_sha256, second.k, second.window,
                     sig.size).values == sig.values
    assert second.signature().values == sig.values
    assert second._fingerprints is None      # served from disk, pass 2 skipped


def test_a_corrupt_cache_entry_is_ignored(upstream_dir, tmp_path):
    cache = SketchCache(tmp_path)
    dp = print_directory(upstream_dir, ["src/**/*.c"], cache=cache)
    good = dp.signature()
    path = cache._path(dp.fileset_sha256, dp.k, dp.window, good.size)
    path.write_text("not hex at all")
    again = print_directory(upstream_dir, ["src/**/*.c"], cache=cache)
    assert again.signature().values == good.values


def test_parallel_and_serial_agree(upstream_dir):
    serial = print_directory(upstream_dir, ["src/**/*.c", "include/**/*.h"], jobs=1)
    parallel = print_directory(upstream_dir, ["src/**/*.c", "include/**/*.h"], jobs=2)
    assert serial.fileset_sha256 == parallel.fileset_sha256
    assert serial.signature().values == parallel.signature().values
