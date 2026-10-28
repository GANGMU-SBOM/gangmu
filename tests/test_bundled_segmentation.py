"""Segmentation that keeps a bundled library's code its own.

Symmetric segmentation (a function in two rules is nobody's) stripped zlib, CMSIS-Core,
lmdb and expat of their identity, because many projects carry a copy of them. When the
signatures show one rule bundling another, the shared code is the bundled one's.
"""

from types import SimpleNamespace

from gangmu.fnsig import FunctionSignature
from gangmu.match.engine import MatchEngine


def _rule(name, releases, family=None):
    """A stand-in rule: just what segmentation reads."""
    sig = FunctionSignature.build([(v, set(h), set()) for v, h in releases])
    return SimpleNamespace(id=name, functions=SimpleNamespace(
        load=lambda: sig, sha256=name, family=family)), sig


def _segment(*rules):
    MatchEngine.segment_rule_base(SimpleNamespace(_segmented=False, rulebase=list(rules)))


LIB = set(range(1, 101))                       # a 100-function library, one release


def test_a_library_bundled_in_a_big_project_keeps_its_code():
    lib, lib_sig = _rule("lib", [("1.0", LIB)])
    host, host_sig = _rule("host", [("5.0", LIB | set(range(1000, 3000)))])
    _segment(lib, host)
    assert lib_sig.application_hashes == LIB                  # still the library's
    assert not host_sig.application_hashes & LIB              # borrowed by the host


def test_every_holder_must_bundle_it():
    # A fork holds the same code and is not a bundling host (the code is half of it):
    # nobody can tell the two apart by it, so it stays nobody's.
    lib, lib_sig = _rule("lib", [("1.0", LIB)])
    host, _ = _rule("host", [("5.0", LIB | set(range(1000, 3000)))])
    fork, fork_sig = _rule("fork", [("1.0", LIB | set(range(200, 300)))])
    _segment(lib, host, fork)
    assert not lib_sig.application_hashes & LIB
    assert not fork_sig.application_hashes & LIB


def test_two_forks_share_nothing():
    a, a_sig = _rule("a", [("1.0", set(range(1, 201)))])
    b, b_sig = _rule("b", [("1.0", set(range(1, 151)) | set(range(500, 560)))])
    _segment(a, b)
    assert a_sig.application_hashes == set(range(151, 201))
    assert b_sig.application_hashes == set(range(500, 560))


def test_a_tiny_recorded_release_proves_no_bundling():
    # 30 functions fit inside an unrelated project by way of a shared helper.
    small = set(range(1, 31))
    lib, lib_sig = _rule("lib", [("0.1", small)])
    host, _ = _rule("host", [("5.0", small | set(range(1000, 3000)))])
    _segment(lib, host)
    assert not lib_sig.application_hashes & small


def test_a_release_far_smaller_than_the_rules_largest_proves_no_bundling():
    # The newest release records 50 functions, all inside the host; the rule's largest
    # records 400. What was recorded for it is some third library, not this project.
    shared = set(range(1, 51))
    lib, lib_sig = _rule("lib", [("1.0", set(range(1, 401))), ("2.0", shared)])
    host, _ = _rule("host", [("5.0", shared | set(range(1000, 3000)))])
    _segment(lib, host)
    assert not lib_sig.application_hashes & shared


def test_the_partial_copy_path_does_not_count_borrowed_code():
    """A copy of the bundled library alone is not a partial copy of the host."""
    from gangmu.match.engine import SUBSET_MIN_FUNCTIONS, SUBSET_MIN_SHARE
    lib, _ = _rule("lib", [("1.0", LIB)])
    host, host_sig = _rule("host", [("5.0", LIB | set(range(1000, 3000)))])
    _segment(lib, host)
    present = set(LIB)
    every = present & host_sig.hash_set
    own = present & host_sig.application_hashes
    assert len(every) >= SUBSET_MIN_FUNCTIONS and len(every) / len(present) >= SUBSET_MIN_SHARE
    assert not own                       # what the partial-copy path now counts


def test_a_partial_copy_beside_a_whole_one_leaves_the_code_the_librarys():
    # tcl carries all of zlib, freetype only its inflate: both are borrowing.
    lib, lib_sig = _rule("lib", [("1.0", LIB)])
    whole, _ = _rule("whole", [("5.0", LIB | set(range(1000, 3000)))])
    part, _ = _rule("part", [("2.0", set(range(1, 31)) | set(range(5000, 7000)))])
    _segment(lib, whole, part)
    assert lib_sig.application_hashes == LIB


def test_a_partial_copy_alone_proves_nothing():
    # Without a whole copy, 30 shared functions may be some third library both carry.
    lib, lib_sig = _rule("lib", [("1.0", LIB)])
    part, _ = _rule("part", [("2.0", set(range(1, 31)) | set(range(5000, 7000)))])
    _segment(lib, part)
    assert not lib_sig.application_hashes & set(range(1, 31))


def test_a_fork_holding_a_small_part_gives_it_up():
    # zlib-ng shares 16 functions with zlib, a few per cent of itself; tcl's whole copy
    # of zlib says they are zlib's.
    lib, lib_sig = _rule("lib", [("1.0", LIB)])
    whole, _ = _rule("whole", [("5.0", LIB | set(range(1000, 3000)))])
    fork, fork_sig = _rule("fork", [("2.0", set(range(1, 17)) | set(range(8000, 8400)))])
    _segment(lib, whole, fork)
    assert lib_sig.application_hashes == LIB
    assert not fork_sig.application_hashes & set(range(1, 17))
