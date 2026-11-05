"""Files between 4 and 16 MiB give their functions but leave the exact-copy hash
and the sketch as they were: rules record both over files up to 4 MiB."""

from pathlib import Path

from gangmu.analysis import AnalysisStore
from gangmu.dirprint import SKETCH_FILE_BYTES, print_directory, print_from_store


def _big_c(path: Path) -> None:
    body = "".join(f"int big_fn_{i}(int a) {{ int b = a * {i}; return b + a - {i}; }}\n"
                   for i in range(80000))
    path.write_text(body)
    assert SKETCH_FILE_BYTES < path.stat().st_size < 16 << 20


def _tree(tmp: Path, with_big: bool) -> Path:
    root = tmp / ("with" if with_big else "without")
    root.mkdir()
    (root / "small.c").write_text("int small(int x) { int y = x + 1; return y * 2; }\n")
    if with_big:
        _big_c(root / "amalgamation.c")
    return root


def test_a_large_file_adds_functions_but_not_hash_or_sketch(tmp_path):
    plain, big = (print_directory(_tree(tmp_path, w)) for w in (False, True))
    assert big.fileset_sha256 == plain.fileset_sha256
    assert big.fingerprints == plain.fingerprints
    assert len(big.functions) > len(plain.functions) + 70000


def test_the_scan_store_agrees(tmp_path):
    root = _tree(tmp_path, True)
    with AnalysisStore(root, k=16, window=8) as store:
        stored = print_from_store(store, root)
        direct = print_directory(root)
        assert stored.fileset_sha256 == direct.fileset_sha256
        assert stored.functions == direct.functions


def test_the_store_sketch_leaves_the_large_file_out(tmp_path):
    root = _tree(tmp_path, True)
    with AnalysisStore(root, k=16, window=8) as store:
        stored = print_from_store(store, root, k=16, window=8)
        plain = print_directory(_tree(tmp_path, False), k=16, window=8)
        assert stored.signature(16, 8, 64).values == plain.signature(16, 8, 64).values
