"""The nested-file lookup read off the store's walk agrees with the glob one."""

from pathlib import Path

from gangmu.analysis import TreeIndex
from gangmu.match.engine import NESTED_LOOKUP_DEPTH, _unique_below, _unique_glob


def _tree(tmp_path: Path) -> Path:
    for rel in ("lib/core/src/include/lwip/init.h",       # one level below lib/src/...
                "lib/a/x/conf.h", "lib/b/x/conf.h",        # two candidates: ambiguous
                "lib/deep/1/2/3/4/only.h",
                "lib/top.h", "other/core/src/include/lwip/init.h"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
    return tmp_path


def test_agrees_with_glob(tmp_path):
    root = _tree(tmp_path)
    index = TreeIndex(root)
    for directory, prefix in ((root / "lib", "lib/"), (root, "")):
        for tail in ("src/include/lwip/init.h", "x/conf.h", "conf.h", "only.h",
                     "top.h", "missing.h", "include/lwip/init.h"):
            for depth in (1, 2, NESTED_LOOKUP_DEPTH, 6):
                for deep in (False, True):
                    assert (_unique_below(directory, (prefix, index), tail, depth, deep)
                            == _unique_glob(directory, tail, depth, deep)), (directory, tail,
                                                                            depth, deep)
