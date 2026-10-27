"""`gangmu rules bundled`: which rules carry another's code, and where the host keeps it."""

import shutil
from pathlib import Path
from types import SimpleNamespace

from gangmu.fnsig import FunctionSignature
from gangmu.rules.bundles import Copy, exclude_globs, find_bundles, locate
from gangmu.rules.loader import load_rules

FIXTURES = Path(__file__).parent / "fixtures"


def _rule(name, releases, family=""):
    sig = FunctionSignature.build([(v, set(h), set()) for v, h in releases])
    return SimpleNamespace(id=name, functions=SimpleNamespace(
        load=lambda: sig, sha256=name, family=family))


LIB = set(range(1, 101))


def _states(*rules):
    return {(b.host, b.bundled): b.state for b in find_bundles(rules)}


def test_a_copy_that_is_a_small_part_of_its_host_is_kept():
    states = _states(_rule("lib", [("1.0", LIB)]),
                     _rule("host", [("5.0", LIB | set(range(1000, 3000)))]))
    assert states == {("host", "lib"): "kept"}


def test_a_copy_that_is_a_large_part_of_its_host_is_lost():
    [bundle] = find_bundles([_rule("lib", [("1.0", LIB)]),
                             _rule("host", [("5.0", LIB | set(range(1000, 1400)))])])
    assert (bundle.host, bundle.bundled, bundle.state) == ("host", "lib", "lost")
    assert (bundle.release, bundle.inside, bundle.size) == ("1.0", 100, 100)
    assert abs(bundle.host_share - 100 / 500) < 1e-9


def test_two_rules_holding_each_other_are_lineage():
    # A library split out of a project: each holds a whole release of the other.
    old = set(range(1, 201))
    states = _states(_rule("project", [("2.0", old | set(range(500, 540)))]),
                     _rule("split", [("1.0", old)]))
    assert states == {("project", "split"): "lineage", ("split", "project"): "lineage"}


def test_one_family_is_not_a_bundle():
    assert not _states(_rule("lib", [("1.0", LIB)], family="f"),
                       _rule("host", [("5.0", LIB | set(range(1000, 1400)))], family="f"))


def test_the_exclusions_are_relative_to_the_rules_root():
    found = [Copy("src/third_party/lib", "lib", "1.0"), Copy("src/third_party/lib/sub", "x", None),
             Copy("src/vendor/other", "other", None),
             Copy("src/fs", "fatfs", None, ["src/fs/ff.c", "src/fs/ff.h"])]
    assert exclude_globs(found, "src") == ["third_party/lib/**", "vendor/other/**",
                                           "fs/ff.c", "fs/ff.h"]
    assert exclude_globs(found)[:2] == ["src/third_party/lib/**", "src/vendor/other/**"]


def test_locate_finds_the_copy_in_the_hosts_checkout(tmp_path):
    host = tmp_path / "host"
    shutil.copytree(FIXTURES / "upstream" / "tinynet", host / "deps" / "tinynet")
    (host / "main.c").write_text("int main(void) { return 0; }\n")
    rulebase = load_rules(FIXTURES / "rules")
    found = locate(host, rulebase, "test/other")
    assert [(c.directory, c.rule_id, c.files) for c in found] == [
        ("deps/tinynet", "test/tinynet", None)]
    assert exclude_globs(found) == ["deps/tinynet/**"]
    assert not locate(host, rulebase, "test/tinynet")      # the host's own code


def test_the_command_prints_the_exclusions(tmp_path, capsys):
    from gangmu.cli import main
    host = tmp_path / "host"
    shutil.copytree(FIXTURES / "upstream" / "tinynet", host / "deps" / "tinynet")
    assert main(["rules", "bundled", "--rules", str(FIXTURES / "rules"),
                 "--rule", "test/tinynet", "--tree", str(host)]) == 0
    assert main(["rules", "bundled", "--rules", str(FIXTURES / "rules"),
                 "--tree", str(host)]) == 2           # --tree needs --rule
    assert main(["rules", "bundled", "--rules", str(FIXTURES / "rules")]) == 0


def test_the_exclusion_takes_the_whole_copy():
    # A finding sits at the copy's source root; its demos and tests beside it are
    # the bundled library's code too.
    from gangmu.rules.bundles import _widen
    rule = SimpleNamespace(path_globs=("libtomcrypt", "**/libtomcrypt", "**/libtomcrypt/src"))
    assert _widen("libtomcrypt/src", rule) == "libtomcrypt"
    assert _widen("third_party/libtomcrypt/src", rule) == "third_party/libtomcrypt"
    assert _widen("crypto/src", rule) == "crypto/src"


def test_a_copy_beside_the_hosts_own_code_is_excluded_file_by_file(tmp_path):
    # swupdate keeps FatFs's ff.c in fs/ beside its own btrfs.c: excluding fs/ would
    # take the host's code with it.
    from gangmu.functions import extract_functions
    from gangmu.rules.bundles import _own_files
    lib = "int ff_mount(int a) { int b = a * 7; while (b > 3) { b -= 2; } return b; }\n"
    own = "int btrfs_mk(int a) { int c = a + 9; if (c % 4 == 1) { c ^= 5; } return c; }\n"
    fs = tmp_path / "fs"
    fs.mkdir()
    (fs / "ff.c").write_text(lib)
    (fs / "ffconf.h").write_text("#define FF_FS_READONLY 0\n")
    (fs / "btrfs.c").write_text(own)
    sig = FunctionSignature.build([("1.0", {f.hash for f in extract_functions(lib.encode())},
                                    set())])
    rule = SimpleNamespace(functions=SimpleNamespace(load=lambda: sig),
                           anchors=(), marker_files=("source/ffconf.h",))
    assert _own_files(fs, rule) == ["ff.c", "ffconf.h"]
    (fs / "btrfs.c").unlink()
    assert _own_files(fs, rule) is None          # the whole directory is the copy
