"""A copy of only the directory a rule's globs sit under (libcbor's ``src/`` carried
as ``external/libcbor``) is found by its functions; the globs selected nothing there."""

import json
from types import SimpleNamespace

from gangmu.cli import main
from gangmu.dirprint import sha256_file
from gangmu.fnsig import FunctionSignature
from gangmu.functions import extract_functions
from gangmu.match.engine import flat_include, flat_prefix


def _fn(name, i):
    return (f"int {name}(int x) {{ int y = x * {i} + 3; while (y > {i}) {{ y -= 3; }} "
            f"if (y % 5 == {i % 5}) {{ y ^= {i}; }} return y + x; }}\n")


FILES = {f"c{n}.c": "".join(_fn(f"fn{n * 50 + i}", n * 50 + i) for i in range(50))
         for n in range(4)}


def _rules(tmp_path):
    hashes = {f.hash for text in FILES.values() for f in extract_functions(text.encode())}
    rules = tmp_path / "rules"
    rules.mkdir()
    digest = FunctionSignature.build([("1.0", hashes, set())]).write(rules / "synth.fnsig")
    (tmp_path / "c0.c").write_text(FILES["c0.c"])
    anchor = sha256_file(tmp_path / "c0.c")
    (rules / "synth.yaml").write_text(f"""id: test/synth
component:
  path_globs: ['**/synth']
  ships_as: synth
upstream:
  name: synth
  purl: pkg:generic/synth
  cpe_status: 'none-in-nvd: test fixture'
  source: {{kind: git, url: 'https://example.invalid/synth', ref: v1.0}}
identity:
  include: ['src/**/*.c', 'src/**/*.h']
  anchors:
  - path: src/c0.c
    sha256: {{'1.0': {anchor}}}
  functions:
    file: synth.fnsig
    sha256: {digest}
    count: 0
    versions: ['1.0']
""")
    return rules


def _scan(rules, tree, tmp_path):
    out = tmp_path / "out.json"
    assert main(["scan", str(tree), "--rules", str(rules), "--format", "json",
                 "-o", str(out)]) == 0
    return [f for f in json.loads(out.read_text())["findings"] if f["rule_id"] == "test/synth"]


def test_the_prefix_is_the_one_directory_every_glob_sits_under():
    def rule(*include):
        return SimpleNamespace(include=include)
    assert flat_prefix(rule("src/**/*.c", "src/**/*.h")) == "src"
    assert flat_include(rule("src/**/*.c", "src/*.h")) == ("**/*.c", "*.h")
    assert flat_prefix(rule("src/**/*.c", "include/**/*.h")) is None
    assert flat_prefix(rule("**/*.c")) is None
    assert flat_prefix(rule("*.c")) is None
    assert flat_prefix(rule()) is None


def test_a_flattened_copy_is_found(tmp_path):
    rules = _rules(tmp_path)
    tree = tmp_path / "fw" / "external" / "synth"
    tree.mkdir(parents=True)
    for name, text in FILES.items():
        (tree / name).write_text(text)
    [finding] = _scan(rules, tmp_path / "fw", tmp_path)
    assert finding["directory"] == "external/synth" and finding["version"] == "1.0"
    summaries = " ".join(e["summary"] for e in finding["evidence"])
    assert "flattened copy" in summaries
    assert "c0.c matches, byte for byte" in summaries and "src/c0.c" not in summaries


def test_the_upstream_layout_is_read_as_before(tmp_path):
    rules = _rules(tmp_path)
    tree = tmp_path / "fw" / "synth" / "src"
    tree.mkdir(parents=True)
    for name, text in FILES.items():
        (tree / name).write_text(text)
    [finding] = _scan(rules, tmp_path / "fw", tmp_path)
    assert finding["directory"] == "synth"
    assert "flattened" not in " ".join(e["summary"] for e in finding["evidence"])
