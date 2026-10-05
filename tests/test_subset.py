"""A partial copy of a component: the reverse containment measure."""

import json

from gangmu.cli import main
from gangmu.fnsig import FunctionSignature, infer_version_subset
from gangmu.functions import function_hashes


def _sig():
    return FunctionSignature.build([
        ("1.0", {1, 2, 3, 10, 11}, set()),
        ("1.1", {1, 2, 3, 20, 21, 11}, set()),
        ("1.2", {1, 2, 3, 20, 21, 11, 30}, set()),
    ])


def test_the_version_is_the_release_that_holds_every_function_found():
    verdict = infer_version_subset(_sig(), {20, 21})
    assert (verdict.low, verdict.high) == ("1.1", "1.2")      # unchanged since 1.1
    assert verdict.is_range
    assert infer_version_subset(_sig(), {10}).label == "1.0"
    assert infer_version_subset(_sig(), {30}).label == "1.2"


def test_releases_that_share_all_the_functions_found_are_a_range():
    verdict = infer_version_subset(_sig(), {1, 2, 11})
    assert (verdict.low, verdict.high) == ("1.0", "1.2")


def test_a_mixture_is_reported_with_what_does_not_fit():
    verdict = infer_version_subset(_sig(), {10, 21})
    assert verdict.multi_version is True
    assert "other releases only" in verdict.detail


def test_nothing_recorded_gives_no_version():
    assert infer_version_subset(_sig(), {777}).best is None


# ------------------------------------------------------------ end to end

def _fn(i, variant):
    return (f"int fn{i}(int x) {{ int y = x * {i} + {variant}; "
            f"while (y > {i}) {{ y -= 3; }} if (y % 5 == {i % 5}) {{ y ^= {i}; }} "
            f"return y + x; }}\n")


def _file(index, variant):
    return "".join(_fn(index * 50 + i, variant) for i in range(50))


def _tree(root, files):
    root.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (root / name).write_text(text)


def _rule(tmp_path, subset):
    versions = {"1": {f"c{n}.c": _file(n, 1) for n in range(4)},
                "2": {**{f"c{n}.c": _file(n, 1) for n in range(1, 4)}, "c0.c": _file(0, 2)}}
    per = []
    for label, files in versions.items():
        hashes = set()
        for text in files.values():
            hashes |= function_hashes(text.encode())
        per.append((label, hashes, set()))
    rules = tmp_path / "rules"
    rules.mkdir()
    digest = FunctionSignature.build(per).write(rules / "synth.fnsig")
    (rules / "synth.yaml").write_text(f"""id: test/synth
component:
  path_globs:
  - '**/synth'
  ships_as: synth
upstream:
  name: synth
  purl: pkg:generic/synth
  cpe_status: 'none-in-nvd: test fixture'
  source: {{kind: git, url: 'https://example.invalid/synth', ref: v2}}
identity:
  include: ['**/*.c']
  functions:
    file: synth.fnsig
    sha256: {digest}
    count: 0
    versions: ['1', '2']
{'    subset: true' if subset else ''}
""")
    return rules


def _scan(rules, tree, tmp_path):
    out = tmp_path / "out.json"
    assert main(["scan", str(tree), "--rules", str(rules), "--format", "json",
                 "--min-confidence", "0.35", "-o", str(out)]) == 0
    return json.loads(out.read_text())


def test_a_pruned_copy_is_identified_when_the_rule_opts_in(tmp_path):
    rules = _rule(tmp_path, subset=True)
    tree = tmp_path / "tree"
    _tree(tree / "synth", {"c0.c": _file(0, 2)})            # one file of four, release 2 only
    data = _scan(rules, tree, tmp_path)
    found = data["findings"]
    assert len(found) == 1 and found[0]["version"] == "2"
    assert 0.7 < found[0]["identity_confidence"] <= 0.8
    assert any("partial copy" in e["summary"] for e in found[0]["evidence"])


def test_code_unchanged_between_releases_gives_a_range(tmp_path):
    rules = _rule(tmp_path, subset=True)
    tree = tmp_path / "tree"
    _tree(tree / "synth", {"c3.c": _file(3, 1)})
    found = _scan(rules, tree, tmp_path)["findings"]
    assert len(found) == 1 and found[0]["version"] == "1~2"


def test_without_the_opt_in_a_pruned_copy_is_not_identified(tmp_path):
    rules = _rule(tmp_path, subset=False)
    tree = tmp_path / "tree"
    _tree(tree / "synth", {"c3.c": _file(3, 1)})
    assert _scan(rules, tree, tmp_path)["findings"] == []


def test_a_directory_mostly_made_of_other_code_is_not_a_partial_copy(tmp_path):
    rules = _rule(tmp_path, subset=True)
    tree = tmp_path / "tree"
    other = "".join(_fn(9000 + i, 7) for i in range(25))   # 25 foreign functions beside 50
    _tree(tree / "synth", {"c3.c": _file(3, 1), "mine.c": other})
    assert _scan(rules, tree, tmp_path)["findings"] == []


def test_too_few_functions_is_not_enough(tmp_path):
    rules = _rule(tmp_path, subset=True)
    tree = tmp_path / "tree"
    _tree(tree / "synth", {"small.c": "".join(_fn(150 + i, 1) for i in range(10))})
    assert _scan(rules, tree, tmp_path)["findings"] == []


def _growing_rule(tmp_path):
    """Release 2 is release 1 plus two files, so a partial copy of release 2 is a
    larger share of the smaller release 1."""
    base = {f"c{n}.c": _file(n, 1) for n in range(4)}
    versions = {"1": base, "2": {**base, "c4.c": _file(4, 1), "c5.c": _file(5, 1)}}
    per = []
    for label, files in versions.items():
        hashes = set()
        for text in files.values():
            hashes |= function_hashes(text.encode())
        per.append((label, hashes, set()))
    rules = tmp_path / "rules"
    rules.mkdir()
    digest = FunctionSignature.build(per).write(rules / "synth.fnsig")
    (rules / "synth.yaml").write_text(f"""id: test/synth
component:
  path_globs:
  - '**/synth'
  ships_as: synth
upstream:
  name: synth
  purl: pkg:generic/synth
  cpe_status: 'none-in-nvd: test fixture'
  source: {{kind: git, url: 'https://example.invalid/synth', ref: v2}}
identity:
  include: ['**/*.c']
  functions:
    file: synth.fnsig
    sha256: {digest}
    count: 0
    versions: ['1', '2']
    subset: true
""")
    return rules


def test_a_partial_copy_of_the_newer_release_is_not_read_as_the_older_one(tmp_path):
    rules = _growing_rule(tmp_path)
    tree = tmp_path / "tree"
    # Three files of release 1 plus one file only release 2 has: 75% of release 1,
    # 67% of release 2, yet the extra file cannot come from release 1.
    _tree(tree / "synth", {"c0.c": _file(0, 1), "c1.c": _file(1, 1),
                           "c2.c": _file(2, 1), "c4.c": _file(4, 1)})
    found = _scan(rules, tree, tmp_path)["findings"]
    assert len(found) == 1 and found[0]["version"] == "2"
