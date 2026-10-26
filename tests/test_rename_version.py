"""A renamed copy: the version comes from the abstracted bodies, and an untouched copy
is never called renamed because the two measures' denominators differ."""

import json

from gangmu.cli import main
from gangmu.fnsig import FunctionSignature, infer_version
from gangmu.functions import extract_functions


def _fn(name, i, variant, var="y"):
    return (f"int {name}(int x) {{ int {var} = x * {i} + {variant}; "
            f"while ({var} > {i}) {{ {var} -= 3; }} if ({var} % 5 == {i % 5}) {{ {var} ^= {i}; }} "
            f"return {var} + x; }}\n")


def _file(index, variant, prefix=""):
    return "".join(_fn(f"{prefix}fn{index * 50 + i}", index * 50 + i, variant,
                       var=f"{prefix}y") for i in range(50))


def _hashes(files):
    exact, abstract = set(), set()
    for text in files.values():
        for f in extract_functions(text.encode()):
            exact.add(f.hash)
            if f.abstract_hash is not None:
                abstract.add(f.abstract_hash)
    return exact, abstract


def _rule(tmp_path, versions):
    per = [(label, *_hashes(files)) for label, files in versions.items()]
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
  source: {{kind: git, url: 'https://example.invalid/synth', ref: v3}}
identity:
  include: ['**/*.c']
  functions:
    file: synth.fnsig
    sha256: {digest}
    count: 0
    versions: {list(versions)}
""")
    return rules


def _scan(rules, tree, tmp_path):
    out = tmp_path / "out.json"
    assert main(["scan", str(tree), "--rules", str(rules), "--format", "json",
                 "--min-confidence", "0.35", "-o", str(out)]) == 0
    return [f for f in json.loads(out.read_text())["findings"] if f["rule_id"] == "test/synth"]


def _releases():
    # Three releases; only c0.c changes between them, so only its functions tell
    # the releases apart.
    return {str(v): {**{f"c{n}.c": _file(n, 1) for n in range(1, 4)}, "c0.c": _file(0, v)}
            for v in (1, 2, 3)}


def test_a_copy_whose_telling_file_was_renamed_still_gets_its_release(tmp_path):
    releases = _releases()
    rules = _rule(tmp_path, releases)
    tree = tmp_path / "fw" / "synth"
    tree.mkdir(parents=True)
    for name, text in releases["3"].items():
        (tree / name).write_text(text)
    # The vendor prefixed every name in the one file that says which release it is.
    (tree / "c0.c").write_text(_file(0, 3, prefix="vnd_"))

    [finding] = _scan(rules, tmp_path / "fw", tmp_path)
    assert finding["version"] == "3"
    summaries = " ".join(e["summary"] for e in finding["evidence"])
    assert "identifier-abstracted" in summaries and "renamed" in summaries


def test_the_exact_bodies_alone_cannot_tell_that_copy_apart():
    """What the abstract view adds: the exact bodies left vote for no release."""
    releases = _releases()
    per = [(label, *_hashes(files)) for label, files in releases.items()]
    sig = FunctionSignature.build(per)
    renamed = {**releases["3"], "c0.c": _file(0, 3, prefix="vnd_")}
    exact, abstract = _hashes(renamed)
    assert infer_version(sig, exact).best is None
    assert infer_version(sig.abstract_view(), abstract).label == "3"


def test_the_abstract_view_leaves_out_what_segmentation_borrowed():
    sig = FunctionSignature.build([("1", {1, 2}, {10, 20}), ("2", {1, 3}, {10, 30})])
    sig.segment_abstract({30})
    view = sig.abstract_view()
    assert view.version_application_hashes(1) == {10}


def test_an_untouched_copy_is_not_called_renamed(tmp_path):
    # Two pairs of functions differ only in their names, so the release has fewer
    # abstract hashes than exact ones; a copy holding part of it then scores a hair
    # higher on the abstract measure without anything having been renamed.
    twins = "".join(_fn(f"twin{k}{side}", 900 + k, 7, var=f"v{side}")
                    for k in range(2) for side in "ab")
    release = {**{f"c{n}.c": _file(n, 1) for n in range(2)}, "twins.c": twins}
    rules = _rule(tmp_path, {"1": release})
    tree = tmp_path / "fw" / "synth"
    tree.mkdir(parents=True)
    (tree / "c0.c").write_text(release["c0.c"])
    (tree / "c1.c").write_text("".join(_fn(f"fn{50 + i}", 50 + i, 1) for i in range(30)))

    [finding] = _scan(rules, tmp_path / "fw", tmp_path)
    summaries = " ".join(e["summary"] for e in finding["evidence"])
    assert "renamed" not in summaries and "identifier-abstracted" not in summaries
