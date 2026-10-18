"""Components copied in as loose files among the project's own."""

import json

from gangmu.cli import main
from gangmu.fnsig import FunctionSignature
from gangmu.functions import function_hashes


def _fn(i, variant=1):
    return (f"int fn{i}(int x) {{ int y = x * {i} + {variant}; "
            f"while (y > {i}) {{ y -= 3; }} if (y % 5 == {i % 5}) {{ y ^= {i}; }} "
            f"return y + x; }}\n")


def _code(start, count, variant=1):
    return "".join(_fn(start + i, variant) for i in range(count))


def _rule(rules, name, files, subset=True, versions=("1", "2")):
    """A rule whose last release holds *files* (name -> text); the ones before it
    lack one of their functions."""
    hashes = set()
    for text in files.values():
        hashes |= function_hashes(text.encode())
    older = hashes - {min(hashes)}
    rules.mkdir(parents=True, exist_ok=True)
    digest = FunctionSignature.build(
        [(v, older if v != versions[-1] else hashes, set()) for v in versions]).write(
        rules / f"{name}.fnsig")
    (rules / f"{name}.yaml").write_text(f"""id: test/{name}
component:
  path_globs:
  - '**/{name}'
  ships_as: {name}
upstream:
  name: {name}
  purl: pkg:generic/{name}
  cpe_status: 'none-in-nvd: test fixture'
  source: {{kind: git, url: 'https://example.invalid/{name}', ref: v2}}
identity:
  include: ['**/*.c', '**/*.h']
  functions:
    file: {name}.fnsig
    sha256: {digest}
    count: 0
    versions: {list(versions)}
{'    subset: true' if subset else ''}
""")


def _tree(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _scan(rules, tree, tmp_path, *extra):
    out = tmp_path / "out.json"
    assert main(["scan", str(tree), "--rules", str(rules), "--format", "json",
                 "-o", str(out), *extra]) == 0
    return json.loads(out.read_text())


APP = {"app/main.c": "int main(void) { return run(); }\n" + _code(5000, 12, 3),
       "app/board.h": "#define LED 3\n", "app/net/net.c": _code(6000, 9, 3)}


def test_a_small_library_dropped_among_the_application_files_is_found(tmp_path):
    lib = {"tinylib.c": _code(100, 9), "tinylib_util.c": _code(200, 3)}
    _rule(tmp_path / "rules", "tinylib", lib)
    tree = tmp_path / "tree"
    _tree(tree, {**APP, **{f"app/{n}": t for n, t in lib.items()},
                 "app/tinylib.h": "int fn100(int);\n", "app/tinylib_opts.h": "#define X 1\n"})
    data = _scan(tmp_path / "rules", tree, tmp_path)
    assert [(f["rule_id"], f["directory"]) for f in data["findings"]] == [("test/tinylib", "app")]
    found = data["findings"][0]
    assert found["files"] == ["app/tinylib.c", "app/tinylib.h", "app/tinylib_opts.h",
                              "app/tinylib_util.c"]
    assert found["version"] == "2"
    assert "copied in among" in found["evidence"][0]["summary"]

    assert main(["scan", str(tree), "--rules", str(tmp_path / "rules"), "--format",
                 "cyclonedx", "-o", str(tmp_path / "bom.json")]) == 0
    bom = json.loads((tmp_path / "bom.json").read_text())
    comp = next(c for c in bom["components"] if c["name"] == "tinylib")
    assert [o["location"] for o in comp["evidence"]["occurrences"]] == found["files"]


def test_no_loose_leaves_them_unfound(tmp_path):
    lib = {"tinylib.c": _code(100, 12)}
    _rule(tmp_path / "rules", "tinylib", lib)
    tree = tmp_path / "tree"
    _tree(tree, {**APP, "app/tinylib.c": lib["tinylib.c"]})
    assert _scan(tmp_path / "rules", tree, tmp_path, "--no-loose")["findings"] == []


def test_a_few_shared_functions_under_another_name_are_a_coincidence(tmp_path):
    # Twelve of the library's functions in a file named for something else: below
    # the count at which unnamed code is believed.
    _rule(tmp_path / "rules", "tinylib", {"tinylib.c": _code(100, 12)})
    tree = tmp_path / "tree"
    _tree(tree, {**APP, "app/helpers.c": _code(100, 12)})
    assert _scan(tmp_path / "rules", tree, tmp_path)["findings"] == []


def test_a_project_file_sharing_one_function_does_not_join(tmp_path):
    lib = {"tinylib.c": _code(100, 12)}
    _rule(tmp_path / "rules", "tinylib", lib)
    tree = tmp_path / "tree"
    _tree(tree, {**APP, "app/tinylib.c": lib["tinylib.c"],
                 "app/glue.c": _fn(100)})            # one function, all of it the library's
    found = _scan(tmp_path / "rules", tree, tmp_path)["findings"]
    assert found[0]["files"] == ["app/tinylib.c"]


def test_a_flat_directory_found_as_one_component_is_narrowed_to_its_files(tmp_path):
    big = {"bigcomp.c": _code(1000, 30)}
    small = {"tinylib.c": _code(100, 10)}
    _rule(tmp_path / "rules", "bigcomp", big, subset=False)
    _rule(tmp_path / "rules", "tinylib", small)
    tree = tmp_path / "tree"
    # bigcomp/ is where its rule says it lives, so the directory is matched as a
    # whole -- but most of what is in it is the project's own, and tinylib's.
    _tree(tree, {"bigcomp/bigcomp.c": big["bigcomp.c"], "bigcomp/tinylib.c": small["tinylib.c"],
                 "bigcomp/main.c": _code(5000, 40, 3)})
    found = {f["rule_id"]: f for f in _scan(tmp_path / "rules", tree, tmp_path)["findings"]}
    assert found["test/bigcomp"]["files"] == ["bigcomp/bigcomp.c"]
    assert found["test/tinylib"]["files"] == ["bigcomp/tinylib.c"]
    assert found["test/bigcomp"]["alternatives"] == []


def test_a_component_directory_keeps_its_own_unrecognised_files(tmp_path):
    big = {"bigcomp.c": _code(1000, 30)}
    _rule(tmp_path / "rules", "bigcomp", big, subset=False)
    tree = tmp_path / "tree"
    # a vendor port beside the component's code: smaller than it, so the
    # directory is still the component
    _tree(tree, {"bigcomp/bigcomp.c": big["bigcomp.c"], "bigcomp/port.c": _code(7000, 6, 3)})
    found = _scan(tmp_path / "rules", tree, tmp_path)["findings"]
    assert [(f["directory"], f["files"]) for f in found] == [("bigcomp", [])]


def test_files_two_rules_want_go_to_the_one_their_names_name(tmp_path):
    code = _code(100, 45)
    _rule(tmp_path / "rules", "tinylib", {"tinylib.c": code})
    # a bundle holding tinylib and code of its own, which tinylib's own files
    # must not be reported as
    _rule(tmp_path / "rules", "bundle", {"x.c": code + _code(300, 40)})
    tree = tmp_path / "tree"
    _tree(tree, {**APP, "app/tinylib.c": code})
    found = _scan(tmp_path / "rules", tree, tmp_path, "--include-possible")["findings"]
    assert "test/bundle" not in [f["rule_id"] for f in found]


def test_a_component_tree_is_never_narrowed_to_files(tmp_path):
    big = {"src/core.c": _code(1000, 30)}
    _rule(tmp_path / "rules", "bigcomp", big, subset=False)
    tree = tmp_path / "tree"
    # the upstream repository itself, with more code in its contrib/ than in src/
    _tree(tree, {"bigcomp/src/core.c": big["src/core.c"], "bigcomp/contrib/apps.c": _code(7000, 45, 3)})
    found = _scan(tmp_path / "rules", tree, tmp_path)["findings"]
    assert [(f["directory"], f["files"]) for f in found] == [("bigcomp", [])]


def test_files_beside_the_directory_it_was_found_at_are_the_same_copy(tmp_path):
    lib = {"tinylib.c": _code(100, 45), "tinylib_sys.c": _code(200, 9)}
    _rule(tmp_path / "rules", "tinylib", lib)
    tree = tmp_path / "tree"
    # found at src/tinylib (where its rule says); its ports sit in the sibling src/system
    _tree(tree, {**APP, "lib/tl/src/tinylib/tinylib.c": lib["tinylib.c"],
                 "lib/tl/src/system/tinylib_sys.c": lib["tinylib_sys.c"]})
    data = _scan(tmp_path / "rules", tree, tmp_path)
    assert [(f["directory"], f["files"]) for f in data["findings"]] == [("lib/tl/src/tinylib", [])]
    assert any("more of its files beside it, in lib/tl/src/system" in e["summary"]
               for e in data["findings"][0]["evidence"])
    assert data["unknown"] == []
