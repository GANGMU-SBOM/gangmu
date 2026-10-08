"""A rule author's fingerprints are tested before they can ship."""

import shutil
import struct
import subprocess

import pytest
import yaml

from gangmu import calibrate, disasm, fprint
from gangmu.rules.loader import load_rules
from gangmu.rules.schema import RuleError

pytestmark = pytest.mark.skipif(not disasm.available() or not shutil.which("gcc"),
                                reason="capstone or gcc missing")


def _build(tmp, name, functions, opt):
    src = "#include <stdio.h>\n"
    for i in range(functions):
        src += (f'int f{i}(int x) {{ if (x > {i}) printf("lib: step {i} failed with code %d and '
                f'gave up", x); return x * 0x{0x5A827999 + i * 7919:X}u ^ 0x{0x6ED9EBA1 + i:X}u; }}\n')
    src += "int main(int c, char **v) { return " + "+".join(f"f{i}(c)" for i in range(functions)) + "; }\n"
    (tmp / f"{name}.c").write_text(src)
    subprocess.run(["gcc", opt, "-o", str(tmp / name), str(tmp / f"{name}.c")], check=True)
    return (tmp / name).read_bytes()


@pytest.fixture(scope="module")
def two_releases(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("cal")
    return {"1.0": {"O1": _build(tmp, "a1", 20, "-O1"), "O2": _build(tmp, "a2", 20, "-O2")},
            "1.1": {"O1": _build(tmp, "b1", 32, "-O1"), "O2": _build(tmp, "b2", 32, "-O2")}}, tmp


def test_two_builds_of_two_releases_pass(two_releases):
    builds, _ = two_releases
    prints, cal = calibrate.calibrate(builds)
    assert cal.passed, cal.reasons
    assert cal.cross_build["wrong"] == 0 and cal.cross_build["none"] == 0
    assert prints.meta["passed"] is True and prints.meta["builds_per_release"] == 2


def test_one_build_per_release_cannot_be_tested_and_fails(two_releases):
    builds, _ = two_releases
    _, cal = calibrate.calibrate({v: {"O1": b["O1"]} for v, b in builds.items()})
    assert not cal.passed and any("at least two builds" in r for r in cal.reasons)


def test_too_few_fingerprintable_functions_fails(tmp_path):
    tiny = {v: {o: _build(tmp_path, f"t{v}{o}", 3, f"-{o}") for o in ("O1", "O2")}
            for v in ("1.0", "1.1")}
    _, cal = calibrate.calibrate(tiny)
    assert not cal.passed and any("fingerprintable" in r for r in cal.reasons)


def test_a_negative_control_that_matches_fails(two_releases):
    builds, _ = two_releases
    _, cal = calibrate.calibrate(builds, negatives=[builds["1.1"]["O2"]])
    assert cal.false_positives > 0 and not cal.passed
    assert any("negative-control" in r for r in cal.reasons)


def test_unrelated_firmware_as_a_negative_control_passes(two_releases, tmp_path):
    builds, _ = two_releases
    # different strings and different constants: nothing to match
    src = ('#include <stdio.h>\nint g(int x){ puts("completely unrelated banner text here");'
           ' return x ^ 0x13572468u ^ 0x24681357u; }\nint main(void){ return g(1); }\n')
    (tmp_path / "u.c").write_text(src)
    subprocess.run(["gcc", "-O2", "-o", str(tmp_path / "u"), str(tmp_path / "u.c")], check=True)
    _, cal = calibrate.calibrate(builds, negatives=[(tmp_path / "u").read_bytes()])
    assert cal.false_positives == 0 and cal.negative_pairs > 0 and cal.passed, cal.reasons


def _old_sidecar(prints, fmt):
    """The layout before the architecture and string counts were recorded."""
    import struct
    out = bytearray(b"GMFP" + bytes([fmt]) + struct.pack("<H", len(prints.versions)))
    for v in prints.versions:
        out += struct.pack("<H", len(v)) + v.encode()
    out += struct.pack("<I", len(prints.functions))
    for bits, feats in prints.functions:
        out += struct.pack("<QH", bits, len(feats)) + struct.pack(f"<{len(feats)}Q", *feats)
    if fmt >= 2:
        out += struct.pack("<I", 2) + b"{}"
    return bytes(out)


def test_older_sidecars_are_still_read():
    prints = fprint.FunctionPrints.build([("1", [{1, 2, 3}]), ("2", [{4, 5, 6}])])
    for fmt in (1, 2):
        again = fprint.FunctionPrints.from_bytes(_old_sidecar(prints, fmt))
        assert again.versions == ["1", "2"] and again.meta == {} and again.functions == prints.functions
        assert again.arch == "" and not again.knows_strings()


def _rule(tmp, prints, calibration, digest=None):
    rules = tmp / "rules"
    rules.mkdir(exist_ok=True)
    sha = prints.write(rules / "lib.fnprint") if digest is None else digest
    block = {"file": "lib.fnprint", "sha256": sha, "versions": prints.versions}
    if calibration is not None:
        block["calibration"] = calibration
    (rules / "lib.yaml").write_text(yaml.safe_dump({
        "id": "test/lib", "component": {"path_globs": ["**/lib"], "ships_as": "lib"},
        "upstream": {"name": "lib", "purl": "pkg:generic/lib", "license": "MIT",
                     "source": {"kind": "git", "url": "https://example.invalid/lib", "ref": "v1"}},
        "identity": {"binary_functions": block}}))
    return rules


def test_a_rule_without_a_calibration_block_is_refused(two_releases, tmp_path):
    prints, _ = calibrate.calibrate(two_releases[0])
    with pytest.raises(RuleError, match="calibration"):
        load_rules(_rule(tmp_path, prints, None), strict=True)


def test_a_rule_whose_self_test_failed_is_refused(two_releases, tmp_path):
    prints, _ = calibrate.calibrate(two_releases[0])
    with pytest.raises(RuleError, match="calibration"):
        load_rules(_rule(tmp_path, prints, dict(prints.meta, passed=False)), strict=True)


def test_a_calibration_block_that_disagrees_with_the_sidecar_is_refused(two_releases, tmp_path):
    prints, _ = calibrate.calibrate(two_releases[0])
    forged = dict(prints.meta, false_positives=0, fingerprintable=prints.meta["fingerprintable"] + 50)
    rules = load_rules(_rule(tmp_path, prints, forged), strict=True)
    with pytest.raises(RuleError, match="does not match"):
        next(iter(rules)).binary_functions.load()


def test_lint_reports_a_rule_whose_calibration_does_not_match(two_releases, tmp_path, capsys):
    from gangmu.cli import main
    prints, _ = calibrate.calibrate(two_releases[0])
    rules = _rule(tmp_path, prints, dict(prints.meta, fingerprintable=1))
    assert main(["rules", "lint", "--rules", str(rules)]) == 1
    assert "does not match" in capsys.readouterr().out


def test_lint_accepts_a_consistent_rule(two_releases, tmp_path, capsys):
    from gangmu.cli import main
    prints, _ = calibrate.calibrate(two_releases[0])
    main(["rules", "lint", "--rules", str(_rule(tmp_path, prints, prints.meta))])
    out = capsys.readouterr().out
    assert "ok   test/lib" in out and "FAIL" not in out
