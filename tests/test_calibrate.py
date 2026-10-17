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


def _program(tmp, name, own, shared, opt):
    """*own* functions with their own strings, plus *shared* that carry the same code in
    every program (a bundled hash routine)."""
    src = "#include <stdio.h>\n"
    for i in range(shared):
        src += (f'int h{i}(int x) {{ if (x > {i}) printf("hash: block {i} is short"); '
                f'return x * 0x{0x2545F491 + i * 104729:X}u ^ 0x{0x9E3779B1 + i:X}u; }}\n')
    for i in range(own):
        src += (f'int {name}{i}(int x) {{ if (x > {i}) printf("{name}: step {i} failed with '
                f'%d", x); return x * 0x{0x5A827999 + i * 7919 + len(name) * 31:X}u '
                f'^ 0x{0x6ED9EBA1 + i:X}u; }}\n')
    calls = [f"{name}{i}(c)" for i in range(own)] + [f"h{i}(c)" for i in range(shared)]
    src += "int main(int c, char **v) { return " + "+".join(calls) + "; }\n"
    (tmp / f"{name}{opt}.c").write_text(src)
    subprocess.run(["gcc", f"-{opt}", "-o", str(tmp / f"{name}{opt}"), str(tmp / f"{name}{opt}.c")],
                   check=True)
    return (tmp / f"{name}{opt}").read_bytes()


def test_functions_shared_with_a_negative_are_dropped_not_reported_as_the_library(tmp_path):
    builds = {"1.0": {o: _program(tmp_path, "liba", 14, 6, o) for o in ("O1", "O2")},
              "1.1": {o: _program(tmp_path, "libb", 22, 6, o) for o in ("O1", "O2")}}
    other = _program(tmp_path, "app", 10, 6, "O2")        # some other program with the hash
    plain, cal0 = calibrate.calibrate(builds)
    assert cal0.passed and cal0.shared_dropped == 0
    stripped = fprint.image_function_features(other, min_features=1, ignore_symbols=True)
    assert plain.match([s for s in stripped if len(s) >= 2], 2) is not None   # the problem

    prints, cal = calibrate.calibrate(builds, negatives=[other])
    assert cal.passed, cal.reasons
    assert cal.shared_dropped > 0 and prints.meta["shared_dropped"] == cal.shared_dropped
    assert prints.match([s for s in stripped if len(s) >= 2], 2) is None
    own = fprint.image_function_features(builds["1.1"]["O2"], min_features=1, ignore_symbols=True)
    hit = prints.match([s for s in own if len(s) >= 2], 2)
    assert hit is not None and hit[0] == "1.1"


def test_a_negative_that_is_the_library_itself_still_fails_instead_of_erasing_it(two_releases):
    builds, _ = two_releases
    _, cal = calibrate.calibrate(builds, negatives=[builds["1.1"]["O2"]])
    assert cal.shared_dropped == 0 and cal.false_positives > 0 and not cal.passed


# ----------------------------------------------------------- one sidecar per architecture

def _two_arch_rule(tmp, prints, order=("thumb", "x86-64"), arches=None):
    """A rule listing a sidecar for each architecture (the same evidence, labelled twice)."""
    rules = tmp / "rules"
    rules.mkdir(exist_ok=True)
    blocks = []
    for arch in (arches or order):
        other = fprint.FunctionPrints.from_bytes(prints.to_bytes())
        other.arch = arch
        name = f"lib-{len(blocks)}-{arch}.fnprint"
        sha = other.write(rules / name)
        blocks.append({"file": name, "sha256": sha, "versions": prints.versions,
                       "calibration": prints.meta})
    (rules / "lib.yaml").write_text(yaml.safe_dump({
        "id": "test/lib", "component": {"path_globs": ["**/lib"], "ships_as": "lib"},
        "upstream": {"name": "lib", "purl": "pkg:generic/lib", "license": "MIT",
                     "cpe_status": "none-found: test rule",
                     "source": {"kind": "git", "url": "https://example.invalid/lib", "ref": "v1"}},
        "identity": {"binary_functions": blocks}}))
    return rules


def test_a_rule_may_list_one_sidecar_per_architecture(two_releases, tmp_path, capsys):
    from gangmu.cli import main
    builds, _ = two_releases
    prints, _ = calibrate.calibrate(builds)
    rules = _two_arch_rule(tmp_path, prints)
    rule = next(iter(load_rules(rules, strict=True)))
    assert [s.load().arch for s in rule.binary_function_specs()] == ["thumb", "x86-64"]
    assert rule.binary_functions is rule.binary_function_specs()[0]
    assert main(["rules", "lint", "--rules", str(rules)]) == 0


def test_a_single_mapping_still_means_one_sidecar(two_releases, tmp_path):
    builds, _ = two_releases
    prints, cal = calibrate.calibrate(builds)
    rule = next(iter(load_rules(_rule(tmp_path, prints, prints.meta), strict=True)))
    assert len(rule.binary_function_specs()) == 1 and rule.binary_functions_more == ()


def test_lint_refuses_two_sidecars_for_the_same_architecture(two_releases, tmp_path, capsys):
    from gangmu.cli import main
    builds, _ = two_releases
    prints, _ = calibrate.calibrate(builds)
    rules = _two_arch_rule(tmp_path, prints, arches=("thumb", "thumb"))
    assert main(["rules", "lint", "--rules", str(rules)]) == 1
    assert "one sidecar per architecture" in capsys.readouterr().out


class _Sidecar:
    """Just enough of FunctionPrints for binaries._by_functions."""
    meta = {}

    def __init__(self, arch, hit, calls):
        self.arch, self.hit, self.calls, self.versions = arch, hit, calls, ["1", "2"]

    def match(self, image, arch=None):
        self.calls.append(self.arch)
        return self.hit

    def knows_strings(self):
        return False


def _by_functions(monkeypatch, sidecars, image_arch):
    from gangmu import binaries
    monkeypatch.setattr(fprint, "image_features", lambda data: ([{1, 2}], image_arch))
    return binaries._by_functions(b"", [], [("Lib", "lib", s) for s in sidecars])


@pytest.mark.parametrize("listed", [("thumb", "aarch64"), ("aarch64", "thumb")])
def test_the_sidecar_built_for_the_images_cpu_is_tried_first(monkeypatch, listed):
    """Constants differ between CPUs, so a sidecar for another architecture compares strings
    only; whichever order the rule lists them in, the image's own architecture wins."""
    calls = []
    hit = ("2", 9, 10, 0.9, "")
    found = _by_functions(monkeypatch, [_Sidecar(a, hit, calls) for a in listed], "aarch64")
    assert calls == ["aarch64"] and len(found) == 1 and found[0].version == "2"


def test_the_next_sidecar_is_tried_when_the_first_finds_nothing(monkeypatch):
    calls = []
    hit = ("2", 9, 10, 0.9, "")
    found = _by_functions(monkeypatch, [_Sidecar("aarch64", None, calls),
                                        _Sidecar("thumb", hit, calls)], "aarch64")
    assert calls == ["aarch64", "thumb"] and len(found) == 1


def test_one_library_is_reported_once_however_many_sidecars_match(monkeypatch):
    calls = []
    hit = ("2", 9, 10, 0.9, "")
    found = _by_functions(monkeypatch, [_Sidecar("thumb", hit, calls),
                                        _Sidecar("aarch64", hit, calls)], "riscv32")
    assert len(found) == 1 and calls == ["thumb"]


class _CrossSidecar(_Sidecar):
    def __init__(self):
        super().__init__("thumb", ("3.1.0", 20, 40, 0.5, ""), [])
        self.versions = ["2.16.12", "2.28.0", "3.1.0", "3.6.2"]

    def knows_strings(self):
        return True


def test_a_cross_architecture_match_names_the_library_and_every_release_of_the_rule(monkeypatch):
    """Strings from a Thumb reference against a RISC-V image named one wrong release (Mbed TLS
    2.28.2 as 3.1.0, confidence 0.60); only the library is claimed, the version is the rule's
    whole range and the evidence says why."""
    found = _by_functions(monkeypatch, [_CrossSidecar()], "riscv32")
    assert len(found) == 1 and found[0].version == "2.16.12~3.6.2"
    assert "not narrowed" in found[0].banner and "only string literals" in found[0].banner
    assert "3.1.0" not in found[0].banner


def test_the_images_own_architecture_still_names_a_single_release(monkeypatch):
    found = _by_functions(monkeypatch, [_CrossSidecar()], "thumb")
    assert found[0].version == "3.1.0"
