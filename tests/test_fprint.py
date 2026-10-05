"""Per-function fingerprints: strings and constants resolved out of machine code."""

import shutil
import struct
import subprocess

import pytest
import yaml

from gangmu import disasm, fprint
from gangmu.binaries import collect_binaries
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan

pytestmark = pytest.mark.skipif(not disasm.available(), reason="capstone not installed")

TEXT = b"netx: handshake failed, aborting the connection\0"
RODATA = 0x2000
SHA1_K = 0x5A827999
SHA1_K2 = 0x6ED9EBA1


def _x86() -> bytes:
    lea_end = 0x1000 + 5 + 7
    return (b"\xb8" + struct.pack("<I", SHA1_K)
            + b"\x48\x8d\x3d" + struct.pack("<i", RODATA - lea_end)
            + b"\xba" + struct.pack("<I", SHA1_K2) + b"\xc3")


def _thumb() -> bytes:
    return (struct.pack("<HH", 0xF647, 0x1099) + struct.pack("<HH", 0xF6C5, 0x2082)  # r0 = K
            + struct.pack("<H", 0x4902)                                              # ldr r1,[pc,#8]
            + struct.pack("<HH", 0xF64E, 0x32A1) + struct.pack("<HH", 0xF6C6, 0x62D9)  # r2 = K2
            + struct.pack("<H", 0x4770)                                              # bx lr
            + struct.pack("<I", RODATA))                                             # literal pool


def _riscv() -> bytes:
    return struct.pack("<7I", 0x5A828537, 0x99950513, 0x6ED9F5B7, 0xBA158593,
                       0x00001617, 0xFF060613, 0x00008067)


def _features(arch, code):
    mem = fprint.Memory([(0x1000, code), (RODATA, TEXT)])
    return fprint.function_features(mem, arch, 0x1000, len(code))


def test_the_same_function_fingerprints_alike_on_x86_thumb_and_riscv():
    x86, thumb, riscv = _features("x86-64", _x86()), _features("thumb", _thumb()), \
        _features("riscv32", _riscv())
    assert len(x86) == 3                           # two constants and a string
    assert x86 == thumb == riscv


def test_small_and_common_constants_are_not_features():
    mem = fprint.Memory([(0x1000, b"\xb8\x01\x00\x00\x00\xba\xff\xff\xff\xff\xc3")])
    assert fprint.function_features(mem, "x86-64", 0x1000, 11) == set()


@pytest.fixture(scope="module")
def builds(tmp_path_factory):
    if not shutil.which("gcc"):
        pytest.skip("no gcc")
    tmp = tmp_path_factory.mktemp("fp")

    def build(extra, opt, name):
        src = "#include <stdio.h>\n"
        for i in range(30):
            src += (f'int fn{i}(int x) {{ if (x > {i}) printf("netx: handshake step {i} failed '
                    f'with code %d, aborting", x); return x * 0x{0x5A827999 + i * 7919:X}u '
                    f'^ 0x{0x6ED9EBA1 + i:X}u; }}\n')
        for i in range(extra):
            src += (f'int ex{i}(int x) {{ puts("netx: extra feature {i} enabled in this build"); '
                    f'return (x ^ 0x{0x8F1BBCDC + i * 31:X}u) + 0x{0xCA62C1D6 + i * 17:X}u; }}\n')
        src += ("int main(int c, char **v) { int s = 0;"
                + "".join(f" s += fn{i}(c);" for i in range(30))
                + "".join(f" s += ex{i}(c);" for i in range(extra)) + " return s; }\n")
        (tmp / f"{name}.c").write_text(src)
        subprocess.run(["gcc", opt, "-s", "-o", str(tmp / name), str(tmp / f"{name}.c")], check=True)
        return (tmp / name).read_bytes()

    return {"1.0": build(0, "-O1", "r10"), "1.1": build(8, "-O1", "r11"),
            "img10": build(0, "-O2", "i10"), "img11": build(8, "-O2", "i11"), "dir": tmp}


def _prints(builds):
    return fprint.FunctionPrints.build([(v, fprint.image_function_features(builds[v]))
                                        for v in ("1.0", "1.1")])


def test_a_differently_optimised_image_is_matched_to_its_release(builds):
    prints = _prints(builds)
    for image, expected in (("img10", "1.0"), ("img11", "1.1")):
        version, matched, total, coverage, tied = prints.match(
            fprint.image_function_features(builds[image]))
        assert (version, tied) == (expected, ""), image
        assert coverage > 0.9


def test_unrelated_code_does_not_match(builds):
    prints = _prints(builds)
    other = [{1, 2, 3, 4}, {5, 6, 7}]
    assert prints.match(other) is None


def test_the_sidecar_round_trips(builds, tmp_path):
    prints = _prints(builds)
    prints.write(tmp_path / "x.fnprint")
    again = fprint.FunctionPrints.from_bytes((tmp_path / "x.fnprint").read_bytes())
    assert again.versions == prints.versions and again.functions == prints.functions


def _calibrated(builds):
    from gangmu.calibrate import calibrate
    prints, cal = calibrate({"1.0": {"O1": builds["1.0"], "O2": builds["img10"]},
                             "1.1": {"O1": builds["1.1"], "O2": builds["img11"]}})
    assert cal.passed, cal.reasons
    return prints


def test_a_scan_names_a_stripped_image_from_the_rules_sidecar(builds, tmp_path):
    prints = _calibrated(builds)
    rules = tmp_path / "rules"
    rules.mkdir()
    digest = prints.write(rules / "netx.fnprint")
    (rules / "netx.yaml").write_text(yaml.safe_dump({
        "id": "test/netx",
        "component": {"path_globs": ["**/netx"], "ships_as": "netx"},
        "upstream": {"name": "netx", "purl": "pkg:generic/netx", "license": "MIT",
                     "source": {"kind": "git", "url": "https://example.invalid/netx",
                                "ref": "v1.1"}},
        "identity": {"binary_functions": {"file": "netx.fnprint", "sha256": digest,
                                          "versions": prints.versions,
                                          "calibration": prints.meta}},
    }))
    project = tmp_path / "project" / "out"
    project.mkdir(parents=True)
    (project / "app.elf").write_bytes(builds["img11"])
    result = scan(tmp_path / "project", load_rules(rules, strict=True), None, ScanOptions())
    finding = next(f for f in result.findings if f.rule_id == "binary/netx")
    assert finding.version == "1.1" and finding.purl == "pkg:generic/netx@1.1"
    assert "fingerprinted functions" in finding.evidence[0].summary
    assert "rule self-test" in finding.evidence[0].summary


def test_the_cli_refuses_to_write_fingerprints_that_were_not_tested_across_builds(
        builds, tmp_path, capsys):
    from gangmu.cli import main
    out = tmp_path / "netx.fnprint"
    for name in ("1.0", "1.1"):
        (tmp_path / f"ref-{name}").write_bytes(builds[name])
    code = main(["rules", "binary-prints", "--ref", f"1.0={tmp_path / 'ref-1.0'}",
                 "--ref", f"1.1={tmp_path / 'ref-1.1'}", "--out", str(out)])
    assert code == 1 and not out.exists()
    assert "at least two builds" in capsys.readouterr().err


def test_the_cli_writes_a_sidecar_and_a_calibration_block_when_the_self_test_passes(
        builds, tmp_path, capsys):
    from gangmu.cli import main
    out = tmp_path / "netx.fnprint"
    for key in ("1.0", "1.1", "img10", "img11"):
        (tmp_path / key).write_bytes(builds[key])
    code = main(["rules", "binary-prints",
                 "--ref", f"1.0:O1={tmp_path / '1.0'}", "--ref", f"1.0:O2={tmp_path / 'img10'}",
                 "--ref", f"1.1:O1={tmp_path / '1.1'}", "--ref", f"1.1:O2={tmp_path / 'img11'}",
                 "--out", str(out)])
    assert code == 0
    block = yaml.safe_load(capsys.readouterr().out)["identity"]["binary_functions"]
    assert block["calibration"]["passed"] is True and block["calibration"]["cross_build"]
    assert fprint.FunctionPrints.from_bytes(out.read_bytes()).meta == block["calibration"]


def _aarch64() -> bytes:
    def movz(rd, imm, hw=0):
        return struct.pack("<I", 0x52800000 | hw << 21 | imm << 5 | rd)

    def movk(rd, imm, hw):
        return struct.pack("<I", 0x72800000 | hw << 21 | imm << 5 | rd)

    adrp_x2 = struct.pack("<I", 0x90000000 | 1 << 29 | 0 << 5 | 2)         # page of 0x2000, from 0x1000
    add_x2 = struct.pack("<I", 0x91000000 | 0 << 10 | 2 << 5 | 2)          # + 0
    return (movz(0, 0x7999) + movk(0, 0x5A82, 1) + adrp_x2 + add_x2
            + movz(1, 0xEBA1) + movk(1, 0x6ED9, 1) + struct.pack("<I", 0xD65F03C0))


def test_the_same_function_fingerprints_alike_on_aarch64_too():
    assert _features("aarch64", _aarch64()) == _features("x86-64", _x86())
