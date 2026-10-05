"""Versions are recovered from the string constants of a compiled image."""

import shutil
import subprocess

import pytest
import yaml

from gangmu.binaries import collect_binaries
from gangmu.binsig import image_strings, match_image, source_literals, tree_strings
from gangmu.fnsig import FunctionSignature
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan

BASE = [f"netx: connection {i} refused by peer, retrying shortly" for i in range(24)]
RELEASES = {
    "1.0.0": BASE,
    "1.1.0": BASE + [f"netx: session ticket {i} expired, renegotiating" for i in range(12)],
    "1.2.0": BASE + [f"netx: session ticket {i} expired, renegotiating" for i in range(12)]
             + [f"netx: keepalive probe {i} timed out after interval" for i in range(12)],
}
DEFAULT = ("**/*.c",)


def _release(root, version):
    d = root / version
    d.mkdir(parents=True)
    body = "".join(f'const char *m{i} = "{s}";\n' for i, s in enumerate(RELEASES[version]))
    (d / "msg.c").write_text(body + 'int netx_run(void) { return 0; }\n')
    return d


def _signature(tmp_path):
    return FunctionSignature.build(
        [(v, tree_strings(_release(tmp_path / "src", v), DEFAULT, ()), set())
         for v in RELEASES])


def test_literals_are_unescaped_and_adjacent_ones_joined():
    src = rb'char *a = "hello, " "world\n"; char *b = "x"; char *c = "tab\there now";'
    assert source_literals(src) == [b"hello, world\n", b"tab\there now"]


def test_a_literal_folded_into_a_longer_string_is_still_found():
    folded = b"\x00" + b"prefix " + b"connection refused by peer" + b"\x00"
    wanted = b"connection refused by peer"
    from gangmu.binsig import _hash
    assert _hash(wanted) in image_strings(folded)


def test_unrelated_text_does_not_match(tmp_path):
    sig = _signature(tmp_path)
    assert match_image(sig, image_strings(b"\x00" + b"completely different text here " * 3)) is None


@pytest.mark.skipif(not shutil.which("gcc"), reason="no gcc")
def test_a_stripped_optimised_image_gives_its_release(tmp_path):
    sig = _signature(tmp_path)
    for version, expected in (("1.0.0", "1.0.0"), ("1.2.0", "1.2.0")):
        out = tmp_path / f"fw-{version}.elf"
        subprocess.run(["gcc", "-O2", "-s", "-o", str(out), "-x", "c",
                        str(tmp_path / "src" / version / "msg.c"), "-x", "c", "-"],
                       input=b"int main(void){return 0;}", check=True)
        label, matched, total, coverage, tied = match_image(sig, image_strings(out.read_bytes()))
        assert label == expected, (version, label)
        assert coverage > 0.5


@pytest.mark.skipif(not shutil.which("gcc"), reason="no gcc")
def test_a_scan_names_a_stripped_image_from_the_rules_sidecar(tmp_path):
    sig = _signature(tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    digest = sig.write(rules / "netx.fnsig")
    (rules / "netx.yaml").write_text(yaml.safe_dump({
        "id": "test/netx",
        "component": {"path_globs": ["**/netx"], "ships_as": "netx"},
        "upstream": {"name": "netx", "purl": "pkg:generic/netx",
                     "license": "MIT",
                     "source": {"kind": "git", "url": "https://example.invalid/netx",
                                "ref": "v1.2.0"}},
        "identity": {"binary_strings": {"file": "netx.fnsig", "sha256": digest,
                                        "versions": list(RELEASES)}},
    }))
    fw = tmp_path / "project" / "out"
    fw.mkdir(parents=True)
    subprocess.run(["gcc", "-O2", "-s", "-o", str(fw / "app.elf"),
                    str(tmp_path / "src" / "1.1.0" / "msg.c"), "-x", "c", "-"],
                   input=b"int main(void){return 0;}", check=True)
    result = scan(tmp_path / "project", load_rules(rules, strict=True), None, ScanOptions())
    finding = next(f for f in result.findings if f.rule_id == "binary/netx")
    assert finding.version == "1.1.0" and finding.purl == "pkg:generic/netx@1.1.0"
    assert finding.directory == "out/app.elf"
    assert "string constants" in finding.evidence[0].summary
