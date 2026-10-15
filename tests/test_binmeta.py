"""Dependency lists that Go and Rust toolchains write into their binaries."""

import json
import os
import shutil
import subprocess
import zlib

import pytest
from pebuild import build_pe, cargo_blob, go_buildinfo_blob

from gangmu.binaries import collect_binaries
from gangmu.binmeta import cargo_auditable, go_buildinfo
from gangmu.elf import parse_elf
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.scan import ScanOptions, scan
from gangmu.rules.loader import load_rules

MODINFO = (
    "path\texample.com/app/cmd\n"
    "mod\texample.com/app\t(devel)\t\n"
    "dep\tgithub.com/Google/UUID\tv1.6.0\th1:abc=\n"
    "dep\tgolang.org/x/text\tv0.21.0\th1:def=\n"
    "dep\texample.com/local\tv0.0.0-00010101000000-000000000000\t\n"
    "=>\t./local\t(devel)\t\n"
    "build\t-buildmode=exe\n"
    "build\tGOOS=windows\n"
    "build\t-ldflags=-s -w\n")


# -- Go -------------------------------------------------------------------------------------

def test_go_build_info_is_decoded_from_the_inline_layout():
    blob = b"\0" * 37 + go_buildinfo_blob("go1.24.7", MODINFO) + b"\0" * 9
    info = go_buildinfo(blob)
    assert info.go_version == "go1.24.7" and info.path == "example.com/app/cmd"
    assert [(m.path, m.version, m.main) for m in info.modules] == [
        ("example.com/app", "(devel)", True),
        ("github.com/Google/UUID", "v1.6.0", False),
        ("golang.org/x/text", "v0.21.0", False),
        ("example.com/local", "v0.0.0-00010101000000-000000000000", False)]
    assert info.modules[1].sum == "h1:abc="
    assert info.modules[3].replaced_by == "./local"
    assert info.settings["GOOS"] == "windows" and info.settings["-ldflags"] == "-s -w"
    assert [m.path for m in info.dependencies] == [
        "github.com/Google/UUID", "golang.org/x/text", "example.com/local"]


def test_go_blob_longer_than_one_varint_byte_is_decoded():
    long_mod = "path\tp\n" + "".join(f"dep\tm{i}.example/x\tv1.0.{i}\th1:z=\n" for i in range(40))
    info = go_buildinfo(go_buildinfo_blob("go1.22.1", long_mod))
    assert len(info.dependencies) == 40 and info.dependencies[39].version == "v1.0.39"


def test_the_older_pointer_layout_and_garbage_are_not_guessed():
    assert go_buildinfo(go_buildinfo_blob("go1.17", MODINFO, flags=0)) is None
    assert go_buildinfo(b"") is None
    assert go_buildinfo(b"\xff Go buildinf:" + b"\0" * 40) is None
    assert go_buildinfo(go_buildinfo_blob("go1.24.7", MODINFO, ptr=3)) is None
    assert go_buildinfo(go_buildinfo_blob("notgo", MODINFO)) is None
    # Cut off inside the module table: the toolchain is known, the dependencies are not, and
    # the result must say so rather than read as "no dependencies".
    cut = go_buildinfo(go_buildinfo_blob("go1.24.7", MODINFO)[:50])
    assert cut.go_version == "go1.24.7" and cut.has_modules is False and cut.modules == []


def test_a_stray_magic_does_not_hide_the_real_blob():
    real = go_buildinfo_blob("go1.24.7", MODINFO)
    data = b"\xff Go buildinf:" + b"\x07" * 5 + b"\0" * 64 + real
    assert go_buildinfo(data).go_version == "go1.24.7"


def test_a_binary_without_module_info_still_names_its_toolchain():
    info = go_buildinfo(go_buildinfo_blob("go1.21.0", "not a module table"))
    assert info.go_version == "go1.21.0" and info.modules == [] and info.has_modules is False
    assert go_buildinfo(go_buildinfo_blob("go1.24.7", MODINFO)).has_modules is True


# -- Rust -----------------------------------------------------------------------------------

PACKAGES = [
    {"name": "itoa", "version": "1.0.11", "source": "crates.io"},
    {"name": "rshello", "version": "0.3.1", "source": "local", "dependencies": [0, 2],
     "root": True},
    {"name": "smallvec", "version": "1.13.2", "source": "crates.io"},
    {"name": "cc", "version": "1.0.0", "source": "crates.io", "kind": "build"},
]


def test_cargo_auditable_data_is_decoded():
    crates = cargo_auditable(cargo_blob(PACKAGES))
    assert [(c.name, c.version, c.source, c.kind, c.root) for c in crates] == [
        ("itoa", "1.0.11", "crates.io", "", False),
        ("rshello", "0.3.1", "local", "", True),
        ("smallvec", "1.13.2", "crates.io", "", False),
        ("cc", "1.0.0", "crates.io", "build", False)]


def test_cargo_auditable_rejects_what_is_not_its_format():
    assert cargo_auditable(b"") is None
    assert cargo_auditable(b"not zlib") is None
    assert cargo_auditable(zlib.compress(b"not json")) is None
    assert cargo_auditable(zlib.compress(b'{"packages": 3}')) is None
    assert cargo_auditable(zlib.compress(json.dumps({"packages": [1, {"x": 1}]}).encode())) == []


def test_a_decompression_bomb_is_cut_off():
    bomb = zlib.compress(b" " * (40 * 1024 * 1024))
    assert cargo_auditable(bomb) is None                  # over the cap: not decoded, no crash


# -- the inventory and the SBOM -------------------------------------------------------------

def test_a_pe_carries_its_go_dependencies_into_the_inventory(tmp_path):
    (tmp_path / "app.exe").write_bytes(build_pe(extra=[(".data", go_buildinfo_blob("go1.24.7", MODINFO))]))
    blob = collect_binaries(tmp_path)[0]
    by_name = {e.name: e for e in blob.embedded}
    assert blob.runtime == "go go1.24.7"
    assert blob.product == {"name": "example.com/app", "version": "(devel)"}
    assert by_name["stdlib"].purl == "pkg:golang/stdlib@1.24.7"
    assert by_name["stdlib"].cpe == "cpe:2.3:a:golang:go:1.24.7:*:*:*:*:*:*:*"
    uuid = by_name["github.com/Google/UUID"]
    assert uuid.purl == "pkg:golang/github.com/google/uuid@v1.6.0" and uuid.method == "go-buildinfo"
    assert uuid.modified is False and by_name["example.com/local"].modified is True
    assert "example.com/app" not in by_name              # the main module is the product


def test_a_pe_carries_its_rust_dependencies_into_the_inventory(tmp_path):
    (tmp_path / "app.exe").write_bytes(build_pe(extra=[(".dep-v0", cargo_blob(PACKAGES))]))
    blob = collect_binaries(tmp_path)[0]
    assert [(e.name, e.version, e.purl) for e in blob.embedded] == [
        ("itoa", "1.0.11", "pkg:cargo/itoa@1.0.11"),
        ("smallvec", "1.13.2", "pkg:cargo/smallvec@1.13.2")]       # no root, no build-only crate
    assert blob.runtime == "rust" and blob.product == {"name": "rshello", "version": "0.3.1"}


def test_findings_from_a_dependency_list_are_exact_and_flag_a_replace(tmp_path, rules_dir):
    (tmp_path / "app.exe").write_bytes(build_pe(extra=[(".data", go_buildinfo_blob("go1.24.7", MODINFO))]))
    result = scan(tmp_path, load_rules(rules_dir, strict=True), None, ScanOptions())
    by_name = {f.upstream_name: f for f in result.findings}
    uuid = by_name["github.com/Google/UUID"]
    assert (uuid.version, uuid.version_source) == ("v1.6.0", "binary-metadata")
    assert uuid.identity_confidence == uuid.version_confidence == 0.9
    assert uuid.purl == "pkg:golang/github.com/google/uuid@v1.6.0" and not uuid.vendor_patched
    local = by_name["example.com/local"]
    assert local.vendor_patched and local.patch_hint == "go.mod replace directive"
    assert "replace directive" in local.evidence[0].summary
    assert by_name["Go standard library"].cpe == "cpe:2.3:a:golang:go:1.24.7:*:*:*:*:*:*:*"
    comps = {c["name"]: c for c in to_cyclonedx(result)["components"]}
    assert comps["golang.org/x/text"]["purl"] == "pkg:golang/golang.org/x/text@v0.21.0"


# -- against the real toolchains ------------------------------------------------------------

def _go_env():
    return {**os.environ, "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod", "GOPROXY": "off",
            "GOWORK": "off", "CGO_ENABLED": "0"}


@pytest.mark.skipif(not shutil.which("go"), reason="needs the Go toolchain")
@pytest.mark.parametrize("goos", ["windows", "linux"])
def test_the_reader_agrees_with_go_version_m(tmp_path, goos):
    """`go version -m` is the reference reader; ours must report exactly what it does."""
    (tmp_path / "dep").mkdir()
    (tmp_path / "dep" / "go.mod").write_text("module example.com/dep\n\ngo 1.20\n")
    (tmp_path / "dep" / "dep.go").write_text("package dep\n\nfunc Name() string { return \"d\" }\n")
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.20\n\n"
        "require example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n")
    (tmp_path / "main.go").write_text(
        "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/dep\"\n)\n\n"
        "func main() { fmt.Println(dep.Name()) }\n")
    out = tmp_path / ("app.exe" if goos == "windows" else "app.elf")
    build = subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(out), "."],
                           cwd=tmp_path, env={**_go_env(), "GOOS": goos, "GOARCH": "amd64"},
                           capture_output=True, text=True)
    if build.returncode != 0:
        pytest.skip(f"could not build: {build.stderr.strip()[:200]}")
    ref = subprocess.run(["go", "version", "-m", str(out)], env=_go_env(),
                         capture_output=True, text=True).stdout.splitlines()
    rows = [line.strip().split("\t") for line in ref[1:]]
    ours = go_buildinfo(out.read_bytes())
    assert ours.go_version == ref[0].split(": ", 1)[1]
    assert [r[1] for r in rows if r[0] == "path"] == [ours.path]
    assert [(r[1], r[2]) for r in rows if r[0] == "dep"] == [(m.path, m.version) for m in ours.dependencies]
    assert [r[1] for r in rows if r[0] == "=>"] == [
        m.replaced_by.split()[0] for m in ours.dependencies if m.replaced_by]
    assert dict(r[1].split("=", 1) for r in rows if r[0] == "build" and "=" in r[1]) == ours.settings
    blob = collect_binaries(tmp_path)[0]
    assert any(e.name == "example.com/dep" and e.modified for e in blob.embedded)


@pytest.mark.skipif(not shutil.which("cargo-auditable") or not shutil.which("cargo"),
                    reason="needs cargo-auditable")
def test_the_reader_agrees_with_a_real_cargo_auditable_build(tmp_path):
    (tmp_path / "util").mkdir()
    (tmp_path / "util" / "Cargo.toml").write_text(
        '[package]\nname = "util"\nversion = "0.2.0"\nedition = "2021"\n')
    (tmp_path / "util" / "src").mkdir()
    (tmp_path / "util" / "src" / "lib.rs").write_text("pub fn one() -> u8 { 1 }\n")
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "rsapp"\nversion = "0.3.1"\nedition = "2021"\n\n'
        '[dependencies]\nutil = { path = "util" }\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text("fn main() { println!(\"{}\", util::one()); }\n")
    build = subprocess.run(["cargo", "auditable", "build", "--release", "--offline"],
                           cwd=tmp_path, capture_output=True, text=True)
    if build.returncode != 0:
        pytest.skip(f"could not build: {build.stderr.strip()[:200]}")
    data = (tmp_path / "target" / "release" / "rsapp").read_bytes()
    section = next(s for s in parse_elf(data).sections if s.name == ".dep-v0")
    crates = cargo_auditable(data[section.offset:section.offset + section.size])
    assert {(c.name, c.version, c.root) for c in crates} == {("rsapp", "0.3.1", True),
                                                             ("util", "0.2.0", False)}
    shutil.rmtree(tmp_path / "target")
    (tmp_path / "rsapp.elf").write_bytes(data)
    blob = collect_binaries(tmp_path)[0]
    assert blob.runtime == "rust" and blob.product["name"] == "rsapp"
