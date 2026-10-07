"""Prebuilt binaries are inventoried and their version banners read."""

import hashlib
from pathlib import Path

from gangmu.binaries import collect_binaries
from gangmu.rules.loader import load_rules
from gangmu.sbom.cyclonedx import to_cyclonedx
from gangmu.sbom.spdx import to_spdx
from gangmu.scan import ScanOptions, scan

OPUS = b"\x00\x01libopus 1.3-fixed\x00xx" + b"\x00" * 8
VORBIS = b"junk\x00Xiph.Org libVorbis 1.3.7\x00"
VENDOR = b"\x00component_version_fhost_1.7.10 b2793912\x00GCC: (Xuantie-900 elf newlib gcc Toolchain V2.6.1) 10.2.0\x00"
PLAIN = b"\x00no banner here\x00"


def _tree(tmp: Path) -> Path:
    for name, data in (("opus/libopus.a", OPUS), ("vorbis/libvorbis.a", VORBIS),
                       ("wifi/libfhost.a", VENDOR), ("misc/libplain.a", PLAIN)):
        path = tmp / "components" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return tmp


def test_every_prebuilt_archive_is_inventoried_with_its_hash(tmp_path):
    blobs = {b.path: b for b in collect_binaries(_tree(tmp_path))}
    assert set(blobs) == {"components/opus/libopus.a", "components/vorbis/libvorbis.a",
                          "components/wifi/libfhost.a", "components/misc/libplain.a"}
    assert blobs["components/misc/libplain.a"].sha256 == hashlib.sha256(PLAIN).hexdigest()
    assert blobs["components/misc/libplain.a"].embedded == []


def test_open_source_banners_are_read(tmp_path):
    blobs = {b.path: b for b in collect_binaries(_tree(tmp_path))}
    opus = blobs["components/opus/libopus.a"].embedded[0]
    assert (opus.name, opus.version) == ("opus", "1.3")
    vorbis = blobs["components/vorbis/libvorbis.a"].embedded[0]
    assert (vorbis.name, vorbis.version) == ("libvorbis", "1.3.7")


def test_a_vendor_component_banner_and_the_toolchain_are_read(tmp_path):
    blob = next(b for b in collect_binaries(_tree(tmp_path)) if b.path.endswith("libfhost.a"))
    assert [(e.name, e.version, e.vendor_component) for e in blob.embedded] == [
        ("fhost", "1.7.10", True)]
    assert blob.toolchain.endswith("10.2.0") and "Xuantie" in blob.toolchain


def test_linked_state_follows_the_link_map_archives(tmp_path):
    _tree(tmp_path)
    blobs = {b.path: b for b in collect_binaries(
        tmp_path, {"/build/sdk/components/opus/libopus.a"})}
    assert blobs["components/opus/libopus.a"].linked is True
    assert blobs["components/misc/libplain.a"].linked is False
    assert all(b.linked is None for b in collect_binaries(tmp_path))


def _scan(tmp, rules_dir, **kw):
    return scan(tmp, load_rules(rules_dir, strict=True), None, ScanOptions(**kw))


def test_an_identified_banner_becomes_a_library_component(tmp_path, rules_dir):
    result = _scan(_tree(tmp_path), rules_dir)
    opus = next(f for f in result.findings if f.upstream_name == "Opus")
    assert opus.version == "1.3" and opus.version_source == "binary-string"
    assert opus.directory == "components/opus/libopus.a"
    assert opus.purl == "pkg:generic/opus@1.3"
    assert opus.content_hash == hashlib.sha256(OPUS).hexdigest()


def test_the_sbom_lists_all_binaries_as_files(tmp_path, rules_dir):
    result = _scan(_tree(tmp_path), rules_dir)
    files = [c for c in to_cyclonedx(result)["components"] if c["type"] == "file"]
    assert len(files) == 4
    plain = next(c for c in files if c["name"].endswith("libplain.a"))
    assert plain["hashes"][0]["content"] == hashlib.sha256(PLAIN).hexdigest()
    assert {"name": "gangmu:sourceAvailable", "value": "false"} in plain["properties"]
    fhost = next(c for c in files if c["name"].endswith("libfhost.a"))
    assert {"name": "gangmu:vendorComponent", "value": "fhost 1.7.10"} in fhost["properties"]
    spdx = to_spdx(result)
    assert sum(1 for p in spdx["packages"] if p.get("checksums")) == 4


def test_an_archive_the_link_map_does_not_name_is_not_a_component(tmp_path, rules_dir):
    from gangmu.build.facts import BuildFacts
    _tree(tmp_path)
    facts = BuildFacts(root=tmp_path, have_link_map=True,
                       linked_archives={"/build/sdk/components/opus/libopus.a"})
    result = scan(tmp_path, load_rules(rules_dir, strict=True), facts, ScanOptions())
    names = {f.upstream_name for f in result.findings}
    assert "Opus" in names and "libvorbis" not in names
    assert len(result.binaries) == 4          # still inventoried, with linked=false
    assert next(b for b in result.binaries if b.path.endswith("libvorbis.a")).linked is False
    assert any("libvorbis.a" in n and "not reported as components" in n for n in result.notes)


def test_binaries_can_be_switched_off(tmp_path, rules_dir):
    result = _scan(_tree(tmp_path), rules_dir, binaries=False)
    assert result.binaries == [] and not result.findings


def _symbols(*names):
    return b"\x00" + b"\x00".join(n.encode() for n in names) + b"\x00"


OGG_API = ("ogg_stream_init ogg_stream_clear ogg_stream_packetin ogg_stream_pageout "
           "ogg_stream_pagein ogg_stream_packetout ogg_stream_flush ogg_sync_init "
           "ogg_sync_buffer ogg_sync_wrote ogg_sync_pageout ogg_sync_pageseek "
           "ogg_page_serialno ogg_page_granulepos ogg_page_checksum_set").split()


def test_an_exported_api_names_the_library_without_a_version(tmp_path):
    (tmp_path / "libogg.a").write_bytes(_symbols(*OGG_API))
    (tmp_path / "libother.a").write_bytes(_symbols(*OGG_API[:6]))     # a few calls: not enough
    (tmp_path / "libsub.a").write_bytes(b"\x00xogg_stream_init\x00" * 3)  # not whole names
    blobs = {b.path: b for b in collect_binaries(tmp_path)}
    emb = blobs["libogg.a"].embedded
    assert [(e.name, e.version) for e in emb] == [("libogg", "")]
    assert blobs["libother.a"].embedded == [] and blobs["libsub.a"].embedded == []


def test_a_banner_wins_over_symbols_and_a_symbol_finding_has_no_version(tmp_path, rules_dir):
    (tmp_path / "libogg.a").write_bytes(_symbols(*OGG_API))
    result = _scan(tmp_path, rules_dir)
    ogg = next(f for f in result.findings if f.rule_id == "binary/libogg")
    assert ogg.version is None and ogg.version_source == "unknown"
    assert ogg.purl == "pkg:generic/libogg" and ogg.identity_confidence < 0.7
    assert ogg.version_confidence == 0.0
    props = {p["value"] for c in to_cyclonedx(result)["components"]
             for p in c.get("properties", []) if p["name"] == "gangmu:embeddedLibrary"}
    assert props == {"libogg"}


def test_a_vendor_wrapper_version_stamp_is_not_an_upstream_version(tmp_path):
    # Bouffalo's version_speex.h / version_sonic.h stamp the SDK component, not the library.
    (tmp_path / "libwrap.a").write_bytes(b"\x00speex_v1.2.1\x00sonic_v1.2.1\x00")
    (tmp_path / "libup.a").write_bytes(b"\x00speex-1.2.1\x00")
    blobs = {b.path: b for b in collect_binaries(tmp_path)}
    assert blobs["libwrap.a"].embedded == []
    assert [(e.name, e.version) for e in blobs["libup.a"].embedded] == [("speex", "1.2.1")]


def test_firmware_images_are_read_like_archives(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "app.bin").write_bytes(b"\x00" * 64 + OPUS + VENDOR)
    (tmp_path / "out" / "app.elf").write_bytes(PLAIN)
    blobs = {b.path: b for b in collect_binaries(tmp_path, {"/b/out/app.bin"})}
    app = blobs["out/app.bin"]
    assert app.kind == "firmware-image" and app.linked is None
    assert {(e.name, e.version) for e in app.embedded} == {("opus", "1.3"), ("fhost", "1.7.10")}
    assert blobs["out/app.elf"].embedded == []


def _elf(tmp, strip):
    import shutil, subprocess
    if not shutil.which("gcc"):
        import pytest
        pytest.skip("no gcc")
    names = ["sonicCreateStream", "sonicDestroyStream", "sonicFlushStream", "sonicSetSpeed",
             "sonicSetPitch", "sonicSetRate", "sonicSetVolume", "sonicSetChordPitch",
             "sonicWriteShortToStream", "sonicReadShortFromStream", "sonicWriteFloatToStream",
             "sonicReadFloatFromStream"]
    (tmp / "a.c").write_text("".join(f"int {n}(void){{return 1;}}\n" for n in names)
                             + "int main(void){return 0;}\n")
    out = tmp / "out" / "fw.elf"
    out.parent.mkdir()
    subprocess.run(["gcc", "-o", str(out), str(tmp / "a.c")] + (["-s"] if strip else []),
                   check=True)
    (tmp / "a.c").unlink()
    return tmp


def test_elf_symbol_table_names_a_library_and_strippedness_is_recorded(tmp_path):
    blob = collect_binaries(_elf(tmp_path, strip=False))[0]
    assert blob.stripped is False and blob.symbols >= 12
    assert [e.name for e in blob.embedded] == ["sonic"]
    assert blob.toolchain


def test_a_stripped_elf_is_reported_as_stripped(tmp_path):
    blob = collect_binaries(_elf(tmp_path, strip=True))[0]
    assert blob.stripped is True and blob.embedded == []


def test_a_malformed_elf_does_not_raise(tmp_path):
    (tmp_path / "bad.elf").write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 100)
    blob = collect_binaries(tmp_path)[0]
    assert blob.kind == "firmware-image"


def test_images_in_test_fixture_directories_are_not_inventoried(tmp_path):
    # lwIP keeps fuzz inputs as .bin files under test/fuzz/inputs; they are packets, not firmware.
    for rel in ("lwip/test/fuzz/inputs/arp_req.bin", "lib/tests/data/blob.elf",
                "lib/fixtures/image.axf"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x00\x01\x02\x03")
    assert collect_binaries(tmp_path) == []


def test_images_outside_test_directories_and_libraries_inside_them_still_count(tmp_path):
    for rel, data in (("out/app.bin", b"\x00\x01\x02\x03"), ("tests/libkept.a", PLAIN)):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    assert {b.path for b in collect_binaries(tmp_path)} == {"out/app.bin", "tests/libkept.a"}
