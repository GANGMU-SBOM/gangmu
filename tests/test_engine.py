import re
import shutil
from pathlib import Path

from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan


def _scan(project, rules_dir, **kw):
    base = load_rules(rules_dir, strict=True)
    return scan(project, base, None, ScanOptions(**kw))


def test_a_vendored_fork_is_identified(project_dir, rules_dir):
    result = _scan(project_dir, rules_dir)
    names = {f.upstream_name for f in result.findings}
    assert "tinynet" in names


def test_version_comes_from_the_probe_not_from_similarity(project_dir, rules_dir):
    result = _scan(project_dir, rules_dir)
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    assert finding.version == "1.4.2"
    assert finding.version_source in ("probe", "anchor")


def test_the_fork_is_flagged_as_vendor_modified(project_dir, rules_dir):
    """The fixture copy is reformatted and has an extra function, so its files
    cannot hash to upstream -- the SBOM must say so rather than claim upstream."""
    result = _scan(project_dir, rules_dir)
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    assert finding.vendor_patched is True
    assert finding.identity_confidence >= 0.75


def test_evidence_is_attached_and_re_checkable(project_dir, rules_dir):
    result = _scan(project_dir, rules_dir)
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    techniques = {e.technique.value for e in finding.evidence}
    assert "ast-fingerprint" in techniques
    assert all(e.locator for e in finding.evidence if e.locator is not None)


def test_pristine_upstream_scores_higher_than_the_fork(upstream_dir, rules_dir, tmp_path):
    pristine = tmp_path / "pristine" / "components" / "tinynet"
    pristine.parent.mkdir(parents=True)
    shutil.copytree(upstream_dir, pristine)
    result = _scan(tmp_path / "pristine", rules_dir)
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    assert finding.version_source == "anchor"
    assert finding.vendor_patched is False


def test_an_unrelated_tree_produces_nothing(tmp_path, rules_dir):
    comp = tmp_path / "project" / "components" / "unrelated"
    comp.mkdir(parents=True)
    (comp / "LICENSE").write_text("MIT")
    (comp / "a.c").write_text("void totally_unrelated(void) { while (1) { tick(); } }\n" * 40)
    result = _scan(tmp_path / "project", rules_dir, deep=True)
    assert result.findings == []
    assert "components/unrelated" in result.unidentified


def test_confidence_is_held_down_when_the_version_is_unknown(project_dir, rules_dir):
    from gangmu.model import Finding
    f = Finding(directory="x", rule_id="r", upstream_name="u",
                identity_confidence=0.9, version_confidence=0.0)
    assert f.confidence == 0.45
    f.version, f.version_confidence = "1.0", 0.85
    assert f.confidence == 0.85


def test_a_nested_match_does_not_shadow_a_stronger_outer_one():
    """Mbed TLS contains tf-psa-crypto, which matches the Mbed TLS rule too.

    An earlier version always preferred the deeper directory and reported the
    sub-library at 0.75 while dropping the 0.95 match on the component root.
    """
    from gangmu.model import Finding
    from gangmu.scan import _drop_nested_duplicates

    outer = Finding(directory="components/mbedtls/mbedtls", rule_id="r",
                    upstream_name="Mbed TLS", version="4.1.1",
                    identity_confidence=0.95, version_confidence=0.95)
    inner = Finding(directory="components/mbedtls/mbedtls/tf-psa-crypto", rule_id="r",
                    upstream_name="Mbed TLS", version="1.1.1",
                    identity_confidence=0.75, version_confidence=0.75)
    kept = _drop_nested_duplicates([outer, inner])
    assert [f.directory for f in kept] == ["components/mbedtls/mbedtls"]


def test_a_stronger_nested_match_still_wins():
    from gangmu.model import Finding
    from gangmu.scan import _drop_nested_duplicates

    outer = Finding(directory="components/lwip", rule_id="r", upstream_name="lwIP",
                    version="2.2.0", identity_confidence=0.6, version_confidence=0.6)
    inner = Finding(directory="components/lwip/lwip", rule_id="r", upstream_name="lwIP",
                    version="2.2.0", identity_confidence=0.95, version_confidence=0.95)
    kept = _drop_nested_duplicates([outer, inner])
    assert [f.directory for f in kept] == ["components/lwip/lwip"]


def test_different_components_nested_in_each_other_both_survive():
    from gangmu.model import Finding
    from gangmu.scan import _drop_nested_duplicates

    outer = Finding(directory="components/net", rule_id="r", upstream_name="lwIP",
                    version="2.2.0", identity_confidence=0.9, version_confidence=0.9)
    inner = Finding(directory="components/net/json", rule_id="r2",
                    upstream_name="cJSON", version="1.7.19",
                    identity_confidence=0.9, version_confidence=0.9)
    assert len(_drop_nested_duplicates([outer, inner])) == 2


def test_a_directory_holding_two_releases_side_by_side_is_neither():
    # Allwinner R128 keeps FreeRTOS/Source (10.2.0) and FreeRTOS-orig/Source
    # (10.4.3) under kernel/; kernel/ matched too, holding both, and swallowed them.
    from gangmu.model import Finding
    from gangmu.scan import _drop_nested_duplicates

    def f(d, v, c):
        return Finding(directory=d, rule_id="r", upstream_name="FreeRTOS", version=v,
                       identity_confidence=c, version_confidence=c)
    kept = _drop_nested_duplicates([f("kernel", "10.4.0~10.4.3", 0.95),
                                    f("kernel/FreeRTOS/Source", "10.2.0", 0.82),
                                    f("kernel/FreeRTOS-orig/Source", "10.4.3", 0.95)])
    assert sorted(x.directory for x in kept) == ["kernel/FreeRTOS-orig/Source",
                                                  "kernel/FreeRTOS/Source"]


def test_a_root_with_two_matching_parts_of_one_release_stays_one_component():
    # pf-ring's drivers/ and kernel/ match its rule at the same release: parts of
    # the component, not copies of it. An anchored root keeps its claim either way.
    from gangmu.model import Evidence, Finding, Technique
    from gangmu.scan import _drop_nested_duplicates

    def f(d, v, c, anchored=False):
        ev = [Evidence(Technique.HASH_COMPARISON, 0.98, "anchor")] if anchored else []
        return Finding(directory=d, rule_id="r", upstream_name="PF_RING", version=v,
                       identity_confidence=c, version_confidence=c, evidence=ev)
    same = _drop_nested_duplicates([f(".", "9.4.0", 0.95),
                                    f("drivers/intel", "9.4.0", 0.9),
                                    f("kernel", "9.4.0", 0.9)])
    assert [x.directory for x in same] == ["."]
    anchored = _drop_nested_duplicates([f(".", "9.4.0", 0.95, anchored=True),
                                        f("drivers/intel", "9.2.0", 0.9),
                                        f("kernel", "9.4.0", 0.9)])
    assert [x.directory for x in anchored] == ["."]


def test_a_shared_file_does_not_make_a_false_exact_match(upstream_dir, rules_dir,
                                                         tmp_path):
    """Two forks of one upstream often share a file byte for byte.

    A rule anchored on such a file would otherwise claim an exact match on a
    directory that is a different component entirely -- this is how a Zephyr
    mbedTLS rule came to out-rank the Espressif one on Espressif's own tree.
    The anchor is evidence about a file; the sketch is evidence about the tree,
    and when they disagree the tree wins.
    """
    import shutil


    other = tmp_path / "project" / "components" / "other"
    other.mkdir(parents=True)
    # A directory that is NOT tinynet, but happens to carry tinynet's version
    # header unchanged -- exactly the shared-file case.
    (other / "src").mkdir()
    (other / "include" / "tinynet").mkdir(parents=True)
    shutil.copy(upstream_dir / "include" / "tinynet" / "version.h",
                other / "include" / "tinynet" / "version.h")
    (other / "LICENSE").write_text("MIT")
    (other / "src" / "elsewhere.c").write_text(
        "void unrelated(void) { while (ready()) { drain(); } }\n" * 60)

    result = _scan(tmp_path / "project", rules_dir, deep=True)
    hits = [f for f in result.findings if f.directory == "components/other"]
    assert not hits or hits[0].identity_confidence <= 0.5
    if hits:
        assert hits[0].version is None
        assert any("shared with another fork" in e.summary for e in hits[0].evidence)


def test_a_vendors_rule_firing_outside_its_own_path_does_not_name_that_vendor(
        project_dir, rules_dir, tmp_path):
    """Rule says "ACME's copy lives under **/acme-sdk/tinynet"; the copy found is
    elsewhere. The upstream identity stands, the supplier is not asserted."""
    import yaml
    shutil.copytree(rules_dir, tmp_path / "r")
    path = next((tmp_path / "r").rglob("*.yaml"))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["vendor"] = "acme"
    data["component"] = {"path_globs": ["**/acme-sdk/tinynet"], "ships_as": "tinynet_acme"}
    data["upstream"]["supplier"] = "ACME Semiconductor"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    result = _scan(project_dir, tmp_path / "r")
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    assert finding.vendor_name is None and finding.supplier is None
    assert any("supplier is not asserted" in e.summary for e in finding.evidence)

    # and at the place the rule names, the vendor is credited as before
    shutil.copytree(project_dir, tmp_path / "p")
    src = next((tmp_path / "p").rglob("tinynet"))
    dest = tmp_path / "p" / "acme-sdk" / "tinynet"
    dest.parent.mkdir(parents=True)
    shutil.move(str(src), str(dest))
    result = _scan(tmp_path / "p", tmp_path / "r")
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    assert finding.supplier == "ACME Semiconductor"


def test_a_rule_without_a_supplier_takes_the_owner_of_its_repository_purl(
        project_dir, rules_dir, tmp_path):
    """823 rules of the free rule base name no supplier but a pkg:github purl; the
    SBOM's first minimum element was then missing for every component they found."""
    import yaml
    shutil.copytree(rules_dir, tmp_path / "r")
    path = next((tmp_path / "r").rglob("*.yaml"))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["upstream"].pop("supplier", None)
    data["upstream"]["purl"] = "pkg:github/tinynet-project/tinynet"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    finding = next(f for f in _scan(project_dir, tmp_path / "r").findings
                   if f.upstream_name == "tinynet")
    assert finding.supplier == "tinynet-project"
    # a purl that names no owner gives none
    data["upstream"]["purl"] = "pkg:generic/tinynet"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    finding = next(f for f in _scan(project_dir, tmp_path / "r").findings
                   if f.upstream_name == "tinynet")
    assert finding.supplier is None


def _shared_anchor_rules(rules_dir, tmp_path, reference=True):
    """The generated rule with its anchor file recorded as shipped unchanged by
    1.4.1, 1.4.2 and 1.4.3, as real releases often do."""
    import yaml
    out = tmp_path / "shared-rules"
    shutil.copytree(rules_dir, out)
    path = next(out.glob("*.yaml"))
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    digest = rule["identity"]["anchors"][0]["sha256"]["1.4.2"]
    rule["identity"]["anchors"][0]["sha256"] = {"1.4.1": digest, "1.4.2": digest,
                                                "1.4.3": digest}
    if not reference:
        rule["identity"]["signature"].pop("reference_version", None)
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
    return out


def _pristine(upstream_dir, tmp_path):
    tree = tmp_path / "pristine" / "components" / "tinynet"
    tree.parent.mkdir(parents=True)
    shutil.copytree(upstream_dir, tree)
    return tree


def test_an_anchor_shared_by_releases_does_not_pin_the_first_of_them(
        upstream_dir, rules_dir, tmp_path):
    """open62541 1.4.3 and 1.4.4 ship the same ua_server.c: the 1.4.4 tree was
    reported as 1.4.3, exact, because the first release with that hash won."""
    rules = _shared_anchor_rules(rules_dir, tmp_path)
    tree = _pristine(upstream_dir, tmp_path)
    result = _scan(tmp_path / "pristine", rules)
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    assert finding.version == "1.4.2"                 # the probe settles it
    assert finding.version_source == "probe"
    (tree / "include" / "tinynet" / "version.h").unlink()
    (tmp_path / "bare").mkdir()
    rules = _shared_anchor_rules(rules_dir, tmp_path / "bare", reference=False)
    result = _scan(tmp_path / "pristine", rules)
    finding = next(f for f in result.findings if f.upstream_name == "tinynet")
    assert finding.version == "1.4.1~1.4.3"           # nothing settles it: a span
    assert finding.version_source == "anchor-shared"
    assert 0 < finding.version_confidence < 0.98
    assert any("3 releases ship it unchanged" in e.summary for e in finding.evidence)


def test_a_version_definition_naming_an_unrecorded_release_beats_the_anchor(
        upstream_dir, rules_dir, tmp_path):
    """Zephyr's Mbed TLS: library/version_features.c is the same in 4.1.0 and
    4.1.1, the rule recorded 4.1.0, and build_info.h said 4.1.1."""
    tree = _pristine(upstream_dir, tmp_path)
    header = tree / "include" / "tinynet" / "version.h"
    header.write_text(re.sub(r"(REVISION\s+)2", r"\g<1>9", header.read_text()))
    finding = next(f for f in _scan(tmp_path / "pristine", rules_dir).findings
                   if f.upstream_name == "tinynet")
    assert finding.version == "1.4.9"
    assert finding.version_source == "probe"
    assert any("does not record" in e.summary for e in finding.evidence)


def test_a_version_definition_naming_a_recorded_release_does_not_beat_the_anchor(
        upstream_dir, rules_dir, tmp_path):
    """Three Mbed TLS tags did not bump their header: the anchor is the better witness."""
    import yaml
    rules = tmp_path / "two"
    shutil.copytree(rules_dir, rules)
    path = next(rules.glob("*.yaml"))
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    rule["identity"]["anchors"][0]["sha256"]["1.4.1"] = "0" * 64
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
    tree = _pristine(upstream_dir, tmp_path)
    header = tree / "include" / "tinynet" / "version.h"
    header.write_text(re.sub(r"(REVISION\s+)2", r"\g<1>1", header.read_text()))
    finding = next(f for f in _scan(tmp_path / "pristine", rules).findings
                   if f.upstream_name == "tinynet")
    assert finding.version == "1.4.2"
    assert finding.version_source == "anchor"

def test_a_version_definition_that_is_a_prefix_of_the_anchor_release_does_not_beat_it(
        upstream_dir, rules_dir, tmp_path):
    """littlefs's lfs.h only gives 0x00020009 (2.9) in the 2.9.1 tree: 2.9 is not a
    release the rule records, but it is the anchor release's own major.minor."""
    import yaml
    rules = tmp_path / "short"
    shutil.copytree(rules_dir, rules)
    path = next(rules.glob("*.yaml"))
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    rule["version"]["probes"][0]["template"] = "{major}.{minor}"
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
    _pristine(upstream_dir, tmp_path)
    finding = next(f for f in _scan(tmp_path / "pristine", rules).findings
                   if f.upstream_name == "tinynet")
    assert finding.version == "1.4.2"
    assert finding.version_source == "anchor"


def test_a_probe_header_beside_the_src_directory_is_read(rules_dir, tmp_path):
    """LVGL is found at ``lvgl/src`` (which has its own, versionless ``lvgl.h``)
    and FreeRTOS at ``freertos/src``; the header naming the version sits beside it."""
    from gangmu.match.engine import MatchEngine
    rule = load_rules(rules_dir, strict=True).rules[0]
    probe = rule.probes[0]
    root = tmp_path / "lib"
    (root / "src" / "inner").mkdir(parents=True)
    (root / "src" / "version.h").write_text("/* no version here */\n")
    (root / "src" / "inner" / "marker.c").write_text("int x;\n")
    target = root / Path(probe.file)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text((Path(__file__).parent / "fixtures" / "upstream"
                       / "tinynet" / probe.file).read_text())
    engine = MatchEngine(load_rules(rules_dir, strict=True))
    evidence = []
    found = engine._probe_version(root / "src", rule, evidence, "lib/src")
    assert found == "1.4.2"
    assert evidence[0].locator == f"lib/{probe.file}"
    # A directory that is not a source subdirectory does not look upwards.
    (root / "other").mkdir()
    assert engine._probe_version(root / "other", rule, [], "lib/other") is None


def test_a_rule_file_one_directory_down_is_found(tmp_path):
    """BTstack ships lwIP as ``lwip/core/src/include/lwip/init.h``: every path the
    rule records is one directory deeper than the rule says."""
    from gangmu.match.engine import _locate

    f = tmp_path / "core" / "src" / "include" / "init.h"
    f.parent.mkdir(parents=True)
    f.write_text("x")
    assert _locate(tmp_path, "src/include/init.h") == f
    assert _locate(tmp_path, "src/include/missing.h") is None


def test_two_candidates_for_a_rule_file_are_not_guessed_between(tmp_path):
    from gangmu.match.engine import _locate

    for name, text in (("a", "1"), ("b", "2")):
        f = tmp_path / name / "include" / "version.h"
        f.parent.mkdir(parents=True)
        f.write_text(text)
    assert _locate(tmp_path, "include/version.h") is None
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "version.h").write_text("0")
    assert _locate(tmp_path, "include/version.h") == tmp_path / "include" / "version.h"


def _weakly_alike(upstream_dir, tmp_path, monkeypatch, namespaced):
    """tinynet copied with its core file altered (no anchor) and judged only
    weakly similar; optionally with the version header moved under another
    directory, as ESP-IDF puts FreeRTOS's under ``include/freertos/``."""
    from gangmu.match.engine import MatchEngine

    tree = tmp_path / "proj" / "components" / "tinynet"
    tree.parent.mkdir(parents=True)
    shutil.copytree(upstream_dir, tree)
    (tree / "src" / "core.c").write_text("/* rewritten by the vendor */\nint f(void){return 1;}\n")
    if namespaced:
        moved = tree / "include" / "tinynet" / "ns"
        moved.mkdir()
        (tree / "include" / "tinynet" / "version.h").rename(moved / "version.h")
    monkeypatch.setattr(MatchEngine, "_similarity",
                        lambda self, directory, rule: (rule.thresholds["floor"] + 0.001, False))
    return tmp_path / "proj"


def test_a_weak_resemblance_that_defines_the_version_is_asserted(
        upstream_dir, rules_dir, tmp_path, monkeypatch):
    project = _weakly_alike(upstream_dir, tmp_path, monkeypatch, namespaced=False)
    finding = next(f for f in _scan(project, rules_dir).findings
                   if f.upstream_name == "tinynet")
    assert finding.version == "1.4.2" and finding.version_source == "probe"
    assert finding.identity_confidence >= 0.75


def test_a_weak_resemblance_with_no_version_definition_stays_weak(
        upstream_dir, rules_dir, tmp_path, monkeypatch):
    project = _weakly_alike(upstream_dir, tmp_path, monkeypatch, namespaced=False)
    (project / "components" / "tinynet" / "include" / "tinynet" / "version.h").unlink()
    result = _scan(project, rules_dir)
    assert not [f for f in result.findings if f.upstream_name == "tinynet"]
    possible = next(f for f in result.possible if f.upstream_name == "tinynet")
    assert possible.identity_confidence < 0.6


def test_the_version_header_is_found_under_a_namespacing_directory(
        upstream_dir, rules_dir, tmp_path, monkeypatch):
    project = _weakly_alike(upstream_dir, tmp_path, monkeypatch, namespaced=True)
    finding = next(f for f in _scan(project, rules_dir).findings
                   if f.upstream_name == "tinynet")
    assert finding.version == "1.4.2" and finding.version_source == "probe"


def test_a_file_name_shared_by_two_nested_files_is_not_guessed(tmp_path):
    from gangmu.match.engine import _locate

    for d in ("a/inc", "b/inc"):
        f = tmp_path / d / "version.h"
        f.parent.mkdir(parents=True)
        f.write_text("x")
    assert _locate(tmp_path, "include/version.h", by_name=True) is None
    (tmp_path / "b" / "inc" / "version.h").unlink()
    assert _locate(tmp_path, "include/version.h", by_name=True) == tmp_path / "a/inc/version.h"
    assert _locate(tmp_path, "include/version.h") is None      # anchors never match by name


def test_a_tree_nearest_the_oldest_recorded_release_is_flagged_as_possibly_older(
        upstream_dir, rules_dir, tmp_path):
    """ESP8266's libsodium is 1.0.12; the rule records 1.0.17 and later, and the
    nearest of those was reported as the version with nothing to say it might be
    older than all of them."""
    from gangmu.fnsig import FunctionSignature, infer_version

    def fn(n):
        return n * 7919 + 13

    shared = [fn(i) for i in range(40)]
    old_only = [fn(100 + i) for i in range(10)]
    new_only = [fn(200 + i) for i in range(10)]
    sig = FunctionSignature(
        versions=["1.0.17", "1.0.18"],
        hashes=shared + old_only + new_only,
        bitmaps=[0b11] * 40 + [0b01] * 10 + [0b10] * 10,
        flags=[1] * 60)
    # A tree with only some of 1.0.17's own functions and many unrecorded ones.
    present = set(shared[:10]) | set(old_only[:4]) | {fn(900 + i) for i in range(60)}
    verdict = infer_version(sig, present)
    assert verdict.best == "1.0.17" and verdict.edge == "oldest"
    # The same tree with every recorded function of 1.0.17 present is not flagged.
    whole = set(shared) | set(old_only)
    assert infer_version(sig, whole).edge == ""


def test_a_probe_can_read_a_packed_hex_version_and_an_optional_suffix():
    from gangmu.rules.schema import VersionProbe
    lfs = VersionProbe(
        file="lfs.h",
        patterns={"hex_major": r"LFS_VERSION\s+0x([0-9a-fA-F]{4})[0-9a-fA-F]{4}",
                  "hex_minor": r"LFS_VERSION\s+0x[0-9a-fA-F]{4}([0-9a-fA-F]{4})"},
        template="{major}.{minor}")
    assert lfs.apply("#define LFS_VERSION 0x0002000a\n") == "2.10"
    zephyr = VersionProbe(
        file="VERSION",
        patterns={"major": r"VERSION_MAJOR\s*=\s*(\d+)",
                  "dash_extra": r"EXTRAVERSION[ \t]*=[ \t]*(\S*)"},
        template="{major}{extra}")
    assert zephyr.apply("VERSION_MAJOR = 4\nEXTRAVERSION = rc2\n") == "4-rc2"
    assert zephyr.apply("VERSION_MAJOR = 4\nEXTRAVERSION =\nNEXT = x\n") == "4"


def test_a_partial_version_definition_narrows_the_span_the_functions_give():
    from types import SimpleNamespace

    from gangmu.match.engine import _narrow_range
    versions = ("2.9.3", "2.10.0", "2.10.1", "2.10.2", "2.11.0", "2.11.1")
    rule = SimpleNamespace(functions=SimpleNamespace(versions=versions))
    assert _narrow_range(rule, "2.10.2~2.11.1", "2.10") == "2.10.2"
    assert _narrow_range(rule, "2.10.0~2.11.0", "2.10") == "2.10.0~2.10.2"
    assert _narrow_range(rule, "2.10.0~2.10.2", "2.10") is None      # nothing to narrow
    assert _narrow_range(rule, "2.10.2~2.11.1", "2.9") is None       # contradicts: not narrowed
    assert _narrow_range(rule, "2.11.1", "2.11") is None
