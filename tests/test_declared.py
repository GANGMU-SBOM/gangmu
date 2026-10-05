"""Package-manager declarations: RT-Thread and OpenHarmony.

Where an ecosystem writes down what it vendored, that is read rather than
estimated. The tests pin the two things that are easy to get wrong: an
RT-Thread package tag is not an upstream version, and a declaration on a
directory a rule already identified must not produce a second component.
"""

import json
from pathlib import Path

from gangmu.cli import main
from gangmu.declared import (collect_declarations, normalise_version,
                             read_openharmony, read_rtthread)
from gangmu.rules.loader import load_rules
from gangmu.scan import ScanOptions, scan
from gangmu.sbom.cyclonedx import to_cyclonedx

from community import REPO_RULES, needs_rules

pytestmark = needs_rules


def _oh_tree(root: Path, entries) -> Path:
    third = root / "third_party" / "cJSON"
    third.mkdir(parents=True)
    (third / "cJSON.c").write_text("int cjson_parse(void){return 0;}\n")
    (third / "README.OpenSource").write_text(json.dumps(entries, ensure_ascii=False))
    return third


CJSON_ENTRY = {
    "Name": "cJSON",
    "License": "MIT License",
    "License File": "LICENSE",
    "Version Number": "v1.7.17",
    "Owner": "someone@example.invalid",
    "Upstream URL": "https://github.com/DaveGamble/cJSON",
    "Description": "Ultralightweight JSON parser in ANSI C",
}


def _rtt_tree(root: Path, download: bool = True) -> None:
    (root / ".config").write_text(
        "CONFIG_RT_USING_COMPONENTS_INIT=y\n"
        "CONFIG_PKG_USING_CJSON=y\n"
        'CONFIG_PKG_CJSON_PATH="/packages/iot/cJSON"\n'
        "CONFIG_PKG_USING_CJSON_V102=y\n"
        'CONFIG_PKG_CJSON_VER="v1.0.2"\n'
        "# CONFIG_PKG_USING_WEBCLIENT is not set\n"
    )
    if download:
        pkg = root / "packages" / "cJSON-v1.0.2"
        pkg.mkdir(parents=True)
        (pkg / "cJSON.c").write_text("int cjson_parse(void){return 0;}\n")


# ---------------------------------------------------------------- readers

def test_openharmony_declares_the_upstream_version(tmp_path):
    _oh_tree(tmp_path, [CJSON_ENTRY])
    (decl,) = read_openharmony(tmp_path)
    assert decl.name == "cJSON" and decl.version == "1.7.17"
    assert decl.version_is_upstream
    assert decl.purl == "pkg:github/davegamble/cjson@1.7.17"
    assert decl.source == "third_party/cJSON/README.OpenSource"


def test_rtthread_reads_the_selected_package_and_finds_it_on_disk(tmp_path):
    _rtt_tree(tmp_path)
    (decl,) = read_rtthread(tmp_path)
    assert decl.name == "cJSON" and decl.version == "v1.0.2"
    assert decl.version_is_upstream is False
    assert decl.directory == (tmp_path / "packages" / "cJSON-v1.0.2").resolve()
    assert decl.purl == "pkg:generic/rt-thread/cjson@v1.0.2"


def test_rtthread_sub_options_are_not_packages(tmp_path):
    """CONFIG_PKG_USING_CJSON_V102 selects a version; it is not a package."""
    _rtt_tree(tmp_path)
    assert [d.name for d in read_rtthread(tmp_path)] == ["cJSON"]


def test_rtthread_installed_list_overrides_the_selection(tmp_path):
    _rtt_tree(tmp_path)
    (tmp_path / "packages" / "pkgs.json").write_text(json.dumps(
        [{"path": "/packages/iot/cJSON", "ver": "v1.0.2", "name": "CJSON"}]))
    (decl,) = read_rtthread(tmp_path)
    assert decl.version == "v1.0.2" and decl.present


def test_rtthread_selected_but_not_downloaded_is_kept_without_a_directory(tmp_path):
    _rtt_tree(tmp_path, download=False)
    (decl,) = read_rtthread(tmp_path)
    assert not decl.present


def test_nothing_declared_means_nothing_returned(tmp_path):
    (tmp_path / "src").mkdir()
    assert collect_declarations(tmp_path) == []


def test_version_prefix_is_dropped_only_from_releases():
    assert normalise_version("v1.7.17") == "1.7.17"
    assert normalise_version("V2.0") == "2.0"
    assert normalise_version("latest") == "latest"
    assert normalise_version("") is None


# ------------------------------------------------------------ scan wiring

def test_openharmony_component_with_no_rule_fingerprint_is_still_reported(tmp_path):
    _oh_tree(tmp_path, [CJSON_ENTRY])
    result = scan(tmp_path, load_rules(REPO_RULES, strict=False))
    (f,) = [f for f in result.findings if f.upstream_name == "cJSON"]
    assert f.version == "1.7.17" and f.version_source == "declared"
    # The upstream version is declared, so the rule base's CPE applies.
    assert f.cpe == "cpe:2.3:a:cjson_project:cjson:1.7.17:*:*:*:*:*:*:*"
    assert f.declared_license == "MIT"
    assert "third_party/cJSON" not in result.unidentified


def test_rtthread_package_version_never_reaches_an_upstream_cpe(tmp_path):
    """A wrapper's tag spliced into cJSON's CPE would match the wrong CVEs."""
    _rtt_tree(tmp_path)
    result = scan(tmp_path, load_rules(REPO_RULES, strict=False))
    (f,) = [f for f in result.findings if f.rule_id.startswith("declared/rt-thread")]
    assert f.cpe is None
    assert f.purl == "pkg:generic/rt-thread/cjson@v1.0.2"
    assert "not necessarily the upstream release" in f.evidence[0].summary


def test_a_missing_package_is_a_note_not_a_component(tmp_path):
    _rtt_tree(tmp_path, download=False)
    result = scan(tmp_path, load_rules(REPO_RULES, strict=False))
    assert not [f for f in result.findings if f.rule_id.startswith("declared/")]
    assert any("not downloaded" in n for n in result.notes)


def test_declaration_on_an_identified_directory_is_evidence_not_a_duplicate(
        tmp_path, upstream_dir, rules_dir):
    import shutil
    target = tmp_path / "third_party" / "tinynet"
    shutil.copytree(upstream_dir, target)
    (target / "README.OpenSource").write_text(json.dumps(
        [{"Name": "tinynet", "Version Number": "1.4.0", "License": "MIT"}]))
    result = scan(tmp_path, load_rules(rules_dir))
    found = [f for f in result.findings if f.upstream_name == "tinynet"]
    assert len(found) == 1
    (f,) = found
    assert f.version == "1.4.2"                 # the anchor outranks the README
    assert any("declares 1.4.0" in e.summary for e in f.evidence)


def test_several_components_in_one_directory_get_distinct_refs(tmp_path):
    _oh_tree(tmp_path, [CJSON_ENTRY, dict(CJSON_ENTRY, Name="cJSON_Utils",
                                          **{"Upstream URL": ""})])
    result = scan(tmp_path, load_rules(REPO_RULES, strict=False))
    bom = to_cyclonedx(result)
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs)) == 2
    graph_refs = [d["ref"] for d in bom["dependencies"]]
    assert len(graph_refs) == len(set(graph_refs))


def test_declarations_can_be_switched_off(tmp_path):
    _oh_tree(tmp_path, [CJSON_ENTRY])
    result = scan(tmp_path, load_rules(REPO_RULES, strict=False),
                  options=ScanOptions(declared=False))
    assert not [f for f in result.findings if f.rule_id.startswith("declared/")]


def test_cli_scan_reports_declared_components(tmp_path, capsys):
    _oh_tree(tmp_path / "tree", [CJSON_ENTRY])
    code = main(["scan", str(tmp_path / "tree"), "--rules", str(REPO_RULES),
                 "--format", "table"])
    assert code == 0
    out = capsys.readouterr().out
    assert "cJSON" in out and "1.7.17" in out and "declared" in out


def test_an_rtthread_package_is_fingerprinted_for_its_upstream_identity(
        tmp_path, upstream_dir, rules_dir):
    """The package tag says which wrapper; the rule base says what is inside."""
    import shutil
    shutil.copytree(upstream_dir, tmp_path / "packages" / "tinynet-v1.0.0")
    (tmp_path / ".config").write_text(
        "CONFIG_PKG_USING_TINYNET=y\n"
        'CONFIG_PKG_TINYNET_PATH="/packages/iot/tinynet"\n'
        'CONFIG_PKG_TINYNET_VER="v1.0.0"\n')
    result = scan(tmp_path, load_rules(rules_dir))
    (f,) = result.findings
    assert f.rule_id == "test/tinynet" and f.version == "1.4.2"
    assert any("RT-Thread package tinynet v1.0.0" in e.summary for e in f.evidence)


# ------------------------------------------------------- OpenHarmony bundle.json

def _bundle(directory: Path, name: str, subsystem: str, version="4.0.2",
            components=(), third_party=()):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "bundle.json").write_text(json.dumps({
        "name": f"@ohos/{name}", "version": version, "license": "Apache License 2.0",
        "component": {"name": name, "subsystem": subsystem,
                      "deps": {"components": list(components),
                               "third_party": list(third_party)}}}))
    (directory / "x.c").write_text("int x(void){return 1;}\n")


def _oh_product(root: Path) -> None:
    _bundle(_oh_tree(root, [CJSON_ENTRY]), "cJSON", "thirdparty", version="3.1")
    _bundle(root / "third_party" / "bounds_checking_function",
            "bounds_checking_function", "thirdparty", version="3.1")
    _bundle(root / "base" / "hiviewdfx" / "hilog_lite", "hilog_lite", "hiviewdfx",
            components=["samgr_lite", "ace_engine_lite"],
            third_party=["bounds_checking_function", "cJSON"])
    _bundle(root / "foundation" / "systemabilitymgr" / "samgr_lite", "samgr_lite",
            "systemabilitymgr", third_party=["bounds_checking_function"])
    web = root / "tools" / "web"           # an unrelated bundle.json
    web.mkdir(parents=True)
    (web / "bundle.json").write_text(json.dumps({"name": "site", "version": "1.0.0"}))


def test_bundles_declare_openharmony_components_and_their_dependencies(tmp_path):
    _oh_product(tmp_path)
    by_name = {d.name: d for d in collect_declarations(tmp_path)}
    assert set(by_name) == {"cJSON", "bounds_checking_function", "hilog_lite",
                            "samgr_lite"}                     # the web bundle is not one
    hilog = by_name["hilog_lite"]
    assert hilog.version == "4.0.2" and hilog.version_is_upstream
    assert hilog.purl == "pkg:generic/openharmony/hilog_lite@4.0.2"
    assert hilog.depends_on == ("samgr_lite", "ace_engine_lite",
                                "bounds_checking_function", "cJSON")
    # README.OpenSource keeps the upstream identity; the bundle adds its name.
    cjson = by_name["cJSON"]
    assert cjson.version == "1.7.17" and cjson.component == "cJSON"
    # Third-party code with only a bundle: OpenHarmony's packaging version is
    # not the upstream release, so it is not reported as one.
    bcf = by_name["bounds_checking_function"]
    assert bcf.version is None and not bcf.version_is_upstream


def test_declared_dependencies_become_sbom_edges(tmp_path):
    from gangmu.sbom.spdx import to_spdx
    _oh_product(tmp_path)
    result = scan(tmp_path, load_rules(REPO_RULES, strict=False))
    bom = to_cyclonedx(result)
    ref = {c["name"]: c["bom-ref"] for c in bom["components"]}
    graph = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert sorted(graph[ref["hilog_lite"]]) == sorted(
        [ref["samgr_lite"], ref["bounds_checking_function"], ref["cJSON"]])
    (hilog,) = [c for c in bom["components"] if c["name"] == "hilog_lite"]
    props = {p["name"]: p["value"] for p in hilog["properties"]}
    assert props["gangmu:declaredDependencyNotFound"] == "ace_engine_lite"
    assert props["gangmu:ecosystemComponent"] == "hilog_lite"

    spdx = to_spdx(result)
    names = {p["SPDXID"]: p["name"] for p in spdx["packages"]}
    edges = {(names[r["spdxElementId"]], names[r["relatedSpdxElement"]])
             for r in spdx["relationships"] if r["relationshipType"] == "DEPENDS_ON"}
    assert ("hilog_lite", "cJSON") in edges and ("samgr_lite", "bounds_checking_function") in edges
