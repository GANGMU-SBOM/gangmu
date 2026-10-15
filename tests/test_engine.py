import shutil

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
