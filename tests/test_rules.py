import copy

import pytest
import yaml

from gangmu.rules.loader import load_rules

from community import REPO_RULES, needs_rules
from gangmu.rules.schema import RuleError, rule_from_dict

MINIMAL = {
    "id": "test/thing",
    "upstream": {
        "name": "thing",
        "purl": "pkg:generic/thing",
        "cpe": "cpe:2.3:a:thing_project:thing:*:*:*:*:*:*:*:*",
        "source": {"kind": "git", "url": "https://example.invalid/thing", "ref": "v1"},
    },
    "identity": {
        "anchors": [{"path": "a.c", "sha256": {"1.0": "0" * 64}}],
    },
}


def test_minimal_rule_parses():
    rule = rule_from_dict(copy.deepcopy(MINIMAL), "t.yaml")
    assert rule.id == "test/thing"
    assert rule.anchors[0].sha256["1.0"] == "0" * 64


def test_mirrors_parse_and_default_to_none():
    assert rule_from_dict(copy.deepcopy(MINIMAL), "t.yaml").mirrors == ()
    data = copy.deepcopy(MINIMAL)
    data["upstream"]["mirrors"] = [{"kind": "git", "url": "https://example.invalid/m",
                                    "ref": "a" * 40, "subdir": "k"}]
    (mirror,) = rule_from_dict(data, "t.yaml").mirrors
    assert (mirror.url, mirror.ref, mirror.subdir) == (
        "https://example.invalid/m", "a" * 40, "k")


def test_malformed_mirrors_are_refused():
    data = copy.deepcopy(MINIMAL)
    data["upstream"]["mirrors"] = ["https://example.invalid/m"]
    with pytest.raises(RuleError, match="mirrors"):
        rule_from_dict(data, "t.yaml")
    data["upstream"]["mirrors"] = [{"kind": "git"}]
    with pytest.raises(RuleError):
        rule_from_dict(data, "t.yaml")


def test_upstream_source_is_mandatory():
    data = copy.deepcopy(MINIMAL)
    del data["upstream"]["source"]
    with pytest.raises(RuleError, match="upstream.source"):
        rule_from_dict(data, "t.yaml")


def test_rule_with_no_checkable_evidence_is_refused():
    data = copy.deepcopy(MINIMAL)
    data["identity"] = {}
    with pytest.raises(RuleError, match="anchor, a signature or a function"):
        rule_from_dict(data, "t.yaml")


def test_malformed_cpe_is_refused():
    data = copy.deepcopy(MINIMAL)
    data["upstream"]["cpe"] = "cpe:/a:thing:thing"
    with pytest.raises(RuleError, match="CPE 2.3"):
        rule_from_dict(data, "t.yaml")


def test_malformed_purl_is_refused():
    data = copy.deepcopy(MINIMAL)
    data["upstream"]["purl"] = "generic/thing"
    with pytest.raises(RuleError, match="pkg:"):
        rule_from_dict(data, "t.yaml")


def test_short_sha256_is_refused():
    data = copy.deepcopy(MINIMAL)
    data["identity"]["anchors"][0]["sha256"] = {"1.0": "abc"}
    with pytest.raises(RuleError, match="64 hex"):
        rule_from_dict(data, "t.yaml")


def test_bad_probe_regex_is_refused():
    data = copy.deepcopy(MINIMAL)
    data["version"] = {"probes": [{"file": "v.h", "patterns": {"v": "("}}]}
    with pytest.raises(RuleError, match="probe regex"):
        rule_from_dict(data, "t.yaml")


def test_duplicate_ids_are_reported_not_merged(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(yaml.safe_dump(MINIMAL))
    base = load_rules(tmp_path)
    assert len(base) == 1
    assert any("duplicate rule id" in e for e in base.errors)


def test_one_broken_rule_does_not_take_down_the_base(tmp_path):
    (tmp_path / "good.yaml").write_text(yaml.safe_dump(MINIMAL))
    (tmp_path / "broken.yaml").write_text("id: x\nupstream: {name: y}\n")
    base = load_rules(tmp_path)
    assert len(base) == 1 and len(base.errors) == 1


def test_specificity_prefers_narrower_rules():
    generic = rule_from_dict(copy.deepcopy(MINIMAL), "g.yaml")
    data = copy.deepcopy(MINIMAL)
    data.update({"id": "v/sdk/thing", "vendor": "v", "sdk": "sdk",
                 "sdk_versions": ">=1", "component": {"path_globs": ["a/b"]}})
    specific = rule_from_dict(data, "s.yaml")
    assert specific.specificity > generic.specificity


def test_version_is_spliced_into_purl_and_cpe():
    rule = rule_from_dict(copy.deepcopy(MINIMAL), "t.yaml")
    assert rule.purl_with_version("1.2.3") == "pkg:generic/thing@1.2.3"
    assert rule.cpe_with_version("1.2.3").split(":")[5] == "1.2.3"


@needs_rules
def test_shipped_rule_base_is_clean():
    base = load_rules(REPO_RULES)
    assert base.errors == []
    assert len(base) >= 3
