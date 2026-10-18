"""Version banners that a rule supplies for its component (identity.binary_banners)."""

import pytest

from gangmu.rules.loader import load_rules
from gangmu.rules.schema import RuleError, rule_from_dict
from gangmu.scan import ScanOptions, scan

PATTERN = r"ThreadX [A-Za-z0-9/ +_-]{0,40}Version G?(\d+\.\d+\.\d+)"


def _rule(banners, name="threadx"):
    return {"id": f"t/{name}",
            "component": {"ships_as": name},
            "upstream": {"name": name, "purl": f"pkg:generic/{name}",
                         "cpe": f"cpe:2.3:a:vendor:{name}:*:*:*:*:*:*:*:*",
                         "cpe_evidence": ["CVE-2024-28115"],
                         "source": {"kind": "git", "url": "https://example.invalid/r",
                                    "ref": "v1"}},
            "identity": {"anchors": [{"path": "a.c", "sha256": {"1": "0" * 64}}],
                         **({"binary_banners": banners} if banners is not None else {})}}


def _parse(banners):
    return rule_from_dict(_rule(banners), source_path="r.yaml")


def test_a_rule_without_banners_has_none():
    assert _parse(None).binary_banners == ()


def test_a_good_pattern_is_kept():
    assert _parse([PATTERN]).binary_banners == (PATTERN,)


@pytest.mark.parametrize("bad,why", [
    (r"(\d+\.\d+\.\d+)", "literal"),                       # no anchor text
    (r"ThreadX Version \d+\.\d+", "group"),                # no capture group
    (r".*ThreadX Version (\d+)", "unbounded"),
    (r"ThreadX \S+ Version (\d+)", "unbounded"),
    (r"ThreadX [^\0]+ Version (\d+)", "unbounded"),
    (r"(ThreadX +)+ Version (\d+)", "unbounded"),
    (r"ThreadX Version (\d+", "compile"),
    ("ThreadX Version (\\d+)" + "x" * 200, "long"),
])
def test_patterns_that_could_be_slow_or_say_nothing_are_refused(bad, why):  # noqa: ARG001
    with pytest.raises(RuleError):
        _parse([bad])


def test_a_banner_list_must_be_strings():
    with pytest.raises(RuleError):
        _parse("ThreadX Version (1)")
    with pytest.raises(RuleError):
        _parse([3])


def _scan(tmp_path, text, extra=()):
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    import yaml
    (rules / "threadx.yaml").write_text(yaml.safe_dump(_rule([PATTERN])))
    tree = tmp_path / "tree"
    tree.mkdir(exist_ok=True)
    (tree / "fw.bin").write_bytes(b"\0" * 64 + text + b"\0" * 64)
    return scan(tree, load_rules(rules, strict=True), None, ScanOptions())


def test_the_banner_names_the_component_from_the_rule(tmp_path):
    result = _scan(tmp_path, b"Copyright  *  ThreadX Cortex-M4/GNU Version 6.1.9 *")
    (found,) = [f for f in result.findings if f.rule_id.startswith("binary/")]
    assert found.version == "6.1.9"
    assert found.cpe == "cpe:2.3:a:vendor:threadx:6.1.9:*:*:*:*:*:*:*"
    assert found.purl.endswith("@6.1.9")
    assert "ThreadX Cortex-M4/GNU Version 6.1.9" in found.evidence[0].summary


def test_text_that_only_resembles_the_banner_is_not_a_finding(tmp_path):
    result = _scan(tmp_path, b"ThreadX has Version 6 of the manual")
    assert not [f for f in result.findings if f.rule_id.startswith("binary/")]
