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


def test_a_banner_is_only_searched_for_in_files_that_hold_its_literal():
    import re
    from gangmu.binaries import _COMPILED, _banners, _needle, _nul_tokens

    assert _needle(re.compile(rb"(?<![A-Za-z0-9_])expat_(\d+\.\d+\.\d+)")) == b"expat_"
    assert _needle(re.compile(rb"(?:deflate|inflate) (\d+\.\d+) Copyright")) == b" Copyright"
    assert _needle(re.compile(rb"(?i)expat_(\d+)")) is None        # case-insensitive: no needle
    assert _needle(re.compile(rb"(a|b)(\d+)")) is None             # nothing every match holds
    # a needle is a byte string the pattern itself spells out, never something it computes
    for _name, _display, pattern in _COMPILED:
        needle = _needle(pattern)
        assert needle is None or re.search(re.escape(needle), pattern.pattern.replace(b"\\", b""))
    data = b"\0\0libpng version 1.6.43\0 padding expat_2.5.0 \0"
    assert {(e.name, e.version) for e in _banners(data)} == {("libpng", "1.6.43"),
                                                              ("expat", "2.5.0")}
    assert _banners(b"nothing of interest here") == []
    assert _nul_tokens(b"a\0bc\0d\0e") == {b"bc", b"d"}


def test_api_symbols_are_found_between_nul_bytes_wherever_they_sit(monkeypatch):
    from gangmu import binaries

    symbols = tuple(f"sym_{i}" for i in range(6))
    monkeypatch.setattr(binaries, "_SYMBOL_SETS",
                        (("demo", "Demo", 5, tuple(f"\0{x}\0".encode() for x in symbols)),))
    stripped = b"\0" + b"\0".join(x.encode() for x in symbols[:5]) + b"\0 tail"
    assert [e.name for e in binaries._banners(stripped)] == ["demo"]
    # a name at the very start or end of the data has no NUL on both sides: not a hit
    edge = b"sym_0\0" + b"\0".join(x.encode() for x in symbols[1:5]) + b"\0sym_5"
    assert binaries._banners(edge) == []
