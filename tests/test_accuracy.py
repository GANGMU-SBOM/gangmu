"""Accuracy fixes found by scanning real Chinese vendor SDKs.

* a ``low~high`` span (what a function signature reports when it cannot split
  neighbouring releases) must not reach a PURL or CPE, and must be matched
  against advisories as a span, never as one malformed version;
* an eight-digit date tag is a version, not a commit id;
* a declared git submodule that is empty is said out loud.
"""

from pathlib import Path
from types import SimpleNamespace

from gangmu.discover import empty_submodules
from gangmu.rules.schema import Rule
from gangmu.vuln.version import in_range, in_tag_set, is_orderable, split_interval


def _rule(**over):
    base = dict(purl="pkg:github/obgm/libcoap",
                cpe="cpe:2.3:a:x:libcoap:*:*:*:*:*:*:*:*")
    base.update(over)
    return SimpleNamespace(**base)


def test_a_span_is_not_written_into_purl_or_cpe():
    purl = Rule.purl_with_version(_rule(), "4.3.2~4.3.4a")
    cpe = Rule.cpe_with_version(_rule(), "4.3.2~4.3.4a")
    assert purl == "pkg:github/obgm/libcoap"
    assert cpe == "cpe:2.3:a:x:libcoap:*:*:*:*:*:*:*:*"


def test_a_plain_version_is_still_spliced_in():
    assert Rule.purl_with_version(_rule(), "4.3.4") == "pkg:github/obgm/libcoap@4.3.4"
    assert Rule.cpe_with_version(_rule(), "4.3.4").split(":")[5] == "4.3.4"


def test_split_interval():
    assert split_interval("10.4.0~10.4.2") == ("10.4.0", "10.4.2")
    assert split_interval("10.4.2") is None


def test_a_span_inside_the_range_is_affected():
    assert in_range("10.4.0~10.4.2", introduced="10.0", fixed="10.5.0") is True


def test_a_span_wholly_outside_the_range_is_not_affected():
    assert in_range("10.4.0~10.4.2", introduced="10.5.0", fixed="10.6.0") is False
    assert in_range("10.4.0~10.4.2", introduced="9.0", fixed="10.4.0") is False


def test_a_span_straddling_the_fix_is_triage_not_a_guess():
    # 10.4.0 is affected, 10.4.2 is fixed: neither answer is safe.
    assert in_range("10.4.0~10.4.2", introduced="10.0", fixed="10.4.1") is None
    assert in_range("10.4.0~10.4.2", introduced="10.4.1", fixed="10.5.0") is None


def test_a_span_that_swallows_a_narrow_range_is_triage():
    assert in_range("10.0.0~10.9.0", introduced="10.4.0", fixed="10.4.2") is None


def test_an_excluded_lower_bound_counts_as_below_the_range():
    # the span ends at the excluded start: still outside, and on the low side
    assert in_range("1.0~2.0", start_excluding="2.0", end_excluding="3.0") is False


def test_a_span_against_a_tag_set_is_only_yes_when_unanimous():
    tags = ["v1.0.0", "v1.0.1", "v1.0.2"]
    assert in_tag_set("1.0.0~1.0.2", tags) is True
    assert in_tag_set("0.9.0~2.0.0", tags) is None


def test_a_date_tag_is_orderable_and_a_hash_is_not():
    assert is_orderable("20250612")
    assert not is_orderable("43cc05a9bcf7")
    assert not is_orderable("git-43cc05a9bcf7")


def test_empty_submodules_are_reported(tmp_path: Path):
    (tmp_path / ".gitmodules").write_text(
        '[submodule "lwip"]\n\tpath = components/lwip\n\turl = https://x/y\n'
        '[submodule "full"]\n\tpath = components/full\n\turl = https://x/z\n'
        '[submodule "gone"]\n\tpath = components/gone\n\turl = https://x/w\n')
    (tmp_path / "components" / "lwip").mkdir(parents=True)
    (tmp_path / "components" / "full").mkdir(parents=True)
    (tmp_path / "components" / "full" / "a.c").write_text("int a;\n")
    assert empty_submodules(tmp_path) == ["components/gone", "components/lwip"]


def test_scan_says_when_submodules_are_empty(tmp_path: Path, rules_dir):
    from gangmu.rules.loader import load_rules
    from gangmu.scan import scan
    (tmp_path / ".gitmodules").write_text(
        '[submodule "lwip"]\n\tpath = components/lwip\n\turl = https://x/y\n')
    (tmp_path / "components" / "lwip").mkdir(parents=True)
    result = scan(tmp_path, load_rules(rules_dir))
    assert any("components/lwip" in n and "empty" in n for n in result.notes)
