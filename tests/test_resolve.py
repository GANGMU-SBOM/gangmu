"""Which of two equally supported rules names a directory."""

from gangmu.model import Evidence, Finding, Technique
from gangmu.rules.resolve import resolve


def _finding(rule_id, path_match):
    # Same upstream, same evidence, same version: nothing but the rule differs.
    return Finding(
        directory="vendored_lib", rule_id=rule_id, upstream_name="lwIP",
        version="2.1.3", version_source="probe",
        identity_confidence=0.95, version_confidence=0.85, path_match=path_match,
        evidence=[Evidence(Technique.AST_FINGERPRINT, 0.95, "1842 of 1842 functions"),
                  Evidence(Technique.SOURCE_CODE_ANALYSIS, 0.85, "version read from init.h")])


SPECIFICITY = {"generic/lwip": 1, "espressif/esp-idf/lwip": 6}


def test_a_vendor_rule_outside_its_own_paths_does_not_name_a_pristine_copy():
    # Pristine upstream lwIP 2.1.3 under a neutral name: both rules reach the
    # identity ceiling and neither is at home. The general rule must win, or a
    # plain upstream copy is labelled as Espressif's fork.
    winners = resolve([_finding("espressif/esp-idf/lwip", 0),
                       _finding("generic/lwip", 0)], SPECIFICITY)
    assert [w.rule_id for w in winners] == ["generic/lwip"]


def test_the_vendor_rule_still_wins_at_its_own_path():
    winners = resolve([_finding("generic/lwip", 0),
                       _finding("espressif/esp-idf/lwip", 2)], SPECIFICITY)
    assert [w.rule_id for w in winners] == ["espressif/esp-idf/lwip"]


def test_a_vendor_rule_wins_when_only_the_directory_name_agrees():
    winners = resolve([_finding("generic/lwip", 0),
                       _finding("espressif/esp-idf/lwip", 1)], SPECIFICITY)
    assert [w.rule_id for w in winners] == ["espressif/esp-idf/lwip"]
