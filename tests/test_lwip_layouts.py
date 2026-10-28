"""One lwIP signature, several directory layouts.

``generic/lwip`` expects upstream's ``src/`` level, and the scan reads it without
``src/`` where an SDK dropped it (LuatOS ``components/network/lwip22``). Older rule
bases carry ``generic/lwip-flat`` for that layout instead; the ESP-IDF rule
(in a commercial rule pack, so present only when that pack is loaded) uses its own
copy of the same sidecar. Code segmentation must treat those as one signature,
not as code shared between components.
"""


from gangmu.core.globbing import matches
from gangmu.match import MatchEngine
from gangmu.rules.loader import load_rules

from community import REPO_RULES, needs_rules

pytestmark = needs_rules
FREE_LWIP_RULES = ("generic/lwip", "generic/lwip-flat")
ESP_IDF_LWIP = "espressif/esp-idf/lwip"       # in a commercial rule pack, not in the free rule base


def test_rules_sharing_one_sidecar_do_not_segment_each_other_away():
    rules = {r.id: r for r in load_rules(REPO_RULES)}
    lwip_rules = tuple(i for i in FREE_LWIP_RULES + (ESP_IDF_LWIP,) if i in rules)
    assert "generic/lwip" in lwip_rules
    assert len({rules[i].functions.sha256 for i in lwip_rules}) == 1
    engine = MatchEngine(load_rules(REPO_RULES))
    engine.segment_rule_base()
    sidecar = rules["generic/lwip"].functions.sha256
    elsewhere = set()          # functions some rule with another sidecar holds too
    for rule in engine.rulebase:
        if rule.functions is not None and rule.functions.sha256 != sidecar:
            try:
                elsewhere |= rule.functions.load().hash_set
            except Exception:                           # noqa: BLE001
                continue
    for rule_id in lwip_rules:
        signature = next(r for r in engine.rulebase if r.id == rule_id).functions.load()
        borrowed = signature.hash_set - signature.application_hashes
        # Only code another component also carries (Mbed OS's lwIP glue) is given up;
        # the rules sharing the sidecar never take it from each other.
        assert borrowed <= elsewhere, rule_id
        assert len(signature.application_hashes) > 0.9 * len(signature.hashes), rule_id


def test_flat_layout_has_its_own_paths_and_the_same_probe_result():
    rules = {r.id: r for r in load_rules(REPO_RULES)}
    if "generic/lwip-flat" not in rules:
        # The rule base relies on the scan reading generic/lwip without src/ instead.
        assert "src/core/init.c" in rules["generic/lwip"].marker_files
        return
    flat = rules["generic/lwip-flat"]
    assert flat.source.subdir == "src"
    # Its paths start below src/: core/ and include/ sit in the component directory.
    assert not any(p.startswith("src/") for p in flat.include)
    assert matches("core/init.c", flat.include)
    assert matches("include/lwip/init.h", flat.include)
    assert [p.file for p in flat.probes] == ["include/lwip/init.h"]
