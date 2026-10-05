"""One lwIP signature, several directory layouts.

``generic/lwip`` expects upstream's ``src/`` level; ``generic/lwip-flat`` is for
SDKs that dropped it (LuatOS ``components/network/lwip22``); the ESP-IDF rule
(in a commercial rule pack, so present only when that pack is loaded) uses its own
copy of the same sidecar. Code segmentation must treat those as one signature,
not as code shared between components.
"""

from pathlib import Path

from gangmu.match import MatchEngine
from gangmu.rules.loader import load_rules

from community import REPO_RULES, needs_rules

pytestmark = needs_rules
FREE_LWIP_RULES = ("generic/lwip", "generic/lwip-flat")
ESP_IDF_LWIP = "espressif/esp-idf/lwip"       # in a commercial rule pack, not in the free rule base


def test_rules_sharing_one_sidecar_do_not_segment_each_other_away():
    rules = {r.id: r for r in load_rules(REPO_RULES)}
    lwip_rules = FREE_LWIP_RULES + ((ESP_IDF_LWIP,) if ESP_IDF_LWIP in rules else ())
    assert len({rules[i].functions.sha256 for i in lwip_rules}) == 1
    engine = MatchEngine(load_rules(REPO_RULES))
    engine.segment_rule_base()
    for rule_id in lwip_rules:
        signature = next(r for r in engine.rulebase if r.id == rule_id).functions.load()
        assert len(signature.application_hashes) > 0.99 * len(signature.hashes), rule_id


def test_flat_layout_has_its_own_paths_and_the_same_probe_result():
    rules = {r.id: r for r in load_rules(REPO_RULES)}
    flat = rules["generic/lwip-flat"]
    assert flat.source.subdir == "src"
    assert "src/**/*.c" not in flat.include
    assert "core/**/*.c" in flat.include
    assert [p.file for p in flat.probes] == ["include/lwip/init.h"]
