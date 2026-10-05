"""国内合规：工信部报送草稿与双重义务提示。

这里要守住的行为是克制：工具标出冲突，不下法律结论。
"""

import pytest
import yaml

from gangmu.config import Config
from gangmu.cn import CONFLICT_NOTICE, check_dual_regime, draft_miit_report
from gangmu.vuln.cn_sources import _parse_entry, load_cn_database


def _config(**extra):
    raw = {
        "product": {"name": "工业网关", "version": "3.4.1"},
        "manufacturer": {"name": "某公司"},
        "china": {"in_china_market": True, "model": "AGW-200",
                  "contact": "张伟 / sec@example.invalid"},
    }
    for section, values in extra.items():
        raw.setdefault(section, {}).update(values)
    return Config(raw=raw)


VEX = {
    "components": [{"bom-ref": "c1", "name": "lwIP", "version": "2.2.0"}],
    "vulnerabilities": [{
        "id": "CVE-2027-10001", "affects": [{"ref": "c1"}],
        "description": "越界读取", "ratings": [{"severity": "high"}],
        "analysis": {"state": "exploitable", "detail": "版本落在区间内"}}],
}


def test_the_draft_uses_the_regulation_deadline_and_platform():
    draft = draft_miit_report(_config(), "CVE-2027-10001", vex=VEX)
    assert "2 日内" in draft.deadline
    assert "cstis.cn" in draft.to_markdown()


def test_the_required_fields_follow_article_seven():
    """产品名称、型号、版本，技术特点、危害程度、影响范围。"""
    labels = [f.label for f in draft_miit_report(_config(), "CVE-2027-10001").fields]
    for required in ("产品名称", "产品型号", "产品版本",
                     "漏洞的技术特点", "危害程度", "影响范围"):
        assert required in labels


def test_the_affected_component_is_filled_from_the_sbom():
    draft = draft_miit_report(_config(), "CVE-2027-10001", vex=VEX)
    values = {f.label: f.value for f in draft.fields}
    assert values["受影响的开源组件及版本"] == "lwIP 2.2.0"
    assert values["危害程度"] == "高危"


def test_a_missing_field_is_marked_not_invented():
    draft = draft_miit_report(_config(product={"version": ""}), "CVE-2027-10001")
    assert "产品版本" in [f.label for f in draft.missing]
    assert "— 缺失 —" in draft.to_markdown()


def test_the_conflict_notice_appears_when_the_product_also_ships_to_the_eu():
    draft = draft_miit_report(_config(market={"member_states": ["DE"]}),
                              "CVE-2027-10001", vex=VEX)
    text = draft.to_markdown()
    assert "第九条第（七）项" in text
    assert "需法务确认" in text


def test_the_notice_does_not_tell_anyone_what_to_do():
    """工具提示冲突，不给法律意见。"""
    assert "不下结论" in CONFLICT_NOTICE
    assert "不判断是否构成冲突" in CONFLICT_NOTICE


def test_dual_regime_check_names_the_difference_in_trigger():
    notes = check_dual_regime(_config(market={"member_states": ["DE", "FR"]}))
    joined = "\n".join(notes)
    assert "2 日内" in joined and "24 小时" in joined
    assert "不以被积极利用为前提" in joined


def test_no_conflict_notice_for_a_domestic_only_product():
    assert check_dual_regime(_config()) == []


def test_an_unknown_stage_is_refused():
    with pytest.raises(ValueError):
        draft_miit_report(_config(), "CVE-2027-10001", stage="whenever")


# ----------------------------------------------- 国内漏洞库

def test_a_cnnvd_entry_parses_with_its_chinese_fields():
    entry = _parse_entry({
        "cnnvdId": "CNNVD-202701-001", "vulnName": "lwIP 越界读取漏洞",
        "vulnDesc": "存在越界读取", "severity": "高危",
        "cveId": "CVE-2027-10001", "affectedProduct": "lwIP 2.2.0"}, "cnnvd")
    assert entry.id == "CNNVD-202701-001"
    assert entry.cve_ids == ["CVE-2027-10001"]
    assert entry.severity == "high" and entry.severity_cn == "高危"


def test_an_entry_without_a_cve_still_parses():
    entry = _parse_entry({"cnvdId": "CNVD-2027-00001", "漏洞名称": "某国产组件漏洞",
                          "危害级别": "中危", "影响产品": "RT-Thread"}, "cnvd")
    assert entry.cve_ids == []
    assert entry.severity == "medium"


def test_a_missing_directory_is_an_explicit_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_cn_database(tmp_path / "nope")


def test_unparseable_files_are_skipped_not_fatal(tmp_path):
    (tmp_path / "broken.json").write_text("{not json")
    (tmp_path / "cnnvd.json").write_text(
        '[{"cnnvdId": "CNNVD-1", "vulnName": "x", "severity": "低危"}]')
    entries = load_cn_database(tmp_path)
    assert [e.id for e in entries] == ["CNNVD-1"]
