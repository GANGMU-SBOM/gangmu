"""CNNVD / CNVD exports: JSON, XML and CSV, UTF-8 and GBK.

The fixtures under tests/fixtures/cn are SYNTHETIC. They are shaped after what
CNNVD and CNVD publish as far as that is publicly documented, but no real export
was available when they were written (both sites reject anonymous access), so
they prove the parser's behaviour, not that a given real export parses. That is
what ``gangmu cn-db-check`` is for.
"""

import shutil
import warnings
from pathlib import Path

import pytest

from gangmu.cli import main
from gangmu.vuln.cn_sources import load_cn_database, load_cn_report

FIX = Path(__file__).resolve().parent / "fixtures" / "cn"


@pytest.fixture
def entries():
    return {e.id: e for e in load_cn_database(FIX)}


def test_every_format_in_the_fixture_directory_loads(entries):
    assert set(entries) == {
        "CNNVD-202701-001", "CNNVD-202701-002", "CNNVD-202701-003",
        "CNVD-2027-00001", "CNVD-2027-00002", "CNVD-2027-00003"}


def test_cnnvd_xml_fields(entries):
    e = entries["CNNVD-202701-001"]
    assert e.title == "lwIP 越界读取漏洞"
    assert e.cve_ids == ["CVE-2027-10001"]
    assert e.severity == "high" and e.severity_cn == "高危"
    assert "lwIP 2.0.0 - 2.2.0" in e.affected_text
    assert e.references == ["https://example.invalid/lwip-advisory"]
    assert e.published == "2027-01-05"
    assert e.source == "cnnvd"


def test_a_cnnvd_entry_without_a_cve_keeps_its_chinese_severity(entries):
    e = entries["CNNVD-202701-002"]
    assert e.cve_ids == [] and e.severity == "critical"      # 超危


def test_cnvd_xml_uses_its_own_spelling_and_nesting(entries):
    e = entries["CNVD-2027-00001"]
    assert e.cve_ids == ["CVE-2027-10002"]
    assert e.severity == "medium"                  # element is spelled <serverity>
    assert "某国产组件 3.1" in e.affected_text and "某国产组件 3.2" in e.affected_text
    assert e.source == "cnvd"


def test_csv_with_chinese_headers_and_quoting(entries):
    e = entries["CNVD-2027-00002"]
    assert e.cve_ids == ["CVE-2027-10003"] and e.severity == "high"
    quoted = entries["CNVD-2027-00003"]
    assert quoted.title == "含逗号, 与引号的名称"
    assert '"引号"' in quoted.summary


def test_a_gbk_csv_is_read_not_skipped(tmp_path):
    shutil.copy(FIX / "cnvd-sample-gbk.csv", tmp_path / "cnvd.csv")
    got = load_cn_database(tmp_path)
    assert [e.id for e in got] == ["CNVD-2027-00002"]
    assert got[0].title == "某国产 TLS 库证书校验绕过"


def test_json_wrapped_in_a_data_key(entries):
    assert entries["CNNVD-202701-003"].severity == "high"


def test_the_id_prefix_beats_the_file_name(tmp_path):
    (tmp_path / "vulns.json").write_text('[{"id": "CNVD-2027-9", "title": "x"}]')
    assert load_cn_database(tmp_path)[0].source == "cnvd"


def test_field_names_ignore_case_and_separators(tmp_path):
    (tmp_path / "a.json").write_text(
        '[{"CNNVD_ID": "CNNVD-1", "Vuln-Name": "n", "HAZARD LEVEL": "低危"}]')
    e = load_cn_database(tmp_path)[0]
    assert e.title == "n" and e.severity == "low"


# ------------------------------------------------- nothing is dropped silently

def test_an_unreadable_file_is_reported_not_swallowed(tmp_path):
    (tmp_path / "broken.xml").write_text("<cnnvd><entry>")
    (tmp_path / "ok.json").write_text('[{"id": "CNNVD-1"}]')
    report = load_cn_report(tmp_path)
    broken = next(f for f in report.files if f.path.name == "broken.xml")
    assert broken.error and "unreadable xml" in broken.error
    assert [e.id for e in report.entries] == ["CNNVD-1"]
    with pytest.warns(UserWarning, match="broken.xml"):
        load_cn_database(tmp_path)


def test_records_without_an_id_are_counted_and_their_keys_shown(tmp_path):
    (tmp_path / "x.json").write_text(
        '[{"漏洞标识": "A-1", "漏洞标题": "t"}, {"id": "CNNVD-2"}]')
    report = load_cn_report(tmp_path)
    f = report.files[0]
    assert (f.records, f.parsed, f.dropped) == (2, 1, 1)
    assert "漏洞标识" in f.unrecognised_keys
    assert any("no recognisable id" in p for p in report.problems)


def test_a_spreadsheet_is_refused_with_the_way_out(tmp_path):
    (tmp_path / "export.xlsx").write_bytes(b"PK")
    report = load_cn_report(tmp_path)
    assert "CSV" in report.files[0].error


def test_xml_entity_declarations_are_refused(tmp_path):
    (tmp_path / "bomb.xml").write_text(
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x><entry><id>&a;</id></entry></x>')
    report = load_cn_report(tmp_path)
    assert report.files[0].error and not report.entries


# ------------------------------------------------------------------ the CLI

def test_cn_db_check_summarises_each_file(capsys):
    assert main(["cn-db-check", str(FIX)]) == 0
    out = capsys.readouterr().out
    assert "cnnvd-sample.xml" in out and "cnvd-sample.csv" in out
    # 7, not 6: the GBK CSV repeats CNVD-2027-00002 from the UTF-8 one.
    assert "7 advisory(ies)" in out and "cnnvd 3" in out and "cnvd 4" in out


def test_cn_db_check_fails_when_a_file_cannot_be_read(tmp_path, capsys):
    (tmp_path / "ok.json").write_text('[{"id": "CNNVD-1"}]')
    (tmp_path / "bad.json").write_text("{")
    assert main(["cn-db-check", str(tmp_path)]) == 1


def test_cn_db_check_fails_on_an_empty_directory(tmp_path):
    assert main(["cn-db-check", str(tmp_path)]) == 1


def test_vuln_warns_when_the_domestic_database_yields_nothing(tmp_path, capsys):
    bom = tmp_path / "sbom.json"
    bom.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
    (tmp_path / "cn").mkdir()
    (tmp_path / "adv").mkdir()
    assert main(["vuln", str(bom), "--db", str(tmp_path / "adv"),
                 "--cn-db", str(tmp_path / "cn")]) in (0, 1)
    assert "yielded no advisories" in capsys.readouterr().err


# ------------------------------------------------ a real CNNVD export, streamed

REAL = Path(__file__).parent / "fixtures" / "cn-real"
"""Two entries copied unchanged from CNNVD's public year file for 2017 (the
export's own namespace, `cncpe` configuration blocks and all): one OpenSSL
entry with a CVE, and one of the many "details not published" stubs with no
CVE at all. Everything else in `fixtures/cn` is synthetic."""


def test_a_real_cnnvd_entry_parses_with_its_cve_and_cpe_list():
    entries = {e.id: e for e in load_cn_database(REAL)}
    ssl = entries["CNNVD-201701-225"]
    assert ssl.cve_ids and ssl.cve_ids[0].startswith("CVE-")
    assert ssl.severity == "medium" and ssl.severity_cn == "中危"
    assert "openssl:openssl:1.0.1u" in ssl.affected_text.lower()
    stub = entries["CNNVD-201701-881"]
    assert stub.cve_ids == [] and stub.affected_text == ""


def test_keep_limits_what_is_retained_but_not_what_is_counted():
    report = load_cn_report(REAL, keep=lambda entry: bool(entry.cve_ids))
    assert report.parsed == 2 and report.no_cve == 1
    assert [e.id for e in report.entries] == ["CNNVD-201701-225"]
    assert report.sources == {"cnnvd": 2}
    nothing = load_cn_report(REAL, keep=lambda entry: False)
    assert nothing.parsed == 2 and nothing.entries == []


def test_a_truncated_xml_export_is_reported_not_silently_shortened(tmp_path):
    text = (REAL / "cnnvd-excerpt.xml").read_text(encoding="utf-8")
    (tmp_path / "cnnvd-cut.xml").write_text(text[: len(text) // 2], encoding="utf-8")
    report = load_cn_report(tmp_path)
    assert report.files[0].error and "unreadable xml" in report.files[0].error
    assert report.problems


def test_gbk_xml_without_a_prolog_still_loads(tmp_path):
    body = ("<root><entry><vuln-id>CNNVD-201701-999</vuln-id><name>测试 安全漏洞</name>"
            "<severity>高危</severity><other-id><cve-id>CVE-2017-0001</cve-id></other-id>"
            "</entry></root>")
    (tmp_path / "gbk.xml").write_bytes(body.encode("gb18030"))
    entries = load_cn_database(tmp_path)
    assert [e.id for e in entries] == ["CNNVD-201701-999"]
    assert entries[0].title == "测试 安全漏洞"


def test_the_vuln_command_reads_only_what_the_sbom_can_use():
    from gangmu.cli import _cn_keeper
    from gangmu.vuln.cn_sources import CnAdvisory

    entries = {e.id: e for e in load_cn_database(REAL)}
    ssl = entries["CNNVD-201701-225"]

    class Component:
        name = "OpenSSL"

    def matched(cve):
        class Advisory:
            id = cve
            aliases = ()
        class Match:
            advisory = Advisory()
        return Match()

    def entry(**kw):
        base = dict(id="x", source="cnnvd", title="", summary="", severity_cn=None,
                    severity=None, cve_ids=[], affected_text="", published=None,
                    references=[])
        return CnAdvisory(**{**base, **kw})

    keep = _cn_keeper([Component()], [matched(ssl.cve_ids[0])])
    assert keep(ssl)                                        # its CVE was matched
    assert not _cn_keeper([Component()], [matched("CVE-1999-0001")])(ssl)
    assert keep(entry(title="OpenSSL 漏洞"))                 # no CVE, names a component
    assert not keep(entry(title="另一个产品"))                # no CVE, names nothing
