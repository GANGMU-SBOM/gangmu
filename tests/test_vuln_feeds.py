"""Reading a full NVD mirror: every format, one record at a time, selectively.

A third of a million records is not something to ``json.load`` and turn into
advisories just to look up a dozen products. These tests pin that the
streaming reader returns exactly what a whole-file read would, across the
formats real mirrors ship, and that the product filter drops nothing an SBOM
could match.
"""

import gzip
import json
import lzma
import shutil
from pathlib import Path

import pytest

from gangmu.vuln import (Candidate, Wanted, iter_feed_items, load_database, match,
                         wanted_for)
from gangmu.vuln import sources

DB = Path(__file__).resolve().parent / "fixtures" / "advisories"


def _records():
    return json.loads((DB / "nvd-sample.json").read_text())["vulnerabilities"]


def _write(path: Path, doc: dict) -> Path:
    text = json.dumps(doc, indent=1)
    if path.name.endswith(".xz"):
        with lzma.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    elif path.name.endswith(".gz"):
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        path.write_text(text)
    return path


@pytest.mark.parametrize("name,doc", [
    ("api.json", lambda r: {"resultsPerPage": len(r), "vulnerabilities": r}),
    ("year.json.xz", lambda r: {"cve_count": len(r),            # fkie-cad mirror
                                "cve_items": [x["cve"] for x in r]}),
    ("legacy.json.gz", lambda r: {"CVE_data_type": "CVE", "CVE_Items": r}),
])
def test_every_feed_format_streams_the_same_records(tmp_path, monkeypatch, name, doc):
    records = _records()
    path = _write(tmp_path / name, doc(records))
    monkeypatch.setattr(sources, "_CHUNK", 7)     # records straddle every read
    got = [item.get("cve", item) for item in iter_feed_items(path)]
    assert got == [r["cve"] for r in records]


def test_an_osv_record_is_not_mistaken_for_a_feed():
    assert list(iter_feed_items(DB / "osv-sample.json")) == []


def test_the_filter_keeps_exactly_what_the_matcher_can_use():
    everything = load_database(DB)
    lwip = Candidate(name="lwip", version="2.1.3", directory="components/lwip",
                     cpes=["cpe:2.3:a:lwip_project:lwip:2.1.3:*:*:*:*:*:*:*"],
                     purls=["pkg:github/littlefs-project/littlefs@2.5.0"])
    wanted = wanted_for([lwip])
    assert wanted == Wanted(cpe_keys=frozenset({"a:lwip_project:lwip"}),
                            purl_keys=frozenset({"pkg:github/littlefs-project/littlefs"}))
    selected = load_database(DB, wanted)
    assert 0 < len(selected) < len(everything)
    full = sorted((m.advisory.id, m.state) for m in match([lwip], everything,
                                                           include_not_affected=True))
    kept = sorted((m.advisory.id, m.state) for m in match([lwip], selected,
                                                          include_not_affected=True))
    assert kept == full


def test_parallel_loading_equals_serial(tmp_path, monkeypatch):
    records = _records()
    for i in range(3):
        _write(tmp_path / f"CVE-{2020 + i}.json.xz", {"cve_items": [
            dict(r["cve"], id=f"{r['cve']['id']}-{i}") for r in records]})
    shutil.copy(DB / "osv-sample.json", tmp_path)
    monkeypatch.setattr(sources, "_PARALLEL_BYTES", 0)
    serial = [a.id for a in load_database(tmp_path)]
    parallel = [a.id for a in load_database(tmp_path, jobs=2)]
    osv = len(json.loads((DB / "osv-sample.json").read_text()))
    assert parallel == serial and len(serial) == 3 * len(records) + osv


def test_an_unreadable_feed_is_reported_not_silently_clean(tmp_path):
    (tmp_path / "CVE-2024.json.xz").write_bytes(b"not xz at all")
    with pytest.warns(UserWarning, match="CVE-2024.json.xz"):
        assert load_database(tmp_path) == []


def test_nvd_vuln_status_is_kept():
    from gangmu.vuln.sources import advisory_from_nvd
    item = {"cve": {"id": "CVE-2026-0001", "vulnStatus": "Awaiting Analysis",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "configurations": [{"nodes": [{"cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"}]}]}]}}
    adv = advisory_from_nvd(item)
    assert adv is not None and adv.vuln_status == "Awaiting Analysis"
    del item["cve"]["vulnStatus"]
    assert advisory_from_nvd(item).vuln_status is None
