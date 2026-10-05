import gzip
import json
import lzma

import pytest

from gangmu.cli import main
from gangmu.vuln.model import Advisory, Match
from gangmu.vuln.threat import (ThreatData, annotate, fetch_threat, load_threat,
                                risk_key)
from gangmu.vuln.vex import to_vex

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2021-0001", "dateAdded": "2022-01-10", "dueDate": "2022-01-24",
     "knownRansomwareCampaignUse": "Known"}]}
EPSS = ("#model_version:v2025.03.14,score_date:2026-10-04T00:00:00Z\n"
        "cve,epss,percentile\nCVE-2021-0001,0.9,0.99\nCVE-2021-0002,0.2,0.7\n")


def _get(url):
    if "kev" in url or "known" in url:
        return json.dumps(KEV).encode()
    return gzip.compress(EPSS.encode())


def _m(cve, cvss=5.0):
    return Match(advisory=Advisory(id=cve, source="nvd", cvss=cvss), component="lwip",
                 directory="lwip", version="2.1.0", channel="cpe", matched_on="x")


def test_fetch_then_load_round_trip(tmp_path):
    assert fetch_threat(tmp_path, get=_get) == (1, 2)
    t = load_threat(tmp_path)
    assert t.kev["CVE-2021-0001"]["ransomware"] is True
    assert t.epss["CVE-2021-0002"] == (0.2, 0.7)
    assert t.epss_date == "2026-10-04T00:00:00Z"


def test_bad_download_keeps_previous_copy(tmp_path):
    fetch_threat(tmp_path, get=_get)
    with pytest.raises(ValueError):
        fetch_threat(tmp_path, get=lambda u: b'{"vulnerabilities": []}')
    assert "CVE-2021-0001" in load_threat(tmp_path).kev


def test_missing_or_damaged_files_are_empty(tmp_path):
    assert not load_threat(tmp_path)
    (tmp_path / "threat").mkdir()
    (tmp_path / "threat" / "epss.csv.xz").write_bytes(b"not xz")
    (tmp_path / "threat" / "kev.jsonl").write_text("{broken")
    assert not load_threat(tmp_path)


def test_annotate_and_order_by_risk():
    a, b, c = _m("CVE-2021-0002", 9.8), _m("CVE-2021-0001", 4.0), _m("CVE-2021-0003", 9.9)
    t = ThreatData(kev={"CVE-2021-0001": {"added": "d", "due": "e"}},
                   epss={"CVE-2021-0002": (0.2, 0.7)})
    assert annotate([a, b, c], t) == 1
    assert [m.advisory.id for m in sorted([a, b, c], key=risk_key)] == [
        "CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"]


def test_alias_is_matched():
    m = _m("GHSA-xxxx")
    m.advisory.aliases = ["CVE-2021-0001"]
    annotate([m], ThreatData(kev={"CVE-2021-0001": {"added": "d"}}))
    assert m.kev


def test_output_carries_signals():
    m = _m("CVE-2021-0001")
    m.kev, m.epss = {"added": "2022-01-10", "due": "2022-01-24", "ransomware": True}, (0.9, 0.99)
    assert m.to_dict()["knownExploited"]["ransomware"] is True
    props = {p["name"]: p["value"] for p in to_vex([m])["vulnerabilities"][0]["properties"]}
    assert props["gangmu:knownExploited"] == "true"
    assert props["gangmu:epssScore"] == "0.90000"


def _db(tmp_path):
    feed = {"vulnerabilities": [
        {"cve": {"id": cve, "descriptions": [{"lang": "en", "value": "s"}],
                 "configurations": [{"nodes": [{"cpeMatch": [{
                     "vulnerable": True,
                     "criteria": "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "2.2.0"}]}]}]}}
        for cve in ("CVE-2021-0002", "CVE-2021-0001")]}
    db = tmp_path / "db"
    db.mkdir()
    (db / "nvd-2021.json").write_text(json.dumps(feed))
    return db


def _sbom(tmp_path):
    p = tmp_path / "sbom.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{"type": "library", "name": "lwip", "version": "2.1.0",
                        "bom-ref": "lwip", "cpe": "cpe:2.3:a:lwip_project:lwip:2.1.0:*:*:*:*:*:*:*",
                        "properties": [{"name": "gangmu:directory", "value": "lwip"}]}]}))
    return p


def test_vuln_ranks_and_fail_on_kev(tmp_path, capsys):
    db, sbom = _db(tmp_path), _sbom(tmp_path)
    fetch_threat(db, get=_get)
    assert main(["vuln", str(sbom), "--db", str(db), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [m["id"] for m in out["matches"]] == ["CVE-2021-0001", "CVE-2021-0002"]
    assert out["matches"][0]["knownExploited"]["dateAdded"] == "2022-01-10"
    assert main(["vuln", str(sbom), "--db", str(db), "--fail-on", "kev",
                 "--format", "json"]) == 1
    capsys.readouterr()
    assert main(["vuln", str(sbom), "--db", str(db), "--no-threat",
                 "--fail-on", "kev", "--format", "json"]) == 0


def test_vuln_without_threat_files_is_unchanged(tmp_path, capsys):
    db, sbom = _db(tmp_path), _sbom(tmp_path)
    assert main(["vuln", str(sbom), "--db", str(db), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert all("knownExploited" not in m and "epss" not in m for m in out["matches"])
