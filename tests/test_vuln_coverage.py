"""CPE-channel coverage. Synthetic records only (CVE-2099-... are not real)."""

import json

from gangmu.vuln import Candidate
from gangmu.vuln.coverage import coverage


def _nvd(cve_id, published, status, cpes):
    configs = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": c,
                                         "versionEndExcluding": "2.0"} for c in cpes]}]}] \
        if cpes else []
    return {"cve": {"id": cve_id, "published": published + "T00:00:00.000",
                    "vulnStatus": status, "descriptions": [], "configurations": configs}}


def _osv(osv_id, alias, purl):
    return {"id": osv_id, "aliases": [alias] if alias else [],
            "affected": [{"package": {"purl": purl}, "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}


LWIP = "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*"


def test_purl_only_findings_are_split_by_what_nvd_says(tmp_path):
    db = tmp_path / "db"
    db.mkdir()
    (db / "nvd.json").write_text(json.dumps({"vulnerabilities": [
        _nvd("CVE-2099-0001", "2026-05-01", "Not Scheduled", []),          # no CPE
        _nvd("CVE-2099-0002", "2026-01-10", "Analyzed", [LWIP]),           # both channels
        _nvd("CVE-2099-0003", "2026-06-01", "Deferred",
             ["cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"]),                   # other product
        _nvd("CVE-2099-0004", "2026-02-01", "Awaiting Analysis", []),      # unrelated
    ]}), encoding="utf-8")
    (db / "osv.json").write_text(json.dumps([
        _osv("GHSA-aaaa", "CVE-2099-0001", "pkg:generic/lwip"),
        _osv("GHSA-bbbb", "CVE-2099-0002", "pkg:generic/lwip"),
        _osv("GHSA-cccc", "CVE-2099-0003", "pkg:generic/lwip"),
        _osv("GHSA-dddd", "CVE-2099-0005", "pkg:generic/lwip"),            # not in NVD
        _osv("GHSA-eeee", None, "pkg:generic/lwip"),                       # no CVE id
    ]), encoding="utf-8")
    candidate = Candidate(name="lwIP", directory="components/lwip", version="1.4.0",
                          cpes=[LWIP], purls=["pkg:generic/lwip"])

    report = coverage([candidate], db, cutoff="2026-04-15")

    f = report["findings"]
    assert f["found_by_both"] == 1 and f["found_by_cpe"] == 1
    assert f["purl_only_missed_by_cpe"] == 3
    assert f["advisories_without_cve_id"] == 1
    assert report["purl_only_cves"] == ["CVE-2099-0001", "CVE-2099-0003", "CVE-2099-0005"]
    by_record = report["purl_only_by_nvd_record"]
    assert by_record["on/after cutoff | NVD lists it, no CPE configuration"] == 1
    assert by_record["on/after cutoff | NVD lists CPEs for other products only"] == 1
    assert by_record["unknown date | not in the NVD mirror"] == 1
    assert report["purl_only_by_vuln_status"]["on/after cutoff | Not Scheduled"] == 1
    # the totals see the unrelated record too, which the ordinary loader would drop
    assert report["nvd_totals"]["records"] == {"before cutoff": 2, "on/after cutoff": 2}
    assert report["nvd_totals"]["has_cpe_configuration"]["on/after cutoff | False"] == 1
