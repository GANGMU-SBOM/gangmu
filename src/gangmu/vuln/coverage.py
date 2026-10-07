"""How much of what an SBOM matches would a CPE-only scanner have found?

``gangmu vuln`` reaches a component by CPE (NVD) and by PURL (OSV). A CVE that
NVD never gave a CPE configuration cannot be found by the first channel at all,
and from 2026-04-15 NVD no longer promises to add one for most CVEs (it enriches
CISA KEV, federal-use and critical-software CVEs first). This module measures the
effect on one SBOM and one local mirror instead of quoting a percentage:

* the findings are computed as usual, then grouped by the channel that found them;
* a finding reached **only** through PURL is one a CPE-only scanner reports as
  clean ("missed by CPE");
* for those CVEs the NVD record is read *before* any filtering -- the ordinary
  loader drops an NVD record with no CPE configuration, which is exactly the
  record this question is about -- to tell "NVD lists it with no CPE" from "NVD
  lists a CPE for another product" and "NVD does not list it";
* NVD totals (by ``vulnStatus``, with and without a CPE configuration, before and
  after the cut-off date) are reported as context.

It counts findings against a version range, not product names, and it does not say
a finding is a true positive: a "missed" CVE still needs a person to confirm it is
real for the firmware.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from .match import Candidate, match as match_vulns, wanted_for
from .model import Advisory, Match
from .sources import FEED_SUFFIXES, _looks_like_feed, iter_feed_items, load_database

DEFAULT_CUTOFF = "2026-04-15"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def cve_ids(advisory: Advisory) -> List[str]:
    return sorted({i for i in [advisory.id, *advisory.aliases] if _CVE.match(i)})


def nvd_meta(item: dict) -> Tuple[Optional[str], Optional[str], Optional[str], FrozenSet[str]]:
    """(cve id, published date, vulnStatus, part:vendor:product keys of its CPEs)."""
    cve = item.get("cve") or item
    cve_id = cve.get("id") or (cve.get("CVE_data_meta") or {}).get("ID")
    published = (cve.get("published") or item.get("publishedDate") or "")[:10] or None
    keys = set()
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = (m.get("criteria") or "").split(":")
                if m.get("vulnerable", True) and len(parts) > 4:
                    keys.add(":".join(parts[2:5]).lower())
    return cve_id, published, cve.get("vulnStatus"), frozenset(keys)


def era(published: Optional[str], cutoff: str) -> str:
    if not published:
        return "unknown date"
    return "on/after cutoff" if published >= cutoff else "before cutoff"


def scan_nvd(db: Path, interest: Set[str], cutoff: str
             ) -> Tuple[Dict[str, tuple], Dict[str, Counter]]:
    """(record metadata for the CVEs in *interest*, totals over every record)."""
    meta: Dict[str, tuple] = {}
    totals: Dict[str, Counter] = {"records": Counter(), "status": Counter(),
                                  "with_cpe": Counter()}
    seen: Set[str] = set()
    files = sorted(p for p in Path(db).rglob("*")
                   if p.is_file() and p.name.lower().endswith(FEED_SUFFIXES)
                   and "threat" not in p.parts)
    for path in files:
        if not _looks_like_feed(path):
            continue
        for item in iter_feed_items(path):
            cve_id, published, status, keys = nvd_meta(item)
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            when = era(published, cutoff)
            totals["records"][when] += 1
            totals["status"][(when, status or "unknown")] += 1
            totals["with_cpe"][(when, bool(keys))] += 1
            if cve_id in interest:
                meta[cve_id] = (published, status, keys)
    return meta, totals


def coverage(candidates: Sequence[Candidate], db: Path,
             cutoff: str = DEFAULT_CUTOFF,
             matches: Optional[Sequence[Match]] = None) -> Dict[str, Any]:
    wanted = wanted_for(candidates)
    if matches is None:
        matches = match_vulns(candidates, load_database(Path(db), wanted))
    cpe_keys = wanted.cpe_keys

    by_cve: Dict[str, Set[str]] = {}       # CVE id -> channels that found it
    no_cve: Set[str] = set()               # advisory ids with no CVE id at all
    for m in matches:
        ids = cve_ids(m.advisory)
        if not ids:
            no_cve.add(m.advisory.id)
        for i in ids:
            by_cve.setdefault(i, set()).add(m.channel)

    purl_only = {c for c, ch in by_cve.items() if ch == {"purl"}}
    meta, totals = scan_nvd(Path(db), set(by_cve), cutoff)

    def classify(cve_id: str) -> str:
        record = meta.get(cve_id)
        if record is None:
            return "not in the NVD mirror"
        _published, _status, keys = record
        if not keys:
            return "NVD lists it, no CPE configuration"
        if not keys & cpe_keys:
            return "NVD lists CPEs for other products only"
        return "NVD has a CPE for this product (version range differs)"

    missed = Counter()
    missed_by_status = Counter()
    for c in purl_only:
        published, status, _keys = meta.get(c, (None, None, frozenset()))
        when = era(published, cutoff)
        missed[(when, classify(c))] += 1
        missed_by_status[(when, status or "unknown")] += 1

    flat = lambda counter: {" | ".join(map(str, k)) if isinstance(k, tuple) else k: v
                            for k, v in sorted(counter.items(), key=lambda kv: str(kv[0]))}
    return {
        "cutoff": cutoff,
        "findings": {
            "cve_ids": len(by_cve),
            "found_by_cpe": sum(1 for ch in by_cve.values() if "cpe" in ch),
            "found_by_purl": sum(1 for ch in by_cve.values() if "purl" in ch),
            "found_by_both": sum(1 for ch in by_cve.values() if len(ch) == 2),
            "purl_only_missed_by_cpe": len(purl_only),
            "advisories_without_cve_id": len(no_cve),
        },
        "purl_only_by_nvd_record": flat(missed),
        "purl_only_by_vuln_status": flat(missed_by_status),
        "nvd_totals": {"records": flat(totals["records"]),
                       "by_vuln_status": flat(totals["status"]),
                       "has_cpe_configuration": flat(totals["with_cpe"])},
        "purl_only_cves": sorted(purl_only),
    }
