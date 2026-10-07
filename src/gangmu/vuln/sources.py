"""Where advisories come from.

Two channels, deliberately:

* **CPE, from NVD.** The channel every compliance process expects.
* **PURL, from OSV.** The channel that actually works for embedded code. Of the
  first eighteen rules in this repository, ten describe components with **no CPE
  at all** -- littlefs, zcbor, FatFs, a GigaDevice HAL, OpenThread, SPIFFS, TLSF.
  A matcher built on CPE alone would report those as clean, which is the exact
  failure mode this project exists to avoid.

OSV addresses C projects two ways: ``package.purl``, and ``GIT`` ranges that
name a repository and list the affected release tags (records imported from
CVEs have no purl at all). Both land on the same ``pkg:github/owner/name`` key.

Both are read from a local directory, because an SBOM pipeline that needs the
public internet at report time is not one you can run inside a factory network
or during the 24-hour window after a vulnerability is disclosed. Fetching is a
separate step, done when the network is there.
"""

from __future__ import annotations

import gzip
import json
import lzma
import re
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional

from .match import cpe_product_key, purl_key, purl_from_package, purl_from_repo
from .model import Advisory


def _cvss_from_nvd(metrics: dict) -> Optional[float]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []) or []:
            data = entry.get("cvssData") or {}
            if data.get("baseScore") is not None:
                return float(data["baseScore"])
    return None


def _severity_from_nvd(metrics: dict) -> Optional[str]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key, []) or []:
            data = entry.get("cvssData") or {}
            if data.get("baseSeverity"):
                return str(data["baseSeverity"]).lower()
    return None


_ARRAY_KEYS = ("vulnerabilities", "CVE_Items", "cve_items")
_ARRAY_START = re.compile(r'"(%s)"\s*:\s*\[' % "|".join(_ARRAY_KEYS))
_CHUNK = 1 << 20
FEED_SUFFIXES = (".json", ".json.xz", ".json.gz")


@dataclass(frozen=True)
class Wanted:
    """The products an SBOM can match, so a full feed can be read selectively.

    The whole NVD is about 330,000 records. Building every one of them into an
    advisory to then look up a dozen products is what made a real mirror
    unusable; skipping the records that name none of the SBOM's products before
    anything is built keeps memory at the size of the answer.
    """

    cpe_keys: FrozenSet[str] = frozenset()       # part:vendor:product
    purl_keys: FrozenSet[str] = frozenset()      # pkg:type/namespace/name


def _open_text(path: Path):
    name = path.name.lower()
    if name.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8")
    if name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")


def iter_feed_items(path: Path) -> Iterator[dict]:
    """Records of an NVD feed, one at a time, without loading the file whole.

    Reads NVD 2.0 feeds and API responses (``vulnerabilities``), the legacy 1.1
    feeds (``CVE_Items``) and the fkie-cad GitHub mirror of NVD
    (``cve_items``), plain or ``.xz``/``.gz``. Anything else -- an OSV record --
    is not a feed and yields nothing.
    """
    path = Path(path)
    decoder = json.JSONDecoder()
    with _open_text(path) as fh:
        buf = fh.read(_CHUNK)
        found = _ARRAY_START.search(buf)
        while found is None and len(buf) < 16 * _CHUNK:
            more = fh.read(_CHUNK)
            if not more:
                return
            buf += more
            found = _ARRAY_START.search(buf)
        if found is None:
            return
        pos = found.end()
        eof = False
        while True:
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos >= len(buf):
                if eof:
                    return
                more = fh.read(_CHUNK)
                eof = not more
                buf, pos = buf[pos:] + more, 0
                continue
            if buf[pos] == "]":
                return
            try:
                item, end = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                if eof:
                    raise
                more = fh.read(max(_CHUNK, len(buf) - pos))
                eof = not more
                buf, pos = buf[pos:] + more, 0
                continue
            yield item
            pos = end
            if pos > _CHUNK:
                buf, pos = buf[pos:], 0


def _nvd_cpe_ranges(cve: dict) -> List[dict]:
    ranges = []
    for config in cve.get("configurations", []) or []:
        nodes = config.get("nodes", []) if isinstance(config, dict) else []
        for node in nodes or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable", True):
                    continue
                criteria = match.get("criteria")
                if not criteria:
                    continue
                ranges.append({
                    "cpe": criteria,
                    "start_including": match.get("versionStartIncluding"),
                    "start_excluding": match.get("versionStartExcluding"),
                    "end_including": match.get("versionEndIncluding"),
                    "end_excluding": match.get("versionEndExcluding"),
                })
    return ranges


def advisory_from_nvd(item: dict, wanted: Optional[Wanted] = None) -> Optional[Advisory]:
    cve = item.get("cve") or item
    cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
    if not cve_id:
        return None
    ranges = _nvd_cpe_ranges(cve)
    if wanted is not None and not any(cpe_product_key(r["cpe"]) in wanted.cpe_keys
                                      for r in ranges):
        return None
    summary = ""
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            summary = desc.get("value", "")
            break
    metrics = cve.get("metrics") or {}
    return Advisory(
        id=cve_id, source="nvd", summary=summary,
        severity=_severity_from_nvd(metrics), cvss=_cvss_from_nvd(metrics),
        references=[r.get("url") for r in cve.get("references", []) or []
                    if r.get("url")],
        cpe_ranges=ranges, vuln_status=cve.get("vulnStatus"))


def load_nvd(path: Path, wanted: Optional[Wanted] = None) -> List[Advisory]:
    """Read an NVD feed (see ``iter_feed_items`` for the formats)."""
    out: List[Advisory] = []
    for item in iter_feed_items(Path(path)):
        advisory = advisory_from_nvd(item, wanted)
        if advisory is not None:
            out.append(advisory)
    return out


def _event_intervals(events: List[dict]) -> List[tuple]:
    """``(introduced, fixed, last_affected)`` for each interval of an OSV event list."""
    out: List[tuple] = []
    start: Optional[str] = None
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            if start is not None:               # the previous interval never closed
                out.append((start, None, None))
            start = event["introduced"]
        elif "fixed" in event or "last_affected" in event:
            out.append(("0" if start is None else start,
                        event.get("fixed"), event.get("last_affected")))
            start = None
    if start is not None:
        out.append((start, None, None))
    return out


def load_osv(path: Path, wanted: Optional[Wanted] = None) -> List[Advisory]:
    """Read an OSV record, or a file holding a list of them."""
    with _open_text(Path(path)) as fh:
        data = json.load(fh)
    records = data if isinstance(data, list) else data.get("vulns", [data])
    out: List[Advisory] = []
    for record in records:
        if not isinstance(record, dict) or not record.get("id"):
            continue
        ranges = []
        for affected in record.get("affected", []) or []:
            package = affected.get("package") or {}
            purl = package.get("purl")
            git_ranges = [r for r in affected.get("ranges", []) or []
                          if r.get("type") == "GIT"]
            if git_ranges:
                # Records imported from CVEs name a repository and list the
                # tags in range; they have no package.purl at all.
                tags = [v for v in affected.get("versions", []) or []
                        if isinstance(v, str)]
                for rng in git_ranges:
                    git_purl = purl_from_repo(rng.get("repo"))
                    if not git_purl:
                        continue
                    kinds = {k for e in rng.get("events", []) or [] for k in e}
                    extracted = ((rng.get("database_specific") or {})
                                 .get("extracted_events"))
                    ranges.append({"purl": git_purl, "type": "GIT", "tags": tags,
                                   "open_ended": not kinds & {"fixed", "last_affected"},
                                   "extracted": extracted if not tags else None,
                                   # What a patch record is built from.
                                   "repo": rng.get("repo"),
                                   "fixed_commits": [
                                       e["fixed"] for e in rng.get("events", []) or []
                                       if isinstance(e.get("fixed"), str)
                                       and re.fullmatch(r"[0-9a-fA-F]{7,64}", e["fixed"])]})
                if not purl:
                    continue
            if not purl:
                # Most OSV records outside GitHub name a package by ecosystem and
                # name only; the purl is optional in the schema.
                purl = purl_from_package(package)
            if not purl:
                continue
            for rng in affected.get("ranges", []) or []:
                if rng.get("type") == "GIT":
                    continue
                # An event list can hold several intervals (introduced, fixed,
                # introduced, fixed, ...). Each one is its own range: folding the
                # list into one dict kept only the last.
                for introduced, fixed, last_affected in _event_intervals(
                        rng.get("events", []) or []):
                    ranges.append({
                        "purl": purl,
                        "type": rng.get("type", "ECOSYSTEM"),
                        "introduced": introduced,
                        "fixed": fixed,
                        "last_affected": last_affected,
                    })
            for version in affected.get("versions", []) or []:
                if git_ranges:
                    break
                ranges.append({"purl": purl, "type": "EXACT",
                               "introduced": version, "last_affected": version})
        severity = None
        for sev in record.get("severity", []) or []:
            if sev.get("type", "").startswith("CVSS"):
                severity = sev.get("score")
        out.append(Advisory(
            id=record["id"], source="osv",
            summary=record.get("summary") or record.get("details", "")[:300],
            severity=severity,
            references=[r.get("url") for r in record.get("references", []) or []
                        if r.get("url")],
            osv_ranges=ranges,
            aliases=list(record.get("aliases") or [])))
    if wanted is not None:
        out = [a for a in out if any(purl_key(r["purl"]) in wanted.purl_keys
                                     for r in a.osv_ranges)]
    return out


def load_database(directory: Path, wanted: Optional[Wanted] = None,
                  jobs: int = 1) -> List[Advisory]:
    """Every NVD feed and OSV record under *directory*.

    Files may be ``.json``, ``.json.xz`` or ``.json.gz``. NVD feeds are read
    one record at a time; with *wanted*, records naming none of those
    products are dropped before they are built. With *jobs* > 1, large feed
    files (a full NVD mirror is one per year) are read in parallel.
    """
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"advisory database not found: {directory}")
    paths = sorted(p for p in directory.rglob("*")
                   if p.is_file() and p.name.lower().endswith(FEED_SUFFIXES))
    big = [p for p in paths if p.stat().st_size >= _PARALLEL_BYTES]
    results: Dict[Path, List[Advisory]] = {}
    if jobs > 1 and len(big) > 1:
        try:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=jobs) as pool:
                # Largest first, so the last year's feed does not finish alone.
                big.sort(key=lambda p: -p.stat().st_size)
                for path, found in zip(big, pool.map(_load_one, big,
                                                      [wanted] * len(big))):
                    results[path] = found
        except (OSError, RuntimeError, ImportError):
            results.clear()
    out: List[Advisory] = []
    for path in paths:
        out.extend(results[path] if path in results else _load_one(path, wanted))
    return out


_PARALLEL_BYTES = 1 << 20


def _load_one(path: Path, wanted: Optional[Wanted]) -> List[Advisory]:
    try:
        if _looks_like_feed(path):
            return load_nvd(path, wanted)
        return load_osv(path, wanted)
    except (OSError, EOFError, lzma.LZMAError, KeyError, TypeError, ValueError) as exc:
        # A feed that cannot be read must not look like a clean bill of health.
        warnings.warn(f"skipped unreadable advisory file {path}: {exc}", stacklevel=2)
        return []


def _looks_like_feed(path: Path) -> bool:
    try:
        with _open_text(path) as fh:
            head = fh.read(1 << 16)
    except (OSError, EOFError, lzma.LZMAError, UnicodeDecodeError):
        return False
    return _ARRAY_START.search(head) is not None
