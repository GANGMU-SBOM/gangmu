"""Exploitation signals: CISA KEV and EPSS.

CVSS says how bad a flaw could be; it does not say whether anyone is using it.
Two public feeds do:

* **KEV** (CISA Known Exploited Vulnerabilities): a CVE on it has been seen
  exploited in the wild.  That is the sentence a CRA Article 14 reporter needs,
  because "actively exploited" is what starts the 24-hour clock.
* **EPSS** (FIRST): the estimated probability a CVE is exploited in the next 30
  days.  A ranking aid, not a verdict.

Like the advisory database, both are read from the local directory, so the
lookup stays offline; ``gangmu vuln-fetch --threat`` is the step that needs the
network.  They live in ``<db>/threat/`` under names the advisory loader does
not read.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import lzma
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional, Sequence, Tuple

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
THREAT_DIR = "threat"
KEV_FILE = "kev.jsonl"
EPSS_FILE = "epss.csv.xz"

ByteGetter = Callable[[str], bytes]


@dataclass
class ThreatData:
    kev: Dict[str, dict] = field(default_factory=dict)
    epss: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    epss_date: str = ""

    def __bool__(self) -> bool:
        return bool(self.kev or self.epss)


def load_threat(db: Path) -> ThreatData:
    """Whatever is under ``<db>/threat/``; an absent or damaged file is empty."""
    data = ThreatData()
    base = Path(db) / THREAT_DIR
    kev = base / KEV_FILE
    if kev.is_file():
        try:
            for line in kev.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    data.kev[row["cve"]] = row
        except (OSError, ValueError, KeyError):
            data.kev.clear()
    epss = base / EPSS_FILE
    if epss.is_file():
        try:
            with lzma.open(epss, "rt", encoding="utf-8") as fh:
                for row in csv.reader(fh):
                    if row and row[0].startswith("#"):
                        data.epss_date = ",".join(row).partition("score_date:")[2].split(",")[0].strip()
                    elif row and row[0].upper().startswith("CVE-"):
                        data.epss[row[0].upper()] = (float(row[1]), float(row[2]))
        except (OSError, EOFError, lzma.LZMAError, ValueError, IndexError):
            data.epss.clear()
    return data


def _http_bytes(url: str) -> bytes:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "gangmu-vuln-fetch"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _replace(path: Path, payload: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, path)


def fetch_threat(db: Path, get: ByteGetter = _http_bytes,
                 kev_url: str = KEV_URL, epss_url: str = EPSS_URL,
                 log: Callable[[str], None] = lambda m: None) -> Tuple[int, int]:
    """Download KEV and EPSS into ``<db>/threat/``; returns (KEV, EPSS) row counts.

    Each file is replaced atomically, and only after it parsed, so a bad
    download leaves the previous copy in place.
    """
    base = Path(db) / THREAT_DIR
    base.mkdir(parents=True, exist_ok=True)

    doc = json.loads(get(kev_url).decode("utf-8"))
    rows = [{"cve": v["cveID"], "added": v.get("dateAdded", ""),
             "due": v.get("dueDate", ""),
             "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known"}
            for v in doc.get("vulnerabilities", []) if v.get("cveID")]
    if not rows:
        raise ValueError("the KEV feed held no entries")
    _replace(base / KEV_FILE,
             "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode())
    log(f"KEV: {len(rows)} entries")

    raw = get(epss_url)
    try:
        raw = gzip.decompress(raw)
    except OSError:
        pass                                    # served already decompressed
    text = raw.decode("utf-8")
    n = sum(1 for line in text.splitlines() if line.upper().startswith("CVE-"))
    if not n:
        raise ValueError("the EPSS feed held no scores")
    buf = io.BytesIO()
    with lzma.open(buf, "wt", encoding="utf-8") as fh:
        fh.write(text)
    _replace(base / EPSS_FILE, buf.getvalue())
    log(f"EPSS: {n} scores")
    return len(rows), n


def annotate(matches: Sequence, threat: ThreatData) -> int:
    """Attach ``kev`` and ``epss`` to each match; returns how many are on KEV."""
    on_kev = 0
    for m in matches:
        cve = m.advisory.id.upper()
        ids = [cve] + [a.upper() for a in m.advisory.aliases]
        for i in ids:
            if m.kev is None and i in threat.kev:
                m.kev = threat.kev[i]
            if m.epss is None and i in threat.epss:
                m.epss = threat.epss[i]
        on_kev += m.kev is not None
    return on_kev


def risk_key(m) -> tuple:
    """Sort key, most urgent first: on KEV, then EPSS, then CVSS."""
    return (m.kev is None, -(m.epss[0] if m.epss else -1.0),
            -(m.advisory.cvss or 0.0))
