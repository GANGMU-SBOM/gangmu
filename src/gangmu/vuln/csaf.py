"""CSAF 2.0 ``csaf_vex`` output.

CSAF is what European CERTs, ENISA's single reporting platform workflow and the
large industrial suppliers (Siemens, Schneider, Bosch) exchange advisories in, so a
manufacturer answering a customer or an authority is often asked for this shape.

Rules of the VEX profile that shape the writer:

* every vulnerability needs a ``product_status``; a product in ``known_affected``
  needs a remediation, so gangmu writes ``none_available`` with the honest reason
  (it identified the match, not a fix);
* a ``known_not_affected`` product needs a flag or an impact statement, and a flag
  is only written for a justification that maps exactly;
* the publisher is a claim of accountability, so it is never invented: the caller
  passes it.

The document is ``draft`` until a person publishes it.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__
from .model import Match, VexState
from .openvex import JUSTIFICATION, RANK as _RANK, evidence_text, product_index

_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_CPE23 = re.compile(r"^cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+(\?*|\*?))|[\*\-])){4}$")

_FLAG = {
    "vulnerable_code_not_present": "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_csaf(matches: Sequence[Match], bom: Optional[dict] = None,
            app_name: str = "firmware", publisher: str = "",
            publisher_url: str = "", timestamp: Optional[str] = None,
            tracking_id: Optional[str] = None) -> Dict[str, Any]:
    """A CSAF 2.0 VEX document; raises ValueError for what the format requires."""
    if not publisher or not publisher_url:
        raise ValueError("CSAF requires a publisher name and namespace: pass "
                         "--publisher and --publisher-url")
    if not matches:
        raise ValueError("no findings: a CSAF VEX document needs at least one "
                         "vulnerability")
    now = timestamp or _now()
    index = product_index(bom)

    # one product per component directory
    product_ids: Dict[str, str] = {}
    products: List[Dict[str, Any]] = []
    for match in matches:
        key = match.directory or match.component
        if key in product_ids:
            continue
        pid = f"CSAFPID-{len(products) + 1:04d}"
        product_ids[key] = pid
        info = index.get(match.directory, {})
        name = info.get("name") or match.component
        version = info.get("version") or match.version
        entry: Dict[str, Any] = {"name": f"{name} {version}".strip() if version else name,
                                 "product_id": pid}
        helper: Dict[str, str] = {}
        if info.get("purl"):
            helper["purl"] = info["purl"]
        if info.get("cpe") and _CPE23.match(info["cpe"]):
            helper["cpe"] = info["cpe"]
        if helper:
            entry["product_identification_helper"] = helper
        products.append(entry)

    by_vuln: Dict[str, Dict[str, Match]] = {}
    for match in matches:
        per = by_vuln.setdefault(match.advisory.id, {})
        key = match.directory or match.component
        if key not in per or _RANK[match.state] < _RANK[per[key].state]:
            per[key] = match

    vulnerabilities: List[Dict[str, Any]] = []
    for advisory_id, per in by_vuln.items():
        sample = next(iter(per.values())).advisory
        vuln: Dict[str, Any] = {}
        if _CVE.match(advisory_id):
            vuln["cve"] = advisory_id
        else:
            vuln["ids"] = [{"system_name": sample.source.upper(), "text": advisory_id}]
            cves = [a for a in sample.aliases if _CVE.match(a)]
            if cves:
                vuln["cve"] = cves[0]
        notes = []
        if sample.summary:
            notes.append({"category": "description", "text": sample.summary[:1000]})
        if sample.severity:
            # OSV records carry the CVSS vector string here, NVD a level name.
            vector = sample.severity.startswith("CVSS:")
            notes.append({"category": "other",
                          "title": "CVSS vector" if vector else "Severity",
                          "text": f"{sample.severity}"
                                  + (f" (CVSS {sample.cvss})" if sample.cvss is not None else "")})
        for key, match in per.items():
            text = evidence_text(match)
            if text:
                label = next((p["name"] for p in products
                              if p["product_id"] == product_ids[key]), key)
                notes.append({"category": "details", "title": "gangmu evidence",
                              "text": f"{label}: {text}"})
        if notes:
            vuln["notes"] = notes
        if sample.references:
            vuln["references"] = [{"category": "external", "summary": "advisory",
                                   "url": u} for u in sample.references[:10]]
        status: Dict[str, List[str]] = {}
        flags: Dict[str, List[str]] = {}
        threats: List[Dict[str, Any]] = []
        remediations: List[str] = []
        for key, match in per.items():
            pid = product_ids[key]
            state = match.state
            if state is VexState.EXPLOITABLE:
                status.setdefault("known_affected", []).append(pid)
                remediations.append(pid)
            elif state is VexState.IN_TRIAGE:
                status.setdefault("under_investigation", []).append(pid)
            elif state is VexState.RESOLVED:
                status.setdefault("fixed", []).append(pid)
            else:
                status.setdefault("known_not_affected", []).append(pid)
                flag = _FLAG.get(JUSTIFICATION.get(match.justification, ""))
                if flag:
                    flags.setdefault(flag, []).append(pid)
                else:
                    prefix = "false positive: " if state is VexState.FALSE_POSITIVE else ""
                    threats.append({"category": "impact",
                                    "details": (prefix + (match.detail or "")) or
                                    "ruled out by gangmu's version comparison",
                                    "product_ids": [pid]})
        vuln["product_status"] = status
        if flags:
            vuln["flags"] = [{"label": label, "product_ids": ids}
                             for label, ids in flags.items()]
        if threats:
            vuln["threats"] = threats
        if remediations:
            vuln["remediations"] = [{
                "category": "none_available",
                "details": ("gangmu matched this component and version against the "
                            "advisory; it has not identified a fixed release. The "
                            "remediation is the manufacturer's decision."),
                "product_ids": remediations}]
        vulnerabilities.append(vuln)

    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": f"VEX for {app_name}",
            "publisher": {"category": "vendor", "name": publisher,
                          "namespace": publisher_url},
            "tracking": {
                "id": tracking_id or re.sub(r"[^A-Za-z0-9._\-]+", "-",
                                            f"gangmu-{app_name}-{now}"),
                "status": "draft",
                "version": "1",
                "initial_release_date": now,
                "current_release_date": now,
                "revision_history": [{"date": now, "number": "1",
                                      "summary": f"Generated by gangmu-sbom {__version__}"}],
                "generator": {"engine": {"name": "gangmu-sbom", "version": __version__},
                              "date": now},
            },
        },
        "product_tree": {"full_product_names": products},
        "vulnerabilities": vulnerabilities,
    }
