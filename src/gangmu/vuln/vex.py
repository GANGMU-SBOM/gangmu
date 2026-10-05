"""CycloneDX VEX output.

The point of emitting VEX rather than a list of CVEs is that a CVE list says
"your firmware contains lwIP 2.2.0 and here are its CVEs", which a customer
cannot act on. VEX says, per vulnerability, what the manufacturer concluded and
why -- and under CRA Article 13 that conclusion is the manufacturer's to make
and to document.

Every ``analysis.detail`` written here says what the tool actually established,
never more. ``in_triage`` with a reason is a true statement; ``not_affected``
with no justification is a liability.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__
from .model import Match, VexState

_SOURCE_URL = {
    "nvd": "https://nvd.nist.gov/vuln/detail/",
    "osv": "https://osv.dev/vulnerability/",
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ref_for(match: Match, bom: Optional[dict]) -> str:
    if bom:
        for component in bom.get("components", []) or []:
            props = {p.get("name"): p.get("value")
                     for p in component.get("properties", []) or []}
            if props.get("gangmu:directory") == match.directory:
                return component.get("bom-ref", match.directory)
    return match.directory or match.component


def _vulnerability(match: Match, bom: Optional[dict]) -> Dict[str, Any]:
    advisory = match.advisory
    entry: Dict[str, Any] = {
        "bom-ref": f"{advisory.id}#{match.directory}#{match.channel}",
        "id": advisory.id,
        "source": {
            "name": advisory.source.upper(),
            "url": _SOURCE_URL.get(advisory.source, "") + advisory.id,
        },
        "affects": [{"ref": _ref_for(match, bom)}],
        "analysis": {"state": match.state.value, "detail": match.detail},
    }
    if match.justification:
        entry["analysis"]["justification"] = match.justification
    if advisory.summary:
        entry["description"] = advisory.summary[:1000]
    ratings = []
    if advisory.cvss is not None:
        ratings.append({"score": advisory.cvss, "method": "CVSSv31",
                        "severity": advisory.severity or "unknown"})
    elif advisory.severity:
        ratings.append({"severity": advisory.severity, "method": "other"})
    if ratings:
        entry["ratings"] = ratings
    if advisory.references:
        entry["advisories"] = [{"url": u} for u in advisory.references[:10]]
    properties = [
        {"name": "gangmu:channel", "value": match.channel},
        {"name": "gangmu:matchedOn", "value": match.matched_on},
        {"name": "gangmu:componentConfidence",
         "value": f"{match.component_confidence:.3f}"},
    ]
    if match.kev is not None:
        properties.append({"name": "gangmu:knownExploited", "value": "true"})
        properties.append({"name": "gangmu:kevDateAdded",
                           "value": match.kev.get("added", "")})
        properties.append({"name": "gangmu:kevDueDate",
                           "value": match.kev.get("due", "")})
    if match.epss is not None:
        properties.append({"name": "gangmu:epssScore",
                           "value": f"{match.epss[0]:.5f}"})
        properties.append({"name": "gangmu:epssPercentile",
                           "value": f"{match.epss[1]:.5f}"})
    if match.reach is not None:
        properties.append({"name": "gangmu:reachability", "value": match.reach.status})
        properties.append({"name": "gangmu:reachabilityDetail",
                           "value": match.reach.detail})
        properties.append({"name": "gangmu:reachabilityBasis",
                           "value": match.reach.basis or "none"})
    entry["properties"] = properties
    return entry


def to_vex(matches: Sequence[Match], bom: Optional[dict] = None,
           app_name: str = "firmware", timestamp: Optional[str] = None,
           serial: Optional[str] = None,
           blind_spots: Sequence[str] = ()) -> Dict[str, Any]:
    """A CycloneDX document carrying the components *and* the analysis.

    When an input BOM is given the vulnerabilities are added to it, so the
    result is one artefact rather than two that have to be kept in step.
    """
    doc: Dict[str, Any] = dict(bom) if bom else {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or _now(),
            "component": {"bom-ref": "root-application", "type": "application",
                          "name": app_name},
        },
        "components": [],
    }
    doc.setdefault("metadata", {})
    doc["metadata"]["timestamp"] = timestamp or doc["metadata"].get("timestamp") or _now()
    tools = doc["metadata"].setdefault("tools", {"components": []})
    if isinstance(tools, dict):
        names = {c.get("name") for c in tools.get("components", [])}
        if "gangmu-sbom" not in names:
            tools.setdefault("components", []).append(
                {"type": "application", "name": "gangmu-sbom", "version": __version__})

    doc["vulnerabilities"] = [_vulnerability(m, bom) for m in matches]

    if blind_spots:
        props = doc["metadata"].setdefault("properties", [])
        for name in blind_spots:
            props.append({"name": "gangmu:notLookedUp", "value": name})
        props.append({
            "name": "gangmu:notLookedUpNote",
            "value": ("These components carry neither a CPE nor a PURL, so no "
                      "advisory database could be queried for them. Absence of "
                      "findings here is absence of evidence."),
        })
    return doc


def summary(matches: Sequence[Match]) -> Dict[str, int]:
    out = {state.value: 0 for state in VexState}
    for match in matches:
        out[match.state.value] += 1
    return out
