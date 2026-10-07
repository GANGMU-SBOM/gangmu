"""OpenVEX 0.2.0 output.

The same analysis the CycloneDX VEX carries, in the format most open-source
tooling (Grype, Trivy, vexctl, Dependency-Track) reads. Two things OpenVEX makes
mandatory that CycloneDX does not, and what is done about each:

* an *author*: the statement is a claim somebody stands behind, so ``gangmu vuln``
  refuses to invent one and asks for ``--publisher``;
* an *action statement* on every ``affected`` finding: gangmu only knows the
  version matched, not what the fix is, so the statement says the remediation is
  the manufacturer's decision and lists the advisory's own references.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__
from .model import Match, VexState

CONTEXT = "https://openvex.dev/ns/v0.2.0"

# CycloneDX analysis.justification -> OpenVEX justification. The others (requires_*,
# protected_*) have no exact OpenVEX counterpart, so only the impact statement is
# written for them rather than a justification that says something else.
JUSTIFICATION = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "protected_by_mitigating_control": "inline_mitigations_already_exist",
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_runtime": "inline_mitigations_already_exist",
    "protected_at_perimeter": "inline_mitigations_already_exist",
}


# When the CPE and the PURL channel both match the same advisory on the same
# component, one statement is written, keeping the state that needs the most action.
RANK = {VexState.EXPLOITABLE: 0, VexState.IN_TRIAGE: 1, VexState.RESOLVED: 2,
        VexState.NOT_AFFECTED: 3, VexState.FALSE_POSITIVE: 4}


def dedupe(matches: Sequence[Match]) -> List[Match]:
    best: Dict[tuple, Match] = {}
    for match in matches:
        key = (match.advisory.id, match.directory or match.component)
        if key not in best or RANK[match.state] < RANK[best[key].state]:
            best[key] = match
    return list(best.values())


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def product_index(bom: Optional[dict]) -> Dict[str, Dict[str, str]]:
    """directory -> the SBOM component's identifiers, from the CycloneDX BOM."""
    out: Dict[str, Dict[str, str]] = {}
    for component in (bom or {}).get("components", []) or []:
        props = {p.get("name"): p.get("value")
                 for p in component.get("properties", []) or []}
        directory = props.get("gangmu:directory")
        if directory:
            out[directory] = {k: v for k, v in (
                ("purl", component.get("purl")), ("cpe", component.get("cpe")),
                ("name", component.get("name")), ("version", component.get("version")),
                ("bom-ref", component.get("bom-ref"))) if v}
    return out


def evidence_text(match: Match) -> str:
    """The facts behind a finding's state (``Match.evidence()``) as plain text.

    Neither OpenVEX nor CSAF has a field for structured evidence, and a private
    property would be dropped by every consumer, so the facts go into the free-text
    field both formats already carry. The wording is stable ("gangmu evidence:") so a
    reader or a script can find it; the CycloneDX output keeps the same facts as
    ``gangmu:*`` properties.
    """
    parts: List[str] = []
    for item in match.evidence():
        kind = item["kind"]
        if kind == "linkage":
            parts.append("link map: not linked into the image")
        elif kind == "subsystem_scope":
            parts.append("subsystem-scoped advisory: the version alone cannot say "
                         "whether the firmware builds the affected subsystem")
        elif kind == "reachability":
            text = f"reachability={item['status']} (basis: {item['basis']})"
            if item.get("functions"):
                text += f"; functions: {', '.join(item['functions'][:5])}"
            if item.get("detail"):
                text += f"; {item['detail']}"
            parts.append(text)
        elif kind == "patch_presence":
            text = f"patch presence={item['status']} (basis: {item['basis']})"
            if item.get("functions"):
                text += "; " + ", ".join(f"{name}: {state}" for name, state
                                         in sorted(item["functions"].items())[:8])
            if item.get("detail"):
                text += f"; {item['detail']}"
            parts.append(text)
    if not parts:
        return ""
    return "gangmu evidence: " + " | ".join(parts)


def _product(match: Match, index: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    info = index.get(match.directory, {})
    purl = info.get("purl")
    cpe = info.get("cpe")
    ident: Dict[str, str] = {}
    if purl:
        ident["purl"] = purl
    if cpe:
        ident["cpe23"] = cpe
    ref = purl or f"urn:gangmu:component:{match.directory or match.component}"
    product: Dict[str, Any] = {"@id": ref}
    if ident:
        product["identifiers"] = ident
    return product


def _statement(match: Match, index: Dict[str, Dict[str, str]], now: str) -> Dict[str, Any]:
    advisory = match.advisory
    vuln: Dict[str, Any] = {"name": advisory.id}
    aliases = [a for a in advisory.aliases if a != advisory.id]
    if aliases:
        vuln["aliases"] = sorted(set(aliases))
    if advisory.summary:
        vuln["description"] = advisory.summary[:1000]
    statement: Dict[str, Any] = {
        "vulnerability": vuln,
        "products": [_product(match, index)],
        "timestamp": now,
    }
    detail = match.detail or ""
    evidence = evidence_text(match)
    if match.state is VexState.EXPLOITABLE:
        statement["status"] = "affected"
        refs = "; ".join(advisory.references[:3])
        statement["action_statement"] = (
            "Matched on component and version by gangmu. No fixed release has been "
            "identified by the tool and the remediation is the manufacturer's decision."
            + (f" Advisory references: {refs}." if refs else ""))
        statement["action_statement_timestamp"] = now
    elif match.state is VexState.IN_TRIAGE:
        statement["status"] = "under_investigation"
    elif match.state is VexState.RESOLVED:
        statement["status"] = "fixed"
    else:                                       # not_affected, false_positive
        statement["status"] = "not_affected"
        justification = JUSTIFICATION.get(match.justification)
        if justification:
            statement["justification"] = justification
        prefix = "false positive: " if match.state is VexState.FALSE_POSITIVE else ""
        statement["impact_statement"] = (prefix + detail) or (
            "ruled out by gangmu's version comparison")
        if evidence:
            statement["impact_statement"] += " " + evidence
    if statement["status"] != "not_affected" and (detail or evidence):
        statement["status_notes"] = " ".join(t for t in (detail, evidence) if t)
    return statement


def to_openvex(matches: Sequence[Match], bom: Optional[dict] = None,
               author: str = "", timestamp: Optional[str] = None,
               doc_id: Optional[str] = None,
               supplier: Optional[str] = None) -> Dict[str, Any]:
    """An OpenVEX document; raises ValueError when there is nothing to state."""
    if not author:
        raise ValueError("OpenVEX requires an author: pass --publisher")
    if not matches:
        raise ValueError("no findings: OpenVEX cannot express an empty document")
    now = timestamp or _now()
    index = product_index(bom)
    statements: List[Dict[str, Any]] = [_statement(m, index, now) for m in dedupe(matches)]
    if supplier:
        for s in statements:
            s["supplier"] = supplier
    return {
        "@context": CONTEXT,
        "@id": doc_id or f"https://gangmu.dev/openvex/{uuid.uuid4()}",
        "author": author,
        "role": "Document Creator",
        "timestamp": now,
        "version": 1,
        "tooling": f"gangmu-sbom {__version__}",
        "statements": statements,
    }
