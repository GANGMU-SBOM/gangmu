"""Advisories, matches and VEX states."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class VexState(str, Enum):
    """CycloneDX ``analysis.state`` values, used with their real meanings."""

    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    NOT_AFFECTED = "not_affected"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Advisory:
    id: str
    source: str                       # "nvd" | "osv" | the file it came from
    summary: str = ""
    severity: Optional[str] = None
    cvss: Optional[float] = None
    references: List[str] = field(default_factory=list)
    cpe_ranges: List[Dict[str, Any]] = field(default_factory=list)
    osv_ranges: List[Dict[str, Any]] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    vuln_status: Optional[str] = None  # NVD ``vulnStatus``, e.g. "Analyzed"; None for other sources


@dataclass
class Match:
    advisory: Advisory
    component: str                    # the SBOM component name
    directory: str
    version: Optional[str]
    channel: str                      # "cpe" | "purl"
    matched_on: str                   # the exact cpe or purl that matched
    state: VexState = VexState.IN_TRIAGE
    detail: str = ""
    component_confidence: float = 1.0
    kev: Optional[Dict[str, Any]] = None          # CISA KEV entry, when listed
    epss: Optional[Any] = None                    # (probability, percentile)
    reach: Optional[Any] = None                   # gangmu.reach.Reach
    patch: Optional[Any] = None                   # gangmu.patchtest.PatchVerdict
    justification: str = ""                       # CycloneDX analysis.justification
    linkage: Optional[str] = None                 # "not_linked": the link map shows it is not in the image
    subsystem_scope: bool = False                 # advisory names one subsystem of an OS/SDK tree

    def evidence(self) -> List[Dict[str, Any]]:
        """Every fact behind the finding's state, in one list, whatever produced it.

        Link map, subsystem scope, reachability and patch presence used to live in
        four places (state text, ``reach``, ``patch``). Each output format now reads
        this list, so a finding says the same thing in CycloneDX, OpenVEX and CSAF.
        """
        out: List[Dict[str, Any]] = []
        if self.linkage:
            out.append({"kind": "linkage", "status": self.linkage, "basis": "link map",
                        "detail": "the component is in the source tree but the build's "
                                  "link map shows it is not in the image"})
        if self.subsystem_scope:
            out.append({"kind": "subsystem_scope", "status": "umbrella", "basis": "rule",
                        "detail": "the advisory names one subsystem or driver of an "
                                  "OS/SDK tree; the version alone cannot say whether "
                                  "the firmware builds it"})
        if self.reach is not None:
            out.append({"kind": "reachability", "status": self.reach.status,
                        "basis": self.reach.basis or "none", "detail": self.reach.detail,
                        "functions": list(self.reach.symbols)})
        if self.patch is not None:
            out.append({"kind": "patch_presence", "status": self.patch.status,
                        "basis": self.patch.basis, "detail": self.patch.detail,
                        "functions": dict(self.patch.per_function)})
        return out

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.advisory.id,
            "component": self.component,
            "directory": self.directory,
            "version": self.version,
            "channel": self.channel,
            "matchedOn": self.matched_on,
            "state": self.state.value,
            "detail": self.detail,
            "severity": self.advisory.severity,
            "summary": self.advisory.summary,
            "componentConfidence": round(self.component_confidence, 3),
        }
        if self.advisory.vuln_status:
            out["nvdStatus"] = self.advisory.vuln_status
        if self.kev is not None:
            out["knownExploited"] = {"dateAdded": self.kev.get("added", ""),
                                     "dueDate": self.kev.get("due", ""),
                                     "ransomware": bool(self.kev.get("ransomware"))}
        if self.epss is not None:
            out["epss"] = {"score": self.epss[0], "percentile": self.epss[1]}
        evidence = self.evidence()
        if evidence:
            out["evidence"] = evidence
        if self.reach is not None:
            out["reachability"] = self.reach.to_dict()
        if self.patch is not None:
            out["patchPresence"] = self.patch.to_dict()
        return out
