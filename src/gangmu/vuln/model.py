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
        if self.reach is not None:
            out["reachability"] = self.reach.to_dict()
        if self.patch is not None:
            out["patchPresence"] = self.patch.to_dict()
        return out
