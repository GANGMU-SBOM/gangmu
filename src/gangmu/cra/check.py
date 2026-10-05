"""The CRA self-check.

Written for the person who has to sign the declaration of conformity. Every
finding names the clause, says what was looked at, and -- when it fails -- what
to do next. A check that says "fail" without saying which file to fix wastes the
only hour that person has.

The check is deliberately strict in one direction: it never upgrades a verdict
on the strength of a declaration. A policy URL in the config makes an obligation
``declared``, never ``met``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Config
from .requirements import REQUIREMENTS, Requirement, Verdict


@dataclass
class Finding:
    requirement: Requirement
    verdict: Verdict
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    next_step: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.requirement.id,
            "clause": self.requirement.clause,
            "title": self.requirement.title,
            "verdict": self.verdict.value,
            "evidence": self.evidence,
            "gaps": self.gaps,
            "nextStep": self.next_step,
            "toolRole": self.requirement.tool_role,
        }


@dataclass
class CheckResult:
    findings: List[Finding] = field(default_factory=list)

    @property
    def blocking(self) -> List[Finding]:
        return [f for f in self.findings if f.verdict is Verdict.NOT_MET]

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for finding in self.findings:
            out[finding.verdict.value] = out.get(finding.verdict.value, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {"findings": [f.to_dict() for f in self.findings],
                "summary": self.counts(),
                "blocking": [f.requirement.id for f in self.blocking]}


def _requirement(requirement_id: str) -> Requirement:
    return next(r for r in REQUIREMENTS if r.id == requirement_id)


def _check_sbom(bom: Optional[dict], scan: Optional[dict]) -> Finding:
    req = _requirement("AI-II-1")
    evidence: List[str] = []
    gaps: List[str] = []

    if bom is None:
        return Finding(req, Verdict.NOT_MET,
                       gaps=["no SBOM was given"],
                       next_step="gangmu scan <root> --format cyclonedx -o sbom.json")

    spec = bom.get("specVersion")
    if bom.get("bomFormat") == "CycloneDX":
        evidence.append(f"CycloneDX {spec}: a commonly used, machine-readable format")
    elif bom.get("spdxVersion"):
        evidence.append(f"{bom['spdxVersion']}: a commonly used, machine-readable format")
    else:
        gaps.append("the document is neither CycloneDX nor SPDX")

    components = bom.get("components") or []
    if not components:
        gaps.append("the SBOM lists no components at all")
    else:
        evidence.append(f"{len(components)} component(s) listed")

    unnamed = [c for c in components if not c.get("name")]
    if unnamed:
        gaps.append(f"{len(unnamed)} component(s) have no name")

    unidentified = [c.get("name") for c in components
                    if not c.get("purl") and not c.get("cpe")]
    if unidentified:
        gaps.append(
            f"{len(unidentified)} component(s) carry neither a purl nor a cpe, so "
            f"they cannot be tracked against any advisory database: "
            + ", ".join(str(n) for n in unidentified[:5]))

    unversioned = [c.get("name") for c in components if not c.get("version")]
    if unversioned:
        gaps.append(f"{len(unversioned)} component(s) have no version: "
                    + ", ".join(str(n) for n in unversioned[:5]))

    props = {p.get("name"): p.get("value")
             for p in (bom.get("metadata", {}).get("properties") or [])}
    left_over = int(props.get("gangmu:unidentifiedDirectories", 0) or 0)
    if scan:
        left_over = len(scan.get("unidentified") or [])
    if left_over:
        gaps.append(
            f"{left_over} director(ies) look like components and were not "
            f"identified. Top-level coverage cannot be claimed while they are "
            f"unexplained.")

    if props.get("gangmu:buildFactsUsed") == "false":
        gaps.append(
            "the SBOM was produced from the source tree alone. Without build "
            "facts it over-reports: code that is present but never compiled or "
            "never linked is listed as shipped.")

    if gaps:
        verdict = Verdict.PARTIAL if evidence and components else Verdict.NOT_MET
    else:
        verdict = Verdict.MET
    next_step = ""
    if left_over:
        next_step = ("Write a rule for each unidentified directory, or record in "
                     "the technical documentation why it is not a component "
                     "(generated code, your own source).")
    elif unidentified:
        next_step = ("Give those components a purl or a cpe in their rule; "
                     "`gangmu rules lint` lists rules that have neither.")
    elif props.get("gangmu:buildFactsUsed") == "false":
        next_step = ("Re-run with --compile-db (and --link-map if the linker "
                     "writes one), or --project for an IAR, Keil or CCS build.")
    return Finding(req, verdict, evidence, gaps, next_step)


def _check_analysis(vex: Optional[dict]) -> Finding:
    req = _requirement("AI-II-2")
    if vex is None:
        return Finding(req, Verdict.NOT_MET,
                       gaps=["no vulnerability analysis was given"],
                       next_step="gangmu vuln sbom.json --db <advisories> "
                                 "--format cyclonedx -o vex.json")
    vulns = vex.get("vulnerabilities") or []
    if not vulns:
        return Finding(req, Verdict.PARTIAL,
                       evidence=["an analysis ran and found nothing"],
                       gaps=["no advisory matched. Check the database is current "
                             "and that components carry identifiers."])
    missing = [v.get("id") for v in vulns
               if not (v.get("analysis") or {}).get("state")]
    detailless = [v.get("id") for v in vulns
                  if not (v.get("analysis") or {}).get("detail")]
    evidence = [f"{len(vulns)} vulnerability record(s), each with a recorded state"]
    gaps = []
    if missing:
        gaps.append(f"{len(missing)} record(s) have no analysis state")
    if detailless:
        gaps.append(f"{len(detailless)} record(s) state a conclusion without a "
                    f"justification. Annex I Part II(4) asks for information that "
                    f"lets a user act; a bare state does not.")
    triage = [v for v in vulns
              if (v.get("analysis") or {}).get("state") == "in_triage"]
    if triage:
        evidence.append(f"{len(triage)} still in triage -- these are the ones a "
                        f"human must close before a declaration of conformity")
    return Finding(req, Verdict.MET if not gaps else Verdict.PARTIAL,
                   evidence, gaps,
                   next_step="Close the in_triage findings: for a vendor fork, "
                             "check the fork's history for the fix." if triage else "")


def _check_documentation(bundle: Optional[Path], config: Config) -> Finding:
    req = _requirement("ART-13-8")
    evidence, gaps = [], []
    if bundle and Path(bundle).exists():
        evidence.append(f"evidence bundle at {bundle}")
    else:
        gaps.append("no evidence bundle was produced")
    years = config.get("retention.years")
    if years:
        evidence.append(f"retention declared as {years} years")
    else:
        gaps.append("retention.years is not declared in the configuration")
    if config.get("market.placed_on_market"):
        evidence.append(f"placed on the market {config.get('market.placed_on_market')}"
                        f" -- the ten years run from there")
    else:
        gaps.append("market.placed_on_market is not declared, so the retention "
                    "period has no start date")
    verdict = Verdict.MET if not gaps else (Verdict.PARTIAL if evidence else Verdict.NOT_MET)
    return Finding(req, verdict, evidence, gaps,
                   next_step="gangmu evidence --out cra-evidence/" if not bundle else "")


def _check_reporting_readiness(config: Config, bom: Optional[dict]) -> Finding:
    req = _requirement("ART-14")
    required = {
        "product.name": "the notification names the product",
        "product.version": "the notification names the affected version",
        "manufacturer.name": "the notification names the manufacturer",
        "market.member_states": "the notification lists the member states the "
                                "product is available in",
        "reporting.assigned_representative": "the platform needs a named person "
                                             "holding the EU Login account",
    }
    evidence, gaps = [], []
    for key, why in required.items():
        if config.get(key):
            evidence.append(f"{key} declared")
        else:
            gaps.append(f"{key} is missing -- {why}")
    if bom and (bom.get("components") or []):
        evidence.append("component name and CVE can be filled from the SBOM, which "
                        "is what makes the 24-hour deadline survivable")
    verdict = Verdict.MET if not gaps else (Verdict.PARTIAL if evidence else Verdict.NOT_MET)
    return Finding(req, verdict, evidence, gaps,
                   next_step="Fill the missing fields in gangmu.yaml; the 24-hour "
                             "clock is not the moment to look them up."
                             if gaps else "")


def _check_declared(requirement_id: str, config: Config, key: str,
                    what: str) -> Finding:
    req = _requirement(requirement_id)
    value = config.get(key)
    if value:
        return Finding(req, Verdict.DECLARED, evidence=[f"{key}: {value}"],
                       next_step="")
    return Finding(req, Verdict.NOT_MET, gaps=[f"{key} is not declared"],
                   next_step=f"Declare {what} in gangmu.yaml under {key}.")


def check_cra(config: Config, bom: Optional[dict] = None,
              vex: Optional[dict] = None, scan: Optional[dict] = None,
              evidence_bundle: Optional[Path] = None) -> CheckResult:
    result = CheckResult()
    result.findings.append(_check_sbom(bom, scan))
    result.findings.append(_check_analysis(vex))
    result.findings.append(Finding(
        _requirement("AI-II-3"), Verdict.OUT_OF_SCOPE,
        gaps=["security testing is not what this tool does"],
        next_step="Record your test regime in the technical documentation."))
    result.findings.append(Finding(
        _requirement("AI-II-4"), Verdict.PARTIAL if vex else Verdict.NOT_MET,
        evidence=["the VEX document carries descriptions, affected components "
                  "and severities"] if vex else [],
        gaps=[] if vex else ["no VEX document"],
        next_step="Publish the VEX alongside each security update."))
    result.findings.append(_check_declared(
        "AI-II-5", config, "manufacturer.cvd_policy_url",
        "your coordinated vulnerability disclosure policy"))
    result.findings.append(_check_declared(
        "AI-II-6", config, "manufacturer.vulnerability_contact",
        "the address people report vulnerabilities to"))
    for rid in ("AI-II-7", "AI-II-8"):
        result.findings.append(Finding(
            _requirement(rid), Verdict.OUT_OF_SCOPE,
            gaps=["update distribution is product engineering, not SBOM tooling"],
            next_step="Describe the update mechanism in the technical "
                      "documentation."))
    result.findings.append(_check_documentation(evidence_bundle, config))
    result.findings.append(_check_reporting_readiness(config, bom))
    result.findings.sort(key=lambda f: f.requirement.id)
    return result
