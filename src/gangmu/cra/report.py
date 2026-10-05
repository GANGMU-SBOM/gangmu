"""Article 14 notification drafts.

The ENISA Single Reporting Platform has no API at its first release, so a
notification is a human filling a web form. The hard part is not the typing: it
is that the 24-hour form asks which product versions are affected and which
component carries the vulnerability, and a team that cannot answer that in
minutes will miss the deadline.

Everything here comes from the SBOM and the project configuration, both of which
exist before the phone rings. The output is laid out in the platform's own field
order so it can be read straight across while typing.

Field lists follow the platform's three stages: early warning within 24 hours,
vulnerability notification within 72 hours, final report within 14 days of a
corrective measure being available.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import Config

REPORT_STAGES = ("early-warning", "notification", "final")

_DEADLINES = {
    "early-warning": "24 hours from becoming aware",
    "notification": "72 hours from becoming aware",
    "final": "14 days after a corrective measure is available",
}


@dataclass
class Field:
    label: str
    value: str
    required: bool = True
    source: str = ""              # where the value came from, or what is missing

    @property
    def filled(self) -> bool:
        return bool(self.value.strip())


@dataclass
class Draft:
    stage: str
    deadline: str
    fields: List[Field] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def missing(self) -> List[Field]:
        return [f for f in self.fields if f.required and not f.filled]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "deadline": self.deadline,
            "fields": [{"label": f.label, "value": f.value, "required": f.required,
                        "source": f.source} for f in self.fields],
            "missing": [f.label for f in self.missing],
            "notes": self.notes,
        }

    def to_markdown(self) -> str:
        lines = [f"# CRA Article 14 — {self.stage}",
                 "",
                 f"**Deadline:** {self.deadline}",
                 "",
                 "Submit at the ENISA Single Reporting Platform. The platform has "
                 "no API at its first release, so copy each value across by hand.",
                 "",
                 "| Field | Value | Source |",
                 "| --- | --- | --- |"]
        for f in self.fields:
            value = f.value.replace("\n", "<br>") if f.filled else (
                "**— MISSING —**" if f.required else "_(optional, not set)_")
            lines.append(f"| {f.label} | {value} | {f.source} |")
        if self.missing:
            lines += ["", "## Before you submit", ""]
            for f in self.missing:
                lines.append(f"- **{f.label}** — {f.source}")
        if self.notes:
            lines += ["", "## Notes", ""] + [f"- {n}" for n in self.notes]
        return "\n".join(lines)


def _component_for(vex: Optional[dict], advisory_id: str) -> Dict[str, str]:
    if not vex:
        return {}
    for vuln in vex.get("vulnerabilities") or []:
        if vuln.get("id") != advisory_id:
            continue
        refs = {a.get("ref") for a in vuln.get("affects") or []}
        for component in vex.get("components") or []:
            if component.get("bom-ref") in refs:
                return {
                    "name": component.get("name", ""),
                    "version": component.get("version", ""),
                    "purl": component.get("purl", ""),
                    "analysis": (vuln.get("analysis") or {}).get("state", ""),
                    "detail": (vuln.get("analysis") or {}).get("detail", ""),
                    "description": vuln.get("description", ""),
                    "severity": ((vuln.get("ratings") or [{}])[0]).get("severity", ""),
                }
        return {
            "name": "", "version": "",
            "analysis": (vuln.get("analysis") or {}).get("state", ""),
            "detail": (vuln.get("analysis") or {}).get("detail", ""),
            "description": vuln.get("description", ""),
            "severity": ((vuln.get("ratings") or [{}])[0]).get("severity", ""),
        }
    return {}


def draft_report(stage: str, config: Config, advisory_id: str,
                 vex: Optional[dict] = None,
                 aware_at: Optional[str] = None,
                 summary: str = "",
                 corrective_measure: str = "",
                 exploited: bool = True) -> Draft:
    if stage not in REPORT_STAGES:
        raise ValueError(f"stage must be one of {REPORT_STAGES}")

    component = _component_for(vex, advisory_id)
    states = config.get("market.member_states") or []
    states_text = ", ".join(states) if isinstance(states, list) else str(states)
    aware = aware_at or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")

    def cfg(key: str, label: str, why: str, required: bool = True) -> Field:
        value = config.get(key)
        return Field(label=label, value=str(value) if value else "",
                     required=required,
                     source=f"gangmu.yaml: {key}" if value else f"set {key} — {why}")

    draft = Draft(stage=stage, deadline=_DEADLINES[stage])

    # Every stage carries the identification block.
    draft.fields += [
        Field("Notification type",
              "Actively exploited vulnerability" if exploited else "Severe incident",
              source="chosen when the report was drafted"),
        cfg("manufacturer.name", "Manufacturer", "Article 14 names the manufacturer"),
        cfg("product.name", "Product name", "the notification identifies the product"),
        cfg("product.version", "Product version(s) affected",
            "the notification identifies the affected versions"),
        Field("Member states where the product is available", states_text,
              source="gangmu.yaml: market.member_states" if states_text
              else "set market.member_states — the platform asks which markets"),
        Field("Date and time of becoming aware", aware,
              source="supplied on the command line" if aware_at
              else "defaulted to now — set --aware-at to the real moment"),
        Field("Vulnerability identifier", advisory_id,
              required=False, source="supplied on the command line"),
    ]

    if stage == "early-warning":
        draft.fields += [
            Field("Title", summary or component.get("description", "")[:120],
                  source="from the advisory" if component else "write one line"),
            Field("Summary",
                  summary or component.get("description", "")[:600],
                  source="from the advisory summary in the VEX"),
            Field("Affected component", component.get("name", ""), required=False,
                  source="from the SBOM" if component.get("name")
                  else "optional on the form, but it is what a CSIRT acts on"),
            Field("Component version", component.get("version", ""), required=False,
                  source="from the SBOM"),
        ]
        draft.notes.append(
            "The early warning may say the assessment is preliminary. It may not "
            "be late: the 24 hours run from awareness, not from confirmation.")
    elif stage == "notification":
        draft.fields += [
            Field("Vulnerability description",
                  component.get("description", "") or summary,
                  source="from the advisory in the VEX"),
            Field("Severity", component.get("severity", ""), required=False,
                  source="from the advisory rating"),
            Field("Affected component", component.get("name", ""),
                  source="from the SBOM"),
            Field("Component version", component.get("version", ""),
                  source="from the SBOM"),
            Field("Initial assessment",
                  component.get("detail", ""),
                  source="from the VEX analysis detail"),
            Field("Corrective or mitigating measures taken", corrective_measure,
                  source="supplied on the command line" if corrective_measure
                  else "describe what you have done so far"),
        ]
    else:
        draft.fields += [
            Field("Vulnerability description",
                  component.get("description", "") or summary,
                  source="from the advisory in the VEX"),
            Field("Severity and impact", component.get("severity", ""),
                  source="from the advisory rating"),
            Field("Corrective measure", corrective_measure,
                  source="supplied on the command line" if corrective_measure
                  else "describe the fix and how users get it"),
            cfg("support.security_update_channel",
                "How the update reaches products in the field",
                "Annex I Part II(7): the distribution mechanism"),
            Field("Date the corrective measure became available", "",
                  source="fill in when the update ships"),
        ]

    csirt = config.get("reporting.csirt")
    if csirt:
        draft.notes.append(f"Coordinating CSIRT on file: {csirt}")
    else:
        draft.notes.append(
            "No coordinating CSIRT recorded. The platform asks you to choose one "
            "at registration, not at report time — set reporting.csirt.")
    if component.get("analysis") == "in_triage":
        draft.notes.append(
            "The VEX still has this one in triage. If the component is a vendor "
            "fork, the version alone does not establish exposure; say so in the "
            "assessment rather than overstating it.")
    return draft
