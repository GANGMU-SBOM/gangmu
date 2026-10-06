"""Maintenance status and end-of-support date of a component.

FDA's premarket cybersecurity guidance asks, for every component in the SBOM,
"the software level of support provided through monitoring and maintenance from
the software component manufacturer" and "the software component's end-of-support
date". The tree cannot say either: they are facts about the upstream project at a
point in time. So they come from two places a reviewer can check -- a rule's
``upstream.support`` block, or a file the product team keeps (``--support``) --
and when neither names the component the SBOM says ``unknown`` instead of staying
silent. A missing field and an asserted "maintained" must not look the same.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

STATUSES = ("maintained", "limited", "no_longer_maintained", "abandoned", "unknown")
"""``limited`` is security fixes only. FDA's own examples are "actively maintained,
no longer maintained, abandoned"."""


class SupportError(ValueError):
    """A support declaration is malformed."""


@dataclass(frozen=True)
class Support:
    status: str = "unknown"
    end_of_support: Optional[str] = None     # YYYY-MM-DD
    source: Optional[str] = None             # where a reviewer can check it
    as_of: Optional[str] = None              # YYYY-MM-DD the claim was checked

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {"status": self.status, "end_of_support": self.end_of_support,
                "source": self.source, "as_of": self.as_of}


UNKNOWN = Support()


def _date(value: Any, what: str, where: str) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, (_dt.date, _dt.datetime)):
        return value.strftime("%Y-%m-%d")
    text = str(value).strip()
    try:
        _dt.datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise SupportError(f"{where}: {what} must be YYYY-MM-DD, got {text!r}") from None
    return text


def parse_support(raw: Mapping[str, Any], where: str) -> Support:
    """Build a Support from a mapping (a rule's block or an override entry)."""
    if not isinstance(raw, Mapping):
        raise SupportError(f"{where}: support must be a mapping")
    status = str(raw.get("status", "unknown")).strip().lower().replace("-", "_")
    if status not in STATUSES:
        raise SupportError(f"{where}: support status {status!r} is not one of "
                           f"{', '.join(STATUSES)}")
    return Support(
        status=status,
        end_of_support=_date(raw.get("end_of_support"), "end_of_support", where),
        source=(str(raw["source"]) if raw.get("source") else None),
        as_of=_date(raw.get("as_of"), "as_of", where),
    )


@dataclass(frozen=True)
class Override:
    """One entry of a ``--support`` file: which components, and what to say."""

    rule: Optional[str] = None
    name: Optional[str] = None
    directory: Optional[str] = None
    version: Optional[str] = None
    support: Support = UNKNOWN

    def matches(self, finding: Any) -> bool:
        if self.rule is not None and finding.rule_id != self.rule:
            return False
        if self.name is not None and finding.upstream_name.lower() != self.name.lower():
            return False
        if self.directory is not None and not fnmatch.fnmatch(finding.directory,
                                                              self.directory):
            return False
        if self.version is not None and (finding.version or "") != self.version:
            return False
        return True


def load_overrides(path: Path) -> List[Override]:
    """Read a JSON or YAML file: ``{"components": [{"name": "FreeRTOS-Kernel",
    "version": "10.4.3", "status": "no_longer_maintained",
    "end_of_support": "2025-01-01", "source": "https://..."}]}``.

    An entry must say which component it is about (``rule``, ``name`` or
    ``directory``); first match wins, so put the specific entry first.
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        if str(path).lower().endswith((".yaml", ".yml")):
            import yaml
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
    except Exception as exc:  # noqa: BLE001 -- parser errors differ per format
        raise SupportError(f"{path}: cannot parse: {exc}") from None
    entries = data.get("components") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise SupportError(f"{path}: expected a list under 'components'")
    out: List[Override] = []
    for i, entry in enumerate(entries):
        where = f"{path} entry {i + 1}"
        if not isinstance(entry, Mapping):
            raise SupportError(f"{where}: must be a mapping")
        keys = {k: (str(entry[k]) if entry.get(k) else None)
                for k in ("rule", "name", "directory", "version")}
        if not (keys["rule"] or keys["name"] or keys["directory"]):
            raise SupportError(f"{where}: name, rule or directory is required, "
                               "otherwise the entry would apply to everything")
        out.append(Override(support=parse_support(entry, where), **keys))
    return out


def stamp(rules_by_id: Mapping[str, Any], overrides: Sequence[Override],
          *groups: Iterable[Any]) -> int:
    """Attach a Support to every finding; return how many remain ``unknown``.

    Precedence: an override file entry, then the matching rule's own block, then
    ``unknown``.
    """
    unknown = 0
    for group in groups:
        for finding in group:
            found: Optional[Support] = None
            for override in overrides:
                if override.matches(finding):
                    found = override.support
                    break
            if found is None:
                rule = rules_by_id.get(finding.rule_id)
                found = getattr(rule, "support", None)
            finding.support = found or UNKNOWN
            if finding.support.status == "unknown":
                unknown += 1
    return unknown


def support_properties(support: Optional[Support]) -> List[Dict[str, str]]:
    """CycloneDX 1.6 has no field for either, so they travel as properties.

    Always written, ``unknown`` included: a reader checking an FDA submission
    needs to tell "nobody checked" from "the tool left it out".
    """
    support = support or UNKNOWN
    props = [{"name": "gangmu:supportStatus", "value": support.status}]
    if support.end_of_support:
        props.append({"name": "gangmu:endOfSupport", "value": support.end_of_support})
    if support.source:
        props.append({"name": "gangmu:supportSource", "value": support.source})
    if support.as_of:
        props.append({"name": "gangmu:supportAsOf", "value": support.as_of})
    return props


def describe(support: Optional[Support]) -> str:
    """One line for comment fields."""
    support = support or UNKNOWN
    text = f"support status: {support.status}"
    if support.end_of_support:
        text += f"; end of support {support.end_of_support}"
    if support.source:
        text += f" (source: {support.source}"
        text += f", checked {support.as_of})" if support.as_of else ")"
    elif support.as_of:
        text += f" (checked {support.as_of})"
    return text
