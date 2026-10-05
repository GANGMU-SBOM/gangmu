"""Scoring an SBOM against the published minimum-element standards.

Two standards, because buyers ask for both and they are not the same list:

* **NTIA 2021** -- the original seven data fields, still what most procurement
  language names.
* **CISA 2026** -- renames those and raises the floor, adding a component hash
  (so a reader can check the bytes shipped are the bytes described), a
  machine-readable licence, the generating tool and version, the generation
  context, and the data format.

The score is per element and per component, and the report says which components
failed, because "73%" is not actionable and "these four components have no
version" is.

This is deliberately comparable to Interlynk's `sbomqs`, which is the de-facto
industry yardstick. Where it differs it is stricter: a placeholder such as
``NOASSERTION`` counts as absent, since an SBOM full of NOASSERTION passes a
field-presence check while telling a reader nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PLACEHOLDERS = {"", "noassertion", "none", "unknown", "n/a", "na", "-", "null"}


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        return bool(value)
    return str(value).strip().lower() not in PLACEHOLDERS


@dataclass
class Element:
    id: str
    name: str
    standard: str
    scope: str                      # "document" | "component"
    check: Callable[[dict], bool]
    why: str


def _meta(bom: dict) -> dict:
    return bom.get("metadata") or {}


def _tools(bom: dict) -> List[dict]:
    tools = _meta(bom).get("tools")
    if isinstance(tools, dict):
        return tools.get("components") or []
    return tools or []


def _component_identifier(c: dict) -> bool:
    return _present(c.get("purl")) or _present(c.get("cpe")) or _present(c.get("swid"))


def _component_supplier(c: dict) -> bool:
    if _present(c.get("supplier")) or _present(c.get("publisher")):
        return True
    props = {p.get("name"): p.get("value") for p in c.get("properties") or []}
    return _present(props.get("gangmu:vendor"))


NTIA_2021: List[Element] = [
    Element("ntia-supplier", "Supplier Name", "NTIA 2021", "component",
            _component_supplier,
            "who produced the component; without it a reader cannot ask anyone"),
    Element("ntia-name", "Component Name", "NTIA 2021", "component",
            lambda c: _present(c.get("name")), "the component's name"),
    Element("ntia-version", "Version of the Component", "NTIA 2021", "component",
            lambda c: _present(c.get("version")),
            "no version means no advisory can be matched"),
    Element("ntia-identifier", "Other Unique Identifiers", "NTIA 2021", "component",
            _component_identifier,
            "a purl, cpe or swid: the key every vulnerability database is indexed by"),
    Element("ntia-dependency", "Dependency Relationship", "NTIA 2021", "document",
            lambda b: bool(b.get("dependencies")),
            "which component contains which"),
    Element("ntia-author", "Author of SBOM Data", "NTIA 2021", "document",
            lambda b: bool(_tools(b)) or _present(_meta(b).get("authors")),
            "who or what produced this document"),
    Element("ntia-timestamp", "Timestamp", "NTIA 2021", "document",
            lambda b: _present(_meta(b).get("timestamp")),
            "when it was produced"),
]

CISA_2026: List[Element] = [
    Element("cisa-producer", "Component Producer", "CISA 2026", "component",
            _component_supplier, "renamed from Supplier Name"),
    Element("cisa-name", "Component Name", "CISA 2026", "component",
            lambda c: _present(c.get("name")), "unchanged"),
    Element("cisa-version", "Component Version", "CISA 2026", "component",
            lambda c: _present(c.get("version")), "renamed"),
    Element("cisa-identifiers", "Component Identifiers", "CISA 2026", "component",
            _component_identifier, "renamed"),
    Element("cisa-hash", "Component Hash", "CISA 2026", "component",
            lambda c: bool(c.get("hashes")),
            "new in 2026: lets a reader verify the bytes shipped are the bytes "
            "described"),
    Element("cisa-license", "Component License", "CISA 2026", "component",
            lambda c: bool(c.get("licenses")),
            "new in 2026: machine-readable licence"),
    Element("cisa-dependency", "Component Dependency Relationship", "CISA 2026",
            "document", lambda b: bool(b.get("dependencies")), "renamed"),
    Element("cisa-author", "SBOM Author", "CISA 2026", "document",
            lambda b: bool(_tools(b)) or _present(_meta(b).get("authors")), "renamed"),
    Element("cisa-timestamp", "SBOM Timestamp", "CISA 2026", "document",
            lambda b: _present(_meta(b).get("timestamp")), "renamed"),
    Element("cisa-tool", "SBOM Tool Name and Version", "CISA 2026", "document",
            lambda b: any(_present(t.get("name")) and _present(t.get("version"))
                          for t in _tools(b)),
            "new in 2026"),
    Element("cisa-context", "SBOM Generation Context", "CISA 2026", "document",
            lambda b: any(p.get("name", "").endswith("generationContext")
                          for p in _meta(b).get("properties") or []),
            "new in 2026: at which stage of development the SBOM was produced"),
    Element("cisa-format", "SBOM Data Format", "CISA 2026", "document",
            lambda b: _present(b.get("bomFormat")) and _present(b.get("specVersion")),
            "new in 2026"),
]


@dataclass
class ElementScore:
    element: Element
    passed: int
    total: int
    failures: List[str] = field(default_factory=list)

    @property
    def ratio(self) -> float:
        return self.passed / self.total if self.total else 0.0


@dataclass
class ScoreReport:
    standard: str
    scores: List[ElementScore] = field(default_factory=list)
    components: int = 0

    @property
    def score(self) -> float:
        if not self.scores:
            return 0.0
        return sum(s.ratio for s in self.scores) / len(self.scores)

    @property
    def out_of_ten(self) -> float:
        return round(self.score * 10, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "standard": self.standard,
            "score": round(self.score, 4),
            "outOfTen": self.out_of_ten,
            "components": self.components,
            "elements": [
                {"id": s.element.id, "name": s.element.name,
                 "scope": s.element.scope, "passed": s.passed, "total": s.total,
                 "ratio": round(s.ratio, 4), "failures": s.failures[:20],
                 "why": s.element.why}
                for s in self.scores
            ],
        }


def score_sbom(bom: dict, elements: Sequence[Element],
               standard: str) -> ScoreReport:
    components = bom.get("components") or []
    report = ScoreReport(standard=standard, components=len(components))
    for element in elements:
        if element.scope == "document":
            ok = bool(element.check(bom))
            report.scores.append(ElementScore(element, 1 if ok else 0, 1,
                                              [] if ok else ["<document>"]))
            continue
        passed, failures = 0, []
        for component in components:
            if element.check(component):
                passed += 1
            else:
                failures.append(component.get("name") or "<unnamed>")
        report.scores.append(ElementScore(element, passed, len(components), failures))
    return report
