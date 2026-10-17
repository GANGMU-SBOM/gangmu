"""Merge CycloneDX documents into one.

A product's SBOM rarely comes from one tool: the Yocto build writes one, the
vendor ships another, a Conan or CMake project has its own, and this tool adds
what it found in source. Re-scanning cannot recover what another tool knew, so
this joins the documents instead. A component is the same component when its
purl matches, else when name and version match; the first document wins every
field it has and later documents only fill in what is missing. Nothing is
invented: a component that two documents give different versions stays twice,
and is reported as a disagreement for a person to settle.

Vulnerabilities (a VEX) are joined by id: the affected components are united, and
when two documents disagree on the analysis state the more cautious one is kept.
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Most cautious first: a merged VEX must not claim "not affected" because one
# source did, while another still says it is exploitable.
_STATE_ORDER = ["exploitable", "in_triage", "resolved", "resolved_with_pedigree",
                "not_affected", "false_positive"]
_FILL = ("version", "description", "cpe", "supplier", "publisher", "group", "licenses",
         "hashes", "externalReferences", "copyright")


class MergeError(ValueError):
    pass


@dataclass
class MergeReport:
    inputs: int = 0
    components_in: int = 0
    components_out: int = 0
    duplicates: int = 0
    disagreements: List[Tuple[str, List[str]]] = field(default_factory=list)
    vulnerabilities_out: int = 0
    state_conflicts: List[str] = field(default_factory=list)
    dangling_dependencies: int = 0


def _spec(doc: dict) -> Tuple[int, ...]:
    try:
        return tuple(int(p) for p in str(doc.get("specVersion", "0")).split("."))
    except ValueError:
        return (0,)


def _key(comp: dict) -> Tuple[str, ...]:
    purl = comp.get("purl")
    if isinstance(purl, str) and purl:
        return ("purl", purl.lower())
    return ("nv", str(comp.get("name", "")).lower(), str(comp.get("version") or ""))


def _union_properties(kept: dict, other: dict, label: str) -> None:
    props = list(kept.get("properties") or [])
    seen = {(p.get("name"), p.get("value")) for p in props if isinstance(p, dict)}
    for prop in other.get("properties") or []:
        if isinstance(prop, dict) and (prop.get("name"), prop.get("value")) not in seen:
            props.append(prop)
            seen.add((prop.get("name"), prop.get("value")))
    also = {"name": "gangmu:alsoIn", "value": label}
    if (also["name"], also["value"]) not in seen:
        props.append(also)
    kept["properties"] = props


def merge_boms(documents: Sequence[Tuple[str, dict]],
               timestamp: Optional[str] = None) -> Tuple[dict, MergeReport]:
    """Join CycloneDX JSON documents; *documents* is ``(label, document)`` pairs."""
    if not documents:
        raise MergeError("nothing to merge")
    for label, doc in documents:
        if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
            raise MergeError(f"{label}: not a CycloneDX JSON document")
    report = MergeReport(inputs=len(documents))

    first = documents[0][1]
    root = copy.deepcopy((first.get("metadata") or {}).get("component"))
    root_ref = root.get("bom-ref") if isinstance(root, dict) else None

    components: List[dict] = []
    by_key: Dict[Tuple[str, ...], dict] = {}
    used_refs: Dict[str, dict] = {}
    if root_ref and root is not None:
        used_refs[root_ref] = root
    remaps: List[Dict[str, str]] = []

    for index, (label, doc) in enumerate(documents):
        remap: Dict[str, str] = {}
        remaps.append(remap)
        doc_root = (doc.get("metadata") or {}).get("component")
        if index and isinstance(doc_root, dict) and doc_root.get("bom-ref") and root_ref:
            remap[doc_root["bom-ref"]] = root_ref      # one product, one root
        for comp in doc.get("components") or []:
            if not isinstance(comp, dict):
                continue
            report.components_in += 1
            key = _key(comp)
            kept = by_key.get(key)
            if kept is not None:
                report.duplicates += 1
                for name in _FILL:
                    if name in comp and not kept.get(name):
                        kept[name] = copy.deepcopy(comp[name])
                _union_properties(kept, comp, label)
                if comp.get("bom-ref") and kept.get("bom-ref"):
                    remap[comp["bom-ref"]] = kept["bom-ref"]
                continue
            new = copy.deepcopy(comp)
            ref = new.get("bom-ref")
            if ref:
                final, n = ref, 1
                while final in used_refs:
                    n += 1
                    final = f"{ref}-{n}"
                new["bom-ref"] = final
                used_refs[final] = new
                remap[ref] = final
            by_key[key] = new
            components.append(new)

    by_name: Dict[str, List[str]] = {}
    for comp in components:
        by_name.setdefault(str(comp.get("name", "")).lower(), []).append(
            str(comp.get("version") or ""))
    for name, versions in sorted(by_name.items()):
        distinct = sorted(set(versions))
        if len(distinct) > 1:
            report.disagreements.append((name, distinct))

    # dependencies
    graph: Dict[str, List[str]] = {}
    for (_label, doc), remap in zip(documents, remaps):
        for dep in doc.get("dependencies") or []:
            if not isinstance(dep, dict) or "ref" not in dep:
                continue
            ref = remap.get(dep["ref"], dep["ref"])
            if ref not in used_refs:
                report.dangling_dependencies += 1
                continue
            targets = graph.setdefault(ref, [])
            for child in dep.get("dependsOn") or []:
                child = remap.get(child, child)
                if child not in used_refs:
                    report.dangling_dependencies += 1
                elif child not in targets:
                    targets.append(child)
    dependencies = [{"ref": r, "dependsOn": t} for r, t in graph.items()]

    # vulnerabilities
    vulns: Dict[Tuple[str, str], dict] = {}
    for (_label, doc), remap in zip(documents, remaps):
        for vuln in doc.get("vulnerabilities") or []:
            if not isinstance(vuln, dict) or not vuln.get("id"):
                continue
            ident = (str((vuln.get("source") or {}).get("name", "")).lower(), vuln["id"])
            mapped = copy.deepcopy(vuln)
            affects = []
            for aff in mapped.get("affects") or []:
                if isinstance(aff, dict) and "ref" in aff:
                    aff["ref"] = remap.get(aff["ref"], aff["ref"])
                    affects.append(aff)
            mapped["affects"] = affects
            kept = vulns.get(ident)
            if kept is None:
                vulns[ident] = mapped
                continue
            have = {a["ref"] for a in kept.get("affects", [])}
            kept.setdefault("affects", []).extend(a for a in affects if a["ref"] not in have)
            a_state = (kept.get("analysis") or {}).get("state")
            b_state = (mapped.get("analysis") or {}).get("state")
            if b_state and not a_state:
                kept["analysis"] = mapped["analysis"]
            elif a_state and b_state and a_state != b_state:
                report.state_conflicts.append(f"{vuln['id']}: {a_state} vs {b_state}")
                order = {s: i for i, s in enumerate(_STATE_ORDER)}
                if order.get(b_state, 99) < order.get(a_state, 99):
                    kept["analysis"] = mapped["analysis"]

    metadata = copy.deepcopy(first.get("metadata") or {})
    metadata["timestamp"] = timestamp or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    props = list(metadata.get("properties") or [])
    props.extend({"name": "gangmu:mergedFrom", "value": label} for label, _ in documents)
    metadata["properties"] = props

    merged: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": max((d.get("specVersion", "1.6") for _, d in documents),
                           key=lambda v: _spec({"specVersion": v})),
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if dependencies:
        merged["dependencies"] = dependencies
    if vulns:
        merged["vulnerabilities"] = list(vulns.values())
    report.components_out = len(components)
    report.vulnerabilities_out = len(vulns)
    return merged, report
