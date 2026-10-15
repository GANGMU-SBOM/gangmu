"""Read the licences in a CycloneDX SBOM for what needs a person's attention.

This is a triage, not a legal conclusion (EDITIONS.md: the tool prompts, a lawyer
decides). It sorts each component's declared licence into permissive, weak
copyleft, strong copyleft, network copyleft or unknown, and flags two things:

* copyleft licences in the product, with the obligation that usually follows;
* pairs of licences in one product that the FSF's licence list says cannot be
  combined into one work (Apache-2.0 with GPL-2.0-only, GPL-2.0-only with
  GPL-3.0-only, the advertising-clause licences with any GPL, CDDL with GPL ...).

The SBOM does not say how two components are combined (linked into one image, or
separate programs on one filesystem), and the second case is usually fine, so a
pair is reported as "possible" and never as a violation.

An ``OR`` expression offers a choice: the component is classed by its most
permissive alternative, and a ``WITH`` exception (``GPL-2.0-only WITH
Classpath-exception-2.0``) is noted but does not change the class, because
whether an exception covers a particular use is the lawyer's call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

PERMISSIVE = frozenset("""0BSD Apache-2.0 BSD-2-Clause BSD-3-Clause BSL-1.0 CC0-1.0 ISC MIT MIT-0
NCSA Unlicense X11 Zlib Apache-1.1 Artistic-2.0 libpng-2.0 curl PSF-2.0 FTL OpenSSL BSD-4-Clause
""".split())
_ORDER = ["permissive", "weak", "strong", "network", "unknown"]


def classify_id(spdx_id: str) -> str:
    base = spdx_id.rstrip("+")
    if base in PERMISSIVE:
        return "permissive"
    if base.startswith("AGPL"):
        return "network"
    if base.startswith("LGPL") or base.startswith(("MPL-", "EPL-", "CDDL-", "EUPL-", "CPL-")):
        return "weak"
    if base.startswith("GPL"):
        return "strong"
    return "unknown"


def _tokens(expression: str) -> List[str]:
    return re.findall(r"\(|\)|[A-Za-z0-9.+\-]+", expression)


def parse_expression(expression: str) -> Tuple[List[List[str]], List[str]]:
    """``(alternatives, exceptions)``: alternatives are the ``OR`` branches, each a list of
    the ids that apply together (``AND``). Nested parentheses are flattened, which is
    exact for the flat expressions real SBOMs carry."""
    exceptions: List[str] = []
    alternatives: List[List[str]] = [[]]
    tokens = _tokens(expression)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        up = tok.upper()
        if tok in "()":
            pass
        elif up == "OR":
            alternatives.append([])
        elif up == "AND":
            pass
        elif up == "WITH":
            if i + 1 < len(tokens):
                exceptions.append(tokens[i + 1])
                i += 1
        else:
            alternatives[-1].append(tok)
        i += 1
    return [a for a in alternatives if a], exceptions


def component_class(expression: str) -> Tuple[str, List[str], List[str]]:
    """``(class, chosen ids, exceptions)`` for one licence expression."""
    alternatives, exceptions = parse_expression(expression)
    if not alternatives:
        return "unknown", [], exceptions
    best: Optional[Tuple[int, List[str]]] = None
    for alt in alternatives:
        worst = max(_ORDER.index(classify_id(i)) for i in alt)
        if best is None or worst < best[0]:
            best = (worst, alt)
    assert best is not None
    return _ORDER[best[0]], best[1], exceptions


# ---------------------------------------------------------------- incompatibility

def _gpl(spdx: str) -> Optional[Tuple[str, bool]]:
    m = re.match(r"^A?GPL-(\d)\.0-(only|or-later)$|^A?GPL-(\d)\.0\+$", spdx)
    if not m:
        return None
    version = m.group(1) or m.group(3)
    return version, bool(m.group(2) == "or-later" or m.group(3))


def incompatible(a: str, b: str) -> Optional[str]:
    """Why licences *a* and *b* cannot be combined in one work, per the FSF licence
    list, or None. Symmetric."""
    for x, y in ((a, b), (b, a)):
        gx, gy = _gpl(x), _gpl(y)
        if x in ("Apache-2.0",) and gy and gy[0] == "2" and not gy[1]:
            return f"{x} is not compatible with {y} (only GPL version 3 or later accepts Apache-2.0)"
        if gx and gy and gx[0] == "2" and not gx[1] and gy[0] == "3" and not gy[1] \
                and not y.startswith("A"):
            return f"{x} and {y} cannot be combined (no 'or later' in the first)"
        if x.startswith("AGPL") and gy and gy[0] == "2" and not gy[1]:
            return f"{x} and {y} cannot be combined"
        if x in ("OpenSSL", "BSD-4-Clause") and gy:
            return f"{x}'s advertising clause is incompatible with {y}"
        if x.startswith("CDDL") and gy:
            return f"{x} is incompatible with {y}"
        if x == "EPL-1.0" and gy:
            return f"{x} is incompatible with {y}"
    return None


# ------------------------------------------------------------------------- report

@dataclass
class ComponentLicense:
    name: str
    version: str
    expression: str
    klass: str
    ids: List[str]
    exceptions: List[str]


@dataclass
class LicenseReport:
    components: List[ComponentLicense] = field(default_factory=list)
    unlicensed: List[str] = field(default_factory=list)
    unlicensed_files: List[str] = field(default_factory=list)   # prebuilt binaries
    copyleft: List[str] = field(default_factory=list)
    network: List[str] = field(default_factory=list)
    possible_conflicts: List[Tuple[str, str, str]] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)


def _expression_of(comp: dict) -> Optional[str]:
    parts: List[str] = []
    for entry in comp.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str):
            parts.append(f"({entry['expression']})")
        lic = entry.get("license")
        if isinstance(lic, dict):
            value = lic.get("id") or lic.get("name")
            if isinstance(value, str) and value.strip():
                parts.append(value.strip())
    if not parts:
        return None
    # CycloneDX: several license entries are all claimed, i.e. AND.
    return " AND ".join(parts)


def check_licenses(bom: dict) -> LicenseReport:
    report = LicenseReport()
    seen_components = set()
    for comp in bom.get("components") or []:
        if not isinstance(comp, dict):
            continue
        label = f"{comp.get('name', '?')} {comp.get('version') or ''}".strip()
        key = (comp.get("name"), comp.get("version"))
        if key in seen_components:
            continue
        seen_components.add(key)
        expression = _expression_of(comp)
        if expression is None:
            if comp.get("type") == "file":          # an inventoried prebuilt binary
                report.unlicensed_files.append(label)
                continue
            report.unlicensed.append(label)
            report.counts["unknown"] = report.counts.get("unknown", 0) + 1
            continue
        klass, ids, exceptions = component_class(expression)
        report.counts[klass] = report.counts.get(klass, 0) + 1
        report.components.append(ComponentLicense(
            comp.get("name", "?"), comp.get("version") or "", expression, klass, ids,
            exceptions))
        if klass == "unknown":
            report.unlicensed.append(f"{label} ({expression})")
        elif klass in ("strong", "weak"):
            report.copyleft.append(f"{label}: {' AND '.join(ids)}")
        elif klass == "network":
            report.network.append(f"{label}: {' AND '.join(ids)}")
    chosen = [(c, i) for c in report.components for i in c.ids]
    pairs = set()
    for ci, (ca, ia) in enumerate(chosen):
        for cb, ib in chosen[ci + 1:]:
            if ca is cb or ia == ib:
                continue
            why = incompatible(ia, ib)
            if why and (ia, ib, ca.name, cb.name) not in pairs:
                pairs.add((ia, ib, ca.name, cb.name))
                report.possible_conflicts.append(
                    (f"{ca.name} ({ia})", f"{cb.name} ({ib})", why))
    return report


def render(report: LicenseReport) -> str:
    lines = [f"components with a licence: {len(report.components)}   "
             + "  ".join(f"{k}: {report.counts.get(k, 0)}" for k in _ORDER)]
    if report.network:
        lines += ["", "network copyleft (AGPL: source offer to users of a network service):"]
        lines += [f"  {x}" for x in report.network]
    strong = [x for x in report.copyleft]
    if strong:
        lines += ["", "copyleft (GPL: source offer for the distributed work; "
                  "LGPL/MPL/EPL: obligations on the library itself and on relinking):"]
        lines += [f"  {x}" for x in strong]
    if report.possible_conflicts:
        lines += ["", "possible incompatibilities (only if the two are combined into one "
                  "work; separate programs on one image usually are not):"]
        lines += [f"  {a} + {b}: {why}" for a, b, why in report.possible_conflicts]
    if report.unlicensed:
        lines += ["", f"no usable licence ({len(report.unlicensed)}):"]
        lines += [f"  {x}" for x in report.unlicensed[:50]]
        if len(report.unlicensed) > 50:
            lines.append(f"  ... and {len(report.unlicensed) - 50} more")
    if report.unlicensed_files:
        lines += ["", f"prebuilt binaries with no licence stated ({len(report.unlicensed_files)}; "
                  "their source and terms are unknown):"]
        lines += [f"  {x}" for x in report.unlicensed_files[:25]]
        if len(report.unlicensed_files) > 25:
            lines.append(f"  ... and {len(report.unlicensed_files) - 25} more")
    lines += ["", "This is a triage for a person to review, not a legal conclusion."]
    return "\n".join(lines)
