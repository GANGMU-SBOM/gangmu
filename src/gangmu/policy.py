"""Policy check: read a CBOM or AIBOM against a written policy and say what is due.

The scanners answer "what is in this firmware". A policy answers "is that allowed, and
until when". It is data in a rule pack of kind ``policy`` (``policies/*.yaml``), so a
regulation's table of algorithm deadlines is a file with a citation, not code::

    policies:
      - id: nist-ir-8547
        name: NIST IR 8547 (draft) transition
        source: {title: "NIST IR 8547 ipd", url: "https://...", status: "initial public draft"}
        checks:
          - id: rsa
            title: RSA
            subject: cbom
            match: {algorithms: [rsa]}
            deprecated-after: 2030-12-31
            disallowed-after: 2035-12-31
            reference: "Table 2, Table 4"
            remediation: "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"

A ``cbom`` check selects the counted assets of the CBOM by algorithm key and/or quantum
status; an ``aibom`` check selects models with something undeclared (``license``,
``training-data``). Each check ends in one status as of a date:

* ``ok`` -- nothing matched;
* ``due`` -- matched, and the first date has not come yet (the migration backlog);
* ``deprecated`` -- past ``deprecated-after``: discouraged, still permitted;
* ``fail`` -- past ``disallowed-after``, or matched a check that has no dates (a ban).

The scan's own limits carry over: algorithms are found by name, so a check cannot tell a
112-bit RSA key from a 3072-bit one, and a policy that depends on the key size says so in
its ``note``. The engine states what it matched and what the policy says; whether that is
a legal or contractual finding is for the person who owns the product.

This module reads the CBOM and AIBOM results; nothing in ``gangmu.core`` imports it.
"""
import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .aibom import AibomResult
from .cbom import CbomResult, QUANTUM_STATUSES
from .core.packs import RuleRoot, check_manifest, default_roots, read_manifest

POLICY_DIR = "policies"
SUBJECTS = ("cbom", "aibom")
STATUSES = ("ok", "due", "deprecated", "fail")      # in increasing seriousness
AIBOM_MISSING = ("license", "training-data")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    subject: str
    algorithms: Tuple[str, ...] = ()
    quantum: Tuple[str, ...] = ()
    missing: Tuple[str, ...] = ()
    deprecated_after: Optional[_dt.date] = None
    disallowed_after: Optional[_dt.date] = None
    reference: str = ""
    remediation: str = ""
    note: str = ""


@dataclass(frozen=True)
class Policy:
    id: str
    name: str
    source_title: str = ""
    source_url: str = ""
    source_status: str = ""
    note: str = ""
    checks: Tuple[Check, ...] = ()
    origin: str = ""


@dataclass
class CheckResult:
    check: Check
    status: str
    findings: List[str] = field(default_factory=list)
    due: Optional[_dt.date] = None        # the next date that matters for this check


@dataclass
class PolicyReport:
    policy: Policy
    as_of: _dt.date
    results: List[CheckResult]

    def worst(self) -> str:
        return max((r.status for r in self.results), key=STATUSES.index, default="ok")


def _date(value: Any, where: str) -> Optional[_dt.date]:
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value))
    except ValueError:
        raise PolicyError(f"{where}: '{value}' is not a date (write YYYY-MM-DD)") from None


def _names(entry: Dict[str, Any], key: str, where: str) -> Tuple[str, ...]:
    value = entry.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise PolicyError(f"{where}: '{key}' must be a list of names")
    return tuple(value)


def _check(entry: Any, where: str) -> Check:
    if not isinstance(entry, dict):
        raise PolicyError(f"{where}: a check must be a mapping")
    for key in ("id", "title", "subject"):
        if not str(entry.get(key) or "").strip():
            raise PolicyError(f"{where}: missing '{key}'")
    subject = str(entry["subject"])
    if subject not in SUBJECTS:
        raise PolicyError(f"{where}: subject '{subject}' is not one of {', '.join(SUBJECTS)}")
    match = entry.get("match")
    if not isinstance(match, dict) or not match:
        raise PolicyError(f"{where}: 'match' must say what to select")
    algorithms = _names(match, "algorithms", where + " match")
    quantum = _names(match, "quantum", where + " match")
    missing = _names(match, "missing", where + " match")
    if subject == "cbom":
        if missing:
            raise PolicyError(f"{where}: 'missing' belongs to aibom checks")
        if not algorithms and not quantum:
            raise PolicyError(f"{where}: a cbom check needs 'algorithms' or 'quantum'")
        bad = [q for q in quantum if q not in QUANTUM_STATUSES]
        if bad:
            raise PolicyError(f"{where}: quantum status '{bad[0]}' is not one of "
                              + ", ".join(sorted(QUANTUM_STATUSES)))
    else:
        if algorithms or quantum:
            raise PolicyError(f"{where}: 'algorithms' and 'quantum' belong to cbom checks")
        bad = [m for m in missing if m not in AIBOM_MISSING]
        if not missing or bad:
            raise PolicyError(f"{where}: an aibom check needs 'missing' from "
                              + ", ".join(AIBOM_MISSING))
    dep = _date(entry.get("deprecated-after"), where + " deprecated-after")
    dis = _date(entry.get("disallowed-after"), where + " disallowed-after")
    if dep and dis and dep > dis:
        raise PolicyError(f"{where}: 'deprecated-after' is later than 'disallowed-after'")
    return Check(str(entry["id"]).strip(), str(entry["title"]).strip(), subject,
                 algorithms, quantum, missing, dep, dis,
                 str(entry.get("reference") or ""), str(entry.get("remediation") or ""),
                 str(entry.get("note") or ""))


def _policy(entry: Any, where: str, origin: str) -> Policy:
    if not isinstance(entry, dict):
        raise PolicyError(f"{where}: a policy must be a mapping")
    for key in ("id", "name"):
        if not str(entry.get(key) or "").strip():
            raise PolicyError(f"{where}: missing '{key}'")
    source = entry.get("source") or {}
    if not isinstance(source, dict):
        raise PolicyError(f"{where}: 'source' must be a mapping")
    raw = entry.get("checks")
    if not isinstance(raw, list) or not raw:
        raise PolicyError(f"{where}: 'checks' must be a non-empty list")
    checks = tuple(_check(c, f"{where} checks[{i}]") for i, c in enumerate(raw))
    seen = set()
    for c in checks:
        if c.id in seen:
            raise PolicyError(f"{where}: duplicate check id '{c.id}'")
        seen.add(c.id)
    return Policy(str(entry["id"]).strip(), str(entry["name"]).strip(),
                  str(source.get("title") or ""), str(source.get("url") or ""),
                  str(source.get("status") or ""), str(entry.get("note") or ""), checks, origin)


def load_policy_roots(roots: Sequence[RuleRoot]) -> List[Policy]:
    """Every policy in ``policies/*.yaml`` of the roots; a later policy with the same id
    replaces an earlier one."""
    import yaml

    found: Dict[str, Policy] = {}
    for root in roots:
        folder = root.path / POLICY_DIR
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.y*ml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
                raise PolicyError(f"{path}: unreadable: {exc}") from exc
            entries = data.get("policies") if isinstance(data, dict) else data
            if not isinstance(entries, list):
                raise PolicyError(f"{path}: expected a list under 'policies:'")
            for i, entry in enumerate(entries):
                policy = _policy(entry, f"{path}[{i}]", root.label)
                found[policy.id] = policy
    return list(found.values())


def policy_roots(given: Sequence[str] = ()) -> List[RuleRoot]:
    """Rule roots for a policy check: the ones named, else installed packs of kind ``policy``."""
    if given:
        roots = [RuleRoot(Path(p), "--policy") for p in given]
        for r in roots:
            r.manifest = read_manifest(r.path)
    else:
        roots = default_roots(kind="policy")
    for r in roots:
        check_manifest(r.path, r.manifest)
    return roots


def _dated_status(check: Check, as_of: _dt.date) -> Tuple[str, Optional[_dt.date]]:
    if check.disallowed_after is None and check.deprecated_after is None:
        return "fail", None
    if check.disallowed_after is not None and as_of > check.disallowed_after:
        return "fail", check.disallowed_after
    if check.deprecated_after is not None and as_of > check.deprecated_after:
        return "deprecated", check.disallowed_after
    return "due", check.deprecated_after or check.disallowed_after


def evaluate(policy: Policy, as_of: _dt.date, cbom: Optional[CbomResult] = None,
             aibom: Optional[AibomResult] = None) -> PolicyReport:
    results: List[CheckResult] = []
    for check in policy.checks:
        findings: List[str] = []
        if check.subject == "cbom":
            if cbom is None:
                raise PolicyError(f"check '{check.id}' needs a CBOM scan")
            for a in cbom.counted():
                if check.algorithms and a.algo.key not in check.algorithms:
                    continue
                if check.quantum and a.algo.quantum not in check.quantum:
                    continue
                first = a.occurrences[0]
                where = first.path + (f":{first.line}" if first.line else "")
                findings.append(f"{a.name} at {where} ({a.count} hit(s), "
                                f"confidence {a.confidence():.2f})")
        else:
            if aibom is None:
                raise PolicyError(f"check '{check.id}' needs an AIBOM scan")
            for where, lacking in aibom.missing():
                hit = [x for x in lacking if x in check.missing]
                if hit:
                    findings.append(f"{where}: {' and '.join(hit)} not declared")
        if not findings:
            results.append(CheckResult(check, "ok"))
            continue
        status, due = _dated_status(check, as_of)
        results.append(CheckResult(check, status, findings, due))
    return PolicyReport(policy, as_of, results)


def needs(policies: Sequence[Policy]) -> Tuple[bool, bool]:
    """Whether the policies need a CBOM scan and an AIBOM scan."""
    subjects = {c.subject for p in policies for c in p.checks}
    return "cbom" in subjects, "aibom" in subjects


_LABEL = {"ok": "ok", "due": "due", "deprecated": "DEPRECATED", "fail": "FAIL"}


def failing(reports: Sequence[PolicyReport], fail_on: Sequence[str]) -> List[Tuple[Policy, CheckResult]]:
    """Results at or above the lowest status in ``fail_on`` (``fail`` by default)."""
    floor = min((STATUSES.index(s) for s in fail_on), default=STATUSES.index("fail"))
    return [(r.policy, c) for r in reports for c in r.results
            if c.status != "ok" and STATUSES.index(c.status) >= floor]


def policy_table(reports: Sequence[PolicyReport]) -> str:
    lines: List[str] = []
    for rep in reports:
        p = rep.policy
        src = ", ".join(x for x in (p.source_title, p.source_status) if x)
        lines.append(f"{p.name}" + (f"  [{src}]" if src else "") + f"  as of {rep.as_of}")
        rows = [("STATUS", "CHECK", "DUE", "FINDINGS")]
        for r in rep.results:
            rows.append((_LABEL[r.status], r.check.title, str(r.due or ""),
                         "; ".join(r.findings) if r.findings else ""))
        widths = [max(len(x[i]) for x in rows) for i in range(3)]
        for row in rows:
            lines.append("  " + "  ".join(c.ljust(w) for c, w in zip(row[:3], widths)) + "  " + row[3])
        if p.note:
            lines.append(f"  note: {p.note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def policy_markdown(reports: Sequence[PolicyReport]) -> str:
    out = ["# Policy check", ""]
    for rep in reports:
        p = rep.policy
        out.append(f"## {p.name}")
        out.append("")
        if p.source_title or p.source_url:
            ref = f"[{p.source_title or p.source_url}]({p.source_url})" if p.source_url \
                else p.source_title
            out.append(f"Source: {ref}" + (f" ({p.source_status})" if p.source_status else "")
                       + f". As of {rep.as_of}.")
            out.append("")
        if p.note:
            out += [f"> {p.note}", ""]
        for r in rep.results:
            if r.status == "ok":
                continue
            due = f", next date {r.due}" if r.due else ""
            out.append(f"- **{_LABEL[r.status]}: {r.check.title}**{due}"
                       + (f" ({r.check.reference})" if r.check.reference else ""))
            out.extend(f"  - {f}" for f in r.findings)
            if r.check.remediation:
                out.append(f"  - Move to: {r.check.remediation}")
            if r.check.note:
                out.append(f"  - {r.check.note}")
        clean = [r.check.title for r in rep.results if r.status == "ok"]
        if clean:
            out.append(f"- Nothing found for: {', '.join(clean)}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def policy_json(reports: Sequence[PolicyReport]) -> str:
    doc = []
    for rep in reports:
        p = rep.policy
        doc.append({
            "policy": p.id, "name": p.name, "asOf": rep.as_of.isoformat(),
            "source": {"title": p.source_title, "url": p.source_url, "status": p.source_status},
            "status": rep.worst(),
            "checks": [{"id": r.check.id, "title": r.check.title, "status": r.status,
                        "due": r.due.isoformat() if r.due else None,
                        "reference": r.check.reference, "findings": r.findings}
                       for r in rep.results]})
    return json.dumps(doc, indent=2, ensure_ascii=False)
