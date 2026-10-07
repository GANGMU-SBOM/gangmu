"""Matching an SBOM against advisories.

Three decisions here are not the obvious ones, and each exists because the
obvious one is wrong for vendor-forked embedded code.

**A fork is never "not affected".** ESP-IDF ships Espressif's lwIP, reporting
itself as 2.2.0. An advisory fixed in 2.2.1 therefore matches. But the fork may
already carry the patch, or may have diverged in a way that makes the advisory
irrelevant -- and nothing in the SBOM can tell. The honest state is
``in_triage``, with the reason spelled out, not ``exploitable`` (which would
cry wolf) and emphatically not ``not_affected``.

**An unorderable version is not an absent one.** A component pinned to a commit
has no place on a version line. Every advisory for that component is reported
``in_triage`` rather than silently dropped, because "we could not tell" and
"there is nothing" must not look the same in a compliance artefact.

**Component confidence propagates.** A component identified at 0.5 produces
findings no more certain than that, and the number travels with them.
"""

from __future__ import annotations

import re
from urllib.parse import unquote
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from .model import Advisory, Match, VexState
from .version import in_event_ranges, in_range, in_tag_set, is_orderable

_CPE_PARTS = 13


def cpe_product_key(cpe: str) -> Optional[str]:
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return ":".join(parts[2:5]).lower()        # part:vendor:product


def purl_key(purl: str) -> Optional[str]:
    """``pkg:type/namespace/name``, lower-cased, without version, qualifiers or subpath.

    The version follows the *last* ``@`` of the last path segment: an npm scope
    (``pkg:npm/@babel/core@7.0.0``) has an ``@`` of its own, and splitting at the
    first one cut every scoped package down to ``pkg:npm/``. Percent-encoding is
    undone (``%40babel`` is ``@babel``), and PyPI names are normalised the way PEP 503
    does, so ``Foo_Bar.baz`` and ``foo-bar-baz`` are one package.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    at = body.find("@", body.rfind("/") + 1)
    if at != -1:
        body = body[:at]
    body = unquote(body).strip("/")
    kind, _, rest = body.partition("/")
    kind = kind.lower()
    if kind == "pypi":
        rest = re.sub(r"[-_.]+", "-", rest)
    return f"pkg:{kind}/{rest}".lower() if rest else f"pkg:{kind}"


_REPO_HOSTS = {"github.com": "github", "gitlab.com": "gitlab",
               "bitbucket.org": "bitbucket"}

# The purl spec registers no type for Gitee or GitCode (AtomGit), so a rule for a project whose
# primary repository is on one of them uses ``pkg:generic/<owner>/<repo>`` (the form
# the OpenHarmony declarations already use). An OSV GIT range names a
# repository by URL, so a URL on those hosts maps to that generic purl, and so does the
# GitHub mirror of an owner that is known to mirror its repositories there
# (OpenHarmony moved from Gitee to GitCode in September 2025):
# one repository, one key.
_GENERIC_HOSTS = ("gitee.com", "gitcode.com", "atomgit.com")
_MIRRORED_OWNERS = {("github.com", "openharmony")}


def purl_from_repo(url: Optional[str]) -> Optional[str]:
    """``https://github.com/o/r.git`` -> ``pkg:github/o/r`` (lower-cased, as
    :func:`purl_key` does), or ``None`` for a host with no purl type. Gitee and
    the GitHub mirror of ``openharmony`` give ``pkg:generic/<owner>/<repo>``."""
    if not url:
        return None
    m = re.match(r"^(?:https?|git|ssh)://(?:[^@/]+@)?(?:www\.)?([^/:]+)(?::\d+)?/"
                 r"([^/]+)/([^/]+?)(?:\.git)?/*$", url.strip(), re.I)
    if not m:
        m = re.match(r"^git@([^:]+):([^/]+)/([^/]+?)(?:\.git)?/*$", url.strip(), re.I)
    if not m:
        return None
    host, owner, repo = m.group(1).lower(), m.group(2), m.group(3)
    if host in _GENERIC_HOSTS or (host, owner.lower()) in _MIRRORED_OWNERS:
        return f"pkg:generic/{owner}/{repo}".lower()
    kind = _REPO_HOSTS.get(host)
    return f"pkg:{kind}/{owner}/{repo}".lower() if kind else None


# OSV ecosystem -> purl type. A record that gives no purl names its package by
# ecosystem and name; an ecosystem not listed here is skipped rather than guessed.
_ECOSYSTEM_PURL = {"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang",
                   "crates.io": "cargo", "nuget": "nuget", "rubygems": "gem",
                   "packagist": "composer", "hex": "hex", "pub": "pub",
                   "conancenter": "conan", "debian": "deb", "alpine": "apk"}
_DISTRO_NAMESPACE = {"debian": "debian", "alpine": "alpine"}


def purl_from_package(package: Optional[dict]) -> Optional[str]:
    """``{"ecosystem": "Maven", "name": "org.x:lib"}`` -> ``pkg:maven/org.x/lib``."""
    package = package or {}
    ecosystem = str(package.get("ecosystem") or "").split(":", 1)[0].strip().lower()
    name = str(package.get("name") or "").strip()
    kind = _ECOSYSTEM_PURL.get(ecosystem)
    if not kind or not name:
        return None
    if kind == "maven":
        name = name.replace(":", "/", 1)
    elif ecosystem in _DISTRO_NAMESPACE:
        name = f"{_DISTRO_NAMESPACE[ecosystem]}/{name}"
    return f"pkg:{kind}/{name}".lower()


@dataclass
class Candidate:
    """What the matcher needs to know about one SBOM component."""

    name: str
    directory: str
    version: Optional[str]
    cpes: List[str]
    purls: List[str]
    is_fork: bool = False
    fork_note: str = ""
    confidence: float = 1.0
    subsystem_advisories: bool = False
    """The component is an OS/SDK tree whose advisories each concern one subsystem."""
    linked: Optional[bool] = None
    """False when a link map showed none of the component's objects in the image;
    None when no link map was used (unknown, not "linked")."""


def candidates_from_scan(result) -> List[Candidate]:
    out: List[Candidate] = []
    for finding in result.findings:
        cpes = [c for c in [finding.cpe] if c]
        out.append(Candidate(
            name=finding.upstream_name, directory=finding.directory,
            version=finding.version, cpes=cpes,
            purls=[p for p in [finding.purl] if p],
            is_fork=finding.vendor_patched,
            fork_note=finding.patch_hint or "",
            confidence=finding.confidence,
            subsystem_advisories=finding.advisory_scope == "subsystem",
            linked=finding.linked))
    return out


def candidates_from_cyclonedx(bom: dict) -> List[Candidate]:
    out: List[Candidate] = []
    for component in bom.get("components", []) or []:
        props = {p.get("name"): p.get("value")
                 for p in component.get("properties", []) or []}
        aliases = [v for k, v in props.items() if k == "gangmu:cpeAlias"]
        cpes = [c for c in [component.get("cpe"), *aliases] if c]
        pedigree = component.get("pedigree") or {}
        try:
            confidence = float(props.get("gangmu:identityConfidence", 1.0))
        except (TypeError, ValueError):
            confidence = 1.0
        linked = props.get("gangmu:linkedIntoImage")
        out.append(Candidate(
            name=component.get("name", "?"),
            directory=props.get("gangmu:directory", ""),
            version=component.get("version"),
            cpes=cpes,
            purls=[p for p in [component.get("purl")] if p],
            is_fork=bool(pedigree.get("patches")),
            fork_note=pedigree.get("notes", ""),
            confidence=confidence,
            subsystem_advisories=props.get("gangmu:advisoryScope") == "subsystem",
            linked={"true": True, "false": False}.get(linked)))
    return out


def wanted_for(candidates: Sequence[Candidate]) -> "Wanted":
    """The products these candidates can match, for a selective feed read."""
    from .sources import Wanted       # sources imports the key helpers above
    return Wanted(
        cpe_keys=frozenset(k for c in candidates for k in map(cpe_product_key, c.cpes) if k),
        purl_keys=frozenset(k for c in candidates for k in map(purl_key, c.purls) if k))


def _index_by_cpe(advisories: Sequence[Advisory]) -> Dict[str, List[tuple]]:
    index: Dict[str, List[tuple]] = {}
    for advisory in advisories:
        for rng in advisory.cpe_ranges:
            key = cpe_product_key(rng["cpe"])
            if key:
                index.setdefault(key, []).append((advisory, rng))
    return index


def _index_by_purl(advisories: Sequence[Advisory]) -> Dict[str, List[tuple]]:
    index: Dict[str, List[tuple]] = {}
    for advisory in advisories:
        for rng in advisory.osv_ranges:
            key = purl_key(rng["purl"])
            if key:
                index.setdefault(key, []).append((advisory, rng))
    return index


def _state_for(candidate: Candidate, verdict: Optional[bool],
               commit_only: bool = False) -> tuple:
    """(state, detail) for one candidate/range pair."""
    if verdict is False:
        return VexState.NOT_AFFECTED, "version is outside the advisory's range"
    if verdict is None and commit_only:
        # OSS-Fuzz records: introduced/fixed commits and no release tags.
        return (VexState.IN_TRIAGE,
                f"the advisory bounds its range by commit only and lists no "
                f"release tags, so version {candidate.version!r} cannot be "
                f"placed in it; compare the fix commit with the vendor's tree")
    if verdict is None:
        return (VexState.IN_TRIAGE,
                f"version {candidate.version!r} cannot be ordered against the "
                f"advisory's range, so neither affected nor unaffected can be "
                f"established from the SBOM alone")
    if candidate.is_fork:
        note = candidate.fork_note or "the vendor's copy differs from upstream"
        return (VexState.IN_TRIAGE,
                f"version is inside the advisory's range, but this is a vendor "
                f"fork ({note}). Whether the vendor already carries the fix "
                f"cannot be read from the version; check the fork's history.")
    return VexState.EXPLOITABLE, "version is inside the advisory's range"


def match(candidates: Sequence[Candidate], advisories: Sequence[Advisory],
          include_not_affected: bool = False) -> List[Match]:
    by_cpe = _index_by_cpe(advisories)
    by_purl = _index_by_purl(advisories)
    # One match per (advisory, component, channel). An advisory can reach a component
    # through several ranges or listed versions; the one that says "affected" must win
    # over an earlier one that says "not affected" or "cannot tell", not be hidden by it.
    found: Dict[tuple, Match] = {}
    severity = {VexState.EXPLOITABLE: 0, VexState.IN_TRIAGE: 1, VexState.NOT_AFFECTED: 2}

    def keep(token: tuple, new: Match) -> None:
        old = found.get(token)
        if old is None or severity.get(new.state, 3) < severity.get(old.state, 3):
            found[token] = new

    for candidate in candidates:
        for cpe in candidate.cpes:
            key = cpe_product_key(cpe)
            for advisory, rng in by_cpe.get(key or "", []):
                verdict = None
                if candidate.version and is_orderable(candidate.version):
                    verdict = in_range(
                        candidate.version,
                        start_including=rng.get("start_including"),
                        start_excluding=rng.get("start_excluding"),
                        end_including=rng.get("end_including"),
                        end_excluding=rng.get("end_excluding"))
                    if verdict is None:
                        pinned = rng["cpe"].split(":")[5]
                        if pinned not in ("*", "-"):
                            from .version import compare
                            cmp = compare(candidate.version, pinned)
                            verdict = (cmp == 0) if cmp is not None else None
                state, detail = _state_for(candidate, verdict)
                if state is VexState.NOT_AFFECTED and not include_not_affected:
                    continue
                keep((advisory.id, candidate.directory, "cpe"),
                     Match(advisory=advisory, component=candidate.name,
                           directory=candidate.directory,
                           version=candidate.version, channel="cpe",
                           matched_on=rng["cpe"], state=state, detail=detail,
                           component_confidence=candidate.confidence))

        for purl in candidate.purls:
            key = purl_key(purl)
            for advisory, rng in by_purl.get(key or "", []):
                verdict = None
                if rng.get("type") == "GIT" and rng.get("extracted"):
                    verdict = in_event_ranges(candidate.version, rng["extracted"])
                elif rng.get("type") == "GIT":
                    verdict = in_tag_set(candidate.version, rng.get("tags", []),
                                         rng.get("open_ended", False))
                elif candidate.version and is_orderable(candidate.version):
                    verdict = in_range(candidate.version,
                                       introduced=rng.get("introduced"),
                                       fixed=rng.get("fixed"),
                                       last_affected=rng.get("last_affected"))
                state, detail = _state_for(
                    candidate, verdict,
                    commit_only=(rng.get("type") == "GIT" and not rng.get("tags")
                                 and not rng.get("extracted")))
                if state is VexState.NOT_AFFECTED and not include_not_affected:
                    continue
                keep((advisory.id, candidate.directory, "purl"),
                     Match(advisory=advisory, component=candidate.name,
                           directory=candidate.directory,
                           version=candidate.version, channel="purl",
                           matched_on=rng["purl"], state=state, detail=detail,
                           component_confidence=candidate.confidence))

    out: List[Match] = list(found.values())

    order = {VexState.EXPLOITABLE: 0, VexState.IN_TRIAGE: 1,
             VexState.NOT_AFFECTED: 2}
    out.sort(key=lambda m: (order.get(m.state, 3), -(m.advisory.cvss or 0),
                            m.advisory.id))
    return out


UNLINKED_NOTE = ("the link map shows none of this component's objects in the image, "
                 "so its code is probably not in the firmware; a map cannot see LTO "
                 "or code loaded another way, so confirm before relying on it")


SUBSYSTEM_NOTE = ("this component is an OS/SDK tree and the advisory concerns one subsystem "
                  "or driver; the version is in range, but whether the firmware builds "
                  "that code needs the file named in the advisory checked against the build")


def apply_linkage(matches: Sequence[Match], candidates: Sequence[Candidate],
                  mark_not_affected: bool = False) -> int:
    """Take the build's link map into account; return how many findings changed.

    A version-range match on a component that is in the source tree but not in the
    image is not an exploitable finding, and "exploitable" would cry wolf. By
    default such a finding drops to ``in_triage`` with the reason written down:
    a link map is strong evidence, not proof. With *mark_not_affected* it is
    recorded as ``not_affected`` / ``code_not_present`` for the team that has
    checked the build and wants the VEX to say so.
    """
    unlinked = {c.directory for c in candidates if c.linked is False}
    umbrella = {c.directory for c in candidates if c.subsystem_advisories}
    changed = 0
    for m in matches:
        if m.directory in unlinked:
            m.linkage = "not_linked"
        if m.directory in umbrella:
            m.subsystem_scope = True
        if (m.directory in umbrella and m.directory not in unlinked
                and m.state is VexState.EXPLOITABLE):
            m.state = VexState.IN_TRIAGE
            m.detail = (m.detail + "; " if m.detail else "") + "subsystem: " + SUBSYSTEM_NOTE
            changed += 1
        if m.directory not in unlinked or m.state not in (VexState.EXPLOITABLE,
                                                          VexState.IN_TRIAGE):
            continue
        before = m.state
        if mark_not_affected:
            m.state, m.justification = VexState.NOT_AFFECTED, "code_not_present"
        elif m.state is VexState.EXPLOITABLE:
            m.state = VexState.IN_TRIAGE
        m.detail = (m.detail + "; " if m.detail else "") + "not linked: " + UNLINKED_NOTE
        changed += m.state is not before
    return changed


def unmatched_components(candidates: Sequence[Candidate]) -> List[Candidate]:
    """Components no channel could even look up. These are the blind spots."""
    return [c for c in candidates if not c.cpes and not c.purls]


def without_cpe(candidates: Sequence[Candidate]) -> List[Candidate]:
    """Components the CPE channel cannot reach.

    Worth reporting separately from a total blind spot, because the compliance
    process on the other side of the SBOM is usually CPE-shaped. In the rule
    base built so far this is the majority: ten of eighteen components -- among
    them littlefs, zcbor, FatFs, OpenThread and a GigaDevice HAL -- have no CPE
    registered anywhere, and can only be reached by PURL.
    """
    return [c for c in candidates if not c.cpes]
