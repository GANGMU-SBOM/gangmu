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
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl.split("@", 1)[0].split("?", 1)[0].lower()


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
            confidence=finding.confidence))
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
        out.append(Candidate(
            name=component.get("name", "?"),
            directory=props.get("gangmu:directory", ""),
            version=component.get("version"),
            cpes=cpes,
            purls=[p for p in [component.get("purl")] if p],
            is_fork=bool(pedigree.get("patches")),
            fork_note=pedigree.get("notes", ""),
            confidence=confidence))
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
    out: List[Match] = []
    seen = set()

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
                token = (advisory.id, candidate.directory, "cpe")
                if token in seen:
                    continue
                seen.add(token)
                out.append(Match(advisory=advisory, component=candidate.name,
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
                token = (advisory.id, candidate.directory, "purl")
                if token in seen:
                    continue
                seen.add(token)
                out.append(Match(advisory=advisory, component=candidate.name,
                                 directory=candidate.directory,
                                 version=candidate.version, channel="purl",
                                 matched_on=rng["purl"], state=state, detail=detail,
                                 component_confidence=candidate.confidence))

    order = {VexState.EXPLOITABLE: 0, VexState.IN_TRIAGE: 1,
             VexState.NOT_AFFECTED: 2}
    out.sort(key=lambda m: (order.get(m.state, 3), -(m.advisory.cvss or 0),
                            m.advisory.id))
    return out


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
