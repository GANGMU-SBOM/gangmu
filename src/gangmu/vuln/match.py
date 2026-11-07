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
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

from .model import Advisory, Match, VexState
from . import distver
from .version import in_event_ranges, in_range, in_tag_set, is_orderable
from ..core.cpe import split_cpe

if TYPE_CHECKING:
    from .sources import Wanted

_CPE_PARTS = 13


def cpe_product_key(cpe: str) -> Optional[str]:
    parts = split_cpe(cpe)
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
    :func:`purl_key` does). Gitee and the GitHub mirror of ``openharmony`` give
    ``pkg:generic/<owner>/<repo>``. Any other host gives ``pkg:generic/<host>/<path>``
    (``https://git.kernel.org/pub/scm/network/tftp/tftp-hpa.git`` ->
    ``pkg:generic/git.kernel.org/pub/scm/network/tftp/tftp-hpa``): the purl spec has no
    type for it, but OSV files real advisories under such repositories (kernel.org,
    savannah, sourceware), and a rule can name the same key in ``upstream.identifiers``.
    ``None`` only for what is not a repository URL."""
    if not url:
        return None
    text = url.strip()
    m = re.match(r"^(?:https?|git|ssh)://(?:[^@/]+@)?(?:www\.)?([^/:]+)(?::\d+)?/"
                 r"(.+?)(?:\.git)?/*$", text, re.I)
    if not m:
        m = re.match(r"^git@([^:]+):(.+?)(?:\.git)?/*$", text, re.I)
    if not m:
        return None
    host, path = m.group(1).lower(), m.group(2).strip("/")
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None
    if len(parts) == 2:
        owner, repo = parts
        if host in _GENERIC_HOSTS or (host, owner.lower()) in _MIRRORED_OWNERS:
            return f"pkg:generic/{owner}/{repo}".lower()
        kind = _REPO_HOSTS.get(host)
        if kind:
            return f"pkg:{kind}/{owner}/{repo}".lower()
    elif host in _REPO_HOSTS or host in _GENERIC_HOSTS:
        if host == "gitlab.com" and len(parts) > 2:      # gitlab subgroups
            return f"pkg:gitlab/{'/'.join(parts[:-1])}/{parts[-1]}".lower()
        return None
    return f"pkg:generic/{host}/{'/'.join(parts)}".lower()


# OSV ecosystem -> purl type. A record that gives no purl names its package by
# ecosystem and name; an ecosystem not listed here is skipped rather than guessed.
_ECOSYSTEM_PURL = {"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang",
                   "crates.io": "cargo", "nuget": "nuget", "rubygems": "gem",
                   "packagist": "composer", "hex": "hex", "pub": "pub",
                   "conancenter": "conan", "debian": "deb", "ubuntu": "deb", "alpine": "apk"}
_DISTRO_NAMESPACE = {"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine"}


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
    distro_package: bool = False
    """The SBOM names this component by a distribution package (``pkg:deb/...``,
    ``pkg:rpm/...``). Distributions backport fixes without raising the upstream version,
    so an upstream version inside an advisory's range does not make the package affected."""
    distro_family: Optional[str] = None
    """``debian``, ``ubuntu`` or ``alpine`` when the SBOM names the component by one of their
    packages: those distributions' own records, in their own version order, decide it."""
    distro_release: Optional[str] = None
    """The release it belongs to (``12``, ``22.04``, ``3.18``) when the purl's ``distro``
    qualifier or the revision says so; each release has its own fixed revision."""
    package_version: Optional[str] = None
    """The version of the distribution package itself (``1:1.2.11.dfsg-2+deb11u2``), when the
    SBOM gives one with a revision; what a Debian advisory's ranges are read against."""
    alias_keys: frozenset = frozenset()
    """Purl keys added through rules' ``upstream.identifiers`` (not written in the SBOM):
    a match reached through one of them says so, so a reviewer can tell it apart."""
    rule_cpes: frozenset = frozenset()
    """CPEs taken from the rule that claims the component's purl, for a component the
    SBOM gives no CPE: NVD's records are keyed by CPE, and a match through one says so."""
    linked: Optional[bool] = None
    """False when a link map showed none of the component's objects in the image;
    None when no link map was used (unknown, not "linked")."""


def candidates_from_scan(result) -> List[Candidate]:
    out: List[Candidate] = []
    for finding in result.findings:
        cpes = [c for c in [finding.cpe, *finding.cpe_aliases] if c]
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


def candidates_from_cyclonedx(bom: dict, purl_aliases=None) -> List[Candidate]:
    """Candidates of a CycloneDX SBOM. *purl_aliases* (:class:`~.aliases.PurlAliases`, built
    from the rules) adds the other purls of each component's upstream, so a record filed
    under a mirror or a distribution package still reaches it; a distribution purl that
    wrote the version into the name (``zlib-1.2.11``) also supplies a missing version."""
    from .aliases import DISTRO_TYPES, version_from_name, _split, purl_version
    from .debver import has_revision, upstream_version
    import re as _re
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
        purls = [p for p in [component.get("purl")] if p]
        family_purl = next((p for p in purls if distver.family_of_purl(p)), None)
        family = distver.family_of_purl(family_purl) if family_purl else None
        revised = family.has_revision if family else has_revision
        package_version = None
        for source in (component.get("version"), *map(purl_version, purls)):
            if source and revised(source):
                package_version = source
                break
        upstream = None
        if package_version:
            upstream = (_re.sub(r"-r[0-9]+$", "", package_version) if family and family.name == "alpine"
                        else upstream_version(package_version))
        version = component.get("version") or next(
            (v for v in map(version_from_name, purls) if v), None) or upstream
        distro = any((_split(p) or ("",))[0] in DISTRO_TYPES for p in purls)
        from .aliases import without_name_version
        purls += [p for p in map(without_name_version, purls) if p and p not in purls]
        alias_keys: frozenset = frozenset()
        rule_cpes: List[str] = []
        if purl_aliases is not None and not cpes:
            rule_cpes = purl_aliases.cpes_for(purls)
            cpes = list(rule_cpes)
        if purl_aliases is not None:
            extra = purl_aliases.expand(purls)
            alias_keys = frozenset(k for k in map(purl_key, extra) if k)
            purls += extra
        out.append(Candidate(
            name=component.get("name", "?"),
            directory=props.get("gangmu:directory", ""),
            version=version,
            cpes=cpes,
            purls=purls,
            distro_package=distro,
            alias_keys=alias_keys,
            rule_cpes=frozenset(rule_cpes),
            package_version=package_version if distro else None,
            distro_family=family.name if family else None,
            distro_release=(distver.release_from_purl(family_purl, package_version)
                            if family_purl else None),
            is_fork=bool(pedigree.get("patches")),
            fork_note=pedigree.get("notes", ""),
            confidence=confidence,
            subsystem_advisories=props.get("gangmu:advisoryScope") == "subsystem",
            linked={"true": True, "false": False}.get(linked or "")))
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


_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def vulnerability_key(advisory: Advisory) -> str:
    """One name for a vulnerability whichever database filed it: its CVE id if the
    record is one or aliases one, else the record's own id."""
    for name in [advisory.id, *advisory.aliases]:
        if _CVE_ID.match(str(name)):
            return str(name).upper()
    return advisory.id.upper()


def _merged(kept: Advisory, other: Advisory) -> Advisory:
    """*kept* with the other record's ids as aliases and its rating where *kept* has none.

    A copy: the advisory objects are shared by every component they match.
    """
    aliases = list(kept.aliases)
    for name in [other.id, *other.aliases]:
        if name != kept.id and name not in aliases:
            aliases.append(name)
    changes: Dict[str, Any] = {"aliases": aliases}
    if kept.cvss is None and other.cvss is not None:
        changes.update(cvss=other.cvss, vector=other.vector, cvss_method=other.cvss_method,
                       severity=other.severity)
    elif kept.severity is None and other.severity is not None:
        changes["severity"] = other.severity
    return replace(kept, **changes)


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
    if candidate.distro_package:
        return (VexState.IN_TRIAGE,
                f"version {candidate.version!r} is inside the advisory's range, but this is a "
                f"distribution package: distributions backport fixes without changing the "
                f"upstream version (Debian fixed zlib CVE-2022-37434 in 1:1.2.11.dfsg-4.1). "
                f"Compare the package revision with the distribution's own advisory")
    if candidate.is_fork:
        note = candidate.fork_note or "the vendor's copy differs from upstream"
        return (VexState.IN_TRIAGE,
                f"version is inside the advisory's range, but this is a vendor "
                f"fork ({note}). Whether the vendor already carries the fix "
                f"cannot be read from the version; check the fork's history.")
    return VexState.EXPLOITABLE, "version is inside the advisory's range"


def _via_alias(detail: str, candidate: Candidate, key: Optional[str]) -> str:
    """*detail*, saying so when the record was reached through a rule's alias rather than
    a purl the SBOM wrote."""
    if key and key in candidate.alias_keys:
        return f"{detail} (matched through {key}, an upstream.identifiers alias of this component)"
    return detail


def match(candidates: Sequence[Candidate], advisories: Sequence[Advisory],
          include_not_affected: bool = False, per_channel: bool = False) -> List[Match]:
    """Matches of *candidates* against *advisories*, one per vulnerability and component.

    *per_channel* keeps one per advisory record, component and channel instead, for
    measuring what each channel reaches on its own (``vuln coverage``).
    """
    by_cpe = _index_by_cpe(advisories)
    by_purl = _index_by_purl(advisories)
    # One match per (vulnerability, component). A vulnerability can reach a component
    # through several ranges, both channels, or two records (an NVD CVE and the GHSA
    # that aliases it); the one that says "affected" must win over one that says "not
    # affected" or "cannot tell", and the vulnerability must be counted once.
    found: Dict[tuple, Match] = {}
    severity = {VexState.EXPLOITABLE: 0, VexState.IN_TRIAGE: 1, VexState.NOT_AFFECTED: 2}

    def rank(m: Match, canonical: str) -> tuple:
        # Most serious state first; then the record filed under the CVE id itself.
        return (severity.get(m.state, 3), m.advisory.id.upper() != canonical)

    # A distribution's verdict on its own package (from the package revision) outranks
    # any upstream range; NVD's CPE range and an OSV record that contradict each other
    # (one "affected", the other "not affected") leave it to a person.
    settled: set = set()
    disputed: set = set()

    def source(m: Match) -> str:
        return f"{m.advisory.id} ({'NVD CPE range' if m.channel == 'cpe' else 'OSV, by purl'})"

    def keep(token: tuple, new: Match, authoritative: bool = False) -> None:
        if per_channel:
            token = (new.advisory.id.upper(), token[1], new.channel)
        old = found.get(token)
        if old is None:
            found[token] = new
            if authoritative:
                settled.add(token)
            return
        if not per_channel and (token in settled) != authoritative:
            best, other = (old, new) if token in settled else (new, old)
            settled.add(token)
            disputed.discard(token)
        elif not per_channel and token in disputed:
            best, other = old, new
        elif (not per_channel and old.channel != new.channel
              and {old.state, new.state} == {VexState.EXPLOITABLE, VexState.NOT_AFFECTED}):
            hit, miss = (old, new) if old.state is VexState.EXPLOITABLE else (new, old)
            best = replace(hit, state=VexState.IN_TRIAGE,
                           detail=f"the sources disagree: {source(hit)} puts version "
                                  f"{hit.version} in range ({hit.detail}), {source(miss)} "
                                  f"does not ({miss.detail}); read the advisory")
            other = miss
            disputed.add(token)
        else:
            best, other = (new, old) if rank(new, token[0]) < rank(old, token[0]) else (old, new)
        if best.advisory is not other.advisory:
            best.advisory = _merged(best.advisory, other.advisory)
        found[token] = best

    for candidate in candidates:
        cpe_seen: set = set()
        for cpe in candidate.cpes:
            key = cpe_product_key(cpe)
            for advisory, rng in by_cpe.get(key or "", []):
                cpe_seen.add(vulnerability_key(advisory))
                verdict = None
                if candidate.version and is_orderable(candidate.version):
                    verdict = in_range(
                        candidate.version,
                        start_including=rng.get("start_including"),
                        start_excluding=rng.get("start_excluding"),
                        end_including=rng.get("end_including"),
                        end_excluding=rng.get("end_excluding"))
                    if verdict is None:
                        pinned = split_cpe(rng["cpe"])[5]
                        if pinned not in ("*", "-"):
                            from .version import compare
                            cmp = compare(candidate.version, pinned)
                            verdict = (cmp == 0) if cmp is not None else None
                state, detail = _state_for(candidate, verdict)
                if cpe in candidate.rule_cpes:
                    detail += (" (CPE taken from the rule that claims this component's purl; "
                               "the SBOM gives none)")
                keep((vulnerability_key(advisory), candidate.directory),
                     Match(advisory=advisory, component=candidate.name,
                           directory=candidate.directory,
                           version=candidate.version, channel="cpe",
                           matched_on=rng["cpe"], state=state, detail=detail,
                           component_confidence=candidate.confidence))

        # A distribution package: its distribution's own records settle it before the
        # upstream ranges are looked at, so they are read first.
        decided: set = set()
        # An upstream component reached by a distribution's record (through an alias):
        # kept aside, and reported only for vulnerabilities no upstream record names.
        distro_only: Dict[str, tuple] = {}
        upstream_seen: set = set()
        ordered = (sorted(candidate.purls, key=lambda p: distver.family_of_purl(p) is None)
                   if candidate.distro_package else candidate.purls)
        for purl in ordered:
            key = purl_key(purl)
            done: set = set()
            range_family = distver.family_of_key(key) if candidate.distro_package else None
            for advisory, rng in by_purl.get(key or "", []):
                if range_family is not None:
                    if range_family.name != candidate.distro_family:
                        continue        # another distribution's package: not this one
                    if key in candidate.alias_keys:
                        # Another package of the same distribution, reached only through an
                        # alias (lua5.1 -> lua5.4): its revisions say nothing of this one's.
                        continue
                    vkey = vulnerability_key(advisory)
                    if vkey in done or rng.get("type") == "GIT":
                        continue
                    done.add(vkey)
                    # A distribution files a CVE per release across records (DEBIAN-CVE-...,
                    # DSA-..., USN-...), so every record of this vulnerability is read together.
                    group = [r for a, r in by_purl.get(key or "", []) if vulnerability_key(a) == vkey]
                    package = candidate.package_version or candidate.version
                    answer = (distver.verdict(range_family, package, group, candidate.distro_release)
                              if package else None)
                    name = range_family.name.capitalize()
                    if answer is not None:
                        decided.add(vkey)
                    if answer is None:
                        why = ("the SBOM gives no version for this package" if not package else
                               f"the package version {package} has no {name} revision, and its "
                               f"upstream release alone does not decide it (it is that of a fix, "
                               f"or {name}'s releases disagree); give the full package version"
                               if not candidate.package_version else
                               f"the package version cannot be placed against {name}'s release "
                               f"ranges for this advisory")
                        state, detail = VexState.IN_TRIAGE, why
                    elif answer:
                        state, detail = (VexState.EXPLOITABLE,
                                         f"package {package} is older than the {name} fix"
                                         if candidate.package_version else
                                         f"upstream release {package} is older than every {name} "
                                         f"fix's (a fix is backported into a revision, never into "
                                         f"an older upstream release)")
                    else:
                        state, detail = (VexState.NOT_AFFECTED,
                                         f"package {package} carries the {name} fix"
                                         if candidate.package_version else
                                         f"upstream release {package} is newer than every {name} fix's")
                    keep((vkey, candidate.directory),
                         Match(advisory=advisory, component=candidate.name,
                               directory=candidate.directory, version=candidate.version,
                               channel="purl", matched_on=rng["purl"], state=state,
                               detail=_via_alias(detail, candidate, key),
                               component_confidence=candidate.confidence),
                         authoritative=answer is not None)
                    continue
                if vulnerability_key(advisory) in decided:
                    continue            # the distribution's revision verdict outranks upstream's range
                key_family = None if candidate.distro_package else distver.family_of_key(key)
                if key_family is not None:
                    # A distribution's range is in its own package versions and starts at
                    # "0": it says when the distribution fixed it, not which upstream
                    # releases are affected (Debian files OpenSSL 3.0-only CVEs that
                    # 1.0.2 never had). It decides nothing for an upstream component.
                    distro_only.setdefault(vulnerability_key(advisory),
                                           (advisory, rng, key, key_family.name.capitalize()))
                    continue
                upstream_seen.add(vulnerability_key(advisory))
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
                keep((vulnerability_key(advisory), candidate.directory),
                     Match(advisory=advisory, component=candidate.name,
                           directory=candidate.directory,
                           version=candidate.version, channel="purl",
                           matched_on=rng["purl"], state=state,
                           detail=_via_alias(detail, candidate, key),
                           component_confidence=candidate.confidence))

        for vkey, (advisory, rng, key, name) in distro_only.items():
            if vkey in upstream_seen or vkey in cpe_seen:
                continue
            detail = (f"only {name}'s records name this vulnerability, and a distribution's "
                      f"ranges give its own package versions, not the upstream releases affected")
            keep((vkey, candidate.directory),
                 Match(advisory=advisory, component=candidate.name,
                       directory=candidate.directory, version=candidate.version,
                       channel="purl", matched_on=rng["purl"], state=VexState.IN_TRIAGE,
                       detail=_via_alias(detail, candidate, key),
                       component_confidence=candidate.confidence))

    out: List[Match] = [m for m in found.values()
                        if include_not_affected or m.state is not VexState.NOT_AFFECTED]

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
