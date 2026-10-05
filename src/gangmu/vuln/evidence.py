"""Which NVD vendor:product a rule's upstream is filed under, with the CVEs to prove it.

A rule without a CPE is invisible to every CPE-based scanner, and a guessed CPE
is worse: it looks verified and silently matches nothing, or the wrong thing.
The NVD itself is the evidence. A CVE whose references point at the
upstream's own repository and whose configuration names ``vendor:product`` is
a record, written by NVD analysts, that the two are the same thing.

This module only finds and ranks that evidence. A human still reads it and
writes the CPE into the rule, citing the CVEs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .match import cpe_product_key
from .sources import FEED_SUFFIXES, iter_feed_items


@dataclass(frozen=True)
class Terms:
    """What identifies one rule's upstream in an NVD record."""

    rule_id: str
    name: str
    repos: Tuple[str, ...]          # "github.com/owner/repo", "host/path"; lower case


@dataclass
class Candidate:
    """One vendor:product NVD uses for a rule's upstream."""

    cpe_key: str                    # part:vendor:product
    by_reference: List[str] = field(default_factory=list)
    """CVEs whose references point into the upstream repository. Strong."""
    by_name: List[str] = field(default_factory=list)
    """CVEs whose description names the project. Weak: names collide."""

    @property
    def cpe(self) -> str:
        return "cpe:2.3:" + self.cpe_key + ":*:*:*:*:*:*:*:*"


_GITHUB = re.compile(r"^github\.com/([^/]+)/([^/#?]+)")
_URL = re.compile(r"^(?:https?://)?(?:www\.)?([^/\s?#]+)([^\s?#]*)", re.I)


def repo_key(url: Optional[str]) -> Optional[str]:
    """Where an upstream lives, as it would appear inside a reference URL.

    ``github.com/owner/repo`` for a GitHub URL or ``pkg:github`` purl, else
    host and path (``elm-chan.org/fsw/ff``): FatFs, lwIP and hostap do not
    live on GitHub, and their CVEs cite their own sites.
    """
    if not url:
        return None
    if url.startswith("pkg:github/"):
        parts = url[len("pkg:github/"):].split("@", 1)[0].split("?", 1)[0].split("/")
        return f"github.com/{parts[0]}/{parts[1]}".lower() if len(parts) >= 2 else None
    if url.startswith("pkg:"):
        return None
    m = _URL.match(url.strip())
    if not m or "." not in m.group(1):
        return None
    key = (m.group(1) + m.group(2)).lower().rstrip("/")
    gh = _GITHUB.match(key)
    if gh:
        repo = gh.group(2)
        key = f"github.com/{gh.group(1)}/{repo[:-4] if repo.endswith('.git') else repo}"
    return key


def terms_for(rule) -> Terms:
    repos = {repo_key(rule.purl), repo_key(rule.homepage),
             repo_key(rule.source.url if rule.source else None),
             *(repo_key(m.url) for m in rule.mirrors)}
    return Terms(rule_id=rule.id, name=rule.upstream_name,
                 repos=tuple(sorted(r for r in repos if r)))


def _compile(terms: Sequence[Terms]):
    repo_owner: Dict[str, List[str]] = {}
    name_owner: Dict[str, List[str]] = {}
    for t in terms:
        for repo in t.repos:
            repo_owner.setdefault(repo, []).append(t.rule_id)
        if t.name:
            name_owner.setdefault(t.name.lower(), []).append(t.rule_id)
    # A repository URL ends at a path separator: openssl/openssl must not
    # claim openssl/openssl-fips.
    repos = (re.compile("(?<=[/.])(%s)(?=[/#?\"'\\s]|$)" % "|".join(
        re.escape(r) for r in sorted(repo_owner, key=len, reverse=True)), re.M)
        if repo_owner else None)
    names = (re.compile(r"(?<![\w.-])(%s)(?![\w-])" % "|".join(
        re.escape(n) for n in sorted(name_owner, key=len, reverse=True)), re.I)
        if name_owner else None)
    return repos, repo_owner, names, name_owner


def _cpe_keys(cve: dict) -> List[str]:
    keys = []
    for config in cve.get("configurations", []) or []:
        nodes = config.get("nodes", []) if isinstance(config, dict) else []
        for node in nodes or []:
            for match in node.get("cpeMatch", []) or []:
                key = cpe_product_key(match.get("criteria") or "")
                if key and key not in keys:
                    keys.append(key)
    return keys


Found = Dict[str, Dict[str, Tuple[List[str], List[str]]]]


def scan_feed(path: Path, terms: Sequence[Terms]) -> Found:
    """Evidence in one feed file: rule id -> cpe key -> (by reference, by name)."""
    repos, repo_owner, names, name_owner = _compile(terms)
    found: Found = {}
    for item in iter_feed_items(path):
        cve = item.get("cve") or item
        refs = "\n".join(r.get("url", "") for r in cve.get("references", []) or []
                         ).lower()
        by_ref = set()
        if repos is not None:
            for m in repos.finditer(refs):
                by_ref.update(repo_owner[m.group(1)])
        by_name = set()
        if names is not None:
            for desc in cve.get("descriptions", []) or []:
                if desc.get("lang") == "en":
                    for m in names.finditer(desc.get("value", "")):
                        by_name.update(name_owner[m.group(1).lower()])
        if not by_ref and not by_name:
            continue
        keys = _cpe_keys(cve)
        if not keys:
            continue
        cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
        for rule_id in by_ref | by_name:
            per_rule = found.setdefault(rule_id, {})
            for key in keys:
                ref_list, name_list = per_rule.setdefault(key, ([], []))
                (ref_list if rule_id in by_ref else name_list).append(cve_id)
    return found


def find_evidence(directory: Path, terms: Sequence[Terms],
                  jobs: int = 1) -> Dict[str, List[Candidate]]:
    """Every vendor:product NVD records for each rule, strongest first.

    Ranked by how many CVEs cite the upstream repository, then by how many
    name the project. Feed files are read in parallel with *jobs* > 1.
    """
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"NVD mirror not found: {directory}")
    paths = sorted((p for p in directory.rglob("*")
                    if p.is_file() and p.name.lower().endswith(FEED_SUFFIXES)),
                   key=lambda p: -p.stat().st_size)
    parts: List[Found] = []
    if jobs > 1 and len(paths) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            parts = list(pool.map(scan_feed, paths, [tuple(terms)] * len(paths)))
    else:
        parts = [scan_feed(p, terms) for p in paths]

    merged: Dict[str, Dict[str, Candidate]] = {t.rule_id: {} for t in terms}
    for part in parts:
        for rule_id, per_rule in part.items():
            for key, (refs, named) in per_rule.items():
                cand = merged[rule_id].setdefault(key, Candidate(cpe_key=key))
                cand.by_reference.extend(refs)
                cand.by_name.extend(named)
    out: Dict[str, List[Candidate]] = {}
    for rule_id, per_rule in merged.items():
        for cand in per_rule.values():
            cand.by_reference.sort()
            cand.by_name.sort()
        out[rule_id] = sorted(per_rule.values(), key=lambda c: (
            -len(c.by_reference), -len(c.by_name), c.cpe_key))
    return out
