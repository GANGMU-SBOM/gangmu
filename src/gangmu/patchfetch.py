"""Patch records for every advisory an SBOM matches: the online half of `vuln --patches`.

`gangmu patch-build` records one advisory from the commit that fixed it. Run for each
finding of a real SBOM that is a chore, and a patch record is what turns a version-range
match on a vendor fork from ``in_triage`` into ``fixed`` or ``vulnerable``. This module
does it in bulk: for the advisories the SBOM matches, it takes the fix commits an OSV
``GIT`` range names, builds a record from each (the one step that needs the network and
``git``), and keeps what it learned in one file, so the next run goes on from there.

Only advisories whose fix commit a database *states* are built (OSV ``fixed`` events of
a ``GIT`` range). A commit URL found in a reference is a guess and is not used.
Everything that cannot be recorded is written down with its reason, so it is not tried
again: a fix that changes no C function, a refactor-sized commit, an unreachable repo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .patchtest import PatchError, PatchRecord, build_record, save_patches
from .vuln.match import vulnerability_key

Build = Callable[[str, str, Sequence[str]], PatchRecord]


def fix_sources(matches: Iterable, advisories: Iterable) -> Dict[str, Tuple[str, List[str]]]:
    """``{record key: (repository, fix commits)}`` for the matched vulnerabilities that state a fix.

    A record is filed under the CVE id when the vulnerability has one, as `patch-build`
    does. The fix commits are read from *advisories*, not from the matches: a match
    whose NVD record won over the OSV record that aliases it no longer carries the OSV
    ranges."""
    wanted = {vulnerability_key(m.advisory) for m in matches}
    out: Dict[str, Tuple[str, List[str]]] = {}
    for adv in advisories:
        key = vulnerability_key(adv)
        if key not in wanted or key in out:
            continue
        for rng in adv.osv_ranges:
            commits = rng.get("fixed_commits") if rng.get("type") == "GIT" else None
            if commits and rng.get("repo"):
                out[key] = (str(rng["repo"]), [str(c) for c in commits])
                break
    return out


@dataclass
class BatchResult:
    built: List[str] = field(default_factory=list)
    skipped: Dict[str, str] = field(default_factory=dict)      # tried now and failed
    already: int = 0                                           # recorded or skipped before
    deferred: int = 0                                          # left for the next run (limit)
    no_fix: int = 0                                            # matches that name no fix commit


def build_missing(sources: Dict[str, Tuple[str, List[str]]], path: Path,
                  records: Dict[str, PatchRecord], skipped: Dict[str, str],
                  limit: int, refresh: bool = False,
                  build: Optional[Build] = None,
                  log: Callable[[str], None] = lambda m: None) -> BatchResult:
    """Build up to *limit* missing records and save the file after each one.

    *records* and *skipped* are what the file held; they are updated in place."""
    do = build or (lambda advisory, repo, commits: build_record(advisory, repo, commits))
    result = BatchResult()
    for key in sorted(sources):
        if not refresh and (key in records or key in skipped):
            result.already += 1
            continue
        if len(result.built) + len(result.skipped) >= limit:
            result.deferred += 1
            continue
        repo, commits = sources[key]
        log(f"{key}: {repo} {', '.join(c[:10] for c in commits)}")
        try:
            records[key] = do(key, repo, commits)
            skipped.pop(key, None)
            result.built.append(key)
        except PatchError as exc:
            result.skipped[key] = str(exc)
            if key not in records:          # a refresh that fails keeps the record it has
                skipped[key] = str(exc)
        save_patches(path, records, skipped)
    return result
