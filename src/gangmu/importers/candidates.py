"""Draft generic rules from a list of upstream projects others found to be widely vendored.

The list comes from outside gangmu: an index of public package registries
(PlatformIO, Arduino, ESP Component Registry, RT-Thread packages, vcpkg) names
the projects their packages republish, with the upstream repository each one
cites. Of an entry gangmu trusts only the repository URL (and an optional
subdirectory). Everything the rule asserts is re-derived here from the
upstream's own release tags -- the fingerprint from the latest release, the
function signature from the recent ones -- so ``gangmu rules verify`` reproduces
it the day it is written, as for any other import.

The file is JSON: a list of objects, or {"candidates": [...]}::

    {"id": "generic/cjson", "name": "cJSON", "url": "https://github.com/DaveGamble/cJSON",
     "subdir": null, "license": "MIT", "tag_pattern": null, "tags": null,
     "note": "republished by 7 packages on 3 registries ..."}

A rule built this way describes the whole upstream repository at a release: its ports,
tools, demo applications and integrations as well as the library a vendor copies. Every
rule is therefore marked ``functions.subset``, so that a copy of the library's part is
accepted (the engine's subset test: at least 40 of the directory's functions are the
component's and at least 90% of its functions are) -- except for an entry flagged
``bundles``: much of its code is also in other, unrelated packages, which it may bundle
or which may bundle it (the index cannot always tell which). Accepting partial copies
could then claim those packages' code, so such a rule fires only where most of it is
present.

What stays manual, as for every import: the CPE. A rule is written with
``cpe_status: unverified ...`` and a review note, and must not be merged before
someone has looked the project up in NVD (``gangmu rules cpe-evidence``).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from ..dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_directory, sha256_file
from ..fingerprint import ALGO
from .common import ProjectImport, VendoredProject, fetch_at, pick_anchors, purl_from_url
from .versions import build_function_signature, list_tags, pick_releases, tag_to_version

# release tags only: a number in it, and not a pre-release
_PRERELEASE = re.compile(r"(?:^|[^a-z])(rc|alpha|beta|pre|preview|dev|snapshot|test)\d*(?:[^a-z]|$)", re.I)
_SLUG = re.compile(r"[^a-z0-9._-]+")


@dataclass
class Candidate:
    id: str
    name: str
    url: str
    subdir: Optional[str] = None
    license: Optional[str] = None
    tags: Optional[List[str]] = None
    tag_pattern: Optional[str] = None
    note: Optional[str] = None
    bundles: Optional[Dict] = None
    evidence: Dict = field(default_factory=dict)

    @property
    def slug(self) -> str:
        return self.id.rsplit("/", 1)[-1]


def load_candidates(path: Path) -> List[Candidate]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data["candidates"] if isinstance(data, dict) else data
    out = []
    for row in rows:
        name = row["name"]
        rid = row.get("id") or f"generic/{_SLUG.sub('-', name.lower()).strip('-')}"
        out.append(Candidate(id=rid, name=name, url=row["url"].rstrip("/").removesuffix(".git"),
                             subdir=row.get("subdir"), license=row.get("license"),
                             tags=row.get("tags"), tag_pattern=row.get("tag_pattern"),
                             note=row.get("note"), bundles=row.get("bundles"),
                             evidence=row.get("evidence") or {}))
    return out


def release_tags(tags: Sequence[str]) -> List[str]:
    """Tags that name a release: they carry a number and no pre-release marker."""
    return [t for t in tags if re.search(r"\d", t) and not _PRERELEASE.search(t)]


def import_candidates(path: Path, out_dir: Path, limit: int = 12,
                      include: Sequence[str] = DEFAULT_INCLUDE,
                      exclude: Sequence[str] = DEFAULT_EXCLUDE,
                      only: Optional[Sequence[str]] = None,
                      date: str = "", jobs: int = 1,
                      workdir: Optional[Path] = None,
                      log: Callable[[str], None] = lambda m: None) -> List[ProjectImport]:
    """One draft rule per candidate, with its function signature written beside it in
    *out_dir* (the rule's ``identity.functions.file`` names it)."""
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="gangmu-cand-"))
    owns_tmp = workdir is None
    results: List[ProjectImport] = []
    try:
        for cand in load_candidates(path):
            if only and cand.id not in only and cand.slug not in only:
                continue
            results.append(_import_one(cand, out_dir, limit, include, exclude, date, jobs,
                                       tmp / cand.slug, log))
    finally:
        if owns_tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    return results


def _import_one(cand: Candidate, out_dir: Path, limit: int, include: Sequence[str],
                exclude: Sequence[str], date: str, jobs: int, work: Path,
                log: Callable[[str], None]) -> ProjectImport:
    project = VendoredProject(name=cand.name, path=cand.slug, url=cand.url)
    try:
        tags = cand.tags or release_tags(list_tags(cand.url, cand.tag_pattern))
    except subprocess.CalledProcessError as exc:
        return ProjectImport(project, cand.id, "error", f"cannot list tags: {(exc.stderr or '').strip()[:160]}")
    if not tags:
        return ProjectImport(project, cand.id, "error",
                             "no release tags: a rule must pin a release, never a branch")
    tags = pick_releases(tags, limit)
    latest = tags[-1]
    project.sha = latest
    try:
        log(f"{cand.id}: fetching {latest}")
        checkout = fetch_at(cand.url, latest, work / "latest")
    except subprocess.CalledProcessError as exc:
        return ProjectImport(project, cand.id, "error", f"fetch failed: {(exc.stderr or '').strip()[:160]}")
    root = checkout / cand.subdir if cand.subdir else checkout
    if not root.is_dir():
        return ProjectImport(project, cand.id, "error", f"{cand.subdir} is not in {latest}")
    dp = print_directory(root, include, exclude, jobs=jobs)
    if dp.file_count == 0:
        return ProjectImport(project, cand.id, "no-source", "no C/C++ sources at the latest release")

    log(f"{cand.id}: function signature from {len(tags)} release(s)")
    report = build_function_signature(cand.url, tags, include=include, exclude=exclude,
                                      subdir=cand.subdir, label=tag_to_version, jobs=jobs,
                                      workdir=work / "releases", log=log)
    if not report.tags:
        return ProjectImport(project, cand.id, "error", "no release yielded functions")
    out_dir.mkdir(parents=True, exist_ok=True)
    sidecar = out_dir / f"{cand.slug}.fnsig"
    digest = report.signature.write(sidecar)
    sig_versions = list(report.signature.versions)

    version = tag_to_version(latest)
    sig = dp.signature()
    anchors = [{"path": p.relative_to(root).as_posix(), "sha256": {version: sha256_file(p)}}
               for p in pick_anchors(root, dp.files)]
    upstream: Dict = {"name": cand.name}
    purl = purl_from_url(cand.url)
    if purl:
        upstream["purl"] = purl
    upstream["cpe_status"] = ("unverified: generated by gangmu rules import --manifest candidates "
                              "from a registry index; nobody has searched NVD for it yet")
    upstream["homepage"] = cand.url
    if cand.license:
        upstream["license"] = cand.license
    upstream["source"] = {"kind": "git", "url": cand.url, "ref": latest}
    if cand.subdir:
        upstream["source"]["subdir"] = cand.subdir
    globs = sorted({cand.slug, Path(cand.url).name, cand.name})
    rule: Dict = {
        "id": cand.id,
        "component": {"ships_as": cand.slug,
                      "path_globs": [g for n in globs for g in (n, f"**/{n}")]},
        "upstream": upstream,
        "identity": {
            "include": list(include),
            "exclude": list(exclude),
            "anchors": anchors,
            "signature": {
                "algo": ALGO, "k": sig.k, "window": sig.window, "size": sig.size,
                "reference_version": version,
                "fileset_sha256": dp.fileset_sha256,
                "values": sig.to_hex(),
            },
            "functions": {"file": sidecar.name, "sha256": digest,
                          "count": len(report.signature.hashes), "versions": sig_versions},
        },
        "confidence_ceiling": 0.95,
        "review": {
            "added": date,
            "by": ["gangmu rules import --manifest candidates"],
            "imported_from": f"{cand.url}@{latest}",
            "todo": ("No CPE: find it with `gangmu rules cpe-evidence` or at "
                     "https://nvd.nist.gov/products/cpe/search before merging, or record "
                     "why there is none -- a missing CPE matches no CVE."),
        },
    }
    if cand.bundles:
        rule["review"]["shared_code"] = (f"{int(100 * cand.bundles.get('share', 0))}% of its code is also in "
                                         f"other packages ({', '.join(cand.bundles.get('libraries', []))}), "
                                         f"which it may bundle or which may bundle it: not marked subset, so a "
                                         f"partial copy of theirs is not claimed")
    else:
        rule["identity"]["functions"]["subset"] = True
    if cand.note:
        rule["review"]["note"] = cand.note
    if cand.evidence:
        rule["review"]["evidence"] = cand.evidence
    skipped = f", {len(report.skipped)} release(s) skipped" if report.skipped else ""
    return ProjectImport(project, cand.id, "ok",
                         detail=f"{dp.file_count} files, {len(report.signature.hashes)} functions over "
                                f"{len(sig_versions)} release(s) up to {version}{skipped}",
                         rule=rule, file_count=dp.file_count, needs_cpe=True)
