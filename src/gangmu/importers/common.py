"""Shared machinery for deriving rules from a vendor SDK's own pins.

A vendor SDK states, in machine-readable form, which upstream projects it
vendors and at which commit. The format differs -- ESP-IDF uses git submodules,
Zephyr uses a west manifest -- but what follows is identical: fetch each project
at its pinned commit, fingerprint it, and emit a rule whose ``upstream.source``
points back at that exact commit.

Every rule produced this way is reproducible by CI on the day it is created,
which is the property the whole review model rests on.

What is deliberately not automated: the CPE when the vendor did not declare one.
A guessed CPE matches no CVE and makes the SBOM look clean, so the importer
leaves it out and marks the rule for a human.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import yaml

from ..dirprint import sha256_file
from ..fingerprint import ALGO
from ..manifest import read_manifest

_VERSION_IN_NAME = re.compile(r"version", re.I)


@dataclass
class VendoredProject:
    """One third-party project an SDK pins, however the SDK expresses it."""

    name: str
    path: str
    url: str
    sha: Optional[str] = None
    declared_version: Optional[str] = None
    declared_cpe: Optional[str] = None
    declared_url: Optional[str] = None
    groups: List[str] = field(default_factory=list)


@dataclass
class ProjectImport:
    project: VendoredProject
    rule_id: str
    status: str                    # "ok" | "no-source" | "error"
    detail: str = ""
    rule: Optional[dict] = None
    file_count: int = 0
    needs_cpe: bool = False


def git(args: Sequence[str], cwd: Optional[Path] = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout


def clone_metadata(url: str, dest: Path, ref: str = "HEAD") -> Path:
    """A blobless, checkout-free clone: enough to read a manifest and ls-tree."""
    dest.mkdir(parents=True, exist_ok=True)
    git(["clone", "--quiet", "--filter=blob:none", "--no-checkout", "--depth", "1",
         url, str(dest)])
    if ref != "HEAD":
        git(["fetch", "--quiet", "--depth", "1", "origin", ref], cwd=dest)
        git(["checkout", "--quiet", "FETCH_HEAD"], cwd=dest)
    return dest


def fetch_at(url: str, sha: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    git(["init", "--quiet"], cwd=dest)
    git(["remote", "add", "origin", url], cwd=dest)
    git(["fetch", "--quiet", "--depth", "1", "origin", sha], cwd=dest)
    git(["checkout", "--quiet", "FETCH_HEAD"], cwd=dest)
    return dest


def purl_from_url(url: str) -> Optional[str]:
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
    return f"pkg:github/{m.group(1)}/{m.group(2)}" if m else None


def pick_anchors(root: Path, files: Sequence[Path], limit: int = 2) -> List[Path]:
    """Prefer a version header: the file least likely to be touched by a port
    layer, and the one whose hash a human can sanity-check."""
    named = [f for f in files if _VERSION_IN_NAME.search(f.name)]
    if named:
        return sorted(named, key=lambda f: f.stat().st_size, reverse=True)[:limit]
    headers = [f for f in files if f.suffix in (".h", ".hpp")]
    pool = headers or list(files)
    return sorted(pool, key=lambda f: f.stat().st_size, reverse=True)[:limit]


def make_rule(project: VendoredProject, rule_id: str, checkout: Path, dp,
              vendor: str, sdk: str, sdk_version: Optional[str],
              include: Sequence[str], exclude: Sequence[str]) -> ProjectImport:
    manifest = read_manifest(checkout)
    name = (manifest.name if manifest and manifest.name else project.name)
    version = (project.declared_version
               or (manifest.version if manifest else None))
    if not version:
        # A component with no release still has an identity: the commit the SDK
        # pins. "UNKNOWN" in an SBOM is worse than useless -- it reads like a
        # version and matches nothing -- whereas a commit is a real locator.
        version = f"git-{project.sha[:12]}"
    cpe = project.declared_cpe or (manifest.cpe.replace("{}", "*")
                                   if manifest and manifest.cpe else None)
    parts = project.url.rstrip("/").split("/")
    owner = parts[-2].lower() if len(parts) >= 2 else ""
    is_fork = owner == vendor.lower() or owner.startswith(f"{sdk.lower()}project")

    sig = dp.signature()
    anchors = [{"path": p.relative_to(checkout).as_posix(),
                "sha256": {str(version): sha256_file(p)}}
               for p in pick_anchors(checkout, dp.files)]

    rule: Dict = {
        "id": rule_id,
        "vendor": vendor,
        "sdk": sdk,
        "component": {
            "path_globs": [project.path, f"**/{project.path}"],
            "ships_as": Path(project.path).name,
        },
        "upstream": {
            "name": name,
            "source": {"kind": "git", "url": project.url, "ref": project.sha},
        },
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
        },
        "confidence_ceiling": 0.95,
        "review": {
            "added": "", "by": ["gangmu rules import"],
            "imported_from": f"{project.url}@{project.sha}",
        },
    }
    if sdk_version:
        rule["sdk_versions"] = sdk_version
        rule["review"]["observed_in"] = f"{sdk} {sdk_version}"
    # A purl the module itself declares names the real upstream project; the
    # purl of the repository we fetched names a fork that no advisory cites.
    declared_purl = manifest.purl if manifest and manifest.purl else None
    purl = declared_purl or purl_from_url(project.url)
    if purl:
        rule["upstream"]["purl"] = purl
    if cpe:
        rule["upstream"]["cpe"] = cpe
    homepage = (manifest.url if manifest and manifest.url else project.declared_url)
    if homepage:
        rule["upstream"]["homepage"] = homepage
    if is_fork:
        rule["vendor_fork"] = {
            "patched": True,
            "note": (f"{vendor} maintains this fork; files will not hash to the "
                     f"upstream project they were forked from."),
        }
    if is_fork and not declared_purl:
        rule["review"]["todo_fork"] = (
            "Set vendor_fork.upstream_of_fork and change upstream.purl to the "
            "project this was forked from -- the fork's own purl matches no "
            "advisory. The importer cannot know which project that is.")
    if not cpe:
        rule["review"]["todo"] = (
            "No CPE: the vendor did not declare one. Find it at "
            "https://nvd.nist.gov/products/cpe/search before merging -- a wrong "
            "or missing CPE makes the SBOM look clean while matching nothing.")

    return ProjectImport(project, rule_id, "ok",
                         detail=f"{dp.file_count} files, version {version}",
                         rule=rule, file_count=dp.file_count, needs_cpe=not cpe)


def dump_rule(rule: Dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=10_000)
