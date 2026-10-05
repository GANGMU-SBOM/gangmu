"""Importing rules from a vendor SDK's ``.gitmodules``.

Writing rules one at a time does not scale to a rule base worth having, and most
of the work is mechanical. A vendor SDK already states, in machine-readable
form, exactly which upstream projects it vendors and at which commit:

* ``.gitmodules`` names each submodule and its upstream URL;
* ``git ls-tree`` gives the **exact commit** the SDK pins;
* Espressif, usefully, also writes ``sbom-version``, ``sbom-cpe``,
  ``sbom-supplier`` and ``sbom-url`` straight into ``.gitmodules`` for the
  submodules they do not fork, and ships an ``sbom.yml`` inside the ones they
  do.

So a rule can be *derived* rather than written: fetch each submodule at its
pinned commit, fingerprint it, and emit a rule whose ``upstream.source`` points
back at that exact commit. Every rule produced this way is reproducible by CI on
the day it is created, which is the property the whole review model rests on.

What is deliberately not automated: the CPE when the vendor did not declare one.
A guessed CPE matches no CVE and makes the SBOM look clean, so the importer
leaves it out and marks the rule for a human.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import yaml

from ..dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_directory
from .common import (ProjectImport, VendoredProject, clone_metadata, dump_rule,
                     fetch_at, git as _git_run, make_rule)

_SECTION = re.compile(r'^\[submodule "(?P<name>[^"]+)"\]\s*$')
_KEYVAL = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.-]+)\s*=\s*(?P<val>.*?)\s*$")
_VERSION_IN_NAME = re.compile(r"version", re.I)


@dataclass
class Submodule:
    name: str
    path: str
    url: str
    sha: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)

    @property
    def sbom_version(self) -> Optional[str]:
        return self.extra.get("sbom-version")

    @property
    def sbom_cpe(self) -> Optional[str]:
        cpe = self.extra.get("sbom-cpe")
        if not cpe:
            return None
        # Espressif writes the version field as the literal {} placeholder.
        return cpe.replace("{}", "*")

    @property
    def sbom_url(self) -> Optional[str]:
        return self.extra.get("sbom-url")


def _absolute_url(raw: str, base: str) -> str:
    """``.gitmodules`` relative URLs are resolved against the SDK's own origin."""
    url = raw.strip()
    if url.startswith(("http://", "https://", "git@", "ssh://", "file://", "/")):
        return url.removesuffix(".git")
    cleaned = url.lstrip("./")
    while cleaned.startswith("../"):
        cleaned = cleaned[3:]
    host = "https://github.com/"
    if base.startswith("http"):
        parts = base.split("/")
        if len(parts) > 3:
            host = "/".join(parts[:3]) + "/"
    return (host + cleaned).removesuffix(".git")


def parse_gitmodules(text: str, origin: str = "https://github.com/") -> List[Submodule]:
    out: List[Submodule] = []
    current: Optional[Dict[str, str]] = None
    name = ""
    for line in text.splitlines():
        if line.lstrip().startswith(("#", ";")):
            continue
        section = _SECTION.match(line)
        if section:
            if current is not None and current.get("path") and current.get("url"):
                out.append(_build(name, current, origin))
            name = section.group("name")
            current = {}
            continue
        if current is None:
            continue
        kv = _KEYVAL.match(line)
        if kv:
            current[kv.group("key")] = kv.group("val")
    if current is not None and current.get("path") and current.get("url"):
        out.append(_build(name, current, origin))
    return out


def _build(name: str, data: Dict[str, str], origin: str) -> Submodule:
    extra = {k: v for k, v in data.items() if k.startswith("sbom-")}
    return Submodule(name=name, path=data["path"],
                     url=_absolute_url(data["url"], origin), extra=extra)


def _git(args: Sequence[str], cwd: Optional[Path] = None) -> str:
    return _git_run(args, cwd)


def pinned_shas(repo: Path, paths: Sequence[str]) -> Dict[str, str]:
    """``git ls-tree`` reports each submodule's pinned commit as a tree entry."""
    if not paths:
        return {}
    out: Dict[str, str] = {}
    for line in _git(["ls-tree", "HEAD", *paths], cwd=repo).splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "commit":
            out[line.split("\t", 1)[1].strip()] = parts[2]
    return out


SubmoduleImport = ProjectImport


def _nested_modules(checkout: Path, parent: Submodule) -> List[Submodule]:
    """Submodules declared inside a fetched checkout, with full paths and SHAs."""
    try:
        text = _git(["show", "HEAD:.gitmodules"], cwd=checkout)
    except subprocess.CalledProcessError:
        return []                   # no .gitmodules at that commit
    nested = parse_gitmodules(text, origin=parent.url)
    try:
        shas = pinned_shas(checkout, [m.path for m in nested])
    except subprocess.CalledProcessError:
        return []
    out: List[Submodule] = []
    for m in nested:
        m.sha = shas.get(m.path)
        m.name = f"{parent.name}/{m.name}"
        m.path = f"{parent.path}/{m.path}"
        out.append(m)
    return out


def import_gitmodules(sdk_repo: str, vendor: str, sdk: str,
                      sdk_version: Optional[str] = None,
                      only: Optional[Sequence[str]] = None,
                      include: Sequence[str] = DEFAULT_INCLUDE,
                      exclude: Sequence[str] = DEFAULT_EXCLUDE,
                      workdir: Optional[Path] = None,
                      jobs: int = 1,
                      recursive: bool = False,
                      max_depth: int = 4,
                      log=lambda msg: None) -> List[SubmoduleImport]:
    """Derive one draft rule per source-bearing submodule of *sdk_repo*.

    With *recursive*, submodules nested inside a fetched submodule are imported
    too, at the commit their parent pins, with ``path`` giving the full nested
    path (``parent/child``). ``--only`` selects top-level modules; everything
    nested under a selected one comes with it.
    """
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="gangmu-import-"))
    owns_tmp = workdir is None
    try:
        local = Path(sdk_repo)
        if local.is_dir() and (local / ".git").exists():
            meta = local
            origin = _git(["remote", "get-url", "origin"], cwd=meta).strip()
        else:
            origin = sdk_repo
            meta = clone_metadata(sdk_repo, tmp / "sdk")
            log(f"cloned SDK metadata from {sdk_repo}")

        modules = parse_gitmodules((meta / ".gitmodules").read_text(encoding="utf-8")
                                   if (meta / ".gitmodules").is_file()
                                   else _git(["show", "HEAD:.gitmodules"], cwd=meta),
                                   origin=origin)
        if only:
            wanted = set(only)
            modules = [m for m in modules if m.path in wanted or m.name in wanted]
        shas = pinned_shas(meta, [m.path for m in modules])
        for m in modules:
            m.sha = shas.get(m.path)

        results: List[SubmoduleImport] = []
        queue: List[Tuple[Submodule, int]] = [(m, 0) for m in modules]
        seen: set = set()
        while queue:
            module, depth = queue.pop(0)
            rule_id = f"{vendor}/{sdk}/{Path(module.path).name}"
            if not module.sha:
                results.append(SubmoduleImport(module, rule_id, "error",
                                               "no pinned commit in the SDK tree"))
                continue
            if (module.url, module.sha) in seen:
                continue           # the same pin reached by two paths
            seen.add((module.url, module.sha))
            checkout = tmp / "sub" / module.path.replace("/", "_")
            try:
                log(f"fetching {module.path} @ {module.sha[:10]}")
                fetch_at(module.url, module.sha, checkout)
            except subprocess.CalledProcessError as exc:
                results.append(ProjectImport(
                    VendoredProject(name=module.name, path=module.path,
                                    url=module.url, sha=module.sha),
                    rule_id, "error", f"fetch failed: {exc.stderr.strip()[:160]}"))
                continue

            if recursive and depth < max_depth:
                queue.extend((n, depth + 1)
                             for n in _nested_modules(checkout, module))

            dp = print_directory(checkout, include, exclude, jobs=jobs)
            if dp.file_count == 0:
                results.append(ProjectImport(
                    VendoredProject(name=module.name, path=module.path,
                                    url=module.url, sha=module.sha),
                    rule_id, "no-source",
                    "no C/C++ sources -- prebuilt library or non-C project"))
                continue

            project = VendoredProject(
                name=Path(module.path).name, path=module.path, url=module.url,
                sha=module.sha, declared_version=module.sbom_version,
                declared_cpe=module.sbom_cpe, declared_url=module.sbom_url)
            results.append(make_rule(project, rule_id, checkout, dp, vendor, sdk,
                                     sdk_version, include, exclude))
        return results
    finally:
        if owns_tmp:
            shutil.rmtree(tmp, ignore_errors=True)
