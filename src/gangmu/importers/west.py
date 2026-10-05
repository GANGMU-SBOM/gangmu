"""Importing rules from a Zephyr-style ``west`` manifest.

West states the same facts as git submodules -- which project, which commit --
in a different shape, so only the parsing differs. That the rest of the pipeline
is unchanged is the point: the rule format is not an ESP-IDF format.

Two things west has that submodules do not, and both matter:

* **Groups.** ``group-filter: [-babblesim, -optional, -testing]`` disables whole
  classes of project by default. Importing those would put simulator plumbing
  and test harnesses into a firmware SBOM.
* **Per-project remotes and ``repo-path``**, so a project's URL is not derivable
  from its name alone.

With ``recursive=True`` the importer also follows west's own composition
mechanism: a project (or ``manifest: self:``) carrying ``import:`` contributes
the projects of that project's manifest, e.g. Zephyr pulled in by an application
manifest. Supported ``import`` forms: ``true`` (``west.yml``), a file or
directory path string (a directory means its ``*.yml``/``*.yaml`` files in
sorted order), a map with ``file``, ``name-allowlist``, ``path-allowlist``,
``name-blocklist``, ``path-blocklist`` and ``path-prefix``, and a list of any of
these. Not supported: ``import-flags``, imports through a ``west`` extension
command, and an import that names a manifest in a *different* project than the
one declaring it. Projects defined by the importing manifest win over imported
ones of the same name, earlier imports win over later ones (west's rule), and
each imported manifest resolves its own ``remotes`` and ``defaults``.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

import yaml

from ..dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_directory
from .common import (ProjectImport, VendoredProject, clone_metadata, fetch_at,
                     git, make_rule)


@dataclass
class WestManifest:
    projects: List[VendoredProject]
    imports: Dict[str, object] = field(default_factory=dict)   # project name -> raw ``import``
    self_import: object = None
    disabled: Set[str] = field(default_factory=set)


def parse_west_manifest(text: str) -> WestManifest:
    """Parse one manifest; group filtering is left to the caller, since west
    merges the ``group-filter`` of every manifest in an import chain."""
    data = yaml.safe_load(text) or {}
    manifest = data.get("manifest") or {}
    remotes = {r["name"]: r["url-base"].rstrip("/")
               for r in manifest.get("remotes", []) if r.get("name")}
    defaults = manifest.get("defaults") or {}
    default_remote = defaults.get("remote")

    disabled: Set[str] = set()
    for entry in manifest.get("group-filter") or []:
        token = str(entry)
        if token.startswith("-"):
            disabled.add(token[1:])

    out = WestManifest(projects=[], disabled=disabled,
                       self_import=(manifest.get("self") or {}).get("import"))
    for raw in manifest.get("projects") or []:
        name = raw.get("name")
        if not name:
            continue
        if raw.get("import"):
            out.imports[name] = raw["import"]
        url = raw.get("url")
        if not url:
            remote = raw.get("remote") or default_remote
            base = remotes.get(remote)
            if not base:
                continue
            url = f"{base}/{raw.get('repo-path') or name}"
        out.projects.append(VendoredProject(
            name=name,
            path=raw.get("path") or name,
            url=url.removesuffix(".git"),
            sha=raw.get("revision"),
            groups=[str(g) for g in (raw.get("groups") or [])],
        ))
    return out


def parse_west(text: str, enable_groups: Sequence[str] = ()) -> List[VendoredProject]:
    manifest = parse_west_manifest(text)
    disabled = manifest.disabled - set(enable_groups)
    return [p for p in manifest.projects if not disabled.intersection(p.groups)]


@dataclass
class ImportSpec:
    file: str = "west.yml"
    name_allow: List[str] = field(default_factory=list)
    path_allow: List[str] = field(default_factory=list)
    name_block: List[str] = field(default_factory=list)
    path_block: List[str] = field(default_factory=list)
    prefix: str = ""

    def accepts(self, project: VendoredProject) -> bool:
        if (project.name in self.name_block or project.path in self.path_block):
            return False
        if self.name_allow or self.path_allow:
            return project.name in self.name_allow or project.path in self.path_allow
        return True


def _strs(value: object) -> List[str]:
    if value is None:
        return []
    return [str(v) for v in (value if isinstance(value, list) else [value])]


def normalize_imports(spec: object) -> List[ImportSpec]:
    """Expand west's ``import`` forms (bool, string, map, list) into specs."""
    if not spec:
        return []
    if spec is True:
        return [ImportSpec()]
    if isinstance(spec, str):
        return [ImportSpec(file=spec)]
    if isinstance(spec, dict):
        return [ImportSpec(
            file=str(spec.get("file") or "west.yml"),
            name_allow=_strs(spec.get("name-allowlist")),
            path_allow=_strs(spec.get("path-allowlist")),
            name_block=_strs(spec.get("name-blocklist")),
            path_block=_strs(spec.get("path-blocklist")),
            prefix=str(spec.get("path-prefix") or "").strip("/"))]
    if isinstance(spec, list):
        return [s for item in spec for s in normalize_imports(item)]
    return []


def _manifest_texts(root: Path, rel: str) -> List[str]:
    """Texts of the manifest file(s) *rel* names inside the repo at *root*.

    A directory stands for its ``*.yml``/``*.yaml`` files in sorted order. The
    filesystem is tried first, then ``HEAD`` (a metadata clone has no checkout).
    """
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        return []                   # an import must stay inside its project
    target = root / rel
    if target.is_file():
        return [target.read_text(encoding="utf-8")]
    if target.is_dir():
        return [f.read_text(encoding="utf-8") for f in sorted(target.iterdir())
                if f.is_file() and f.suffix in (".yml", ".yaml")]
    try:
        return [git(["show", f"HEAD:{rel}"], cwd=root)]
    except subprocess.CalledProcessError:
        pass
    try:
        names = git(["ls-tree", "--name-only", "HEAD", rel.rstrip("/") + "/"],
                    cwd=root).split()
    except subprocess.CalledProcessError:
        return []
    return [git(["show", f"HEAD:{n}"], cwd=root)
            for n in sorted(names) if n.endswith((".yml", ".yaml"))]


def imported_projects(root: Path, spec: object) -> Tuple[List[Tuple[VendoredProject, object]], Set[str]]:
    """Projects (with their own raw ``import``) that *spec* pulls out of *root*,
    plus the groups the imported manifests disable by default."""
    found: List[Tuple[VendoredProject, object]] = []
    disabled: Set[str] = set()
    for imp in normalize_imports(spec):
        for text in _manifest_texts(root, imp.file):
            manifest = parse_west_manifest(text)
            disabled |= manifest.disabled
            for project in manifest.projects:
                if not imp.accepts(project):
                    continue
                if imp.prefix:
                    project.path = f"{imp.prefix}/{project.path}"
                found.append((project, manifest.imports.get(project.name)))
    return found, disabled


def import_west(sdk_repo: str, vendor: str, sdk: str,
                sdk_version: Optional[str] = None,
                only: Optional[Sequence[str]] = None,
                enable_groups: Sequence[str] = (),
                include: Sequence[str] = DEFAULT_INCLUDE,
                exclude: Sequence[str] = DEFAULT_EXCLUDE,
                manifest_file: str = "west.yml",
                workdir: Optional[Path] = None,
                jobs: int = 1,
                recursive: bool = False,
                max_depth: int = 4,
                log=lambda msg: None) -> List[ProjectImport]:
    """Derive one draft rule per source-bearing project of a west manifest.

    With *recursive*, ``import:`` entries are followed into each fetched project
    (and ``self: import:`` into the SDK repo), up to *max_depth* levels. Cycles
    are cut by project name and by (url, commit).
    """
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="gangmu-west-"))
    owns_tmp = workdir is None
    try:
        local = Path(sdk_repo)
        if local.is_dir() and (local / ".git").exists():
            meta = local
        else:
            meta = clone_metadata(sdk_repo, tmp / "sdk")
            log(f"cloned SDK metadata from {sdk_repo}")

        manifest_path = meta / manifest_file
        text = (manifest_path.read_text(encoding="utf-8") if manifest_path.is_file()
                else git(["show", f"HEAD:{manifest_file}"], cwd=meta))
        manifest = parse_west_manifest(text)
        disabled = set(manifest.disabled)
        queue: List[Tuple[VendoredProject, object, int]] = [
            (p, manifest.imports.get(p.name), 0) for p in manifest.projects]
        if recursive:
            extra, more = imported_projects(meta, manifest.self_import)
            names = {p.name for p, _, _ in queue}
            for project, nested in extra:
                if project.name not in names:
                    names.add(project.name)
                    queue.append((project, nested, 1))
            disabled |= more
        disabled -= set(enable_groups)
        queue = [q for q in queue if not disabled.intersection(q[0].groups)]
        if only:
            wanted = set(only)
            queue = [q for q in queue
                     if q[0].name in wanted or q[0].path in wanted or q[2] > 0]

        names = {p.name for p, _, _ in queue}
        results: List[ProjectImport] = []
        seen: set = set()
        while queue:
            project, nested_spec, depth = queue.pop(0)
            rule_id = f"{vendor}/{sdk}/{Path(project.path).name}"
            if not project.sha or len(project.sha) < 7:
                results.append(ProjectImport(
                    project, rule_id, "error",
                    f"revision '{project.sha}' is not a pinned commit; west "
                    f"allows a branch name here, which is not reproducible"))
                continue
            if (project.url, project.sha) in seen:
                continue           # the same pin reached by two paths
            seen.add((project.url, project.sha))
            checkout = tmp / "proj" / project.path.replace("/", "_")
            try:
                log(f"fetching {project.path} @ {project.sha[:10]}")
                fetch_at(project.url, project.sha, checkout)
            except subprocess.CalledProcessError as exc:
                results.append(ProjectImport(
                    project, rule_id, "error",
                    f"fetch failed: {exc.stderr.strip()[:160]}"))
                continue

            if recursive and nested_spec and depth < max_depth:
                found, more = imported_projects(checkout, nested_spec)
                disabled |= more - set(enable_groups)
                for child, child_spec in found:
                    if child.name in names or disabled.intersection(child.groups):
                        continue   # importing manifest (or an earlier import) wins
                    names.add(child.name)
                    queue.append((child, child_spec, depth + 1))

            dp = print_directory(checkout, include, exclude, jobs=jobs)
            if dp.file_count == 0:
                results.append(ProjectImport(
                    project, rule_id, "no-source",
                    "no C/C++ sources -- tooling, docs or a binary-only project"))
                continue
            results.append(make_rule(project, rule_id, checkout, dp, vendor, sdk,
                                     sdk_version, include, exclude))
        return results
    finally:
        if owns_tmp:
            shutil.rmtree(tmp, ignore_errors=True)
