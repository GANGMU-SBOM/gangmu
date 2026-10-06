"""IDE project files as a source of build facts.

``compile_commands.json`` covers everything built with CMake -- ESP-IDF, Zephyr,
nRF Connect SDK -- but a large part of the embedded world never touches CMake.
IAR Embedded Workbench, Keil MDK and TI Code Composer keep the file list in
their own project XML, and those projects are exactly the ones whose SBOMs are
hardest to produce today.

Each parser answers one question: **which source files does this project
actually build?** Not which files exist on disk -- a project routinely carries
four ports of a driver and compiles one, and per-configuration exclusions are
how that is expressed. A parser that ignored them would over-report, which is
the failure these build facts exist to prevent.

None of these formats records object-file paths, so a project parsed this way
yields compiled sources with no link map. The scan says so rather than implying
the linker was consulted.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

from .compile_db import CompileDB, CompileEntry

# IAR and Keil both use $VAR$ / %VAR% style placeholders for well-known roots.
_IAR_VAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\$")
# Eclipse/CCS writes linked-resource locations relative to the project with
# PARENT-<n>-PROJECT_LOC. Vendor SDKs are almost always linked in this way, so a
# parser that skipped these would lose the entire SDK from the SBOM.
_ECLIPSE_PARENT = re.compile(r"^PARENT-(\d+)-PROJECT_LOC/?(.*)$")
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".s", ".asm"}


@dataclass
class ProjectParse:
    kind: str
    project: Path
    configuration: Optional[str] = None
    sources: List[Path] = field(default_factory=list)
    excluded: List[Path] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_compile_db(self) -> CompileDB:
        db = CompileDB(path=self.project)
        root = self.project.parent
        suffix = ".obj" if self.kind == "ccs" else ".o"
        for source in self.sources:
            # No project format records object paths, but IAR, Keil and CCS name
            # an object after its source, which is what a link map lists. The
            # name is what lets --link-map apply to an IDE project.
            output = Path(source.stem + suffix)
            db.entries.append(CompileEntry(source=source, directory=root,
                                           output=output, arguments=[]))
        return db


def _resolve(raw: str, project_dir: Path, variables: Dict[str, str]) -> Optional[Path]:
    text = raw.strip().replace("\\", "/")
    if not text:
        return None
    # $PROJ_DIR$ becomes this path; a relative one would be joined to the
    # project directory a second time below and every source would go missing.
    project_dir = Path(project_dir).resolve()

    def sub(match: re.Match) -> str:
        name = match.group(1)
        if name in variables:
            return variables[name]
        if name in ("PROJ_DIR", "ProjectDir", "PROJECT_DIR"):
            return str(project_dir)
        return match.group(0)

    text = _IAR_VAR.sub(sub, text)
    if "$" in text:          # an unresolved toolchain variable: not our source
        return None
    path = Path(text)
    if not path.is_absolute():
        path = project_dir / path
    try:
        return path.resolve()
    except OSError:
        return path


def parse_iar_ewp(path: Path, configuration: Optional[str] = None,
                  variables: Optional[Dict[str, str]] = None) -> ProjectParse:
    """IAR Embedded Workbench ``.ewp``.

    Files live in nested ``<group>`` elements. A file carries
    ``<excluded><configuration>Debug</configuration></excluded>`` when it is not
    built in that configuration, which is how IAR projects express "four ports,
    one target".
    """
    path = Path(path)
    out = ProjectParse(kind="iar", project=path, configuration=configuration)
    root = ET.parse(path).getroot()
    project_dir = path.resolve().parent
    variables = dict(variables or {})

    configs = [c.findtext("name", "").strip()
               for c in root.findall("configuration")]
    if configuration is None and configs:
        configuration = configs[0]
        out.configuration = configuration
        if len(configs) > 1:
            out.notes.append(
                f"project has configurations {configs}; used '{configuration}'. "
                f"Pass --configuration to pick another.")

    for file_el in root.iter("file"):
        name = file_el.findtext("name")
        if not name:
            continue
        resolved = _resolve(name, project_dir, variables)
        if resolved is None or resolved.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        excluded_in = {e.text.strip() for e in file_el.findall("excluded/configuration")
                       if e.text}
        if configuration and configuration in excluded_in:
            out.excluded.append(resolved)
        else:
            out.sources.append(resolved)
    return out


def parse_keil_uvprojx(path: Path, target: Optional[str] = None) -> ProjectParse:
    """Keil MDK ``.uvprojx`` / ``.uvproj``.

    ``<IncludeInBuild>0</IncludeInBuild>`` on a file's ``<FileOption>`` is Keil's
    way of excluding it from a target.
    """
    path = Path(path)
    out = ProjectParse(kind="keil", project=path, configuration=target)
    root = ET.parse(path).getroot()
    project_dir = path.resolve().parent

    targets = [t.findtext("TargetName", "").strip() for t in root.iter("Target")]
    if target is None and targets:
        target = targets[0]
        out.configuration = target
        if len(targets) > 1:
            out.notes.append(
                f"project has targets {targets}; used '{target}'. "
                f"Pass --configuration to pick another.")

    for target_el in root.iter("Target"):
        name = (target_el.findtext("TargetName") or "").strip()
        if target and name != target:
            continue
        for file_el in target_el.iter("File"):
            raw = file_el.findtext("FilePath")
            if not raw:
                continue
            resolved = _resolve(raw, project_dir, {})
            if resolved is None or resolved.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            include = file_el.find(".//IncludeInBuild")
            if include is not None and (include.text or "").strip() == "0":
                out.excluded.append(resolved)
            else:
                out.sources.append(resolved)
    return out


def parse_ccs_project(path: Path, configuration: Optional[str] = None) -> ProjectParse:
    """TI Code Composer Studio / Eclipse CDT.

    CDT does not list files: it lists *source folders* plus exclusion patterns,
    so the file set has to be walked. ``.project`` additionally carries linked
    resources, which is how CCS pulls a vendor SDK in from outside the project
    directory -- miss those and the SBOM loses the SDK entirely.
    """
    path = Path(path)
    project_dir = path.resolve().parent if path.is_file() else path.resolve()
    out = ProjectParse(kind="ccs", project=path, configuration=configuration)

    roots: List[Path] = [project_dir]
    dot_project = project_dir / ".project"
    if dot_project.is_file():
        try:
            for link in ET.parse(dot_project).getroot().iter("link"):
                location = link.findtext("location") or link.findtext("locationURI")
                if not location:
                    continue
                text = location.strip()
                parent = _ECLIPSE_PARENT.match(text)
                if parent:
                    base = project_dir
                    for _ in range(int(parent.group(1))):
                        base = base.parent
                    text = str(base / parent.group(2))
                elif text.startswith("file:"):
                    text = "/" + text[5:].lstrip("/")
                resolved = _resolve(text, project_dir, {})
                if resolved and resolved.is_dir():
                    roots.append(resolved)
                elif resolved and resolved.suffix.lower() in _SOURCE_SUFFIXES:
                    out.sources.append(resolved)
        except ET.ParseError as exc:
            out.notes.append(f".project is not valid XML: {exc}")

    excludes: Set[str] = set()
    cproject = project_dir / ".cproject"
    if cproject.is_file():
        try:
            tree = ET.parse(cproject).getroot()
            for conf in tree.iter("configuration"):
                name = (conf.get("name") or "").strip()
                if configuration and name != configuration:
                    continue
                if configuration is None and out.configuration is None and name:
                    out.configuration = name
                for entry in conf.iter("entry"):
                    excluding = entry.get("excluding")
                    if excluding:
                        excludes.update(p for p in excluding.split("|") if p)
        except ET.ParseError as exc:
            out.notes.append(f".cproject is not valid XML: {exc}")

    from ..globbing import matches_suffix
    seen: Set[Path] = set(out.sources)
    for base in roots:
        for candidate in sorted(base.rglob("*")):
            if candidate.suffix.lower() not in _SOURCE_SUFFIXES or not candidate.is_file():
                continue
            try:
                rel = candidate.relative_to(base).as_posix()
            except ValueError:
                continue
            resolved = candidate.resolve()
            if excludes and matches_suffix(rel, sorted(excludes)):
                out.excluded.append(resolved)
                continue
            if resolved not in seen:
                seen.add(resolved)
                out.sources.append(resolved)
    return out


PARSERS = {
    ".ewp": parse_iar_ewp,
    ".uvprojx": parse_keil_uvprojx,
    ".uvproj": parse_keil_uvprojx,
    ".cproject": parse_ccs_project,
    ".project": parse_ccs_project,
}


def parse_project(path: Path, configuration: Optional[str] = None) -> ProjectParse:
    parsed = _parse_project(path, configuration)
    _check_sources_exist(parsed)
    return parsed


def _check_sources_exist(parsed: ProjectParse) -> None:
    """An IDE project whose listed sources are all missing is a path problem,
    not an empty build: say so instead of producing an empty SBOM."""
    missing = [s for s in parsed.sources if not s.is_file()]
    if parsed.sources and len(missing) == len(parsed.sources):
        raise ValueError(
            f"none of the {len(parsed.sources)} source files listed in "
            f"{parsed.project.name} exist on disk (first: {missing[0]}); "
            f"check that the project is in the checkout it was written for")
    if missing:
        parsed.notes.append(
            f"{len(missing)} of {len(parsed.sources)} source files listed in "
            f"{parsed.project.name} do not exist on disk (first: {missing[0]})")


def _parse_project(path: Path, configuration: Optional[str] = None) -> ProjectParse:
    path = Path(path)
    if path.is_dir():
        for name in (".cproject", ".project"):
            if (path / name).is_file():
                return parse_ccs_project(path, configuration)
        for suffix in (".ewp", ".uvprojx", ".uvproj"):
            found = sorted(path.glob(f"*{suffix}"))
            if found:
                return PARSERS[suffix](found[0], configuration)
        raise ValueError(f"no IAR, Keil or CCS project found in {path}")
    # ``.cproject`` and ``.project`` are dot-files, so they have no suffix.
    key = path.suffix.lower() or path.name.lower()
    parser = PARSERS.get(key)
    if parser is None:
        raise ValueError(
            f"unsupported project file: {path.name}. Supported: "
            f"{', '.join(sorted(PARSERS))}, or compile_commands.json")
    return parser(path, configuration)
