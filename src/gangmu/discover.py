"""Deciding which directories are worth asking about.

Fingerprinting every directory in a 300 MB SDK is both slow and wrong -- most
directories are not components.  Candidates come from signals that a human
would use:

* a rule says a component normally lives here;
* the directory carries a vendor manifest (``sbom.yml``, ``idf_component.yml``);
* it carries its own licence file, which is what vendoring third-party code
  looks like on disk;
* it is a git submodule, i.e. the project itself says it is foreign;
* it holds the files a rule names as markers (``tasks.c`` + ``queue.c`` +
  ``list.c``), wherever it is and whatever the vendor renamed it to;
* ``--deep`` adds anything with enough source files to be worth a look.

When build facts are available, candidates with nothing compiled under them are
dropped before any fingerprint is taken -- that is where most of the speed and
most of the accuracy comes from.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .build.facts import BuildFacts
from .dirprint import DEFAULT_INCLUDE
from .globbing import matches_suffix
from .manifest import MANIFEST_NAMES, ZEPHYR_MODULE
from .rules.loader import RuleBase

LICENSE_MARKERS = {
    "LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "LICENCE.txt",
    "COPYING", "COPYING.txt", "COPYRIGHT", "NOTICE",
}
SKIP_DIRS = {".git", ".github", "build", "out", "node_modules", "__pycache__",
             ".venv", "venv", "managed_components"}
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hxx", ".s", ".S"}

_SUBMODULE_PATH = re.compile(r"^\s*path\s*=\s*(.+?)\s*$", re.M)


def _submodule_paths(root: Path) -> Set[str]:
    gitmodules = root / ".gitmodules"
    if not gitmodules.is_file():
        return set()
    try:
        return {m.group(1).strip() for m in
                _SUBMODULE_PATH.finditer(gitmodules.read_text(encoding="utf-8",
                                                              errors="replace"))}
    except OSError:
        return set()


def empty_submodules(root: Path) -> List[str]:
    """Submodule paths declared in ``.gitmodules`` that hold no files.

    A fresh ``git clone`` leaves them empty. Without saying so, a scan reports
    the SDK as having no lwIP or Mbed TLS when it merely was not checked out.
    """
    root = Path(root)
    out: List[str] = []
    for rel in sorted(_submodule_paths(root)):
        path = root / rel.strip("/")
        try:
            populated = path.is_dir() and any(path.iterdir())
        except OSError:
            populated = True      # unreadable is not the same as empty
        if not populated:
            out.append(rel.strip("/"))
    return out


def discover_roots(root: Path, rulebase: RuleBase,
                   build_facts: Optional[BuildFacts] = None,
                   deep: bool = False, min_sources: int = 3,
                   max_depth: int = 10) -> List[Path]:
    root = Path(root).resolve()
    submodules = {s.strip("/") for s in _submodule_paths(root)}
    globs: List[str] = []
    names: Set[str] = set()
    for rule in rulebase:
        globs.extend(g.strip("/") for g in rule.path_globs)
        if rule.ships_as:
            names.add(rule.ships_as)

    # Marker sets, keyed by the file that triggers a check: when the walk sees
    # that file in a directory whose path ends as the marker says, the
    # component root is that directory minus the marker's own subdirectory.
    triggers: Dict[str, List[Tuple[str, Tuple[str, ...]]]] = {}
    for rule in rulebase:
        markers = tuple(m.strip("/") for m in rule.marker_files if m.strip("/"))
        if markers:
            parent, _, name = markers[0].rpartition("/")
            triggers.setdefault(name, []).append((parent, markers[1:]))

    candidates: Set[Path] = set()

    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        rel = here.relative_to(root).as_posix()
        depth = 0 if rel == "." else rel.count("/") + 1
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        if rel == ".":
            continue

        fileset = set(filenames)
        for name in fileset.intersection(triggers) if triggers else ():
            for parent, others in triggers[name]:
                base = _strip_suffix(here, parent)
                if (base is not None and base != root
                        and all((base / other).is_file() for other in others)):
                    candidates.add(base)
        reason = None
        if globs and matches_suffix(rel, globs):
            reason = "rule-path"
        elif here.name in names:
            reason = "rule-name"
        elif fileset & set(MANIFEST_NAMES) or (here / ZEPHYR_MODULE).is_file():
            reason = "manifest"
        elif fileset & LICENSE_MARKERS:
            reason = "license-file"
        elif rel in submodules:
            reason = "submodule"
        elif deep and _source_count(here) >= min_sources:
            reason = "deep"

        if reason:
            candidates.add(here)

    if build_facts and build_facts.compiled:
        candidates = {c for c in candidates if build_facts.sources_under(c)}

    return sorted(candidates)


def _strip_suffix(here: Path, parent: str) -> Optional[Path]:
    """*here* without its trailing *parent* components, if it ends with them."""
    if not parent:
        return here
    parts = parent.split("/")
    if list(here.parts[-len(parts):]) != parts:
        return None
    return here.parents[len(parts) - 1]


def _source_count(directory: Path, limit: int = 64) -> int:
    count = 0
    try:
        for entry in os.scandir(directory):
            if entry.is_file() and Path(entry.name).suffix in SOURCE_SUFFIXES:
                count += 1
                if count >= limit:
                    break
    except OSError:
        return 0
    return count
