"""Joining the compile database and the link map.

The join is on object-file basenames, which is crude but is what the two
artefacts actually share.  Collisions (two ``main.o`` in different components)
are detected and reported rather than silently resolved: a wrong join would
quietly drop a real component from the SBOM, and a loud "ambiguous" is the
honest output.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .compile_db import CompileDB, load_compile_db
from .linkmap import LinkMap, parse_link_map


_OBJECT_SUFFIX = re.compile(r"\.(?:o|obj)$", re.I)
_SOURCE_IN_OBJECT = re.compile(r"\.(?:c|cc|cpp|cxx|s|asm)$", re.I)


def _object_stem(name: str) -> str:
    """``init.c.obj`` / ``init.o`` / ``INIT.OBJ`` -> ``init``.

    GNU/CMake names objects ``init.c.obj``; IAR, Keil and CCS name them
    ``init.o`` or ``init.obj``. IDE projects record no object path, so the join
    falls back to this stem when the exact name is not in the link map.
    """
    stem = _OBJECT_SUFFIX.sub("", name)
    return _SOURCE_IN_OBJECT.sub("", stem).lower()


@dataclass
class BuildFacts:
    root: Path
    compiled: Set[Path] = field(default_factory=set)
    linked: Set[Path] = field(default_factory=set)
    dropped: Set[Path] = field(default_factory=set)
    ambiguous_objects: List[str] = field(default_factory=list)
    have_link_map: bool = False
    linked_archives: Set[str] = field(default_factory=set)   # archive paths the link map names
    link_map_stem: str = ""          # fw.map -> "fw": the build's own product is fw.elf / fw.bin

    def sources_under(self, directory: Path) -> Set[Path]:
        directory = directory.resolve()
        return {s for s in self.compiled if _is_under(s, directory)}

    def linked_under(self, directory: Path) -> Set[Path]:
        directory = directory.resolve()
        return {s for s in self.linked if _is_under(s, directory)}

    def summary(self) -> Dict[str, int]:
        return {
            "compiled": len(self.compiled),
            "linked": len(self.linked),
            "droppedAtLink": len(self.dropped),
            "ambiguousObjects": len(self.ambiguous_objects),
        }


def _is_under(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def collect_build_facts(root: Path, compile_db: Optional[Path] = None,
                        link_map: Optional[Path] = None,
                        db: Optional[CompileDB] = None) -> BuildFacts:
    """Build facts from a compile database (a file, or one already in hand).

    ``db`` is how the IDE project parsers and the compiler wrapper get in: they
    produce the same structure, so everything downstream is identical.
    """
    root = Path(root).resolve()
    facts = BuildFacts(root=root)

    if db is None and compile_db is not None:
        db = load_compile_db(compile_db)
    if db is not None:
        facts.compiled = {s for s in db.sources if _is_under(s, root)}

    if link_map is None or db is None:
        # Without a link map every compiled unit is assumed to ship. That is
        # the over-reporting failure mode, so it is recorded as such.
        facts.linked = set(facts.compiled)
        return facts

    lmap: LinkMap = parse_link_map(link_map)
    facts.have_link_map = True
    facts.linked_archives = set(lmap.archives)
    facts.link_map_stem = Path(link_map).stem.lower()

    obj_to_sources: Dict[str, List[Path]] = {}
    obj_paths: Dict[Path, Path] = {}
    for entry in db.entries:
        if entry.output is None:
            continue
        obj_to_sources.setdefault(entry.output.name, []).append(entry.source)
        obj_paths[entry.source] = entry.output

    linked_names = lmap.linked_object_names
    linked_stems = {_object_stem(n) for n in linked_names}
    kept_keys = lmap.qualified_keys()
    dropped_keys = lmap.discarded_keys()
    unresolved: List[str] = []

    for name, sources in obj_to_sources.items():
        for source in sources:
            if not _is_under(source, root):
                continue
            parts = set(source.parts) | set(obj_paths.get(source, Path(name)).parts)
            if any((part, name) in kept_keys for part in parts):
                facts.linked.add(source)              # the archive path agrees
            elif any((part, name) in dropped_keys for part in parts):
                facts.dropped.add(source)             # named in the discard list
            elif len(sources) > 1:
                # Basename collision the archive paths could not resolve.
                # Keep it: understating an SBOM is the worse error under audit.
                facts.linked.add(source)
                unresolved.append(name)
            elif name in linked_names:
                facts.linked.add(source)
            elif _object_stem(name) in linked_stems:
                facts.linked.add(source)
            else:
                facts.dropped.add(source)

    facts.ambiguous_objects = sorted(set(unresolved))

    # Sources with no recorded object (header-only, or a build that hid -o)
    # stay in: absence of evidence is not evidence of absence.
    for source in facts.compiled:
        if source not in facts.linked and source not in facts.dropped:
            facts.linked.add(source)
    return facts
