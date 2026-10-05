"""Reading ``compile_commands.json``.

This is the cheapest honest answer to "what is actually in this firmware".
CMake writes it with one flag, and ESP-IDF, Zephyr and nRF Connect SDK all
build on CMake, so no vendor-specific plumbing is needed for the common case.

What it gives us that a source tree cannot: the set of translation units the
build really compiled.  A tree holds four ports of a driver and compiles one.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class CompileEntry:
    source: Path
    directory: Path
    output: Optional[Path] = None
    arguments: List[str] = field(default_factory=list)


@dataclass
class CompileDB:
    entries: List[CompileEntry] = field(default_factory=list)
    path: Optional[Path] = None

    @property
    def sources(self) -> Set[Path]:
        return {e.source for e in self.entries}

    def object_to_source(self) -> Dict[str, Path]:
        """Map object basename -> source. Used to join with the link map."""
        out: Dict[str, Path] = {}
        for entry in self.entries:
            if entry.output is not None:
                out.setdefault(entry.output.name, entry.source)
                out.setdefault(entry.output.as_posix(), entry.source)
        return out


def _resolve(base: Path, raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    try:
        return path.resolve()
    except OSError:
        return path


def load_compile_db(path: Path) -> CompileDB:
    path = Path(path)
    if path.is_dir():
        path = path / "compile_commands.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    db = CompileDB(path=path)
    for raw in data:
        try:
            directory = Path(raw["directory"])
            source = _resolve(directory, raw["file"])
        except (KeyError, TypeError):
            continue
        args: List[str] = raw.get("arguments") or []
        if not args and raw.get("command"):
            try:
                args = shlex.split(raw["command"])
            except ValueError:
                args = raw["command"].split()
        output: Optional[Path] = None
        if raw.get("output"):
            output = _resolve(directory, raw["output"])
        else:
            for i, arg in enumerate(args):
                if arg == "-o" and i + 1 < len(args):
                    output = _resolve(directory, args[i + 1])
                    break
                if arg.startswith("-o") and len(arg) > 2:
                    output = _resolve(directory, arg[2:])
                    break
        db.entries.append(CompileEntry(source=source, directory=directory,
                                       output=output, arguments=args))
    return db
