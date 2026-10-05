"""Is the vulnerable function of an advisory reachable from the product's code?

A CVE list says a component *version* is affected. Most CVEs sit in one
function, and a firmware that links the component often never calls it, or
shipped a pruned copy that does not contain it. This module answers, from the
source tree alone, three narrower questions:

``absent``       the function is not defined in the component's directory
``unreachable``  it is defined, but nothing outside the component's own
                 entry points leads to it
``reachable``    a chain of references from code outside the component, or
                 from an entry point inside it, reaches it

The graph is deliberately an over-approximation in the direction that keeps a
function reachable: an edge is *any* mention of a defined function's name, not
only a call (so function pointers and callback tables count), macros are
expanded by name, and a name defined twice is one node. What it cannot see is
code that is not source on disk (a binary blob, assembly, a linker script that
places a handler) and calls made through a name built at run time. A verdict of
``unreachable`` therefore means "no path in the source we read", never "proved
safe", and ``gangmu vuln`` leaves the VEX state alone unless it is told to
trust it.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .functions import extract_functions
from .normalize import tokenize

SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".inc")
_MAX_FILE = 4_000_000
_ENTRY_NAME = re.compile(r"^(main|app_main|_start|Reset_Handler|"
                         r".*_(IRQ)?Handler|.*_ISR|.*_isr|.*IRQHandler)$")
_DEFINE = re.compile(rb"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(?:\([^)]*\))?"
                     rb"((?:[^\n]|\\\n)*)", re.M)
_IDENT = re.compile(rb"[A-Za-z_]\w*")
_SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__"}


@dataclass
class Graph:
    defined: Dict[str, Set[str]] = field(default_factory=dict)   # name -> files
    edges: Dict[str, Set[str]] = field(default_factory=dict)     # name -> names
    roots_by_file: Dict[str, Set[str]] = field(default_factory=dict)
    file_scope: Dict[str, Set[str]] = field(default_factory=dict)  # file -> names
    files: int = 0
    unreadable: int = 0

    def functions_in(self, directory: str) -> Set[str]:
        prefix = _prefix(directory)
        return {name for name, files in self.defined.items()
                if any(_inside(f, prefix) for f in files)}


def _prefix(directory: str) -> str:
    directory = directory.strip("/").replace("\\", "/")
    return "" if directory in ("", ".") else directory + "/"


def _inside(path: str, prefix: str) -> bool:
    return not prefix or path.startswith(prefix)


def iter_source(root: Path) -> Iterable[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            elif entry.suffix in SOURCE_SUFFIXES:
                yield entry


def _macros(data: bytes) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for m in _DEFINE.finditer(data):
        ids = {i.decode() for i in _IDENT.findall(m.group(2))}
        out.setdefault(m.group(1).decode(), set()).update(ids)
    return out


def build_graph(root: Path) -> Graph:
    """Parse every C/C++ source under ``root`` once."""
    graph = Graph()
    macros: Dict[str, Set[str]] = {}
    bodies: Dict[str, List[Tuple[str, frozenset]]] = {}      # file -> (name, refs)
    scope_tokens: Dict[str, Set[str]] = {}
    for path in iter_source(root):
        rel = path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > _MAX_FILE:
                graph.unreadable += 1
                continue
            data = path.read_bytes()
        except OSError:
            graph.unreadable += 1
            continue
        graph.files += 1
        for name, ids in _macros(data).items():
            macros.setdefault(name, set()).update(ids)
        toks = tokenize(data)
        funcs = extract_functions(data, toks, with_refs=True, min_tokens=1)
        inside = bytearray(len(toks))
        for fn in funcs:
            graph.defined.setdefault(fn.name, set()).add(rel)
            for k in range(*fn.span):
                inside[k] = 1
        bodies[rel] = [(fn.name, fn.refs) for fn in funcs]
        # Mentions outside any body that are not a call or a declaration:
        # `.read = f`, `&f`, a table entry. They make f reachable wherever the
        # table lives.
        loose: Set[str] = set()
        for k, tok in enumerate(toks):
            if inside[k] or not (tok[:1].isalpha() or tok[:1] == b"_"):
                continue
            nxt = toks[k + 1] if k + 1 < len(toks) else b""
            if nxt != b"(":
                loose.add(tok.decode("utf-8", "replace"))
        scope_tokens[rel] = loose

    names = set(graph.defined)

    def expand(refs: Iterable[str]) -> Set[str]:
        seen: Set[str] = set()
        todo = list(refs)
        while todo:
            ref = todo.pop()
            if ref in seen:
                continue
            seen.add(ref)
            if ref in macros and len(seen) < 4000:
                todo.extend(macros[ref])
        return seen & names

    for rel, items in bodies.items():
        for name, refs in items:
            graph.edges.setdefault(name, set()).update(expand(refs) - {name})
    for rel, loose in scope_tokens.items():
        graph.file_scope[rel] = expand(loose)
    return graph


@dataclass
class Reach:
    status: str                       # reachable | unreachable | absent | unknown
    detail: str
    symbols: List[str] = field(default_factory=list)
    path: List[str] = field(default_factory=list)
    basis: str = ""                   # "curated" | "advisory text"

    def to_dict(self) -> dict:
        out = {"status": self.status, "detail": self.detail,
               "symbols": self.symbols, "basis": self.basis}
        if self.path:
            out["path"] = self.path
        return out


def _reached(graph: Graph, directory: str) -> Tuple[Dict[str, Optional[str]], Set[str]]:
    """Functions reachable from outside the component (or its entry points),
    with the predecessor that first reached each, for reporting a path."""
    prefix = _prefix(directory)
    parent: Dict[str, Optional[str]] = {}
    queue: deque = deque()

    def seed(name: str) -> None:
        if name not in parent:
            parent[name] = None
            queue.append(name)

    for name, files in graph.defined.items():
        if any(not _inside(f, prefix) for f in files) or _ENTRY_NAME.match(name):
            seed(name)
    for rel, names in graph.file_scope.items():
        for name in names:
            seed(name)                # an address taken in a table: assume used
    outside = set(parent)
    while queue:
        current = queue.popleft()
        for nxt in graph.edges.get(current, ()):
            if nxt not in parent:
                parent[nxt] = current
                queue.append(nxt)
    return parent, outside


def _path(parent: Dict[str, Optional[str]], name: str) -> List[str]:
    chain = [name]
    while parent.get(chain[-1]) is not None and len(chain) < 12:
        chain.append(parent[chain[-1]])
    return list(reversed(chain))


def assess(graph: Graph, directory: str, symbols: Sequence[str],
           basis: str, cache: Optional[dict] = None) -> Reach:
    """One advisory's symbols against one component directory.

    ``basis`` decides what a missing definition means: for a curated list the
    function must exist in a complete copy, so its absence is informative; for
    names mined from advisory text it only means the guess was wrong.
    """
    if not symbols:
        return Reach("unknown", "no vulnerable function is recorded for this advisory")
    inside = graph.functions_in(directory)
    if cache is not None and directory in cache:
        parent, outside = cache[directory]
    else:
        parent, outside = _reached(graph, directory)
        if cache is not None:
            cache[directory] = (parent, outside)
    present = [s for s in symbols if s in inside]
    absent = [s for s in symbols if s not in inside]
    if not present:
        if basis == "curated":
            return Reach("absent",
                         f"{', '.join(absent[:4])} is not defined anywhere under "
                         f"{directory or '.'}: this copy does not contain it",
                         list(symbols), basis=basis)
        return Reach("unknown", "the functions named in the advisory text are not "
                                "defined in this component", list(symbols), basis=basis)
    hit = [s for s in present if s in parent]
    if hit:
        chain = _path(parent, hit[0])
        return Reach("reachable",
                     f"{hit[0]} is referenced: {' -> '.join(chain)}",
                     present, chain, basis)
    return Reach("unreachable",
                 f"{', '.join(present[:4])} is defined but no function or table "
                 f"outside the component's entry points refers to it "
                 f"(read {graph.files} source file(s))",
                 present, basis=basis)


# -------------------------------------------------------------- symbol data

_MINE = (
    re.compile(r"`([A-Za-z_][A-Za-z0-9_]{2,})(?:\(\))?`"),
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\(\)"),
    re.compile(r"\b(?:function|routine)\s+([A-Za-z_][A-Za-z0-9_]*_[A-Za-z0-9_]+)\b"),
    re.compile(r"\b([A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+)\s+(?:function|routine)\b"),
)


def mine_symbols(text: str) -> List[str]:
    out: List[str] = []
    for pattern in _MINE:
        for m in pattern.finditer(text or ""):
            if m.group(1) not in out:
                out.append(m.group(1))
    return out


def load_symbols(path: Path) -> Dict[str, List[str]]:
    """``{"CVE-2021-1234": ["func_a", "func_b"], ...}``, keys upper-cased."""
    import json
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out: Dict[str, List[str]] = {}
    for key, value in raw.items():
        names = value.get("symbols", []) if isinstance(value, dict) else value
        out[str(key).upper()] = [str(n) for n in names]
    return out
