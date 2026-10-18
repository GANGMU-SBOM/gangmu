"""Components copied in as loose files among the project's own.

Directory matching asks "is this directory component X?". A vendor who drops
``lwprintf.c``, ``lwprintf.h`` and ``lwprintf_opt.h`` into ``app/`` beside
``main.c`` defeats it twice: ``app/`` carries none of the signs that make it a
candidate (no licence file, no manifest, not where a rule says), and if it were
asked, most of its functions are the project's, so a partial copy's test (90% of
the directory's functions are the component's) fails.

This pass looks at files instead. Every source file outside what the scan has
already identified is analysed once (the same per-file function hashes the
directory prints use); a file belongs to a rule's component when nearly all of
its functions are in the rule's signature. The files of one directory that
belong to one rule are then put to the engine's own tiers as if they were a
directory of their own (``MatchEngine.identify_files``), so identity, version
and probes are decided as for any other copy.

Three guards keep it from claiming what is not there:

* a file joins only when at least ``FILE_SHARE`` of its functions are the
  component's, and either several are or its name says so;
* a partial copy needs ``LOOSE_MIN_FUNCTIONS`` of the component's functions when
  the files' names corroborate the component (``lwshell.c`` for lwshell), and the
  engine's usual ``SUBSET_MIN_FUNCTIONS`` when they do not;
* a file is given to one component only: where two rules want the same files,
  the one their names corroborate, then the one explaining more functions, wins.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ..analysis import AnalysisStore
from ..dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_from_store
from ..model import Evidence, Finding, Technique
from ..rules.schema import Rule
from .engine import SUBSET_MIN_FUNCTIONS, MatchEngine

FILE_SHARE = 0.80           # of a file's functions that must be the component's
FILE_MIN_FUNCTIONS = 3      # matched functions that let a file join without its name
LOOSE_MIN_FUNCTIONS = 8     # a named partial copy; below this, a coincidence is plausible
NAME_MIN = 4                # shorter name keys ("c", "fat") corroborate nothing
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx", ".inc")

_NOT_ALNUM = re.compile(r"[^a-z0-9]+")


@dataclass
class _Group:
    rule: Rule
    files: List[str]                         # root-relative, functions matched
    matched: Set[int] = field(default_factory=set)
    named: bool = False


def _key(text: str) -> str:
    return _NOT_ALNUM.sub("", text.lower())


def rule_names(rule: Rule) -> Set[str]:
    """Name keys a file of this component may carry: its name, what it ships as,
    the rule id's last part and the last part of each path glob."""
    raw = [rule.upstream_name, rule.ships_as or "", rule.id.rsplit("/", 1)[-1]]
    raw += [g.rstrip("/").rsplit("/", 1)[-1] for g in rule.path_globs]
    keys = set()
    for name in raw:
        k = _key(name)
        if k.startswith("lib") and len(k) - 3 >= NAME_MIN:
            keys.add(k[3:])
        if len(k) >= NAME_MIN and "*" not in name:
            keys.add(k)
    return keys


def _named(stem: str, names: Set[str]) -> bool:
    k = _key(stem)
    return any(k.startswith(n) or (len(k) >= NAME_MIN and n.startswith(k)) for n in names)


def find_loose(root: Path, engine: MatchEngine, store: AnalysisStore,
               findings: Sequence[Finding], compiled: Optional[Set[Path]] = None,
               asserted: float = 0.0,
               absorbed: Optional[List[Tuple[str, List[str], str]]] = None) -> List[Finding]:
    """Findings for components copied in as loose files.

    *findings* are the directories already identified. Their files are not looked
    at again, except those a function signature shows are not the component's: a
    directory found to hold protobuf-c may hold lwprintf's files beside it, and the
    project's own. Where the component's files lie loose in that directory and are
    under half of its functions, its finding is narrowed to them (in place). With
    *compiled* (build facts), only directories holding a compiled file are looked at.
    A directory identified below *asserted* (a resemblance, not a component) holds
    nothing back.

    Files of a component found beside the directory it was found at (lwmem's
    ``src/system`` ports beside ``src/lwmem``) are that same copy, not a second
    one: they are recorded on its finding's evidence and, as (directory, files,
    name), in *absorbed*, instead of being reported again.
    """
    root = Path(root)
    signatures = {}
    for rule in engine.rulebase:
        if rule.functions is None:
            continue
        try:
            signatures[rule.id] = (rule, rule.functions.load())
        except Exception:                               # noqa: BLE001
            continue
    if not signatures:
        return []

    rels = store.select(root, DEFAULT_INCLUDE, DEFAULT_EXCLUDE) or []
    if compiled is not None:
        built = {p.relative_to(root).as_posix() for p in compiled
                 if p.is_relative_to(root)}
        dirs = {str(PurePosixPath(r).parent) for r in built}
        rels = [r for r in rels if str(PurePosixPath(r).parent) in dirs]
    if not rels:
        return []
    shas = store.shas(rels)
    rels = [r for r in rels if r in shas]
    store.ensure(rels)
    functions = {r: set(store.analysis(r).functions) for r in rels}
    covered = _covered(root, store, rels, functions,
                       [f for f in findings if f.identity_confidence >= asserted], signatures)
    rels = [r for r in rels if r not in covered]
    if not rels:
        return []

    # Which rules hold each function found here: one pass over the rule base's
    # hashes, kept only for hashes present in these files.
    present: Set[int] = set().union(*(functions[r] for r in rels))
    holders: Dict[int, List[str]] = defaultdict(list)
    for rid, (_, sig) in signatures.items():
        for h in sig.hashes:
            if h in present:
                holders[h].append(rid)
    if not holders:
        return []

    by_dir: Dict[str, List[str]] = defaultdict(list)
    for r in rels:
        by_dir[str(PurePosixPath(r).parent)].append(r)

    homes: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if not f.files and f.identity_confidence >= asserted:
            homes[f.rule_id].append(f)
    out: List[Finding] = []
    for d, files in sorted(by_dir.items()):
        hit_rules = {rid for r in files for h in functions[r] for rid in holders.get(h, ())}
        if not hit_rules:
            continue
        groups = []
        for rid in hit_rules:
            group = _group(signatures[rid], files, functions)
            if group is not None:
                groups.append(group)
        for group in _assign(groups, functions, {rid: signatures[rid] for rid in hit_rules}):
            home = next((f for f in homes.get(group.rule.id, ()) if _beside(d, f.directory)), None)
            if home is not None:
                members = _members(group, files, functions)
                home.evidence.append(Evidence(
                    technique=Technique.AST_FINGERPRINT, confidence=0.0,
                    summary=(f"{len(members)} more of its files beside it, in {d}: "
                             + ", ".join(PurePosixPath(m).name for m in members[:8])
                             + (" ..." if len(members) > 8 else "")),
                    locator=d))
                if absorbed is not None:
                    absorbed.append((d, members, home.upstream_name))
                continue
            under = store.select(root / d if d != "." else root, DEFAULT_INCLUDE,
                                 DEFAULT_EXCLUDE) or []
            finding = _identify(root, d, group, files, under, engine, functions)
            if finding is not None:
                out.append(finding)
    return out


def _covered(root: Path, store: AnalysisStore, rels: Sequence[str],
             functions: Dict[str, Set[int]], findings: Sequence[Finding],
             signatures) -> Set[str]:
    """Files the identified directories account for; narrows flat ones in place."""
    dirs = sorted({f.directory.strip("/") or "." for f in findings if not f.files},
                  key=lambda d: (-d.count("/"), d))
    owner: Dict[str, str] = {}               # file -> deepest identified directory
    for r in rels:
        for d in dirs:
            if d == "." or r.startswith(d + "/"):
                owner[r] = d
                break
    files_of: Dict[str, List[str]] = defaultdict(list)
    for r, d in owner.items():
        files_of[d].append(r)
    covered: Set[str] = set()
    for f in findings:
        d = f.directory.strip("/") or "."
        if f.files or d not in files_of:
            continue
        mine = files_of[d]
        entry = signatures.get(f.rule_id)
        if entry is None:
            covered.update(mine)             # no functions to tell its files apart
            continue
        hashes = entry[1].hash_set
        claimed = [r for r in mine if functions[r]
                   and len(functions[r] & hashes) >= FILE_SHARE * len(functions[r])]
        total = sum(len(functions[r]) for r in mine)
        theirs = sum(len(functions[r]) for r in claimed)
        flat = all(str(PurePosixPath(r).parent) == d for r in claimed)
        if claimed and flat and theirs < 0.5 * total:
            names = rule_names(entry[0])
            stems = {_key(PurePosixPath(r).stem) for r in claimed}
            members = sorted(claimed + [r for r in mine if not functions[r]
                                        and r.endswith(HEADER_SUFFIXES)
                                        and _belongs(r, names, stems)])
            f.files = members
            directory = root / d if d != "." else root
            f.content_hash = print_from_store(store, directory, only=members).fileset_sha256
            f.evidence.insert(0, Evidence(
                technique=Technique.OTHER, confidence=0.0,
                summary=(f"{len(claimed)} of the directory's files hold "
                         f"{theirs} of its {total} functions and are "
                         f"{f.upstream_name}'s; the rest are other code, so the "
                         f"component is those files, not the directory"),
                locator=f.directory))
            covered.update(members)
        else:
            covered.update(r for r in mine if not functions[r] or r in claimed)
    return covered


def _belongs(rel: str, names: Set[str], stems: Set[str]) -> bool:
    """A header goes with a component when its name is the component's or one of
    its files' (lwprintf_opt.h with lwprintf.c)."""
    stem = PurePosixPath(rel).stem
    return _named(stem, names) or any(_key(stem).startswith(s) for s in stems if len(s) >= NAME_MIN)


def _group(entry, files: Sequence[str], functions: Dict[str, Set[int]]) -> Optional[_Group]:
    rule, sig = entry
    names = rule_names(rule)
    hashes = sig.hash_set
    group = _Group(rule, [])
    for r in files:
        fns = functions[r]
        if not fns:
            continue
        matched = fns & hashes
        named = _named(PurePosixPath(r).stem, names)
        if (len(matched) >= FILE_SHARE * len(fns)
                and (len(matched) >= FILE_MIN_FUNCTIONS or named)):
            group.files.append(r)
            group.matched |= matched
            group.named |= named
    return group if group.files else None


def _assign(groups: List[_Group], functions: Dict[str, Set[int]], signatures) -> List[_Group]:
    """Each file to one component: named groups first, then the larger."""
    taken: Set[str] = set()
    out = []
    for group in sorted(groups, key=lambda g: (not g.named, -len(g.matched), g.rule.id)):
        files = [f for f in group.files if f not in taken]
        if not files:
            continue
        if len(files) < len(group.files):
            rest = _group(signatures[group.rule.id], files, functions)
            if rest is None:
                continue
            group = rest
        need = LOOSE_MIN_FUNCTIONS if group.named else SUBSET_MIN_FUNCTIONS
        if len(group.matched) < need:
            continue
        taken.update(group.files)
        out.append(group)
    return out


def _beside(d: str, home: str) -> bool:
    """*d* is within the parent of *home*, a directory below the scan root."""
    parent = str(PurePosixPath(home.strip("/")).parent)
    return parent not in ("", ".") and (d == parent or d.startswith(parent + "/"))


def _members(group: _Group, files: Sequence[str], functions: Dict[str, Set[int]]) -> List[str]:
    """The group's files and the headers that go with them: headers declare rather
    than define, so they rarely carry functions."""
    names = rule_names(group.rule)
    stems = {_key(PurePosixPath(f).stem) for f in group.files}
    extra = [f for f in files if f not in group.files and f.endswith(HEADER_SUFFIXES)
             and not functions[f] and _belongs(f, names, stems)]
    return sorted(group.files + extra)


def _identify(root: Path, d: str, group: _Group, files: Sequence[str], under: Sequence[str],
              engine: MatchEngine, functions: Dict[str, Set[int]]) -> Optional[Finding]:
    members = _members(group, files, functions)
    directory = root / d if d != "." else root
    subset_min = LOOSE_MIN_FUNCTIONS if group.named else SUBSET_MIN_FUNCTIONS
    finding = engine.identify_files(root, directory, members, group.rule, subset_min)
    if finding is None:
        return None
    if set(under) != set(members):       # else the directory is the component
        finding.files = members
        finding.evidence.insert(0, Evidence(
            technique=Technique.FILENAME if group.named else Technique.OTHER,
            confidence=0.3 if group.named else 0.0,
            summary=(f"{len(members)} file(s) of {group.rule.upstream_name} copied in among "
                     f"{len(files) - len(members)} other file(s) of {finding.directory}: "
                     + ", ".join(PurePosixPath(m).name for m in members[:8])
                     + (" ..." if len(members) > 8 else "")
                     + ("" if group.named else "; their names do not say so")),
            locator=finding.directory))
    return finding
