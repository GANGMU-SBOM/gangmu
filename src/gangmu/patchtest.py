"""Patch presence: is the fix for an advisory in this copy of the component?

A version range answers "which releases are affected". A vendor fork reports the
release it started from, so every advisory fixed in a later release matches it,
whether or not the vendor already took the fix. Without more evidence the only
honest state is ``in_triage``, and it stays there for ever. That is the largest
single source of noise in an embedded SBOM, and the 1-day-vulnerability
literature (VULTURE, NDSS 2025; V1SCAN, USENIX Security 2023) agrees on the
cure: test the code, not the version.

A *patch record* holds, for one advisory, the functions its fix commit touched,
each with the hash of the body before the fix (vulnerable) and after it (fixed).
They are the same token-stream hashes the identification engine uses, so
reformatting and comments never matter. The test classifies every recorded
function in a component directory:

``fixed``       the fixed body is present
``vulnerable``  the vulnerable body is present
``modified``    the function is defined, but with neither body: the vendor edited
                it, and nothing here says whether that closes the hole
``absent``      the function is not defined anywhere in the directory

and then states one verdict for the advisory:

``fixed``       at least one fixed body, and no vulnerable one
``vulnerable``  a vulnerable body, and no fixed one
``partial``     both: the fix was taken for some functions and not for others
``modified``    neither body anywhere, but the function exists in an edited form
``likely_fixed`` / ``likely_vulnerable``
                an edited form that carries the fix's added code and none of what
                it removed (or the reverse); never identical, never final
``absent``      none of the functions is here (a pruned copy, or a rename)

What this cannot see, and says so rather than guessing: a function the vendor
renamed (it looks absent), a fix whose effect lies outside the recorded
functions (a changed macro, a struct, a build flag), and an advisory whose fix
was split over commits that were not all recorded. A verdict of ``fixed`` is
"the fixed code is here", not a proof that the weakness is gone.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from .dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, iter_source_files
from . import fuzzy
from .functions import extract_functions
from .normalize import tokenize

FORMAT = 1
SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".inc")
# A "fix" that rewrites dozens of functions is a refactor, and its hashes would
# call every tree that merely differs from it modified. Larger commits need the
# functions to be named.
MAX_FUNCTIONS = 40
_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")


class PatchError(Exception):
    """A record could not be built or read; the message is for the user."""


@dataclass(frozen=True)
class FunctionPatch:
    """One function a fix touched."""

    function: str
    file: str
    vulnerable: FrozenSet[int] = frozenset()      # body hashes before the fix
    fixed: FrozenSet[int] = frozenset()           # body hashes after the fix
    vulnerable_abstract: FrozenSet[int] = frozenset()
    fixed_abstract: FrozenSet[int] = frozenset()
    # What the fix changed, as token windows: lets an edited copy be placed on
    # the vulnerable or the fixed side. Absent for records without it.
    near: Optional[fuzzy.NearDiff] = None

    def to_dict(self) -> dict:
        out: dict = {"function": self.function, "file": self.file}
        if self.near:
            out["near"] = self.near.to_dict()
        for key, values in (("vulnerable", self.vulnerable), ("fixed", self.fixed),
                            ("vulnerableAbstract", self.vulnerable_abstract),
                            ("fixedAbstract", self.fixed_abstract)):
            if values:
                out[key] = sorted(f"{h:016x}" for h in values)
        return out

    @classmethod
    def from_dict(cls, raw: dict) -> "FunctionPatch":
        def hashes(key: str) -> FrozenSet[int]:
            return frozenset(int(h, 16) for h in raw.get(key, []) or [])
        name = raw.get("function")
        if not isinstance(name, str) or not name:
            raise PatchError("a recorded function has no name")
        return cls(function=name, file=str(raw.get("file", "")),
                   vulnerable=hashes("vulnerable"), fixed=hashes("fixed"),
                   vulnerable_abstract=hashes("vulnerableAbstract"),
                   fixed_abstract=hashes("fixedAbstract"),
                   near=(fuzzy.NearDiff.from_dict(raw["near"])
                         if isinstance(raw.get("near"), dict) else None))


@dataclass
class PatchRecord:
    advisory: str
    functions: List[FunctionPatch] = field(default_factory=list)
    repo: str = ""
    commits: List[str] = field(default_factory=list)
    note: str = ""
    first_parent: bool = False        # a merge's net change against its first parent

    def to_dict(self) -> dict:
        out: dict = {"functions": [f.to_dict() for f in self.functions]}
        if self.first_parent:
            out["firstParent"] = True
        if self.repo:
            out["repo"] = self.repo
        if self.commits:
            out["commits"] = list(self.commits)
        if self.note:
            out["note"] = self.note
        return out


def load_patches(path: Path) -> Dict[str, PatchRecord]:
    """``{"format": 1, "patches": {"CVE-...": {...}}}``, keys upper-cased."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("patches"), dict):
        raise PatchError(f"{path} is not a patch record file (no \"patches\" object)")
    if raw.get("format", FORMAT) != FORMAT:
        raise PatchError(f"{path} has patch format {raw.get('format')}, "
                         f"this gangmu reads {FORMAT}")
    out: Dict[str, PatchRecord] = {}
    for key, value in raw["patches"].items():
        try:
            functions = [FunctionPatch.from_dict(f) for f in value.get("functions", [])]
        except (ValueError, AttributeError, TypeError) as exc:
            raise PatchError(f"{path}: record {key} is malformed: {exc}") from exc
        out[str(key).upper()] = PatchRecord(
            advisory=str(key).upper(), functions=functions,
            repo=str(value.get("repo", "")), commits=list(value.get("commits", [])),
            note=str(value.get("note", "")),
            first_parent=bool(value.get("firstParent", False)))
    return out


def save_patches(path: Path, records: Dict[str, PatchRecord]) -> None:
    body = {"format": FORMAT,
            "patches": {k: records[k].to_dict() for k in sorted(records)}}
    Path(path).write_text(json.dumps(body, indent=1, sort_keys=True) + "\n",
                          encoding="utf-8")


# ---------------------------------------------------------------- building

def _git(args: Sequence[str], cwd: Path) -> str:
    try:
        return subprocess.run(["git", *args], cwd=cwd, check=True,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace").stdout
    except FileNotFoundError as exc:
        raise PatchError("git is required to build patch records") from exc
    except subprocess.CalledProcessError as exc:
        raise PatchError(f"git {' '.join(args[:3])} failed: "
                         f"{(exc.stderr or '').strip()[:200]}") from exc


def _show(repo: Path, rev: str, path: str) -> Optional[bytes]:
    try:
        return subprocess.run(["git", "show", f"{rev}:{path}"], cwd=repo, check=True,
                              capture_output=True).stdout
    except subprocess.CalledProcessError:
        return None                       # the file did not exist at that revision


class _Bodies:
    """The bodies of one function name in one file revision."""

    def __init__(self) -> None:
        self.exact: Set[int] = set()
        self.abstract: Set[int] = set()
        self.windows: Dict[int, Set[int]] = {}      # body hash -> token windows


def _by_name(data: Optional[bytes]) -> Dict[str, _Bodies]:
    out: Dict[str, _Bodies] = {}
    if not data:
        return out
    tokens = tokenize(data)
    for fn in extract_functions(data, tokens):
        bodies = out.setdefault(fn.name, _Bodies())
        bodies.exact.add(fn.hash)
        if fn.abstract_hash is not None:
            bodies.abstract.add(fn.abstract_hash)
        bodies.windows[fn.hash] = fuzzy.shingles(tokens[fn.span[0]:fn.span[1]])
    return out


def functions_changed_by(repo: Path, commit: str,
                         only: Optional[Sequence[str]] = None,
                         first_parent: bool = False) -> List[FunctionPatch]:
    """Every function whose body differs between *commit*'s parent and *commit*.

    Functions are paired by name within a file: a name that exists on both sides
    with different bodies is an edit; a name only before is removed by the fix
    (vulnerable body only); a name only after is new (a fixed body only, which is
    evidence of the fix when present and says nothing when absent).

    A merge commit is refused unless *first_parent* is set: a fix merged as a pull
    request is then the net change the merge made to its first parent, which is
    well defined but also carries whatever else the pull request held, so it is
    asked for explicitly.
    """
    parents = _git(["rev-list", "--parents", "-n", "1", commit], repo).split()
    if len(parents) < 2:
        raise PatchError(
            f"{commit} has no parent in this clone (a root commit, or a shallow "
            f"boundary: fetch with --depth 2)")
    if len(parents) > 2 and not first_parent:
        raise PatchError(
            f"{commit} has {len(parents) - 1} parents; a fix must be a single "
            f"non-merge commit (give the commit that made the change, or ask for "
            f"the merge's net change against its first parent with --first-parent)")
    parent = parents[1]
    names = _git(["diff", "--name-only", "-z", "--no-renames", parent, commit],
                 repo).split("\0")
    wanted = set(only or ())
    out: List[FunctionPatch] = []
    for path in filter(None, names):
        if not path.lower().endswith(SOURCE_SUFFIXES):
            continue
        before, after = _by_name(_show(repo, parent, path)), _by_name(_show(repo, commit, path))
        for name in sorted(set(before) | set(after)):
            if wanted and name not in wanted:
                continue
            b, a = before.get(name, _Bodies()), after.get(name, _Bodies())
            vulnerable, fixed = b.exact - a.exact, a.exact - b.exact
            if not vulnerable and not fixed:
                continue
            out.append(FunctionPatch(
                function=name, file=path,
                vulnerable=frozenset(vulnerable), fixed=frozenset(fixed),
                # Where a one-identifier fix leaves the abstract body unchanged,
                # abstraction cannot tell the two apart, so it is not recorded.
                vulnerable_abstract=frozenset(b.abstract - a.abstract),
                fixed_abstract=frozenset(a.abstract - b.abstract),
                near=fuzzy.diff([b.windows[h] for h in vulnerable],
                                [a.windows[h] for h in fixed])))
    return out


def _ensure_parent(checkout: Path, commit: str, attempts: int = 4) -> None:
    """Make sure *commit*'s parent is in a shallow clone.

    When one fix commit is the parent of another, fetching the second leaves the
    first as a shallow boundary, and a later fetch of it is a no-op: it has no
    parent here. Deepen until it does, or give up for a true root commit.
    """
    for _ in range(attempts):
        if len(_git(["rev-list", "--parents", "-n", "1", commit], checkout).split()) > 1:
            return
        if not (checkout / ".git" / "shallow").is_file():
            return                                  # a full clone: a real root commit
        _git(["fetch", "--quiet", "--deepen", "1", "origin"], checkout)


def build_record(advisory: str, repo: str, commits: Sequence[str],
                 only: Optional[Sequence[str]] = None,
                 workdir: Optional[Path] = None,
                 first_parent: bool = False) -> PatchRecord:
    """A patch record from the commit(s) that fixed *advisory* in *repo*.

    *repo* is a local clone or a URL; a URL is fetched shallowly at each commit
    and its parent, into *workdir* or a temporary directory.
    """
    commits = [c.strip() for c in commits if c and c.strip()]
    if not commits:
        raise PatchError(f"no fix commit given for {advisory}")
    for c in commits:
        if not _SHA.match(c):
            raise PatchError(f"{c!r} is not a commit id; give the hash of the fix")
    local = Path(repo).expanduser()
    tmp = None
    try:
        if local.is_dir():
            checkout = local
        else:
            tmp = tempfile.TemporaryDirectory(prefix="gangmu-patch-") \
                if workdir is None else None
            checkout = Path(workdir) if workdir else Path(tmp.name)
            checkout.mkdir(parents=True, exist_ok=True)
            _git(["init", "--quiet"], checkout)
            _git(["remote", "add", "origin", repo], checkout)
            for c in commits:
                _git(["fetch", "--quiet", "--depth", "2", "origin", c], checkout)
            for c in commits:
                _ensure_parent(checkout, c)
        functions: List[FunctionPatch] = []
        for c in commits:
            functions.extend(functions_changed_by(checkout, c, only, first_parent))
    finally:
        if tmp is not None:
            tmp.cleanup()
    if not functions:
        raise PatchError(
            f"{', '.join(commits)} changes no C/C++ function body"
            + (f" named {', '.join(only)}" if only else "")
            + "; there is nothing to test for")
    if len(functions) > MAX_FUNCTIONS and not only:
        raise PatchError(
            f"{', '.join(commits)} changes {len(functions)} functions, which is a "
            f"refactor rather than a fix; name the ones that matter with "
            f"--function (more than {MAX_FUNCTIONS} would make any tree that "
            f"merely differs look modified)")
    return PatchRecord(advisory=advisory.upper(), functions=functions,
                       repo=repo, commits=list(commits), first_parent=first_parent)


# ----------------------------------------------------------- rule-pack records

PACK_DIR = "patches"


def pack_patch_files(roots: Iterable[Path]) -> List[Path]:
    """``<root>/patches/*.json`` of every rule root, in root order."""
    out: List[Path] = []
    for root in roots:
        directory = Path(root) / PACK_DIR
        if directory.is_dir():
            out.extend(sorted(p for p in directory.glob("*.json") if p.is_file()))
    return out


def load_pack_patches(roots: Iterable[Path]) -> Dict[str, PatchRecord]:
    """Records shipped with rule packs; a later root's record replaces an earlier one's."""
    records: Dict[str, PatchRecord] = {}
    for path in pack_patch_files(roots):
        records.update(load_patches(path))
    return records


def verify_record(record: PatchRecord, workdir: Optional[Path] = None) -> List[str]:
    """Rebuild *record* from its upstream commits; the differences, or ``[]``.

    A record is only worth trusting if anyone can reproduce it: the commits are
    named, so the hashes are re-derived from them and compared. Every function
    stored must come back identical; the rebuild is limited to the stored
    functions, because a record may deliberately name only part of a large commit.
    """
    if not record.repo or not record.commits:
        return ["the record names no repository and commit, so it cannot be re-derived"]
    names = sorted({f.function for f in record.functions})
    try:
        again = build_record(record.advisory, record.repo, record.commits, only=names,
                             workdir=workdir, first_parent=record.first_parent)
    except PatchError as exc:
        return [f"cannot rebuild: {exc}"]
    fresh = list(again.functions)
    problems: List[str] = []
    for f in record.functions:
        # Several fix commits (one per release branch) can touch the same
        # function in the same file, so a stored entry only has to be one of the
        # entries the commits give, not the only one.
        if f in fresh:
            continue
        same = [g for g in fresh if (g.function, g.file) == (f.function, f.file)]
        problems.append(f"{f.function} ({f.file}) differs from what the commit gives"
                        if same else
                        f"{f.function} ({f.file}) is no longer changed by the commit")
    return problems


# ----------------------------------------------------------------- testing

@dataclass
class Present:
    """What one component directory defines."""

    exact: Set[int] = field(default_factory=set)
    abstract: Set[int] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)
    files: int = 0
    # Token windows of every body of the functions a record names (and only
    # those: windows for a whole tree would be most of its size again).
    windows: Dict[str, List[Set[int]]] = field(default_factory=dict)


def scan_directory(root: Path, directory: str, cache: Optional[dict] = None,
                   near_names: FrozenSet[str] = frozenset()) -> Present:
    """Every function defined under ``root/directory``, hashed as the engine does.

    Tests, examples and documentation are not shipped, so they are not read
    (the same exclusions the identification engine applies).
    """
    key = directory
    if cache is not None and key in cache:
        return cache[key]
    base = Path(root) / directory if directory not in ("", ".") else Path(root)
    present = Present()
    for path in iter_source_files(base, DEFAULT_INCLUDE,
                                  DEFAULT_EXCLUDE):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        present.files += 1
        tokens = tokenize(data)
        for fn in extract_functions(data, tokens):
            present.exact.add(fn.hash)
            present.names.add(fn.name)
            if fn.abstract_hash is not None:
                present.abstract.add(fn.abstract_hash)
            if fn.name in near_names:
                present.windows.setdefault(fn.name, []).append(
                    fuzzy.shingles(tokens[fn.span[0]:fn.span[1]]))
    if cache is not None:
        cache[key] = present
    return present


@dataclass
class PatchVerdict:
    status: str                       # fixed | vulnerable | partial | modified | absent
    detail: str
    advisory: str = ""
    per_function: Dict[str, str] = field(default_factory=dict)
    basis: str = "exact"              # "exact" | "identifier-abstracted"

    def to_dict(self) -> dict:
        return {"status": self.status, "detail": self.detail, "basis": self.basis,
                "functions": dict(self.per_function)}


def _classify(patch: FunctionPatch, present: Present) -> Tuple[str, str, Optional[fuzzy.Near]]:
    """(state, basis, near) for one function.

    ``near`` is set only for a ``modified`` function, when the record carries a
    diff to compare it with; the state itself stays ``modified``.
    """
    if patch.fixed & present.exact:
        return "fixed", "exact", None
    if patch.vulnerable & present.exact:
        return "vulnerable", "exact", None
    if patch.fixed_abstract & present.abstract:
        return "fixed", "abstract", None
    if patch.vulnerable_abstract & present.abstract:
        return "vulnerable", "abstract", None
    if patch.function in present.names:
        near = None
        if patch.near:
            # Several definitions of one name (conditional builds): the one
            # closest to either body is the one the build most likely uses.
            candidates = [fuzzy.classify(w, patch.near)
                          for w in present.windows.get(patch.function, [])]
            if candidates:
                near = max(candidates, key=lambda n: n.related)
        return "modified", "exact", near
    return "absent", "exact", None


def assess_patch(record: PatchRecord, present: Present) -> PatchVerdict:
    states: Dict[str, str] = {}
    nears: Dict[str, fuzzy.Near] = {}
    basis = "exact"
    for patch in record.functions:
        state, how, near = _classify(patch, present)
        label = f"{patch.function} ({patch.file})" if patch.file else patch.function
        states[label] = state
        if near is not None:
            nears[label] = near
        if how == "abstract" and state in ("fixed", "vulnerable"):
            basis = "identifier-abstracted"
    fixed = [k for k, v in states.items() if v == "fixed"]
    vulnerable = [k for k, v in states.items() if v == "vulnerable"]
    modified = [k for k, v in states.items() if v == "modified"]
    how = (" (found under renamed identifiers)"
           if basis == "identifier-abstracted" else "")
    if fixed and vulnerable:
        return PatchVerdict(
            "partial",
            f"the fix is incomplete here: {', '.join(fixed[:3])} carries the "
            f"fixed body, {', '.join(vulnerable[:3])} still carries the "
            f"vulnerable one{how}", record.advisory, states, basis)
    if vulnerable:
        return PatchVerdict(
            "vulnerable",
            f"the vulnerable body of {', '.join(vulnerable[:3])} is present, "
            f"identical to the code before the fix{how}",
            record.advisory, states, basis)
    if fixed:
        extra = (f"; {', '.join(modified[:2])} is edited and was not compared"
                 if modified else "")
        return PatchVerdict(
            "fixed",
            f"the fixed body of {', '.join(fixed[:3])} is present, identical to "
            f"the code after the fix{how}{extra}", record.advisory, states, basis)
    if modified:
        return _modified(record, states, nears, modified)
    return PatchVerdict(
        "absent",
        f"none of the {len(record.functions)} function(s) the fix touches is "
        f"defined under this directory (a pruned copy, or renamed symbols)",
        record.advisory, states, "exact")


def _modified(record: PatchRecord, states: Dict[str, str],
              nears: Dict[str, "fuzzy.Near"], modified: List[str]) -> PatchVerdict:
    """Edited functions and nothing exact: say which side of the fix they are on.

    Near matching never makes an edited function ``fixed`` or ``vulnerable``;
    those words are kept for an identical body. It reports ``likely_fixed`` or
    ``likely_vulnerable`` when every edited function the record can compare
    agrees, and leaves the rest as ``modified`` with the numbers.
    """
    for label, near in nears.items():
        states[label] = {"fixed": "likely_fixed",
                         "vulnerable": "likely_vulnerable"}.get(near.label, "modified")
    lean_fixed = [k for k, n in nears.items() if n.label == "fixed"]
    lean_vuln = [k for k, n in nears.items() if n.label == "vulnerable"]
    other = [k for k in modified if k not in lean_fixed and k not in lean_vuln]
    facts = "; ".join(f"{k}: {n.summary()}" for k, n in nears.items()
                      if n.label in ("fixed", "vulnerable", "unclear"))
    if lean_fixed and not lean_vuln and not other:
        return PatchVerdict(
            "likely_fixed",
            f"{', '.join(lean_fixed[:3])} is edited but is a variant of the fixed "
            f"code ({facts}); not byte-identical, so a person should confirm",
            record.advisory, states, "near")
    if lean_vuln and not lean_fixed and not other:
        return PatchVerdict(
            "likely_vulnerable",
            f"{', '.join(lean_vuln[:3])} is edited but is a variant of the "
            f"vulnerable code ({facts}); not byte-identical, so a person should "
            f"confirm", record.advisory, states, "near")
    return PatchVerdict(
        "modified",
        f"{', '.join(modified[:3])} is defined here but matches neither the "
        f"vulnerable nor the fixed body: the vendor changed it, and whether "
        f"that closes the hole needs a person to read it"
        + (f" ({facts})" if facts else ""),
        record.advisory, states, "exact")


def near_names(records: Iterable[PatchRecord]) -> FrozenSet[str]:
    """The functions whose edited copies are worth keeping token windows for."""
    return frozenset(f.function for r in records for f in r.functions if f.near)


def assess(record: PatchRecord, root: Path, directory: str,
           cache: Optional[dict] = None,
           near: FrozenSet[str] = frozenset()) -> PatchVerdict:
    return assess_patch(record, scan_directory(root, directory, cache, near))


def records_for(advisory_id: str, aliases: Iterable[str],
                records: Dict[str, PatchRecord]) -> Optional[PatchRecord]:
    for key in [advisory_id, *aliases]:
        record = records.get(str(key).upper())
        if record is not None:
            return record
    return None
