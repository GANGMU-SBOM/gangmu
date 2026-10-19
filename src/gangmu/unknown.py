"""Third-party code no rule names.

Identification can only name what a rule describes. This asks a different
question of what is left once the scan's findings are subtracted: is this
directory, or this group of files, someone else's code? That needs no knowledge
of the component, only of what vendored code looks like on disk:

  markers     its own licence file, package manifest (library.json,
              idf_component.yml, CMake project(), AC_INIT ...), repository
              leftovers (.github, Doxyfile, tests/ and examples/ beside the code),
              a git submodule
  placement   a child of third_party/, lib/, components/, Middlewares/ ...
  provenance  its files carry a copyright holder or licence header that the rest
              of the tree does not
  namespace   its functions share a prefix that the rest of the tree does not use
  versioning  it defines its own <NAME>_VERSION
  dependency  it does not include the project's headers (only its own, and the
              configuration headers a library expects its user to supply)

Each directory is scored on these (weights set a priori, see SCORE) and the
outermost directory that passes is reported, unless it holds several
independently marked libraries (a container) or is mostly a component already
found. Files dropped loose into a project directory (cJSON.c beside main.c) are
grouped by name, include links, holder and function prefix, and scored the same
way without the directory markers.

Measured on 120 generated firmware projects holding 66 open-source libraries
(the GangmuAI discovery benchmark, held-out libraries): 160 of 167 vendored
copies found against 97 for licence files, manifests and submodules alone, with
one false candidate. Every candidate is a lead, not a component: it carries a
name and version hint read from the code, never a purl or CPE, and stays out of
the SBOM.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from .analysis import ANALYSIS_DIGEST, AnalysisStore
from .discover import SKIP_DIRS as DISCOVER_SKIP_DIRS
from .functions import extract_functions

SOURCE_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".inc", ".ipp"}
SKIP_DIRS = DISCOVER_SKIP_DIRS | {"node_modules", "__pycache__"}
MAX_BYTES = 8 << 20
HEAD_BYTES = 4096

# directories whose children are, by convention, other people's code
CONTAINERS = {"third_party", "thirdparty", "third-party", "3rdparty", "3rd_party", "3rd-party", "vendor",
              "vendors", "external", "externals", "extern", "deps", "dependencies", "lib", "libs", "libraries",
              "library", "components", "modules", "contrib", "middlewares", "packages", "ext", "submodules",
              "managed_components", "subprojects"}
LICENSE_FILE = re.compile(r"^(licen[sc]e|copying|copyright|unlicense|notice)([-_.].*)?$", re.I)
README_FILE = re.compile(r"^(readme|changelog|changes|history|news|authors|contributors)([-_.].*)?$", re.I)
REPO_ARTIFACTS = {".github", ".gitignore", ".gitattributes", ".clang-format", ".travis.yml", "appveyor.yml",
                  "azure-pipelines.yml", ".editorconfig", "doxyfile", ".gitlab-ci.yml", "contributing.md",
                  "security.md", "code_of_conduct.md", ".pre-commit-config.yaml", "cspell.config.yaml"}
REPO_SUBDIRS = {"test", "tests", "example", "examples", "doc", "docs", "fuzzing", "fuzz", "samples", "demo",
                "demos", "benchmark", "benchmarks", "unittest", "unittests"}
# a package's description of itself; build files that also sit in every
# subdirectory of an autotools or meson project count only as BUILD_FILES
PACKAGES = {"library.json", "library.properties", "idf_component.yml", "module.yml", "vcpkg.json",
            "conanfile.py", "conanfile.txt", "package.json", "manifest.yml", "sbom.spdx",
            "platformio-build.py", "package.xml", "build.bazel", "configure.ac", "configure.in"}
BUILD_FILES = {"meson.build", "makefile.am"}
MANIFESTS = PACKAGES | BUILD_FILES
# headers a library includes from its user: configuration, ports, options
CONFIG_HEADER = re.compile(r"(conf|config|cfg|opts|options|port|settings|user|glue|platform|target|board|arch)",
                           re.I)
# version macros a firmware project defines for itself
OWN_VERSION = {"app", "fw", "firmware", "project", "board", "hw", "sw", "hardware", "software", "build",
               "product", "device", "my", "api", "abi", "protocol", "proto", "config", "cfg"}
GENERIC_DIRS = {"src", "source", "sources", "inc", "include", "includes", "lib", "dev", "code", "core",
                "library", "port", "ports", "c", "csrc", "api", "main"}
ENTRY_POINTS = {"main", "app_main", "user_main", "WinMain", "wmain"}

# a priori weights: strong evidence ~2, supporting evidence ~1; a candidate needs THRESHOLD
SCORE = {"submodule": 3.0, "manifest": 2.0, "license": 2.0, "readme": 0.5, "repo": 1.0, "repo_subdirs": 0.5,
         "container_child": 1.5, "container": -3.0, "foreign_holder": 2.5, "namespace": 1.0, "version": 1.0,
         "self_contained": 1.0, "includes_project": -2.0}
THRESHOLD = 3.0
MIN_FUNCTIONS = 3

_INCLUDE = re.compile(rb'^\s*#\s*include\s*["<]([^">]+)[">]', re.M)
_COPYRIGHT = re.compile(rb"(?:copyright\s*(?:\(c\)|\xc2\xa9|&copy;)?|\(c\)|\xc2\xa9)\s*[:]?\s*(.{3,120})", re.I)
_SPDX = re.compile(rb"SPDX-License-Identifier:\s*([A-Za-z0-9.+\- ()]+)")
_LICENSE_TEXT = (
    (b"permission is hereby granted, free of charge", "MIT"),
    (b"licensed under the apache license", "Apache-2.0"),
    (b"redistribution and use in source and binary forms", "BSD"),
    (b"gnu general public license", "GPL"),
    (b"gnu lesser general public license", "LGPL"),
    (b"this software is provided 'as-is'", "Zlib"),
    (b"mozilla public license", "MPL"),
    (b"eclipse public license", "EPL"),
)
_VERSION_MACRO = re.compile(
    rb'^\s*#\s*define\s+([A-Za-z][A-Za-z0-9_]*?)_?VER(?:SION)?(?:_?STR(?:ING)?)?\s+"?[vV]?(\d+\.\d+(?:\.\d+){0,2})',
    re.M)
# a plain number, not an expression (littlefs: (0xffff & (LFS_VERSION >> 16)))
_SPLIT_VERSION = re.compile(
    rb'^\s*#\s*define\s+([A-Za-z][A-Za-z0-9_]*?)_?(?:VERSION|VER)_?'
    rb'(MAJOR|MINOR|PATCH|MICRO|BUGFIX|REVISION|RELEASE|BUILD|PATCHLEVEL|SUBMINOR)'
    rb'\s+\(?(\d+)[uUlL]*\)?[ \t]*(?:/[/*].*)?$', re.M)
_THIRD_PART = ("PATCH", "MICRO", "BUGFIX", "REVISION", "RELEASE", "BUILD", "PATCHLEVEL", "SUBMINOR")
_CMAKE_PROJECT = re.compile(rb"^\s*project\s*\(\s*([A-Za-z0-9_.+-]+)(?:[^)]*?VERSION\s+([0-9.]+))?",
                            re.M | re.I)
_AC_INIT = re.compile(rb"AC_INIT\(\s*\[?([A-Za-z0-9_.+-]+)\]?\s*,\s*\[?([0-9][0-9.]*)", re.M)
_NAME_FIELD = re.compile(rb'(?:"name"\s*:\s*"|^\s*name\s*[:=]\s*["\']?)([A-Za-z0-9_.+/@-]+)', re.M | re.I)
_VERSION_FIELD = re.compile(rb'(?:"version"\s*:\s*"|^\s*version\s*[:=]\s*["\']?)[vV]?(\d+(?:\.\d+)+)',
                            re.M | re.I)
_HOLDER_DROP = re.compile(r"\b(all rights reserved|and/or its affiliates|and (?:its )?contributors|inc|ltd|"
                          r"llc|gmbh|co|corp|corporation|limited|the|by|authors?|\d{4}(?:\s*[-,]\s*\d{2,4})*)\b",
                          re.I)
_NOT_HOLDER = re.compile(r"\W*(notice|holders?|owners?|law|laws|statement|info|information|of|is|and|on|for|"
                         r"to)\b", re.I)


@dataclass
class FileFacts:
    holder: Optional[str] = None             # copyright holder, or "license:<id>" with no holder
    includes: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    versions: List[Tuple[str, str]] = field(default_factory=list)   # (macro prefix, version)


@dataclass
class Tree:
    root: Path
    files: Dict[str, FileFacts]                 # source files, root-relative
    other: Dict[str, List[str]]                 # directory -> non-source file names directly in it
    subdirs: Dict[str, List[str]]               # directory -> child directory names
    submodules: Set[str]
    by_name: Dict[str, List[str]]               # file basename (lower case) -> paths


@dataclass
class Score:
    total: float
    signals: Dict[str, float]
    holder: Optional[str] = None
    prefix: Optional[str] = None
    outward: List[str] = field(default_factory=list)


@dataclass
class Unknown:
    """Code that looks vendored and that no rule names."""

    kind: str                       # "directory", or "files" dropped among others
    directory: str
    files: List[str]
    functions: int
    score: float
    signals: Dict[str, float]
    holder: Optional[str] = None
    prefix: Optional[str] = None
    includes_project: List[str] = field(default_factory=list)
    name_hint: Optional[str] = None
    version_hint: Optional[str] = None
    resembles: List[str] = field(default_factory=list)
    """Rules a weak (``possible``) match of this code came from."""

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        out["files"] = len(self.files)
        out["paths"] = self.files
        return out


def _holder(head: bytes) -> Optional[str]:
    for m in _COPYRIGHT.finditer(head):
        text = m.group(1).split(b"\n")[0].decode("utf-8", "replace")
        if _NOT_HOLDER.match(text):
            continue                       # "copyright notice", "copyright holders": not a holder
        text = re.sub(r"<[^>]*>|\([^)]*@[^)]*\)|\S+@\S+|https?://\S+", " ", text)   # e-mail, URL
        text = re.sub(r"[*/#\\]+", " ", text)
        text = _HOLDER_DROP.sub(" ", text)
        words = [w for w in re.findall(r"[a-z][a-z0-9+-]+", text.lower()) if w not in {"c", "copyright", "and"}]
        if words:
            return " ".join(words[:2])
        break
    spdx = _SPDX.search(head)
    if spdx:
        return "license:" + spdx.group(1).decode().strip().split()[0].lower()
    low = head.lower()
    for text_, name in _LICENSE_TEXT:
        if text_ in low:
            return "license:" + name.lower()
    return None


def _top(counter: Counter) -> Tuple[str, int]:
    """The most common key; of equal counts the smallest, so the answer does not depend on the order
    a set of names happened to be iterated in (it changes with the interpreter's hash seed)."""
    return min(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def _prefix(name: str) -> Optional[str]:
    """`cJSON_Parse` -> cjson, `lfs_mount` -> lfs, `SEGGER_RTT_Init` -> segger."""
    name = name.lstrip("_")
    if "_" in name:
        p: Optional[str] = name.split("_", 1)[0]
    else:
        m = re.match(r"^([a-z]+)[A-Z]", name)       # camelCase: prvTaskFoo -> prv
        p = m.group(1) if m else None
    if not p or len(p) < 2 or p.lower() in {"main", "static", "get", "set", "is", "do", "on", "test", "init"}:
        return None
    return p.lower()


def _versions(data: bytes) -> List[Tuple[str, str]]:
    out = [(p.decode().rstrip("_").lower(), v.decode()) for p, v in _VERSION_MACRO.findall(data)]
    split: Dict[str, Dict[str, int]] = defaultdict(dict)
    for p, part, v in _SPLIT_VERSION.findall(data):
        split[p.decode().rstrip("_").lower()][part.decode().upper()] = int(v)
    for p, parts in split.items():
        if "MAJOR" in parts and "MINOR" in parts:
            nums = [parts["MAJOR"], parts["MINOR"]] + [parts[k] for k in _THIRD_PART if k in parts][:1]
            out.append((p, ".".join(map(str, nums))))
    return out


FACTS_VERSION = "unknown-1-" + ANALYSIS_DIGEST


def _facts_of(data: bytes) -> FileFacts:
    return FileFacts(
        holder=_holder(data[:HEAD_BYTES]),
        includes=[m.decode("utf-8", "replace") for m in _INCLUDE.findall(data)],
        functions=[f.name for f in extract_functions(data) if f.name],
        versions=_versions(data))


def read_tree(root: Path, known: Callable[[str], bool] = lambda rel: False,
              store: Optional[AnalysisStore] = None) -> Tree:
    """What discovery needs from every source file: provenance, includes, function
    names. Of a file *known* accounts for, only the head is read, for its holder.
    With a *store* that has an on-disk cache, a file seen before (same content) is
    not read or tokenised again."""
    root = Path(root)
    cached: Dict[str, str] = {}
    fresh: List[Tuple[str, str]] = []
    if store is not None and store.root == root:
        rels = [r for r in store.index.rels
                if os.path.splitext(r)[1].lower() in SOURCE_EXTS and not known(r)]
        shas = store.shas(rels)
        cached = {r: sha for r, sha in shas.items()}
        hits = store.facts_lookup(sorted(set(shas.values())), FACTS_VERSION)
    else:
        store, hits = None, {}
    files: Dict[str, FileFacts] = {}
    other: Dict[str, List[str]] = defaultdict(list)
    subdirs: Dict[str, List[str]] = {}
    by_name: Dict[str, List[str]] = defaultdict(list)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        subdirs[rel_dir] = list(dirnames) + (
            [".github"] if os.path.isdir(os.path.join(dirpath, ".github")) else [])
        for fn in sorted(filenames):
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            if os.path.splitext(fn)[1].lower() not in SOURCE_EXTS:
                other[rel_dir].append(fn)
                continue
            by_name[fn.lower()].append(rel)
            if known(rel):
                try:
                    with open(os.path.join(dirpath, fn), "rb") as fh:
                        files[rel] = FileFacts(holder=_holder(fh.read(HEAD_BYTES)))
                except OSError:
                    pass
                continue
            sha = cached.get(rel)
            if sha is not None and sha in hits:
                got = json.loads(hits[sha])
                files[rel] = FileFacts(got["holder"], got["includes"], got["functions"],
                                       [(p, v) for p, v in got["versions"]])
                continue
            try:
                data = (Path(dirpath) / fn).read_bytes()
            except OSError:
                continue
            if len(data) > MAX_BYTES:
                continue
            files[rel] = facts = _facts_of(data)
            if sha is not None:
                fresh.append((sha, json.dumps(asdict(facts))))
                hits[sha] = fresh[-1][1]        # the same content again in this tree
    if store is not None:
        store.facts_store(fresh, FACTS_VERSION)
    return Tree(root, files, dict(other), subdirs, _submodules(root), dict(by_name))


def _submodules(root: Path) -> Set[str]:
    p = root / ".gitmodules"
    if not p.is_file():
        return set()
    try:
        text = p.read_text("utf-8", "replace")
    except OSError:
        return set()
    return {m.strip().strip("/") for m in re.findall(r"^\s*path\s*=\s*(.+?)\s*$", text, re.M)}


def _under(path: str, d: str) -> bool:
    return d == "" or path == d or path.startswith(d + "/")


# words in component names that say nothing about which library it is
STOP_TOKENS = {"generic", "sdk", "core", "lib", "libs", "library", "driver", "drivers", "hal", "kernel", "the",
               "iot", "embedded", "components", "component", "common", "src", "platform", "services",
               "middleware", "stack", "device", "firmware", "api"}


def _tokens(text: str) -> Set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3 and t not in STOP_TOKENS}


def accounted(tree: Tree, known: Iterable[Tuple[str, List[str], str]]) -> Set[str]:
    """Files the known components account for, from (directory, files, name)."""
    test = _accounts(known)
    return {p for p in tree.files if test(p)}


def _accounts(known: Iterable[Tuple[str, List[str], str]]) -> Callable[[str], bool]:
    """Whether a file is a known component's: one of its files when it has some,
    else in its directory. A component placed at the root of the scan (a vendor
    SDK declared for the whole tree) accounts for no file in particular."""
    files: Set[str] = set()
    dirs: List[str] = []
    for directory, listed, _ in known:
        d = directory.strip("/")
        if listed:
            files.update(listed)
        elif d and d != ".":
            dirs.append(d + "/")
    prefixes = tuple(dirs)
    return lambda rel: rel in files or rel.startswith(prefixes)


class Discoverer:
    def __init__(self, tree: Tree, known: Iterable[Tuple[str, List[str], str]] = ()):
        self.t = tree
        self.known = list(known)
        self.known_files = accounted(tree, self.known)
        self.residual = [p for p in tree.files if p not in self.known_files]
        self.holders = Counter(tree.files[p].holder for p in self.residual if tree.files[p].holder)
        # the project's own holder: that of its main() (of the main()s, the one that
        # includes most of the tree; examples and tests in vendored code have theirs)
        # and of its root licence
        entry = [p for p in self.residual if ENTRY_POINTS & set(tree.files[p].functions)]
        self.home: Set[str] = set()
        if entry:
            main = max(entry, key=lambda p: (sum(1 for i in tree.files[p].includes
                                                  if tree.by_name.get(i.rsplit("/", 1)[-1].lower())),
                                             -p.count("/")))
            main_holder = tree.files[main].holder
            if main_holder:
                self.home.add(main_holder)
        for fn in tree.other.get("", []):
            if LICENSE_FILE.match(fn):
                try:
                    h = _holder((tree.root / fn).read_bytes()[:HEAD_BYTES])
                except OSError:
                    h = None
                if h and not h.startswith("license:"):
                    self.home.add(h)
        self.prefix_files: Counter = Counter()
        for p in self.residual:
            for x in {_prefix(f) for f in tree.files[p].functions}:
                if x:
                    self.prefix_files[x] += 1
        self.subtree: Dict[str, List[str]] = defaultdict(list)
        for p in tree.files:
            parts = p.split("/")[:-1]
            self.subtree[""].append(p)
            for i in range(1, len(parts) + 1):
                self.subtree["/".join(parts[:i])].append(p)

    # -- per file-set evidence -------------------------------------------------------
    def _resolve(self, inc: str) -> List[str]:
        hits = self.t.by_name.get(inc.rsplit("/", 1)[-1].lower(), [])
        if "/" in inc:
            tail = "/" + inc.lower()
            hits = [h for h in hits if ("/" + h.lower()).endswith(tail)] or hits
        return hits

    def evidence(self, files: List[str], context: Optional[Set[str]] = None) -> Score:
        """Evidence that *files* are someone else's code; includes resolving into
        *context* (default: the files themselves) count as internal."""
        sig: Dict[str, float] = {}
        inside = set(files) | (context or set())
        res = [p for p in files if p not in self.known_files]
        # namespace: the dominant function prefix, and how much of it is found outside
        names = Counter(x for p in res for x in {_prefix(f) for f in self.t.files[p].functions} if x)
        n_funcs = sum(len(self.t.files[p].functions) for p in res)
        prefix = None
        if names and n_funcs >= MIN_FUNCTIONS:
            prefix, n = _top(names)
            files_with = sum(1 for p in res if self.t.files[p].functions)
            share = n / max(files_with, 1)
            out = self.prefix_files[prefix] - n
            ns = min(1.0, share) * max(0.0, 1.0 - out / max(n, 1))
            if ns > 0:
                sig["namespace"] = round(SCORE["namespace"] * ns, 2)
        # provenance: the dominant header holder, and how much of it is found outside
        own = Counter(self.t.files[p].holder for p in res if self.t.files[p].holder)
        holder = None
        if own and res:
            holder = _top(own)[0]
            # files whose holder is (nearly) only found here -- a library's files often
            # name several holders -- or found elsewhere too, but on code under a prefix
            # only used here (two libraries by one author side by side)
            local = sum(n for h, n in own.items() if h not in self.home and (
                self.holders[h] - n <= 0.1 * n or sig.get("namespace", 0) >= 0.8 * SCORE["namespace"]))
            foreign = local / len(res)
            if foreign > 0:
                sig["foreign_holder"] = round(SCORE["foreign_holder"] * foreign, 2)
        # its own version macro: in full when it names the code it sits in, else half
        # (another library's version header dropped among these files)
        vers = [p for f in res for p, v in self.t.files[f].versions if p.split("_")[0] not in OWN_VERSION]
        if vers:
            dirs = {f.rsplit("/", 1)[0] for f in files}
            where = files[0].rsplit("/", 1)[0] if len(dirs) == 1 else os.path.commonpath(files)
            here = {prefix} | set(re.split(r"[^a-z0-9]+", where.lower()))
            mine = any(p.split("_")[0] in here or (prefix and p.startswith(prefix)) for p in vers)
            sig["version"] = SCORE["version"] * (1.0 if mine else 0.5)
        # dependency direction: project headers it includes
        outward: Set[str] = set()
        internal = 0
        for p in res:
            for inc in self.t.files[p].includes:
                hits = self._resolve(inc)
                if not hits:
                    continue
                if any(h in inside for h in hits):
                    internal += 1
                elif (not any(h in self.known_files for h in hits)
                      and not CONFIG_HEADER.search(inc.rsplit("/", 1)[-1])):
                    outward.add(inc.rsplit("/", 1)[-1])
        if len(outward) >= 3:
            sig["includes_project"] = SCORE["includes_project"]
        elif len(outward) == 2:
            sig["includes_project"] = SCORE["includes_project"] / 4
        elif internal and not outward:
            sig["self_contained"] = SCORE["self_contained"]
        elif internal:
            sig["self_contained"] = SCORE["self_contained"] / 2
        return Score(round(sum(sig.values()), 2), sig, holder, prefix, sorted(outward))

    def dir_score(self, d: str) -> Score:
        s = self.evidence(self.subtree.get(d, []))
        names = {n.lower() for n in self.t.other.get(d, [])}
        kids = {k.lower() for k in self.t.subdirs.get(d, [])}
        base = d.rsplit("/", 1)[-1].lower()
        parent = d.rsplit("/", 1)[0].rsplit("/", 1)[-1].lower() if "/" in d else ""
        sig = dict(s.signals)
        if d in self.t.submodules:
            sig["submodule"] = SCORE["submodule"]
        if names & MANIFESTS or self._cmake_project(d):
            sig["manifest"] = SCORE["manifest"]
        if any(LICENSE_FILE.match(n) for n in names):
            sig["license"] = SCORE["license"]
        if any(README_FILE.match(n) for n in names):
            sig["readme"] = SCORE["readme"]
        if (names | kids) & REPO_ARTIFACTS:
            sig["repo"] = SCORE["repo"]
        if len(kids & REPO_SUBDIRS) >= 1 and kids - REPO_SUBDIRS:
            sig["repo_subdirs"] = SCORE["repo_subdirs"]
        if parent in CONTAINERS:
            sig["container_child"] = SCORE["container_child"]
        if base in CONTAINERS:
            sig["container"] = SCORE["container"]
        s.signals = sig
        s.total = round(sum(sig.values()), 2)
        return s

    def _cmake_project(self, d: str) -> bool:
        if "CMakeLists.txt" not in self.t.other.get(d, []):
            return False
        try:
            return bool(_CMAKE_PROJECT.search((self.t.root / d / "CMakeLists.txt").read_bytes()[:64 << 10]))
        except OSError:
            return False

    def _marked(self, d: str) -> bool:
        """Its own package: a licence file, a package manifest or a submodule entry."""
        names = {n.lower() for n in self.t.other.get(d, [])}
        return d in self.t.submodules or bool(names & PACKAGES) or any(LICENSE_FILE.match(n) for n in names)

    # -- selection -------------------------------------------------------------------
    def run(self) -> List[Unknown]:
        return self._select("")

    def _select(self, d: str) -> List[Unknown]:
        """Candidates in d's subtree, children first: d itself replaces what was found
        below it when it passes and either carries its own markers or adds nothing
        beside one child's candidate (lwip/src under lwip/); otherwise (Core/ holding
        Src/, Inc/ and a library) the candidates below stand."""
        files = self.subtree.get(d, [])
        if not files or all(p in self.known_files for p in files):
            return []
        kids = [f"{d}/{k}" if d else k for k in self.t.subdirs.get(d, [])]
        kids = [k for k in kids if k in self.subtree]
        below: List[Unknown] = []
        for k in kids:
            below += self._select(k)
        loose = self._loose(d)
        if not d:
            return below + loose
        s = self.dir_score(d)
        res = [p for p in files if p not in self.known_files]
        n_funcs = sum(len(self.t.files[p].functions) for p in res)
        own_markers = bool({"license", "manifest", "submodule", "repo"} & set(s.signals))
        marked_kids = [k for k in kids if self._marked(k)]
        if (s.total < THRESHOLD or "container" in s.signals or len(marked_kids) >= 2
                or n_funcs < (1 if own_markers else MIN_FUNCTIONS)):
            return below + loose
        known_share = 1 - len(res) / len(files)
        # a package of its own (licence, manifest) that bundles a library of another
        # name -- kuba/zip around miniz -- is not that library: what is left is reported
        bundles = own_markers and known_share < 0.5 and not self._known_root(d, s)
        if (known_share >= 0.3 or self._known_root(d, s)) and not bundles:
            # mostly a component already found, a level deeper; what was found below
            # it under other holders is not that component
            kh = {self.t.files[p].holder for p in files if p in self.known_files} - {None}
            return [c for c in below + loose if c.holder and c.holder not in kh and "namespace" in c.signals]
        mine = [self._candidate("directory", d, res, s)]
        if own_markers or not below:
            return mine
        covered = {p for c in below for p in c.files}
        rest = [p for p in res if p not in covered]
        if len(rest) <= 0.1 * len(res):
            return below     # what is below explains d (a neutral parent holding one library)
        # d replaces the candidates below when the rest of it looks foreign too (a
        # plugin of the library found on its own), not when the rest is first-party
        r = self.evidence(rest, set(res))
        if r.total >= THRESHOLD - 1 and "foreign_holder" in r.signals and "includes_project" not in r.signals:
            return mine
        # or the rest carries only the holders of what was found below: pieces of one
        # library found on their own prefixes (lwrb/src beside lwrb/include)
        rest_holders = {self.t.files[p].holder for p in rest} - {None}
        below_holders = {c.holder for c in below} - {None}
        if rest_holders and rest_holders <= below_holders - self.home:
            return mine
        return below

    def _known_root(self, d: str, s: Score) -> bool:
        """d holds a component found further down that it is named after (sfud/
        around sfud/sfud/src)."""
        inside = [name for directory, _, name in self.known
                  if directory.strip("/") not in ("", ".") and _under(directory.strip("/"), d)]
        if not inside:
            return False
        words = [w for w in re.split(r"[^a-z0-9]+", f"{d} {self._hints(d, [], s)[0] or ''}".lower()) if w]
        text = " ".join(words + ["".join(words)])
        return any(t in text for name in inside for t in _tokens(name))

    def _loose(self, d: str) -> List[Unknown]:
        """Files directly in a first-party directory that came from elsewhere."""
        loose = [p for p in self.subtree.get(d, [])
                 if (p.rsplit("/", 1)[0] == d if "/" in p else d == "") and p not in self.known_files]
        if not loose:
            return []
        parent = {p: p for p in loose}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            parent[find(a)] = find(b)

        # by file stem, then files one includes the other of, then a shared holder
        stems: Dict[str, List[str]] = defaultdict(list)
        for p in loose:
            stems[os.path.splitext(p.rsplit("/", 1)[-1])[0].lower()].append(p)
        for group in stems.values():
            for p in group[1:]:
                union(p, group[0])
        names = {p.rsplit("/", 1)[-1].lower(): p for p in loose}
        for p in loose:
            hp = self.t.files[p].holder
            if not hp or self.holders[hp] > sum(1 for x in loose if self.t.files[x].holder == hp):
                continue       # only a file with a holder local to these files pulls in what it includes
            for inc in self.t.files[p].includes:
                q = names.get(inc.rsplit("/", 1)[-1].lower())
                if q and q != p and self.t.files[q].holder in (None, hp):
                    union(p, q)
        # files sharing a function prefix no other file in the tree uses (agile_modbus_*)
        by_prefix: Dict[str, List[str]] = defaultdict(list)
        for p in loose:
            top = Counter(x for x in (_prefix(f) for f in self.t.files[p].functions) if x)
            if top:
                by_prefix[_top(top)[0]].append(p)
        for pre, group in by_prefix.items():
            if len(group) >= 2 and self.prefix_files[pre] == len(group):
                for p in group[1:]:
                    union(p, group[0])
        by_holder: Dict[str, List[str]] = defaultdict(list)
        for p in loose:
            h = self.t.files[p].holder
            if h:
                by_holder[h].append(p)
        for h, group in by_holder.items():
            if self.holders[h] == len(group):   # a holder found only here
                for p in group[1:]:
                    union(p, group[0])
        groups: Dict[str, List[str]] = defaultdict(list)
        for p in loose:
            groups[find(p)].append(p)
        out = []
        for g in groups.values():
            if len(g) == len(loose) and d:
                continue     # the whole directory: already scored as a directory
            if sum(len(self.t.files[p].functions) for p in g) < MIN_FUNCTIONS:
                continue
            s = self.evidence(sorted(g))
            if s.total >= THRESHOLD and "foreign_holder" in s.signals:
                out.append(self._candidate("files", d, sorted(g), s))
        return out

    def _candidate(self, kind: str, d: str, files: List[str], s: Score) -> Unknown:
        name, version = self._hints(d if kind == "directory" else None, files, s)
        return Unknown(kind=kind, directory=d or ".", files=files,
                       functions=sum(len(self.t.files[p].functions) for p in files),
                       score=s.total, signals=s.signals, holder=s.holder, prefix=s.prefix,
                       includes_project=s.outward, name_hint=name, version_hint=version)

    def _hints(self, d: Optional[str], files: List[str], s: Score) -> Tuple[Optional[str], Optional[str]]:
        name = version = None
        if d is not None:
            # a package's own manifest names it better than its build file
            for fn in sorted(self.t.other.get(d, []), key=lambda n: (n.lower() not in PACKAGES, n)):
                low = fn.lower()
                if low != "cmakelists.txt" and low not in MANIFESTS:
                    continue
                try:
                    data = (self.t.root / d / fn).read_bytes()[:64 << 10]
                except OSError:
                    continue
                if low == "cmakelists.txt":
                    m = _CMAKE_PROJECT.search(data)
                    if m:
                        name = name or m.group(1).decode()
                        version = version or (m.group(2).decode() if m.group(2) else None)
                elif low in ("configure.ac", "configure.in"):
                    m = _AC_INIT.search(data)
                    if m:
                        name, version = name or m.group(1).decode(), version or m.group(2).decode()
                else:
                    m = _NAME_FIELD.search(data)
                    if m and not name:
                        name = m.group(1).decode().rsplit("/", 1)[-1]
                    m = _VERSION_FIELD.search(data)
                    if m and not version:
                        version = m.group(1).decode()
        vers = [(p, v) for f in files for p, v in self.t.files[f].versions]
        version = version or pick_version(vers, Counter({s.prefix: 1}) if s.prefix else Counter())
        # the name the vendor gave the directory is usually the library's
        parts = [re.sub(r"[-_.]v?\d+(?:[._]\d+)*$", "", x) for x in (d or "").split("/") if x]
        while parts and parts[-1].lower() in GENERIC_DIRS:
            parts.pop()
        base = parts[-1] if parts else ""
        if not name and base and base.lower() not in CONTAINERS:
            name = base
        if not name and d is None and files:   # loose files: the largest file's stem
            big = max(files, key=lambda f: (len(self.t.files[f].functions), f))
            name = os.path.splitext(big.rsplit("/", 1)[-1])[0]
        own = [p for p, _ in vers if p.split("_")[0] not in OWN_VERSION]
        if not name and own:
            name = _top(Counter(own))[0]
        if not name and s.prefix:
            name = s.prefix
        return name, version


def pick_version(vers: List[Tuple[str, str]], prefixes: Counter) -> Optional[str]:
    """Of several version macros, one named like the code's functions (FASTLZ_VERSION
    among fastlz_*), then the most common; never one a project defines for itself."""
    vers = [(x, v) for x, v in vers if x.split("_")[0] not in OWN_VERSION]
    if not vers:
        return None
    count = Counter(vers)
    top = _top(prefixes)[0] if prefixes else None
    return max(count, key=lambda xv: (bool(top) and xv[0].split("_")[0] == top, count[xv]))[1]


def discover_unknown(root: Path, known: Iterable[Tuple[str, List[str], str]],
                     possible: Iterable[Tuple[str, List[str], str]] = (),
                     store: Optional[AnalysisStore] = None) -> List[Unknown]:
    """Candidate third-party code in *root* outside the *known* components, given as
    (directory, files, name). *possible* (directory, files, rule id) are weak
    matches, recorded on the candidates that hold their code."""
    known = list(known)
    tree = read_tree(root, _accounts(known), store)
    found = Discoverer(tree, known).run()
    for d, files, rule_id in possible:
        theirs = set(files) or {p for p in tree.files if _under(p, d.strip("/")) and d.strip("/") not in ("", ".")}
        for c in found:
            if theirs and len(theirs & set(c.files)) >= 0.5 * len(theirs) and rule_id not in c.resembles:
                c.resembles.append(rule_id)
    found.sort(key=lambda c: (-c.score, c.directory, c.files[:1]))
    return found
