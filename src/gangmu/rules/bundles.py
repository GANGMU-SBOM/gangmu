"""Which rules carry another rule's code, read off the signatures.

A rule built from a whole upstream tree records the libraries that project bundles
(dropbear's libtomcrypt, picotool's littlefs, tcl's zlib). Segmentation then has to
decide whose those functions are. It keeps them the bundled library's when the copy
is a small part of the host (``match.engine.BUNDLE_HOST_SHARE``); where the bundled
library is a large part of a small host, it cannot tell that from a library split out
of another (Mbed Crypto from Mbed TLS), so the functions are nobody's and the bundled
library loses its identity. What fixes that is data: the host's rule excludes the
directory it keeps the copy in, as ``identity.exclude``, and its signature is rebuilt.

``find_bundles`` lists the cases from the signatures alone; ``locate`` finds the
directories in a checkout of the host.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from itertools import chain
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..match.engine import (BUNDLE_HOST_SHARE, BUNDLE_MAX_OWNERS, BUNDLED_MIN_FUNCTIONS,
                            BUNDLED_MIN_OF_LARGEST, BUNDLED_SHARE, _release_counts,
                            _release_sizes, _repeated)


@dataclass
class Bundle:
    host: str
    bundled: str
    release: str             # the bundled rule's release that is (nearly) whole in the host
    inside: int              # of its functions, how many the host's signature holds
    size: int
    host_share: float        # the shared functions as a share of the host's signature
    mutual: bool = False     # each holds a whole release of the other: lineage, not a copy

    @property
    def kept(self) -> bool:
        """Does segmentation already keep the shared code the bundled library's?"""
        return self.host_share <= BUNDLE_HOST_SHARE

    @property
    def state(self) -> str:
        """kept; lineage (a fork or split, whose shared code rightly is nobody's); or lost
        (a copy too large a part of its host, which an ``identity.exclude`` fixes)."""
        return "kept" if self.kept else ("lineage" if self.mutual else "lost")


def find_bundles(rules) -> List[Bundle]:
    """Every (host, bundled) pair where the host's signature holds a whole bundled release."""
    sigs: Dict[str, Tuple[str, Any]] = {}       # sidecar digest -> (rule id, signature)
    family: Dict[str, Optional[str]] = {}
    for rule in rules:
        if rule.functions is None or rule.functions.sha256 in sigs:
            continue
        try:
            sigs[rule.functions.sha256] = (rule.id, rule.functions.load())
        except Exception:                           # noqa: BLE001
            continue
        family[rule.id] = rule.functions.family
    entries = list(sigs.values())
    shared_any = _repeated(chain.from_iterable(sig.hashes for _, sig in entries))
    owners: Dict[int, List[int]] = {}
    for i, (_, sig) in enumerate(entries):
        for h in shared_any.intersection(sig.hashes):
            owners.setdefault(h, []).append(i)
    common: Dict[Tuple[int, int], List[int]] = {}
    for h, held in owners.items():
        if 1 < len(held) <= BUNDLE_MAX_OWNERS:
            for a in held:
                for b in held:
                    if a != b:
                        common.setdefault((a, b), []).append(h)
    out: List[Bundle] = []
    for (a, b), shared in common.items():
        if len(shared) < BUNDLED_SHARE * BUNDLED_MIN_FUNCTIONS:
            continue
        (host, hsig), (bundled, bsig) = entries[a], entries[b]
        if family[host] and family[host] == family[bundled]:
            continue
        sizes = _release_sizes(bsig)
        floor = max(BUNDLED_MIN_FUNCTIONS, BUNDLED_MIN_OF_LARGEST * max(sizes, default=0))
        inside = _release_counts(bsig, shared)
        best = max((v for v, size in enumerate(sizes)
                    if size >= floor and inside[v] >= BUNDLED_SHARE * size),
                   key=lambda v: (inside[v] / sizes[v], v), default=None)
        if best is None:
            continue
        out.append(Bundle(host, bundled, bsig.versions[best], inside[best], sizes[best],
                          len(shared) / len(hsig.hash_set)))
    pairs = {(b.host, b.bundled) for b in out}
    out = [replace(b, mutual=(b.bundled, b.host) in pairs) for b in out]
    order = {"lost": 0, "lineage": 1, "kept": 2}
    out.sort(key=lambda x: (order[x.state], x.host, x.bundled))
    return out


@dataclass
class Copy:
    directory: str
    rule_id: str
    version: Optional[str]
    # None: the whole directory is the copy. Otherwise the copy shares the directory
    # with the host's own code (swupdate keeps FatFs's ff.c beside its own btrfs.c),
    # and these are its files.
    files: Optional[List[str]] = None


SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".inc")
HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".inc")
# A file is the bundled library's when this share of its functions is in its signature.
FILE_SHARE = 0.5


def locate(tree: Path, rulebase, host: str) -> List[Copy]:
    """Every other component a scan finds in *tree*, and what of it is the copy."""
    from ..scan import scan

    tree = Path(tree)
    sidecar = next((r.functions.sha256 for r in rulebase.rules
                    if r.id == host and r.functions is not None), None)
    others = [r for r in rulebase.rules
              if r.id != host and not (sidecar and r.functions is not None
                                       and r.functions.sha256 == sidecar)]
    result = scan(tree, replace(rulebase, rules=others), None)
    by_id = {r.id: r for r in others}
    out = []
    for f in result.findings:
        if f.directory in (".", ""):
            continue
        rule = by_id.get(f.rule_id)
        files = _own_files(tree / f.directory, rule)
        if files is None:
            out.append(Copy(_widen(f.directory, rule), f.rule_id, f.version))
        else:
            out.append(Copy(f.directory, f.rule_id, f.version,
                            [f"{f.directory}/{name}" for name in files]))
    out.sort(key=lambda c: (c.directory, c.rule_id))
    return out


def _own_files(directory: Path, rule) -> Optional[List[str]]:
    """None when the files directly in *directory* are all the bundled library's;
    otherwise the names of those that are: by their functions, or for a file without
    any (a configuration header), by the rule naming it as an anchor or marker."""
    from ..functions import extract_functions
    if rule is None or rule.functions is None:
        return None
    try:
        known = rule.functions.load().hash_set
    except Exception:                                   # noqa: BLE001
        return None
    named = {Path(a.path).name for a in rule.anchors} | {Path(m).name for m in rule.marker_files}
    theirs, mixed = [], False
    for path in sorted(p for p in directory.iterdir()
                       if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES):
        try:
            hashes = {fn.hash for fn in extract_functions(path.read_bytes())}
        except OSError:
            continue
        if hashes:
            if len(hashes & known) >= FILE_SHARE * len(hashes):
                theirs.append(path.name)
            elif path.suffix.lower() not in HEADER_SUFFIXES:
                # A header's inline functions (lodepng.h's C++ wrappers) may be ones the
                # signature does not record; only a source file says the host's own
                # code is here.
                mixed = True
        elif path.name in named:
            theirs.append(path.name)
    return theirs if mixed else None


def _widen(directory: str, rule) -> str:
    """The outermost directory holding the copy: a finding sits at the component's
    root (``libtomcrypt/src``), and the copy's demos and tests next to it
    (``libtomcrypt/testprof``) are its code too. Widened to the outermost ancestor
    the rule's own path globs name."""
    from ..core.globbing import matches_suffix
    if rule is None or not rule.path_globs:
        return directory
    parts = directory.split("/")
    for n in range(1, len(parts)):
        ancestor = "/".join(parts[:n])
        if matches_suffix(ancestor, rule.path_globs):
            return ancestor
    return directory


def exclude_globs(found: Sequence[Copy], subdir: str = "") -> List[str]:
    """The ``identity.exclude`` entries for *found*, relative to the rule's own root."""
    prefix = subdir.strip("/") + "/" if subdir and subdir not in (".", "") else ""

    def rel(path: str) -> str:
        return path[len(prefix):] if prefix and path.startswith(prefix) else path

    dirs: List[str] = []
    for copy in sorted((c for c in found if c.files is None), key=lambda c: c.directory):
        d = rel(copy.directory)
        if not any(d == s or d.startswith(s + "/") for s in dirs):   # already inside one
            dirs.append(d)
    globs = [f"{d}/**" for d in dirs]
    for copy in found:
        for name in copy.files or ():
            r = rel(name)
            if r not in globs and not any(r.startswith(d + "/") for d in dirs):
                globs.append(r)
    return globs
