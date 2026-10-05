"""Directory-level fingerprints.

A component is a directory, not a file, so identity is decided over the union of
the fingerprints of the files a rule says to look at. Taking the union (rather
than, say, averaging per-file scores) is what makes similarity degrade
gracefully: a vendor who adds ten files of their own to a hundred upstream ones
loses roughly ten percent, not a category.

Performance shape
-----------------
Two passes, and the second one usually does not run.

1. **Hashes.** Read each file once, sha256 it, and fold the ``(path, digest)``
   pairs into one ``fileset_sha256``. This is I/O plus a fast hash.
2. **Fingerprints.** Tokenise and winnow. An order of magnitude more expensive,
   so it is lazy: a vendored copy that is byte-identical to the release a rule
   records never reaches this pass at all, and in practice most of them are.

A sketch computed in pass 2 is cached on disk under its ``fileset_sha256``, so a
re-scan of an unchanged tree skips pass 2 as well.
"""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Set, Tuple

from .fingerprint import (ALGO, DEFAULT_K, DEFAULT_SKETCH, DEFAULT_WINDOW, Signature,
                          kgram_hashes, signature_from_fingerprints, winnow)
from .functions import extract_functions
from .globbing import matches as _glob_matches
from .normalize import tokenize

if TYPE_CHECKING:                   # pragma: no cover
    from .analysis import AnalysisStore

DEFAULT_INCLUDE: Tuple[str, ...] = ("**/*.c", "**/*.h", "**/*.cc", "**/*.cpp", "**/*.hpp")
DEFAULT_EXCLUDE: Tuple[str, ...] = (
    "**/test/**", "**/tests/**", "**/doc/**", "**/docs/**",
    "**/example/**", "**/examples/**", "**/contrib/**", "**/.git/**",
)
MAX_FILE_BYTES = 4 * 1024 * 1024
PARALLEL_FILE_THRESHOLD = 64        # below this, process startup costs more than it saves


def _matches(rel: str, patterns: Sequence[str]) -> bool:
    return _glob_matches(rel, patterns)


def iter_source_files(root: Path, include: Sequence[str] = DEFAULT_INCLUDE,
                      exclude: Sequence[str] = DEFAULT_EXCLUDE) -> List[Path]:
    """Deterministically ordered list of files a rule should look at."""
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in {".git", "__pycache__"})
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if not _matches(rel, include) or _matches(rel, exclude):
                continue
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            found.append(path)
    return found


def _analyse_one(args) -> Tuple[str, List[int], List[int], List[int]]:
    """Tokenise once, produce whatever was asked for. Top-level for workers.

    Functions and winnowed fingerprints both start from the same token stream,
    so computing them together costs one tokenise instead of two. Functions
    alone are about half the cost of winnowing, so a rule base that has moved to
    function signatures gets faster, not slower.
    """
    path, k, window, want_functions, want_fingerprints = args
    try:
        data = Path(path).read_bytes()
    except OSError:
        return path, [], [], []
    tokens = tokenize(data)
    functions: List[int] = []
    abstract: List[int] = []
    if want_functions:
        for f in extract_functions(data, tokens):
            functions.append(f.hash)
            if f.abstract_hash is not None:
                abstract.append(f.abstract_hash)
    fingerprints = list(winnow(kgram_hashes(tokens, k), window)) if want_fingerprints else []
    return path, functions, abstract, fingerprints


@dataclass
class DirectoryPrint:
    root: Path
    files: List[Path] = field(default_factory=list)
    file_hashes: Dict[str, str] = field(default_factory=dict)
    k: int = DEFAULT_K
    window: int = DEFAULT_WINDOW
    jobs: int = 1
    cache: Optional["SketchCache"] = None
    # When a scan-wide AnalysisStore is attached, pass 2 is answered from its
    # per-file results instead of tokenising here. ``rels`` are the files'
    # paths relative to the store's root, aligned with ``files``.
    store: Optional["AnalysisStore"] = None
    rels: List[str] = field(default_factory=list)

    _fingerprints: Optional[Set[int]] = field(default=None, repr=False)
    _functions: Optional[Set[int]] = field(default=None, repr=False)
    _abstract: Optional[Set[int]] = field(default=None, repr=False)
    _fileset: Optional[str] = field(default=None, repr=False)
    _sketches: Dict[Tuple[int, int, int], Signature] = field(default_factory=dict,
                                                             repr=False)

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def fileset_sha256(self) -> str:
        """Hash over the sorted (relpath, sha256) pairs: an exact-copy check."""
        if self._fileset is None:
            h = hashlib.sha256()
            for rel in sorted(self.file_hashes):
                h.update(rel.encode())
                h.update(b"\0")
                h.update(self.file_hashes[rel].encode())
                h.update(b"\n")
            self._fileset = h.hexdigest()
        return self._fileset

    @property
    def fingerprints(self) -> Set[int]:
        """Pass 2, winnowed k-grams. Lazy -- see the module docstring."""
        if self._fingerprints is None:
            self._analyse(functions=self._functions is None, fingerprints=True)
        return self._fingerprints or set()

    @property
    def functions(self) -> Set[int]:
        """Pass 2, function body hashes. Preferred: cheaper and more precise."""
        if self._functions is None:
            self._analyse(functions=True, fingerprints=False)
        return self._functions or set()

    @property
    def abstract_functions(self) -> Set[int]:
        """The same bodies with identifiers collapsed, for renamed copies."""
        if self._abstract is None:
            self._analyse(functions=True, fingerprints=False)
        return self._abstract or set()

    def _analyse(self, functions: bool, fingerprints: bool) -> None:
        if self.store is not None and functions and not fingerprints:
            self._from_store()
            return
        want_fn = functions and self._functions is None
        want_fp = fingerprints and self._fingerprints is None
        if not (want_fn or want_fp):
            return
        fn_out: Set[int] = set()
        ab_out: Set[int] = set()
        fp_out: Set[int] = set()
        payload = [(str(p), self.k, self.window, want_fn, want_fp)
                   for p in self.files]
        done = False
        if self.jobs > 1 and len(self.files) >= PARALLEL_FILE_THRESHOLD:
            chunk = max(1, len(payload) // (self.jobs * 4))
            try:
                with ProcessPoolExecutor(max_workers=self.jobs) as pool:
                    for _, fns, abs_, fps in pool.map(_analyse_one, payload,
                                                       chunksize=chunk):
                        fn_out.update(fns)
                        ab_out.update(abs_)
                        fp_out.update(fps)
                done = True
            except (OSError, RuntimeError, ImportError):
                fn_out.clear(); ab_out.clear(); fp_out.clear()
        if not done:
            for args in payload:
                _, fns, abs_, fps = _analyse_one(args)
                fn_out.update(fns)
                ab_out.update(abs_)
                fp_out.update(fps)
        if want_fn:
            self._functions = fn_out
            self._abstract = ab_out
        if want_fp:
            self._fingerprints = fp_out

    def _from_store(self) -> None:
        store = self.store
        assert store is not None
        store.ensure(self.rels)
        fn_out: Set[int] = set()
        ab_out: Set[int] = set()
        for rel in self.rels:
            a = store.analysis(rel)
            fn_out.update(a.functions)
            ab_out.update(a.abstract)
        self._functions = fn_out
        self._abstract = ab_out

    def _store_sketch(self, size: int) -> Optional[Signature]:
        """Exact bottom-k sketch from per-file bottoms; see analysis.py."""
        store = self.store
        if store is None or size > store.cap or (self.k, self.window) != (
                store.k, store.window):
            return None
        store.ensure(self.rels)
        union: Set[int] = set()
        for rel in self.rels:
            union.update(store.analysis(rel).bottom)
        return signature_from_fingerprints(union, self.k, self.window, size)

    def signature(self, k: Optional[int] = None, window: Optional[int] = None,
                  size: int = DEFAULT_SKETCH) -> Signature:
        k = self.k if k is None else k
        window = self.window if window is None else window
        memo = self._sketches.get((k, window, size))
        if memo is not None:
            return memo
        if (k, window) == (self.k, self.window):
            sig = self._store_sketch(size)
            if sig is not None:
                self._sketches[(k, window, size)] = sig
                return sig
        if self.cache is not None and (k, window) == (self.k, self.window):
            cached = self.cache.get(self.fileset_sha256, k, window, size)
            if cached is not None:
                return cached
        sig = signature_from_fingerprints(self.fingerprints, k, window, size)
        if self.cache is not None and (k, window) == (self.k, self.window):
            self.cache.put(self.fileset_sha256, k, window, size, sig)
        self._sketches[(k, window, size)] = sig
        return sig


class SketchCache:
    """Disk cache of sketches, keyed by the content of the directory itself.

    Keyed by ``fileset_sha256``, so it is correct by construction: a tree whose
    files all hash the same cannot have a different sketch. Nothing is
    invalidated by time, and a corrupt or unreadable entry is simply ignored.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def _path(self, fileset: str, k: int, window: int, size: int) -> Path:
        name = f"{fileset}-{ALGO}-{k}-{window}-{size}.hex"
        return self.directory / fileset[:2] / name

    def get(self, fileset: str, k: int, window: int, size: int) -> Optional[Signature]:
        path = self._path(fileset, k, window, size)
        try:
            return Signature.from_hex(path.read_text(), k, window, size)
        except (OSError, ValueError):
            return None

    def put(self, fileset: str, k: int, window: int, size: int,
            sig: Signature) -> None:
        path = self._path(fileset, k, window, size)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(sig.to_hex())
            tmp.replace(path)
        except OSError:
            pass          # a cache that cannot be written is not an error


def _hash_one(path_str: str) -> Tuple[str, str]:
    h = hashlib.sha256()
    try:
        with open(path_str, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return path_str, ""
    return path_str, h.hexdigest()


def print_directory(root: Path, include: Sequence[str] = DEFAULT_INCLUDE,
                    exclude: Sequence[str] = DEFAULT_EXCLUDE,
                    k: int = DEFAULT_K, window: int = DEFAULT_WINDOW,
                    jobs: int = 1,
                    cache: Optional[SketchCache] = None) -> DirectoryPrint:
    """Pass 1 only. Fingerprints are computed on first access, if ever."""
    root = Path(root)
    files = iter_source_files(root, include, exclude)
    out = DirectoryPrint(root=root, files=files, k=k, window=window,
                         jobs=jobs, cache=cache)
    if jobs > 1 and len(files) >= PARALLEL_FILE_THRESHOLD:
        try:
            with ProcessPoolExecutor(max_workers=jobs) as pool:
                results = list(pool.map(_hash_one, [str(p) for p in files],
                                        chunksize=max(1, len(files) // (jobs * 4))))
        except (OSError, RuntimeError, ImportError):
            results = [_hash_one(str(p)) for p in files]
    else:
        results = [_hash_one(str(p)) for p in files]
    for path, digest in results:
        if digest:
            out.file_hashes[Path(path).relative_to(root).as_posix()] = digest
    return out


def print_from_store(store: "AnalysisStore", directory: Path,
                     include: Sequence[str] = DEFAULT_INCLUDE,
                     exclude: Sequence[str] = DEFAULT_EXCLUDE,
                     k: int = DEFAULT_K, window: int = DEFAULT_WINDOW
                     ) -> DirectoryPrint:
    """Pass 1 from a scan-wide store: no walk, and no file hashed twice."""
    rels = store.select(Path(directory), include, exclude)
    if rels is None:
        return print_directory(directory, include, exclude, k, window,
                               jobs=store.jobs)
    shas = store.shas(rels)
    base = store.root
    cut = 0 if Path(directory) == base else len(
        Path(directory).relative_to(base).as_posix()) + 1
    kept = [r for r in rels if r in shas]
    out = DirectoryPrint(root=Path(directory), files=[base / r for r in rels],
                         k=k, window=window, jobs=store.jobs,
                         store=store, rels=kept)
    for rel in kept:
        out.file_hashes[rel[cut:]] = shas[rel]
    return out


def sha256_file(path: Path) -> str:
    return _hash_one(str(path))[1]
