"""File-level analysis, shared by every directory and rule in a scan.

Why per file
------------
The engine asks about directories, but the expensive work -- reading a file,
tokenising it, extracting functions, winnowing -- is per file, and the same file
is asked about many times over:

* candidates nest. ESP-IDF has ``components/openthread`` wrapping
  ``openthread/third_party/mbedtls/repo``; every file of the inner copy belongs
  to both, and the outer one was being tokenised in full for each.
* rules disagree on globs, and each distinct ``include``/``exclude`` pair was its
  own directory print, re-reading and re-tokenising the files they share.
* a function-signature rule and a sketch rule wanted different halves of the
  same token pass, and asking for the second half after the first re-tokenised.

So the unit of work is a file, keyed by its content hash, analysed once per scan
in one pass that yields everything any rule needs. Directory-level answers are
unions over those per-file results and cost no tokenising at all.

Only the bottom of each file's fingerprints is kept
---------------------------------------------------
A directory sketch is the ``size`` smallest distinct fingerprints of the union of
its files. Any value in that bottom set is also among the ``size`` smallest of
its own file (every smaller value in the file is in the union too), so keeping
each file's bottom ``size`` values loses nothing and the directory sketch is
*exactly* what the full sets would give. It also caps memory: a file contributes
at most ``size`` integers however long it is.

Incremental across scans
------------------------
With a cache directory, per-file results go into a small SQLite database keyed
by content hash and by a digest of the analysing code itself, so a change to the
tokenizer or the extractor invalidates every entry without anybody remembering
to bump a version. A ``(path, size, mtime)`` table lets an unchanged file skip
even its sha256. Editing one file in a 10,000-file SDK re-tokenises one file.
"""

from __future__ import annotations

import bisect
import hashlib
import os
import sqlite3
import sys
import time
from array import array
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .fingerprint import DEFAULT_SKETCH, sorted_fingerprints
from .functions import extract_functions
from .globbing import compile_any
from .normalize import tokenize

MAX_FILE_BYTES = 4 * 1024 * 1024
WALK_SKIP = frozenset({".git", "__pycache__"})
PARALLEL_FILE_THRESHOLD = 32       # below this a pool costs more than it saves
BOTTOM_CAP = DEFAULT_SKETCH        # per-file fingerprints kept; see module docstring
_RACY_SECONDS = 2.0                # a file this fresh may change within its mtime tick


def _code_digest() -> str:
    """Digest of the modules whose output the cache stores."""
    h = hashlib.sha256(b"gangmu-analysis-1")
    here = Path(__file__).resolve().parent
    for name in ("normalize.py", "functions.py", "fingerprint.py", "analysis.py"):
        try:
            h.update((here / name).read_bytes())
        except OSError:
            h.update(name.encode())
    return h.hexdigest()[:16]


ANALYSIS_DIGEST = _code_digest()


@dataclass(frozen=True)
class FileAnalysis:
    functions: array          # unique exact body hashes
    abstract: array           # unique identifier-abstracted body hashes
    bottom: array             # ascending; the smallest BOTTOM_CAP fingerprints
    fingerprints: int         # how many distinct fingerprints the file had

    def to_blob(self) -> bytes:
        header = array("Q", [len(self.functions), len(self.abstract),
                             len(self.bottom), self.fingerprints])
        parts = [header, self.functions, self.abstract, self.bottom]
        if sys.byteorder != "little":
            parts = [array("Q", p) for p in parts]
            for p in parts:
                p.byteswap()
        return b"".join(p.tobytes() for p in parts)

    @classmethod
    def from_blob(cls, blob: bytes) -> "FileAnalysis":
        values = array("Q")
        values.frombytes(blob)
        if sys.byteorder != "little":
            values.byteswap()
        nf, na, nb, total = values[:4]
        if len(values) != 4 + nf + na + nb:
            raise ValueError("truncated analysis record")
        a, b, c = 4, 4 + nf, 4 + nf + na
        return cls(functions=values[a:b], abstract=values[b:c],
                   bottom=values[c:c + nb], fingerprints=total)


EMPTY = FileAnalysis(array("Q"), array("Q"), array("Q"), 0)


def analyse_bytes(data: bytes, k: int, window: int,
                  cap: int = BOTTOM_CAP) -> FileAnalysis:
    """One tokenise; functions, abstract functions and bottom fingerprints."""
    tokens = tokenize(data)
    functions = set()
    abstract = set()
    for f in extract_functions(data, tokens):
        functions.add(f.hash)
        if f.abstract_hash is not None:
            abstract.add(f.abstract_hash)
    bottom, total = sorted_fingerprints(tokens, k, window, cap)
    return FileAnalysis(array("Q", sorted(functions)), array("Q", sorted(abstract)),
                        array("Q", bottom), total)


def _analyse_path(args) -> Tuple[str, Optional[bytes]]:
    """Worker entry point. Returns the blob so the result pickles as bytes."""
    path, sha, k, window, cap = args
    try:
        data = Path(path).read_bytes()
    except OSError:
        return sha, None
    return sha, analyse_bytes(data, k, window, cap).to_blob()


def sha256_path(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# ------------------------------------------------------------------ tree index

class TreeIndex:
    """Every file under a root, walked once, sliced per directory by bisect.

    The walk prunes what ``dirprint.iter_source_files`` prunes and nothing else,
    so the files a directory print sees are the same whether they come from
    here or from walking that directory on its own.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        rels: List[str] = []
        base = str(self.root)
        cut = len(base) + 1
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in WALK_SKIP]
            prefix = dirpath[cut:].replace(os.sep, "/")
            for name in filenames:
                rels.append(f"{prefix}/{name}" if prefix else name)
        rels.sort()
        self.rels = rels
        self._ok: Dict[str, Optional[os.stat_result]] = {}

    def under(self, rel_dir: str) -> List[str]:
        """Root-relative paths of every file below *rel_dir* (posix)."""
        if rel_dir in ("", "."):
            return self.rels
        prefix = rel_dir.rstrip("/") + "/"
        lo = bisect.bisect_left(self.rels, prefix)
        hi = bisect.bisect_left(self.rels, prefix[:-1] + "0")   # '0' sorts after '/'
        return self.rels[lo:hi]

    def stat(self, rel: str) -> Optional[os.stat_result]:
        """lstat, or None when the file is not one a print may read."""
        if rel in self._ok:
            return self._ok[rel]
        path = os.path.join(str(self.root), rel)
        try:
            st = os.lstat(path)
            import stat as _stat
            ok = _stat.S_ISREG(st.st_mode) and st.st_size <= MAX_FILE_BYTES
        except OSError:
            st, ok = None, False
        self._ok[rel] = st if ok else None
        return self._ok[rel]


# ---------------------------------------------------------------------- store

class AnalysisStore:
    """Per-file content hashes and analyses for one scan, optionally on disk."""

    def __init__(self, root: Path, k: int, window: int, jobs: int = 1,
                 cache_dir: Optional[Path] = None, cap: int = BOTTOM_CAP) -> None:
        self.root = Path(root)
        self.index = TreeIndex(self.root)
        self.k, self.window, self.cap = k, window, cap
        self.jobs = max(1, jobs)
        self._sha: Dict[str, str] = {}
        self._analysis: Dict[str, FileAnalysis] = {}
        self._pool: Optional[ProcessPoolExecutor] = None
        self._params = f"{ANALYSIS_DIGEST}-{k}-{window}-{cap}"
        self._db: Optional[sqlite3.Connection] = None
        self.stats = {"files_hashed": 0, "files_tokenised": 0, "cache_hits": 0,
                      "stat_hits": 0}
        if cache_dir is not None:
            self._db = _open_db(Path(cache_dir))

    # ---- lifecycle
    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)
            self._pool = None
        if self._db is not None:
            try:
                self._db.close()
            except sqlite3.Error:
                pass
            self._db = None

    def __enter__(self) -> "AnalysisStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _executor(self) -> Optional[ProcessPoolExecutor]:
        if self.jobs <= 1:
            return None
        if self._pool is None:
            try:
                self._pool = ProcessPoolExecutor(max_workers=self.jobs)
            except (OSError, RuntimeError, ImportError):
                self.jobs = 1
                return None
        return self._pool

    # ---- selection
    def select(self, directory: Path, include: Sequence[str],
               exclude: Sequence[str]) -> Optional[List[str]]:
        """Root-relative files a print of *directory* covers, or None if the
        directory is not under this store's root."""
        try:
            rel_dir = directory.relative_to(self.root).as_posix()
        except ValueError:
            return None
        inc, exc = compile_any(include), compile_any(exclude)
        cut = 0 if rel_dir in ("", ".") else len(rel_dir) + 1
        out: List[str] = []
        for rel in self.index.under(rel_dir):
            sub = rel[cut:]
            if inc is None or not inc.match(sub):
                continue
            if exc is not None and exc.match(sub):
                continue
            if self.index.stat(rel) is None:
                continue
            out.append(rel)
        return out

    # ---- pass 1: content hashes
    def shas(self, rels: Sequence[str]) -> Dict[str, str]:
        missing = [r for r in rels if r not in self._sha]
        if missing:
            self._hash(missing)
        return {r: self._sha[r] for r in rels if self._sha.get(r)}

    def _hash(self, rels: List[str]) -> None:
        todo: List[str] = []
        now = time.time()
        if self._db is not None:
            known = self._stat_lookup(rels)
        else:
            known = {}
        for rel in rels:
            st = self.index.stat(rel)
            hit = known.get(rel)
            if st is not None and hit and hit[0] == st.st_size and hit[1] == st.st_mtime_ns:
                self._sha[rel] = hit[2]
                self.stats["stat_hits"] += 1
            else:
                todo.append(rel)
        base = str(self.root)
        paths = [os.path.join(base, r) for r in todo]
        pool = self._executor() if len(todo) >= PARALLEL_FILE_THRESHOLD * 4 else None
        if pool is not None:
            digests = list(pool.map(sha256_path, paths,
                                    chunksize=max(1, len(paths) // (self.jobs * 4))))
        else:
            digests = [sha256_path(p) for p in paths]
        self.stats["files_hashed"] += len(todo)
        fresh = []
        for rel, digest in zip(todo, digests):
            self._sha[rel] = digest
            st = self.index.stat(rel)
            if digest and st is not None and now - st.st_mtime_ns / 1e9 > _RACY_SECONDS:
                fresh.append((os.path.join(base, rel), st.st_size, st.st_mtime_ns, digest))
        if fresh and self._db is not None:
            try:
                with self._db:
                    self._db.executemany(
                        "INSERT OR REPLACE INTO stats VALUES (?,?,?,?)", fresh)
            except sqlite3.Error:
                pass

    def _stat_lookup(self, rels: List[str]) -> Dict[str, Tuple[int, int, str]]:
        base = str(self.root)
        out: Dict[str, Tuple[int, int, str]] = {}
        try:
            cur = self._db.cursor()
            for i in range(0, len(rels), 500):
                chunk = rels[i:i + 500]
                paths = {os.path.join(base, r): r for r in chunk}
                marks = ",".join("?" * len(paths))
                for path, size, mtime, sha in cur.execute(
                        f"SELECT path,size,mtime,sha FROM stats WHERE path IN ({marks})",
                        list(paths)):
                    out[paths[path]] = (size, mtime, sha)
        except sqlite3.Error:
            return {}
        return out

    # ---- pass 2: analyses
    def ensure(self, rels: Iterable[str]) -> None:
        """Analyse every file in *rels* not analysed yet, in one parallel batch."""
        wanted: Dict[str, str] = {}
        for rel in rels:
            sha = self._sha.get(rel)
            if sha and sha not in self._analysis and sha not in wanted:
                wanted[sha] = rel
        if not wanted:
            return
        if self._db is not None:
            for sha, blob in self._blob_lookup(list(wanted)):
                try:
                    self._analysis[sha] = FileAnalysis.from_blob(blob)
                    del wanted[sha]
                    self.stats["cache_hits"] += 1
                except (ValueError, KeyError):
                    pass
        if not wanted:
            return
        base = str(self.root)
        payload = [(os.path.join(base, rel), sha, self.k, self.window, self.cap)
                   for sha, rel in wanted.items()]
        pool = self._executor() if len(payload) >= PARALLEL_FILE_THRESHOLD else None
        if pool is not None:
            # Largest first, so one big file does not finish the batch alone.
            payload.sort(key=lambda p: -(self.index.stat(wanted[p[1]]).st_size
                                         if self.index.stat(wanted[p[1]]) else 0))
            results = pool.map(_analyse_path, payload,
                               chunksize=max(1, len(payload) // (self.jobs * 8)))
        else:
            results = map(_analyse_path, payload)
        rows = []
        for sha, blob in results:
            self.stats["files_tokenised"] += 1
            if blob is None:
                self._analysis[sha] = EMPTY
                continue
            self._analysis[sha] = FileAnalysis.from_blob(blob)
            rows.append((sha, self._params, blob))
        if rows and self._db is not None:
            try:
                with self._db:
                    self._db.executemany(
                        "INSERT OR REPLACE INTO files VALUES (?,?,?)", rows)
            except sqlite3.Error:
                pass

    def _blob_lookup(self, shas: List[str]):
        try:
            cur = self._db.cursor()
            for i in range(0, len(shas), 500):
                chunk = shas[i:i + 500]
                marks = ",".join("?" * len(chunk))
                yield from cur.execute(
                    f"SELECT sha,data FROM files WHERE params=? AND sha IN ({marks})",
                    [self._params, *chunk]).fetchall()
        except sqlite3.Error:
            return

    def analysis(self, rel: str) -> FileAnalysis:
        sha = self._sha.get(rel)
        if not sha:
            return EMPTY
        if sha not in self._analysis:
            self.ensure([rel])
        return self._analysis.get(sha, EMPTY)


def _open_db(directory: Path) -> Optional[sqlite3.Connection]:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(directory / "analysis-v1.sqlite"), timeout=30)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("CREATE TABLE IF NOT EXISTS files "
                   "(sha TEXT, params TEXT, data BLOB, PRIMARY KEY (sha, params))")
        db.execute("CREATE TABLE IF NOT EXISTS stats "
                   "(path TEXT PRIMARY KEY, size INTEGER, mtime INTEGER, sha TEXT)")
        return db
    except (sqlite3.Error, OSError):
        return None          # a cache that cannot be opened is not an error
