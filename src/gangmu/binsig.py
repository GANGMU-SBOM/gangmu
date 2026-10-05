"""String-constant fingerprints for code that only exists as machine code.

Source-level function hashes (``functions.py``) cannot see a compiled image: the
tokens are gone, and instruction bytes change with the compiler, the optimisation
level and the architecture. String literals survive all three. Log lines, error
messages, protocol names and format strings are copied into ``.rodata`` as written,
and between releases they appear and disappear the way functions do, so they carry
the same version signal.

The signature is an ordinary :class:`~gangmu.fnsig.FunctionSignature` -- 64-bit
hashes with a per-version bitmap -- so ``infer_version`` works on it unchanged. Only
what is hashed differs: the string literals of an upstream release tree on one side,
the printable runs of a firmware image on the other.

Linkers merge identical constants and, with suffix merging, store a string as the
tail of a longer one. The image side therefore hashes every suffix of a run, so a
literal that was folded into another is still found.

What this is not: proof of an unmodified copy, or a function-level match. A
vendor can change code and keep its strings. The evidence is reported at modest
confidence for that reason.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple

from .normalize import tokenize

MIN_LEN = 8                  # shorter strings are in too many unrelated programs
MAX_SUFFIX_RUN = 256         # longer runs are hashed whole, not at every offset
MIN_MATCHES = 8              # literals that must match before a library is claimed
MIN_COVERAGE = 0.10          # share of the best release's literals that must be present
_SALT = (0x6D62_7367).to_bytes(8, "big")
_RUN = re.compile(rb"[\x20-\x7e\t\n\r]{%d,}" % MIN_LEN)
_ESCAPES = {b"n": b"\n", b"t": b"\t", b"r": b"\r", b"\\": b"\\", b'"': b'"',
            b"'": b"'", b"a": b"\a", b"b": b"\b", b"f": b"\f", b"v": b"\v", b"?": b"?"}
_ESCAPE = re.compile(rb"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", re.DOTALL)


def _hash(raw: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8, salt=_SALT).digest(), "big")


def _unescape(body: bytes) -> bytes:
    def one(m: "re.Match[bytes]") -> bytes:
        e = m.group(1)
        if e[:1] == b"x":
            return bytes([int(e[1:], 16)])
        if e[:1].isdigit():
            return bytes([int(e, 8) & 0xFF])
        return _ESCAPES.get(e, e)
    return _ESCAPE.sub(one, body)


def _wanted(text: bytes) -> bool:
    """Prose-like enough to be distinctive: some letters, not a bare identifier list."""
    return len(text) >= MIN_LEN and sum(65 <= (c | 32) <= 122 and (c | 32) >= 97 for c in text) >= 4


def source_literals(data: bytes) -> List[bytes]:
    """String literals of one C file, adjacent literals joined, escapes resolved."""
    out: List[bytes] = []
    pending: List[bytes] = []
    for tok in tokenize(data) + [b";"]:
        if tok[:1] == b'"' and len(tok) >= 2 and tok[-1:] == b'"':
            pending.append(_unescape(tok[1:-1]))
            continue
        if pending:
            text = b"".join(pending).split(b"\0", 1)[0]
            if _wanted(text):
                out.append(text)
            pending = []
    return out


def source_strings(data: bytes) -> Set[int]:
    return {_hash(s) for s in source_literals(data)}


def tree_strings(root: Path, include: Sequence[str], exclude: Sequence[str]) -> Set[int]:
    from .dirprint import iter_source_files
    found: Set[int] = set()
    for path in iter_source_files(Path(root), include, exclude):
        try:
            found |= source_strings(Path(path).read_bytes())
        except OSError:
            continue
    return found


def image_strings(data: bytes) -> Set[int]:
    """Hashes of the printable runs of an image, each also at every suffix offset."""
    found: Set[int] = set()
    for m in _RUN.finditer(data):
        run = m.group(0)
        # a run may sit between other printable bytes of a packed table: split at
        # newlines too would lose multi-line literals, so only whole runs and tails
        found.add(_hash(run))
        if len(run) <= MAX_SUFFIX_RUN:
            for i in range(1, len(run) - MIN_LEN + 1):
                found.add(_hash(run[i:]))
    return found


def match_image(signature, present: Set[int]
                ) -> Optional[Tuple[str, int, int, float, str]]:
    """(best version, matched, of, coverage, tied range or ""), or None when it is not there.

    Unlike a source tree, an image is one complete build, so what is *absent* counts:
    each release is scored by Jaccard between its literals and the matched ones. An
    image of 1.0.0 contains no literal that only 1.1.0 added, which is what separates
    it from 1.1.0 even though every literal it has is shared by both.
    """
    matched = present & signature.hash_set
    if len(matched) < MIN_MATCHES:
        return None
    scores = []
    for v in range(len(signature.versions)):
        own = signature.version_hashes(v)
        union = len(own | matched)
        scores.append(len(own & matched) / union if union else 0.0)
    best = max(scores) if scores else 0.0
    own = signature.version_hashes(scores.index(best)) if scores else frozenset()
    coverage = len(matched & own) / len(own) if own else 0.0
    if coverage < MIN_COVERAGE:
        return None
    index = scores.index(best)
    tied = [i for i, sc in enumerate(scores) if sc >= best * 0.95]
    low, high = signature.versions[min(tied)], signature.versions[max(tied)]
    return (signature.versions[index], len(matched & own), len(own), coverage,
            "" if low == high else f"{low}~{high}")
