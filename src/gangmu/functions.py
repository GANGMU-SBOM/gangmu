"""Function-level extraction and hashing.

Why functions rather than k-grams
---------------------------------
Directory-level winnowing answers "how similar are these two trees", which is
the wrong question twice over. It cannot separate a vendor fork from an adjacent
release (measured: 0.949 vs 0.867 -- the fork sits *between* two versions), and
it cannot say which parts of the tree came from where.

The research literature settled this. CENTRIS (ICSE 2021) matches at function
granularity and shows that a component's *application code* -- the functions
unique to it, with nested third-party code subtracted -- is what identifies it.
TIVER (ICSE 2025) adds the observation this tool most needed: a modified
component usually contains functions from **several upstream versions at once**,
so mapping one version onto it is wrong, and reporting a version *range* removes
the bulk of the false positives that follow.

And it is cheaper
-----------------
lwIP 2.2.0 yields about 4,000 functions against 105,000 winnowed fingerprints:
a set 25 times smaller. Small enough to store whole, so similarity becomes an
exact Jaccard with no sketching error at all, and the comparison is a set
intersection over a few thousand integers rather than a merge over a quarter of
a million. Function extraction rides on the same token pass that already runs,
so it costs no extra I/O and no extra tokenising.

The extractor
-------------
Not a parser. It walks the token stream looking for the shape ``name ( ... ) {``
at brace depth zero and takes the balanced block that follows. That accepts K&R
declarations, attributes and macro-wrapped definitions, and it rejects control
statements by name. It will miss functions built entirely inside macros, which
is why a file that yields nothing falls back to winnowing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .normalize import tokenize

# Keywords that can precede a parenthesised group and a brace without being a
# function definition.
_CONTROL = frozenset(
    b"if while for switch do else return sizeof catch synchronized "
    b"__attribute__ __declspec typeof decltype alignof static_assert "
    b"_Static_assert".split()
)
_OPEN = b"{"
_CLOSE = b"}"
_LPAREN = b"("
_RPAREN = b")"
_SEMI = b";"
_EQ = b"="

MIN_BODY_TOKENS = 6      # below this a "function" is a stub and matches everything
MIN_ABSTRACT_TOKENS = 24 # abstraction destroys names, so short bodies collide
_KR_LOOKAHEAD = 64       # K&R parameter blocks are short; anything longer is not one
_DECL_PUNCT = frozenset((b"*", b"[", b"]", b",", b";", b"&", b"const", b"volatile"))

# Abstraction level 1: identifiers become a placeholder, keywords and structure
# stay. A vendor that renames symbols -- prefixing a whole library with its own
# vendor tag is routine -- defeats exact function hashing entirely: renaming a
# tenth of the identifiers was measured to drop exact containment from 1.00 to
# 0.48, because almost every function touches at least one renamed name. The
# literature's answer (VUDDY's abstraction levels, MOVERY) is to hash the same
# body more than once at decreasing specificity and take the most specific match
# available. An abstract match is weaker evidence and is scored as such.
_C_KEYWORDS = frozenset(b"""auto break case char const continue default do double
else enum extern float for goto if inline int long register restrict return short
signed sizeof static struct switch typedef union unsigned void volatile while
_Bool _Complex _Atomic bool true false NULL class namespace template typename
public private protected virtual operator new delete this nullptr constexpr
static_cast const_cast dynamic_cast reinterpret_cast""".split())
_IDENT_PLACEHOLDER = b"@"
SEED = 0x6761_6E67


def _hash_tokens(tokens: Sequence[bytes]) -> int:
    h = hashlib.blake2b(b"\x1f".join(tokens), digest_size=8,
                        salt=SEED.to_bytes(8, "big"))
    return int.from_bytes(h.digest(), "big")


def _abstract(tokens: Sequence[bytes]) -> List[bytes]:
    """Keywords, operators, literals and structure; every other name collapsed."""
    out: List[bytes] = []
    for tok in tokens:
        first = tok[:1]
        if (first.isalpha() or first == b"_") and tok not in _C_KEYWORDS:
            out.append(_IDENT_PLACEHOLDER)
        else:
            out.append(tok)
    return out


@dataclass(frozen=True)
class Function:
    name: str
    hash: int
    tokens: int
    abstract_hash: Optional[int] = None
    # Every identifier in the body, filled only when asked for (reachability).
    refs: frozenset = field(default=frozenset(), compare=False, repr=False)
    span: Tuple[int, int] = field(default=(0, 0), compare=False, repr=False)

    def __hash__(self) -> int:         # dedupe by body, not by name
        return self.hash


def extract_functions(data: bytes, tokens: Optional[List[bytes]] = None,
                      with_refs: bool = False,
                      min_tokens: int = MIN_BODY_TOKENS) -> List[Function]:
    """Functions in one translation unit, each hashed over its token body.

    The body hash deliberately includes the parameter list and the name: a
    vendor renaming a symbol *is* a modification and should reduce similarity.
    """
    toks = tokenize(data) if tokens is None else tokens
    out: List[Function] = []
    n = len(toks)
    depth = 0
    wrappers = 0                    # open `extern "C" {` blocks around the file
    i = 0
    while i < n:
        tok = toks[i]
        if tok == _OPEN:
            # `extern "C" {` wraps a whole header or source file in many C
            # libraries; the functions inside it are still at file scope.
            if depth == 0 and i >= 2 and toks[i - 2] == b"extern" \
                    and toks[i - 1] == b'"C"':
                wrappers += 1
            else:
                depth += 1
            i += 1
            continue
        if tok == _CLOSE:
            if depth == 0 and wrappers:
                wrappers -= 1
            else:
                depth -= 1
            i += 1
            continue
        if depth != 0 or tok != _LPAREN or i == 0:
            i += 1
            continue

        name_index = i - 1
        name = toks[name_index]
        if not (name[:1].isalpha() or name[:1] == b"_") or name in _CONTROL:
            i += 1
            continue

        # Balanced parameter list.
        para = 1
        j = i + 1
        while j < n and para:
            if toks[j] == _LPAREN:
                para += 1
            elif toks[j] == _RPAREN:
                para -= 1
            j += 1
        if para:
            break

        # Between ')' and '{' a definition may carry const/noexcept/attributes,
        # or -- in the older embedded code this tool exists for -- K&R parameter
        # declarations, which contain semicolons. So semicolons are tolerated
        # only while everything in between still looks like a declaration.
        # A semicolon *immediately* after the parameter list ends a
        # declaration: `int f(void);`. K&R definitions always put a type first,
        # so this one token separates the two cases. Without the check, a
        # prototype swallows everything up to the next unrelated brace.
        if j < n and toks[j] == _SEMI:
            i = j
            continue
        k = j
        ok = True
        while k < n and toks[k] != _OPEN:
            tok_k = toks[k]
            if tok_k == _EQ or tok_k == _LPAREN:
                ok = False
                break
            if tok_k == _SEMI:
                if k - j > _KR_LOOKAHEAD:
                    ok = False
                    break
            elif not (tok_k[:1].isalpha() or tok_k[:1] == b"_"
                      or tok_k in _DECL_PUNCT):
                ok = False
                break
            k += 1
        if not ok or k >= n or toks[k] != _OPEN:
            i = j
            continue

        # Balanced body.
        body = 1
        end = k + 1
        while end < n and body:
            if toks[end] == _OPEN:
                body += 1
            elif toks[end] == _CLOSE:
                body -= 1
            end += 1
        if body:
            break

        start = name_index
        span = toks[start:end]
        if len(span) >= min_tokens:
            abstract = (_hash_tokens(_abstract(span))
                        if len(span) >= MIN_ABSTRACT_TOKENS else None)
            refs = frozenset(
                t.decode("utf-8", "replace") for t in span[1:]
                if (t[:1].isalpha() or t[:1] == b"_") and t not in _CONTROL
            ) if with_refs else frozenset()
            out.append(Function(name=name.decode("utf-8", "replace"),
                                hash=_hash_tokens(span), tokens=len(span),
                                abstract_hash=abstract, refs=refs,
                                span=(start, end)))
        i = end
    return out


def function_hashes(data: bytes) -> Set[int]:
    return {f.hash for f in extract_functions(data)}


@dataclass
class FunctionSet:
    """The functions of one tree, with enough structure for TIVER clustering."""

    hashes: Set[int]
    by_directory: Dict[str, Set[int]]
    names: Dict[int, str]

    @property
    def count(self) -> int:
        return len(self.hashes)

    def jaccard(self, other: "FunctionSet") -> float:
        if not self.hashes or not other.hashes:
            return 0.0
        union = len(self.hashes | other.hashes)
        return len(self.hashes & other.hashes) / union if union else 0.0

    def containment(self, other: "FunctionSet") -> float:
        """How much of *other* is present here.

        CENTRIS's component metric. Containment, not Jaccard, is what identifies
        a component inside a much larger tree: a 4,000-function library inside a
        200,000-function firmware has a tiny Jaccard and a containment near 1.
        """
        if not other.hashes:
            return 0.0
        return len(self.hashes & other.hashes) / len(other.hashes)
