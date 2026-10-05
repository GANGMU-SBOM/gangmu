"""Source normalisation.

Vendor forks differ from upstream in ways that carry no meaning for identity:
re-indentation, a licence header swapped in, comments translated, CRLF, a brace
moved. Fingerprints are therefore taken over a *token stream*, not over raw
bytes -- ``f(a, b)`` and ``f(a,b)`` must fingerprint identically or every
re-formatted fork looks like a different project.

The tokenizer is deliberately small and is not a preprocessor. It only has to be
*consistent*: the same function runs over the pristine upstream release when a
rule is authored and over the candidate directory when the rule is applied.
Identifiers are kept verbatim, because a vendor renaming symbols is a real
modification that should show up as reduced similarity.

Performance note: comments are skipped by the same regex that produces tokens,
in one pass. The previous byte-at-a-time stripper cost a third of total scan
time on a 300-file tree.
"""

from __future__ import annotations

import re
from typing import List

_TOKEN = re.compile(
    rb"""
      (?P<bc>   /\*.*?\*/ | /\*.* )   # the second form: unterminated, runs to EOF
    | (?P<lc>   //[^\n]* )
    | (?P<str>  "(?:[^"\\\n]|\\.)*" | '(?:[^'\\\n]|\\.)*' )
    | (?P<num>  0[xXbB][0-9a-fA-F]+[uUlL]*
              | \d+\.\d*(?:[eE][+-]?\d+)?[fFlL]*
              | \.\d+(?:[eE][+-]?\d+)?[fFlL]*
              | \d+(?:[eE][+-]?\d+)?[uUlLfF]* )
    | (?P<id>   [A-Za-z_][A-Za-z0-9_]* )
    | (?P<op>   <<=|>>=|\.\.\.|->\*|::|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||
                \+=|-=|\*=|/=|%=|&=|\|=|\^=|\#\#|[-+*/%&|^~!<>=?:;,.(){}\[\]\#] )
    """,
    re.VERBOSE | re.DOTALL,
)

# A hex literal's digits include f/F and b/B, so the decimal suffix set would
# eat them: 0xFF must not normalise to 0x.
_DEC_SUFFIX = re.compile(rb"[uUlLfF]+$")
_HEX_SUFFIX = re.compile(rb"[uUlL]+$")

_COMMENT_GROUPS = frozenset({"bc", "lc"})


def _strip_numeric_suffix(tok: bytes) -> bytes:
    if tok[:2].lower() in (b"0x", b"0b"):
        return _HEX_SUFFIX.sub(b"", tok)
    return _DEC_SUFFIX.sub(b"", tok)


# The same pattern without named groups, for ``findall``: returning whole
# matches from C is a third faster than ``finditer`` plus ``lastgroup``, and a
# token's first bytes say which group it was.
_TOKEN_PLAIN = re.compile(re.sub(rb"\(\?P<\w+>", b"(?:", _TOKEN.pattern),
                          re.VERBOSE | re.DOTALL)
_SLASH, _STAR, _DOT = 0x2F, 0x2A, 0x2E
_NUM_SUFFIX = frozenset(b"uUlLfF")


def tokenize(data: bytes) -> List[bytes]:
    """Comment-free token stream. Whitespace and line breaks carry no weight."""
    tokens: List[bytes] = []
    append = tokens.append
    for tok in _TOKEN_PLAIN.findall(data):
        first = tok[0]
        if first == _SLASH and len(tok) > 1 and tok[1] in (_STAR, _SLASH):
            continue                                    # a comment
        if (48 <= first <= 57 or (first == _DOT and len(tok) > 1)) \
                and tok[-1] in _NUM_SUFFIX:
            tok = _strip_numeric_suffix(tok)            # a numeric literal
        append(tok)
    return tokens


def strip_c_comments(data: bytes) -> bytes:
    """Comments replaced by a newline, string and char literals untouched.

    Kept because it is the readable statement of what the tokenizer does with
    comments, and the test suite checks the two agree.
    """
    out = bytearray()
    pos = 0
    for m in _TOKEN.finditer(data):
        if m.lastgroup in _COMMENT_GROUPS:
            out += data[pos:m.start()]
            out += b"\n"
            pos = m.end()
    out += data[pos:]
    return bytes(out)
