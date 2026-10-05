"""Path globbing with real ``**`` semantics.

``fnmatch`` is not a path matcher: its ``*`` happily crosses ``/`` and it has no
notion of ``**``.  Using it meant ``src/**/*.c`` silently failed to match
``src/init.c`` -- a whole directory level vanishing from a rule's view without
any error.  For a tool whose output is a compliance artefact, a matcher that
quietly matches the wrong set of files is the worst kind of bug, so this module
translates globs to anchored regexes with the semantics people expect:

    ``**/``   zero or more directories
    ``**``    anything, including ``/``
    ``*``     anything except ``/``
    ``?``     one character except ``/``
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, Optional, Pattern, Sequence, Tuple


@lru_cache(maxsize=4096)
def compile_glob(pattern: str) -> Pattern[str]:
    pattern = pattern.replace("\\", "/").strip("/")
    out: list = ["^"]
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**/", i):
                out.append("(?:[^/]+/)*")
                i += 3
                continue
            if pattern.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        if c == "[":
            close = pattern.find("]", i + 1)
            if close != -1:
                body = pattern[i + 1:close].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = close + 1
                continue
        out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


@lru_cache(maxsize=1024)
def _compile_any(patterns: Tuple[str, ...], suffix: bool) -> Optional[Pattern[str]]:
    """One alternation for a whole pattern list: a single regex call per path
    instead of one per pattern, which is what discovery spent its time on."""
    parts = [compile_glob(p).pattern for p in patterns]
    if suffix:
        parts += [compile_glob("**/" + p.strip("/")).pattern for p in patterns]
    return re.compile("|".join(f"(?:{p})" for p in parts)) if parts else None


def compile_any(patterns: Sequence[str], suffix: bool = False) -> Optional[Pattern[str]]:
    return _compile_any(tuple(patterns), suffix)


def matches(rel_path: str, patterns: Sequence[str]) -> bool:
    rel_path = rel_path.replace("\\", "/").strip("/")
    rx = _compile_any(tuple(patterns), False)
    return bool(rx and rx.match(rel_path))


def matches_suffix(rel_path: str, patterns: Sequence[str]) -> bool:
    """Match, allowing the pattern to describe only the tail of the path.

    A rule saying a component lives at ``components/lwip/lwip`` should still
    fire when the SDK is itself nested inside the scanned tree.
    """
    rel_path = rel_path.replace("\\", "/").strip("/")
    rx = _compile_any(tuple(patterns), True)
    return bool(rx and rx.match(rel_path))
