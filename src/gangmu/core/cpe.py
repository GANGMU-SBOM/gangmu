"""CPE 2.3 formatted strings, split the way the specification binds them.

A component may hold an escaped colon (``cpe:2.3:a:foo\\:bar:baz:...``, NISTIR 7695
section 6.2), so splitting on every ``:`` shifts vendor, product and version by one.
"""

from __future__ import annotations

import re
from typing import List

_UNESCAPED_COLON = re.compile(r"(?<!\\)((?:\\\\)*):")


def split_cpe(cpe: str) -> List[str]:
    """The colon-separated components of *cpe*, escapes kept as written."""
    out, start = [], 0
    for found in _UNESCAPED_COLON.finditer(cpe):
        end = found.end() - 1                       # the colon itself
        out.append(cpe[start:end])
        start = found.end()
    out.append(cpe[start:])
    return out


def join_cpe(parts: List[str]) -> str:
    return ":".join(parts)


def escape_value(value: str) -> str:
    """*value* as one CPE component: backslashes and colons quoted."""
    return value.replace("\\", "\\\\").replace(":", "\\:")
