"""What the files themselves say about their licence.

A rule records the licence its upstream is released under.  That is the right
default, and wrong in the cases an SBOM reader cares about most: a vendor who
relicensed a file, a component that is dual-licensed, a directory the rule base
does not know at all.  So a scan also reads what is written in the tree:

* ``SPDX-License-Identifier:`` lines in the head of source files -- exact, and
  the only source trusted for copyleft licences, where guessing is expensive;
* the licence text of a top-level ``LICENSE`` / ``COPYING`` file, recognised
  only for a short list of permissive licences whose wording is unmistakable.

The result is evidence, never a legal conclusion.  Where it disagrees with the
rule's licence the SBOM says so instead of choosing.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".s", ".S",
                   ".asm", ".ld", ".py", ".rs", ".go", ".ts", ".js", ".cmake")
LICENSE_NAMES = re.compile(r"^(licen[sc]e|copying|copyright|unlicense)([-_.].*)?$", re.I)
SKIP_DIRS = {".git", "node_modules", "__pycache__", "build", "out", ".github"}
HEAD_BYTES = 1024
MAX_FILES = 250                 # per component: bounds the cost on a huge SDK
MAX_LICENSE_BYTES = 64 * 1024

_SPDX_LINE = re.compile(r"SPDX-License-Identifier:\s*([^\r\n*]+?)\s*(?:\*/|-->|$)", re.M)
_TOKEN = re.compile(r"[A-Za-z0-9.+\-]+")
_OPERATORS = {"AND", "OR", "WITH"}


def expression_ids(expression: str) -> List[str]:
    """The licence ids in an SPDX expression, without operators or parentheses."""
    return [t for t in _TOKEN.findall(expression) if t.upper() not in _OPERATORS]


def parse_spdx_headers(head: str) -> List[str]:
    return [m.group(1).strip().rstrip(".") for m in _SPDX_LINE.finditer(head)]


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[#*/;]+", " ", text)).lower()


def detect_license_text(text: str) -> Optional[str]:
    """SPDX id of a licence text, for the permissive licences recognised exactly."""
    t = _squash(text)
    if "apache license" in t and "version 2.0" in t:
        return "Apache-2.0"
    if "mozilla public license" in t and "2.0" in t:
        return "MPL-2.0"
    if "boost software license" in t:
        return "BSL-1.0"
    if "permission is hereby granted, free of charge, to any person obtaining a copy" in t:
        return "MIT"
    if ("permission to use, copy, modify, and/or distribute this software for any purpose "
            "with or without fee is hereby granted") in t:
        return "ISC"
    if "this software is provided 'as-is'" in t and "altered source versions" in t:
        return "Zlib"
    if "redistribution and use in source and binary forms" in t:
        if "all advertising materials" in t:
            return "BSD-4-Clause"
        if "neither the name" in t or "may be used to endorse or promote" in t:
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    return None


def observe(directory: Path) -> Tuple[List[str], Dict[str, str]]:
    """(SPDX identifiers from source headers, {top-level licence file: id}).

    Identifiers are ordered by how many files carry them, so the first one is the
    licence most of the component is under.
    """
    counts: Counter = Counter()
    files: Dict[str, str] = {}
    seen = 0
    try:
        top = sorted(os.listdir(directory))
    except OSError:
        return [], {}
    for name in top:
        path = directory / name
        if path.is_file() and LICENSE_NAMES.match(name):
            try:
                with open(path, "rb") as fh:
                    text = fh.read(MAX_LICENSE_BYTES).decode("utf-8", "replace")
            except OSError:
                continue
            found = detect_license_text(text)
            files[name] = found or ""
    for base, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if not name.endswith(SOURCE_SUFFIXES):
                continue
            seen += 1
            if seen > MAX_FILES:
                break
            try:
                with open(os.path.join(base, name), "rb") as fh:
                    head = fh.read(HEAD_BYTES).decode("utf-8", "replace")
            except OSError:
                continue
            for expr in set(parse_spdx_headers(head)):
                counts[expr] += 1
        if seen > MAX_FILES:
            break
    return [expr for expr, _ in counts.most_common(8)], files


def observed_license_ids(headers: Iterable[str], files: Dict[str, str]) -> List[str]:
    """Licence ids seen anywhere, header expressions split into their ids."""
    ids: List[str] = []
    for expr in headers:
        for one in expression_ids(expr):
            if one not in ids:
                ids.append(one)
    for found in files.values():
        if found and found not in ids:
            ids.append(found)
    return ids


def differs(declared: Optional[str], observed_ids: List[str]) -> bool:
    """True when the tree shows a licence the rule's licence does not mention."""
    if not observed_ids:
        return False
    if not declared:
        return False
    known = {i.lower() for i in expression_ids(declared)}
    return any(i.lower() not in known for i in observed_ids)


# Ids CycloneDX's schema accepts in ``license.id``; anything else goes out as an
# SPDX expression, which the schema takes as free text.
COMMON_IDS = frozenset("""
0BSD AFL-3.0 AGPL-3.0-only AGPL-3.0-or-later Apache-1.1 Apache-2.0 Artistic-2.0 BSD-2-Clause
BSD-3-Clause BSD-4-Clause BSL-1.0 CC0-1.0 CDDL-1.0 EPL-1.0 EPL-2.0 GPL-2.0-only GPL-2.0-or-later
GPL-3.0-only GPL-3.0-or-later ISC LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later
MIT MIT-0 MPL-1.1 MPL-2.0 NCSA OpenSSL Unlicense WTFPL X11 Zlib
""".split())


def observed_ids(finding) -> List[str]:
    return observed_license_ids(finding.observed_licenses, finding.license_files)


def _is_simple(expression: str) -> bool:
    return len(expression_ids(expression)) == 1 and not re.search(
        r"\b(AND|OR|WITH)\b|[()]", expression)


def cyclonedx_licenses(declared: Optional[str], headers: List[str],
                       files: Dict[str, str]) -> List[dict]:
    """The CycloneDX ``licenses`` array: the rule's licence if there is one,
    otherwise what the tree declares for itself."""
    if declared:
        if declared in COMMON_IDS:
            return [{"license": {"id": declared}}]
        return [{"expression": declared}]
    exprs = list(headers)
    for found in files.values():
        if found and found not in exprs and not any(found in expression_ids(e) for e in exprs):
            exprs.append(found)
    if not exprs:
        return []
    if all(_is_simple(e) and e in COMMON_IDS for e in exprs):
        return [{"license": {"id": e, "acknowledgement": "declared"}} for e in exprs]
    parts = [e if _is_simple(e) else f"({e})" for e in exprs]
    return [{"expression": " AND ".join(parts), "acknowledgement": "declared"}]


def spdx_license_declared(declared: Optional[str], headers: List[str],
                          files: Dict[str, str]) -> str:
    """``licenseDeclared`` for an SPDX 2.3 package: the rule's licence, else what
    the tree declares for itself (``licenseInfoFromFiles`` is not used: SPDX
    reserves it for packages whose files were analysed one by one)."""
    if declared:
        return declared
    exprs = list(headers)
    for found in files.values():
        if found and not any(found in expression_ids(e) for e in exprs):
            exprs.append(found)
    if not exprs:
        return "NOASSERTION"
    return " AND ".join(e if _is_simple(e) else f"({e})" for e in dict.fromkeys(exprs))
