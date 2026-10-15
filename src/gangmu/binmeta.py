"""Dependency lists that a toolchain wrote into a binary on purpose.

Most evidence in a binary is circumstantial: a banner string, an exported symbol, a
fingerprint of a function. Two toolchains instead record the full dependency list in the
artifact, in a documented format, for exactly this use. Reading it is exact, not a guess:

* **Go** (``debug/buildinfo``): the linker embeds the Go version and, for binaries built in
  module mode, every module with its version and checksum (``go version -m`` prints the
  same data). The blob is found by a 16-byte-aligned magic, so it works on PE, ELF and
  Mach-O alike. Only the inline layout of Go 1.18 and later is read; the older
  pointer-to-string layout needs the image's address map and is reported as unread.
* **Rust** (``cargo auditable``): a zlib-compressed JSON list of crates in a section named
  ``.dep-v0``. Present only when the project was built with ``cargo auditable``.

Both are bounded (size caps, no recursion) and return ``None`` for anything malformed.
What they say is what the *build* resolved, which is the strongest statement a binary can
make about its dependencies; it still does not say whether a module's code was patched
after resolution (a ``replace`` directive is reported so a reader can see it).
"""

from __future__ import annotations

import json
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

GO_MAGIC = b"\xff Go buildinf:"
GO_HEADER = 32
MAX_GO_STRING = 4 * 1024 * 1024
MAX_GO_MODULES = 10000
MAX_CARGO_JSON = 16 * 1024 * 1024
MAX_CARGO_PACKAGES = 50000
CARGO_SECTION = ".dep-v0"


@dataclass
class GoModule:
    path: str
    version: str
    sum: str = ""
    replaced_by: str = ""             # "path version" of a ``=>`` replacement, if any
    main: bool = False


@dataclass
class GoBuildInfo:
    go_version: str                    # "go1.24.7"
    path: str = ""                     # the main package's import path
    modules: List[GoModule] = field(default_factory=list)   # main module first, then deps
    settings: Dict[str, str] = field(default_factory=dict)  # ``build`` lines (GOOS, -ldflags...)
    has_modules: bool = False          # False: no module table was read (GOPATH build, or cut off)

    @property
    def dependencies(self) -> List[GoModule]:
        return [m for m in self.modules if not m.main]


def _uvarint(data: bytes, at: int) -> Optional[Tuple[int, int]]:
    value = shift = 0
    for i in range(10):
        if at + i >= len(data):
            return None
        b = data[at + i]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, at + i + 1
        shift += 7
    return None


def _go_string(data: bytes, at: int) -> Optional[Tuple[str, int]]:
    got = _uvarint(data, at)
    if got is None:
        return None
    size, at = got
    if size > MAX_GO_STRING or at + size > len(data):
        return None
    return data[at:at + size].decode("utf-8", "replace"), at + size


def go_buildinfo(data: bytes) -> Optional[GoBuildInfo]:
    """The Go build info embedded in an executable, or None."""
    at = data.find(GO_MAGIC)
    while at >= 0:
        info = _go_at(data, at)
        if info is not None:
            return info
        at = data.find(GO_MAGIC, at + 1)
    return None


def _go_at(data: bytes, at: int) -> Optional[GoBuildInfo]:
    if at + GO_HEADER > len(data) or data[at + 14] not in (4, 8):
        return None
    if not data[at + 15] & 0x2:
        return None                    # pre-1.18: pointers into the image, not read here
    version = _go_string(data, at + GO_HEADER)
    if version is None or not version[0].startswith("go"):
        return None
    mod = _go_string(data, version[1])
    text = mod[0] if mod else ""
    if len(text) >= 33 and text[-17] == "\n":
        text = text[16:-16]            # the linker wraps the text in two 16-byte sentinels
    else:
        text = ""
    return _parse_modinfo(version[0], text)


def _parse_modinfo(go_version: str, text: str) -> GoBuildInfo:
    info = GoBuildInfo(go_version, has_modules=bool(text))
    last: Optional[GoModule] = None
    for line in text.split("\n"):
        parts = line.split("\t")
        kind = parts[0]
        if kind == "path" and len(parts) > 1:
            info.path = parts[1]
        elif kind in ("mod", "dep") and len(parts) > 1 and len(info.modules) < MAX_GO_MODULES:
            last = GoModule(parts[1], parts[2] if len(parts) > 2 else "",
                            parts[3] if len(parts) > 3 else "", main=kind == "mod")
            info.modules.append(last)
        elif kind == "=>" and last is not None and len(parts) > 1:
            # a local replacement has no version; the linker writes "(devel)" in its place
            last.replaced_by = " ".join(p for p in parts[1:3] if p and p != "(devel)")
        elif kind == "build" and len(parts) > 1:
            key, _, value = parts[1].partition("=")
            info.settings[key] = value
    return info


@dataclass
class CargoPackage:
    name: str
    version: str
    source: str = ""                   # "crates.io", "git", "local", "registry"
    kind: str = ""                     # "runtime" | "build"
    root: bool = False


def cargo_auditable(blob: bytes) -> Optional[List[CargoPackage]]:
    """The crate list from the bytes of a ``.dep-v0`` section, or None."""
    if not blob:
        return None
    try:
        raw = zlib.decompressobj().decompress(blob, MAX_CARGO_JSON)
        doc = json.loads(raw)
    except (zlib.error, ValueError):
        return None
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, list):
        return None
    out: List[CargoPackage] = []
    for p in packages[:MAX_CARGO_PACKAGES]:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str):
            continue
        out.append(CargoPackage(p["name"], str(p.get("version", "")), str(p.get("source", "")),
                                str(p.get("kind", "")), bool(p.get("root", False))))
    return out
