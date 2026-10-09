"""Firmware containers, unwrapped so the same banner and string scan can read them.

A release image is rarely the bare machine code: it is an Intel HEX or UF2 file a
programmer flashes, or it carries gzip/xz/bzip2 streams (a compressed application,
a root file system, an OTA payload). The text inside is invisible until each layer is
undone. This module only undoes layers; it never interprets what is in them.

Everything is standard library, and every expansion is bounded -- by output size per
stream, by total bytes and by nesting depth -- so a hostile or corrupt image cannot
exhaust memory (a decompression bomb is cut off, not followed).
"""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional, Tuple

MAX_STREAM = 64 * 1024 * 1024        # bytes out of any one compressed stream
MAX_TOTAL = 256 * 1024 * 1024        # bytes out of one file, all layers together
MAX_DEPTH = 3                        # containers inside containers
MAX_STREAMS = 64                     # compressed streams tried per layer
MIN_STREAM = 256                     # smaller output is a false positive on a magic number
MAX_GAP = 1 << 20                    # an address hole bigger than this starts a new segment

IMAGE_SUFFIXES = {".hex", ".ihx", ".srec", ".s19", ".s28", ".s37", ".mot", ".uf2"}


@dataclass
class Layer:
    label: str            # "" for the file itself; else e.g. "intel-hex", "gzip@0x4000"
    data: bytes


# ------------------------------------------------------------ flat images

def _segments_to_image(segments: List[Tuple[int, bytes]]) -> bytes:
    """Contiguous runs joined; a hole larger than MAX_GAP is dropped, not padded."""
    out = bytearray()
    end: Optional[int] = None
    for addr, chunk in sorted(segments):
        if end is not None and addr > end:
            out += b"\xff" * min(addr - end, MAX_GAP)
        if end is not None and addr < end:
            chunk = chunk[end - addr:]
            addr = end
        out += chunk
        end = addr + len(chunk)
    return bytes(out)


def intel_hex(text: bytes) -> Optional[bytes]:
    base = 0
    segments: List[Tuple[int, bytes]] = []
    seen = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(b":"):
            continue
        try:
            raw = bytes.fromhex(line[1:].decode("ascii"))
        except ValueError:
            return None
        if len(raw) < 5 or raw[0] != len(raw) - 5 or sum(raw) & 0xFF:
            return None                                   # bad length or checksum
        count, addr, kind = raw[0], (raw[1] << 8) | raw[2], raw[3]
        body = raw[4:4 + count]
        seen += 1
        if kind == 0:
            segments.append((base + addr, body))
        elif kind == 2:
            base = int.from_bytes(body, "big") << 4
        elif kind == 4:
            base = int.from_bytes(body, "big") << 16
        elif kind == 1:
            break
    return _segments_to_image(segments) if seen and segments else None


def srec(text: bytes) -> Optional[bytes]:
    segments: List[Tuple[int, bytes]] = []
    for line in text.splitlines():
        line = line.strip()
        if len(line) < 10 or line[:1] != b"S" or line[1:2] not in b"123":
            continue
        width = {b"1": 2, b"2": 3, b"3": 4}[line[1:2]]
        try:
            raw = bytes.fromhex(line[2:].decode("ascii"))
        except ValueError:
            return None
        if len(raw) < 1 + width + 1 or raw[0] != len(raw) - 1 or (sum(raw) & 0xFF) != 0xFF:
            return None
        addr = int.from_bytes(raw[1:1 + width], "big")
        segments.append((addr, raw[1 + width:-1]))
    return _segments_to_image(segments) if segments else None


def uf2(data: bytes) -> Optional[bytes]:
    if len(data) < 512 or len(data) % 512:
        return None
    segments: List[Tuple[int, bytes]] = []
    for off in range(0, len(data), 512):
        m0, m1, flags, addr, size = struct.unpack_from("<5I", data, off)
        end = struct.unpack_from("<I", data, off + 508)[0]
        if m0 != 0x0A324655 or m1 != 0x9E5D5157 or end != 0x0AB16F30 or size > 476:
            return None
        if not flags & 1:                                 # bit 0: not main flash
            segments.append((addr, data[off + 32:off + 32 + size]))
    return _segments_to_image(segments) if segments else None


# ------------------------------------------------------------ compressed streams

# (label, start magic, decompress function). Magic alone is a weak signal -- these
# strings occur in unrelated data -- so a stream only counts if it decompresses to at
# least MIN_STREAM bytes without error.
_MAGIC = re.compile(
    rb"(?P<gzip>\x1f\x8b\x08)|(?P<xz>\xfd7zXZ\x00)|(?P<bzip2>BZh[1-9]1AY&SY)"
    rb"|(?P<zlib>\x78[\x01\x5e\x9c\xda])", re.DOTALL)


def _bounded(decompressor, data: bytes) -> Optional[bytes]:
    try:
        out = decompressor.decompress(data, MAX_STREAM)
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return None
    return out if len(out) >= MIN_STREAM else None


def _streams(data: bytes) -> Iterator[Tuple[str, int, bytes]]:
    tried = 0
    for m in _MAGIC.finditer(data):
        kind = m.lastgroup
        start = m.start()
        if kind == "gzip":
            out = _bounded(zlib.decompressobj(16 + zlib.MAX_WBITS), data[start:])
        elif kind == "zlib":
            out = _bounded(zlib.decompressobj(), data[start:])
        elif kind == "xz":
            out = _bounded(lzma.LZMADecompressor(), data[start:])
        else:
            out = _bounded(bz2.BZ2Decompressor(), data[start:])
        tried += 1
        if out is not None:
            yield f"{kind}@{start:#x}", start, out
        if tried >= MAX_STREAMS:
            return


def _zip_members(data: bytes) -> Iterator[Tuple[str, bytes]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return
    budget = MAX_STREAM
    for info in archive.infolist()[:MAX_STREAMS]:
        if info.is_dir() or info.file_size > MAX_STREAM or info.file_size > budget:
            continue
        try:
            body = archive.read(info)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError,
                EOFError, zlib.error):
            continue
        budget -= len(body)
        yield f"zip:{info.filename}", body


# ------------------------------------------------------------ driver

def expand(data: bytes, suffix: str = "") -> List[Layer]:
    """The file itself, its flat image if it is a flashing format, and every stream
    that can be unwrapped from either, to MAX_DEPTH. The first layer is always the
    original bytes, unless the file is a text image (HEX/S-record) whose flat image
    replaces it."""
    layers: List[Layer] = []
    total = [0]
    seen = set()
    suffix = suffix.lower()

    def add(label: str, blob: bytes, depth: int) -> None:
        if total[0] + len(blob) > MAX_TOTAL:
            return
        key = hashlib.blake2b(blob, digest_size=16).digest()
        if key in seen:
            return                  # the same bytes reached by two routes (a stored
        seen.add(key)               # stream is also found as a substring of its wrapper)
        total[0] += len(blob)
        layers.append(Layer(label, blob))
        if depth >= MAX_DEPTH:
            return
        children: List[Tuple[str, bytes]] = []
        if blob[:4] == b"PK\x03\x04":
            children.extend(_zip_members(blob))
        for label2, _, out in _streams(blob):
            children.append((label2, out))
        for label2, out in children:
            add(f"{label}>{label2}" if label else label2, out, depth + 1)

    flat: Optional[Tuple[str, bytes]] = None
    parsers: List[Tuple[str, Callable[[bytes], Optional[bytes]]]] = []
    if suffix in (".hex", ".ihx"):
        parsers = [("intel-hex", intel_hex)]
    elif suffix in (".srec", ".s19", ".s28", ".s37", ".mot"):
        parsers = [("srec", srec)]
    elif suffix == ".uf2":
        parsers = [("uf2", uf2)]
    for label, parse in parsers:
        image = parse(data)
        if image:
            flat = (label, image)
    if flat:
        add(flat[0], flat[1], 0)
    else:
        add("", data, 0)
    return layers
