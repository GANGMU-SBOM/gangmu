"""Read a cramfs file system out of a firmware image.

cramfs, the compressed ROM file system, is what older IP cameras, set-top boxes and
embedded boards before SquashFS used for a read-only root (Linux removed write support
long ago, but the images are still in the field). The layout is that of the kernel's
``include/uapi/linux/cramfs_fs.h``: a 76-byte superblock (magic ``0x28cd3d45``, the
signature ``Compressed ROMFS``), then 12-byte inodes with bit-field mode, size and a
26-bit offset in 4-byte units, each followed by its name. A directory's offset points
at its children; a regular file's at a table of block end pointers, each 4 KiB block
compressed with zlib on its own. Images in either byte order are read
(``mkfs.cramfs -N big``); an uncompressed block (the ``EXT_BLOCK_POINTERS`` flag) and a
hole (an empty block) are read too. The limits and the naming rules are those of
``squashfs``.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .squashfs import MAX_BYTES, MAX_DEPTH, MAX_FILE, MAX_FILES, Extracted, _safe

MAGIC = 0x28CD3D45
SIGNATURE = b"Compressed ROMFS"
SUPER = 76
INODE = 12
PAGE = 4096
S_IFMT, S_IFDIR, S_IFREG = 0o170000, 0o040000, 0o100000
EXT_BLOCK_POINTERS = 0x800
BLK_UNCOMPRESSED, BLK_DIRECT = 1 << 31, 1 << 30


@dataclass
class Superblock:
    offset: int
    big: bool
    size: int
    flags: int
    files: int
    root: Tuple[int, int, int]                   # mode, size, offset (bytes)

    @property
    def describe(self) -> str:
        return "big-endian" if self.big else "little-endian"


def _inode(data: bytes, at: int, big: bool) -> Tuple[int, int, int, int]:
    """(mode, size, name length in bytes, offset in bytes) of the inode at *at*."""
    n = int.from_bytes(data[at:at + INODE], "big" if big else "little")

    def field(pos: int, width: int) -> int:
        shift = 96 - pos - width if big else pos
        return (n >> shift) & ((1 << width) - 1)
    return field(0, 16), field(32, 24), field(64, 6) * 4, field(70, 26) * 4


def superblock_at(data: bytes, at: int) -> Optional[Superblock]:
    if at + SUPER > len(data) or data[at + 16:at + 32] != SIGNATURE:
        return None
    for big in (False, True):
        e = ">" if big else "<"
        magic, size, flags = struct.unpack_from(e + "III", data, at)
        if magic != MAGIC:
            continue
        files, = struct.unpack_from(e + "I", data, at + 44)
        mode, rsize, _nlen, roff = _inode(data, at + 64, big)
        if size < SUPER or at + size > len(data) or mode & S_IFMT != S_IFDIR \
                or roff >= size:
            return None
        return Superblock(at, big, size, flags, files, (mode, rsize, roff))
    return None


def find(data: bytes, limit: int = 8) -> List[Superblock]:
    out: List[Superblock] = []
    at = data.find(SIGNATURE)
    while at >= 0 and len(out) < limit:
        sb = superblock_at(data, at - 16) if at >= 16 else None
        if sb is not None:
            out.append(sb)
        at = data.find(SIGNATURE, at + 16)
    return out


class CramfsError(ValueError):
    pass


def _read_file(data: bytes, base: int, sb: Superblock, size: int, offset: int) -> bytes:
    e = ">" if sb.big else "<"
    blocks = (size + PAGE - 1) // PAGE
    table = base + offset
    if table + 4 * blocks > base + sb.size:
        raise CramfsError("block table past the end of the file system")
    out = bytearray()
    start = table + 4 * blocks
    ext = bool(sb.flags & EXT_BLOCK_POINTERS)
    for i in range(blocks):
        word, = struct.unpack_from(e + "I", data, table + 4 * i)
        want = min(PAGE, size - len(out))
        if ext and word & BLK_DIRECT:
            raise CramfsError("direct block pointers are not read")
        uncompressed = ext and bool(word & BLK_UNCOMPRESSED)
        end = base + (word & ~(BLK_UNCOMPRESSED | BLK_DIRECT) if ext else word)
        if end < start or end > base + sb.size:
            raise CramfsError("block pointer out of range")
        raw = data[start:end]
        if not raw:
            out += bytes(want)                           # a hole
        elif uncompressed:
            out += raw[:want]
        else:
            d = zlib.decompressobj()
            out += d.decompress(raw, want)
        start = end
    if len(out) != size:
        raise CramfsError("file shorter than its inode says")
    return bytes(out)


def extract(data: bytes, sb: Superblock, dest: Path, max_bytes: int = MAX_BYTES) -> Extracted:
    """Write the regular files of the cramfs at *sb* below *dest*."""
    result = Extracted(sb.offset, f"cramfs ({sb.describe})")
    base = sb.offset
    dest.mkdir(parents=True, exist_ok=True)
    seen: Set[int] = set()
    stack: List[Tuple[int, int, Path, int]] = [(sb.root[2], sb.root[1], dest, 0)]
    big = 0
    try:
        while stack:
            offset, size, here, depth = stack.pop()
            if offset in seen or not size:
                continue
            seen.add(offset)
            at, end = base + offset, base + offset + size
            if end > base + sb.size:
                raise CramfsError("directory past the end of the file system")
            while at + INODE <= end:
                mode, fsize, nlen, foff = _inode(data, at, sb.big)
                name = data[at + INODE:at + INODE + nlen].rstrip(b"\0").decode("utf-8", "replace")
                at += INODE + nlen
                if not _safe(name):
                    continue
                kind = mode & S_IFMT
                if kind == S_IFDIR:
                    if depth + 1 < MAX_DEPTH:
                        (here / name).mkdir(exist_ok=True)
                        stack.append((foff, fsize, here / name, depth + 1))
                    continue
                if kind != S_IFREG:
                    continue
                if fsize > MAX_FILE:
                    big += 1
                    continue
                if result.files >= MAX_FILES:
                    result.skipped.append(f"more than {MAX_FILES} files")
                    return result
                if result.bytes + fsize > max_bytes:
                    result.skipped.append(f"more than {max_bytes >> 20} MiB of files")
                    return result
                body = _read_file(data, base, sb, fsize, foff) if fsize else b""
                with open(here / name, "wb") as fh:
                    fh.write(body)
                result.files += 1
                result.bytes += fsize
    except (CramfsError, struct.error, zlib.error, OSError) as exc:
        result.error = str(exc) or type(exc).__name__
    if big:
        result.skipped.append(f"{big} file(s) over {MAX_FILE >> 20} MiB")
    return result


def label(offset: int) -> str:
    return f"!cramfs@{offset:#x}"
