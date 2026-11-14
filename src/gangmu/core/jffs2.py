"""Read a JFFS2 file system out of a firmware image.

JFFS2 is the log-structured flash file system of many older routers, IP cameras and
industrial controllers. It has no tree on flash: the image is a sequence of nodes, each
naming one directory entry (parent inode, name, child inode) or one range of a file's
data, with a version number. The file system is what the newest node for each name and
each range says. This module scans the nodes (either byte order), keeps the newest, and
writes the regular files below a directory.

Data is read when stored uncompressed, as zeros, or compressed with rtime or zlib (what
``mkfs.jffs2`` uses by default), with LZO (the built-in decoder), or with LZMA as OpenWrt's
kernel and mtd-utils patches write it. Nodes compressed with rubin are skipped and
counted. Every node
header is checked against its CRC and every data range against its own, so stale or
half-written flash is passed over rather than trusted. The limits and the naming rules
are those of ``squashfs``.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from . import lzo
from .squashfs import MAX_BYTES, MAX_DEPTH, MAX_FILE, MAX_FILES, Extracted, _safe

MAGIC = 0x1985
DIRENT, INODE, CLEANMARKER, PADDING, SUMMARY = 0xE001, 0xE002, 0x2003, 0x2004, 0x2006
HEADER = 12
DIRENT_SIZE, INODE_SIZE = 40, 68
NONE, ZERO, RTIME, COPY, ZLIB, LZO, LZMA = 0, 1, 2, 4, 6, 7, 8
# OpenWrt's LZMA compressor (target/linux/generic/pending-*/530-jffs2_make_lzma_available
# .patch): a raw LZMA1 stream with fixed properties and no end marker
_LZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 0, "pb": 0, "dict_size": 0x2000}]
ROOT = 1
S_IFMT, S_IFDIR, S_IFREG = 0o170000, 0o040000, 0o100000
MIN_NODES = 4               # a run of valid nodes this long is a file system, not chance
MAX_NODE = 1 << 20


def crc(data: bytes) -> int:
    """JFFS2's CRC-32: the reflected polynomial with seed 0 and no final inversion."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


@dataclass
class Found:
    offset: int
    little: bool

    @property
    def compression_name(self) -> str:
        return "jffs2-" + ("le" if self.little else "be")


def _header(data: bytes, at: int, little: bool) -> Optional[Tuple[int, int]]:
    """(node type, total length) of a node whose header CRC is right, else None."""
    if at + HEADER > len(data):
        return None
    e = "<" if little else ">"
    magic, kind, total, hcrc = struct.unpack_from(e + "HHII", data, at)
    if magic != MAGIC or total < HEADER or total > MAX_NODE or at + total > len(data):
        return None
    if crc(data[at:at + 8]) != hcrc:
        return None
    return kind, total


def find(data: bytes, limit: int = 4) -> List[Found]:
    """Where JFFS2 file systems start in *data*: the first of MIN_NODES consecutive nodes
    whose header CRCs are right. A second file system is looked for after the first one's
    last node."""
    out: List[Found] = []
    at = 0
    while at < len(data) and len(out) < limit:
        le = data.find(b"\x85\x19", at)
        be = data.find(b"\x19\x85", at)
        cands = [c for c in (le, be) if c >= 0]
        if not cands:
            break
        here = min(cands)
        if here % 4:
            at = here + 1
            continue
        little = here == le
        end = _run(data, here, little)
        if end is not None:
            out.append(Found(here, little))
            at = _last_node_end(data, here, little)
        else:
            at = here + 4
    return out


def _run(data: bytes, at: int, little: bool) -> Optional[int]:
    """The end of MIN_NODES nodes starting at *at* (erased flash between them skipped)."""
    for i in range(MIN_NODES):
        node = _header(data, at, little)
        if node is None:
            return None
        nxt = _next(data, at + node[1])
        if nxt is None:                                  # the data ends here
            return len(data) if i == MIN_NODES - 1 else None
        at = nxt
    return at


def _next(data: bytes, at: int) -> Optional[int]:
    """The next 4-byte aligned position after *at* that is not erased flash or padding."""
    at = (at + 3) & ~3
    while at + 4 <= len(data) and data[at:at + 4] in (b"\xff\xff\xff\xff", b"\0\0\0\0"):
        at += 4
    return at if at + HEADER <= len(data) else None


def _last_node_end(data: bytes, at: int, little: bool) -> int:
    end = at
    for pos, total, _ in _nodes(data, at, little):
        end = pos + total
    return max(end, at + 4)


def _nodes(data: bytes, start: int, little: bool):
    """(position, length, type) of every node with a right header CRC from *start*.
    Corrupt bytes are stepped over four at a time: one bad node does not hide the rest."""
    magic = b"\x85\x19" if little else b"\x19\x85"
    at = start
    while at + HEADER <= len(data):
        node = _header(data, at, little)
        if node is None:
            # erased flash and corrupt bytes are skipped to the next aligned magic number
            at = data.find(magic, at + 4)
            while at > 0 and at % 4:
                at = data.find(magic, at + 1)
            if at < 0:
                return
            continue
        yield at, node[1], node[0]
        at = (at + node[1] + 3) & ~3


# ------------------------------------------------------------ decompression

def _rtime(src: bytes, size: int) -> bytes:
    out = bytearray()
    positions = [0] * 256
    pos = 0
    while len(out) < size and pos + 1 < len(src):
        value = src[pos]
        repeat = src[pos + 1]
        pos += 2
        out.append(value)
        back = positions[value]
        positions[value] = len(out)
        for _ in range(repeat):
            if back >= len(out):
                break
            out.append(out[back])
            back += 1
    return bytes(out[:size])


def _inflate(kind: int, raw: bytes, size: int) -> Optional[bytes]:
    if kind in (NONE, COPY):
        return raw[:size]
    if kind == ZERO:
        return bytes(size)
    if kind == RTIME:
        return _rtime(raw, size)
    if kind == ZLIB:
        d = zlib.decompressobj()
        return d.decompress(raw, size)
    if kind == LZO:
        return lzo.decompress(raw, size)
    if kind == LZMA:
        return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=_LZMA_FILTERS).decompress(raw, size)
    return None


# ------------------------------------------------------------ reader

@dataclass
class _Inode:
    mode: int = 0
    size: int = 0
    version: int = -1
    pieces: List[Tuple[int, int, int, bytes]] = field(default_factory=list)  # ver, off, len, data


def extract(data: bytes, fs: Found, dest: Path, max_bytes: int = MAX_BYTES) -> Extracted:
    """Write the regular files of the JFFS2 file system starting at *fs* below *dest*."""
    result = Extracted(fs.offset, "jffs2")
    e = "<" if fs.little else ">"
    names: Dict[Tuple[int, bytes], Tuple[int, int, int]] = {}    # (parent, name) -> ver, ino, type
    inodes: Dict[int, _Inode] = {}
    unread = 0
    for at, total, kind in _nodes(data, fs.offset, fs.little):
        if kind == DIRENT and total >= DIRENT_SIZE:
            pino, version, ino, _t, nsize, dtype = struct.unpack_from(e + "IIIIBB", data, at + 12)
            node_crc, name_crc = struct.unpack_from(e + "II", data, at + 32)
            name = data[at + 40:at + 40 + nsize]
            if crc(data[at:at + 32]) != node_crc or crc(name) != name_crc:
                continue
            old = names.get((pino, name))
            if old is None or version > old[0]:
                names[(pino, name)] = (version, ino, dtype)
        elif kind == INODE and total >= INODE_SIZE:
            (ino, version, mode, _uid, _gid, isize, _a, _m, _c, offset, csize, dsize, compr,
             _uc, _fl, data_crc, node_crc) = struct.unpack_from(e + "IIIHHIIIIIIIBBHII", data, at + 12)
            if crc(data[at:at + 60]) != node_crc:
                continue
            raw = data[at + INODE_SIZE:at + INODE_SIZE + csize]
            node = inodes.setdefault(ino, _Inode())
            if version > node.version:
                node.version, node.mode, node.size = version, mode, isize
            if dsize == 0:
                continue
            if len(raw) != csize or (compr != ZERO and crc(raw) != data_crc):
                continue
            if dsize > MAX_FILE:
                continue
            try:
                body = _inflate(compr, raw, dsize)
            except Exception:          # each codec raises its own error type on corrupt input
                body = None
            if body is None:
                unread += 1
                continue
            node.pieces.append((version, offset, dsize, body))
    if unread:
        result.skipped.append(f"{unread} data node(s) compressed with a scheme not read here")

    children: Dict[int, List[Tuple[str, int, int]]] = {}
    for (parent, name), (_v, ino, dtype) in names.items():
        if ino == 0:
            continue                                   # a deletion
        children.setdefault(parent, []).append((name.decode("utf-8", "replace"), ino, dtype))
    dest.mkdir(parents=True, exist_ok=True)
    seen: Set[int] = set()
    stack = [(ROOT, dest, 0)]
    big = 0
    try:
        while stack:
            ino, here, depth = stack.pop()
            if ino in seen:
                continue
            seen.add(ino)
            for entry_name, child, dtype in sorted(children.get(ino, [])):
                if not _safe(entry_name):
                    continue
                inode = inodes.get(child)
                mode = inode.mode & S_IFMT if inode else 0
                if dtype == 4 or mode == S_IFDIR:
                    if depth + 1 < MAX_DEPTH:
                        (here / entry_name).mkdir(exist_ok=True)
                        stack.append((child, here / entry_name, depth + 1))
                    continue
                if inode is None or mode != S_IFREG:
                    continue
                if inode.size > MAX_FILE:
                    big += 1
                    continue
                if result.files >= MAX_FILES:
                    result.skipped.append(f"more than {MAX_FILES} files")
                    return result
                if result.bytes + inode.size > max_bytes:
                    result.skipped.append(f"more than {max_bytes >> 20} MiB of files")
                    return result
                out_bytes = bytearray(inode.size)
                for _v, offset, length, piece in sorted(inode.pieces, key=lambda p: p[0]):
                    end = min(offset + length, inode.size)
                    if offset < end:
                        out_bytes[offset:end] = piece[:end - offset]
                with open(here / entry_name, "wb") as fh:
                    fh.write(out_bytes)
                result.files += 1
                result.bytes += inode.size
    except OSError as exc:
        result.error = str(exc)
    if big:
        result.skipped.append(f"{big} file(s) over {MAX_FILE >> 20} MiB")
    return result
