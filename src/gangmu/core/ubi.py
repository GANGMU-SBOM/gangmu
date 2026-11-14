"""Read UBI volumes and UBIFS file systems out of a firmware image.

NAND-based routers, cameras and gateways store their file systems in UBI: the flash is
cut into physical eraseblocks, each starting with an erase-counter header (``UBI#``)
and a volume-identifier header (``UBI!``) that say which volume and which logical block
it holds. A volume is its logical blocks put back in order. A volume holds UBIFS (the
writable file system) or a read-only image such as SquashFS (OpenWrt's NAND layout).

UBIFS is read without its on-flash index: every node of every logical block is scanned,
and for each key (an inode, a directory entry, a 4 KiB data block) the node with the
highest sequence number wins. That is also right for a dump of a live device, whose
newest nodes are still in the journal and not in the index. A directory entry pointing
to inode 0 is a deletion. Data is read when stored uncompressed, with zlib or with LZO
(the built-in decoder); zstd when ``zstandard`` is installed. Headers and nodes are checked
against their CRCs. The limits and the naming rules are those of ``squashfs``.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from . import lzo
from .squashfs import MAX_BYTES, MAX_DEPTH, MAX_FILE, MAX_FILES, Extracted, _safe

EC_MAGIC, VID_MAGIC = b"UBI#", b"UBI!"
LAYOUT_VOLUME = 0x7FFFEFFF
VTBL_RECORD = 172
MAX_VOLUMES = 128
MAX_VOLUME_BYTES = 512 * 1024 * 1024

UBIFS_MAGIC = 0x06101831
INO, DATA, DENT, SB = 0, 1, 2, 6
BLOCK = 4096
ROOT = 1
DENT_DIR, DENT_REG = 1, 0
S_IFMT, S_IFREG = 0o170000, 0o100000
NONE, LZO, ZLIB, ZSTD = 0, 1, 2, 3
MAX_NODE = 1 << 20


def crc(data: bytes) -> int:
    """UBI's and UBIFS's CRC-32: seed 0xFFFFFFFF, no final inversion."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


# ------------------------------------------------------------ UBI

@dataclass
class Volume:
    name: str
    vol_id: int
    data: bytes


@dataclass
class UbiImage:
    offset: int
    peb_size: int
    volumes: List[Volume] = field(default_factory=list)


def _ec_header(data: bytes, at: int) -> Optional[Tuple[int, int]]:
    """(VID header offset, data offset) of a valid erase-counter header at *at*."""
    if data[at:at + 4] != EC_MAGIC or at + 64 > len(data):
        return None
    if crc(data[at:at + 60]) != struct.unpack_from(">I", data, at + 60)[0]:
        return None
    vid, start = struct.unpack_from(">II", data, at + 16)
    return vid, start


def _vid_header(data: bytes, at: int) -> Optional[Tuple[int, int]]:
    """(volume id, logical block) of a valid volume-identifier header at *at*."""
    if data[at:at + 4] != VID_MAGIC or at + 64 > len(data):
        return None
    if crc(data[at:at + 60]) != struct.unpack_from(">I", data, at + 60)[0]:
        return None
    vol_id, lnum = struct.unpack_from(">II", data, at + 8)
    return vol_id, lnum


def find_ubi(data: bytes) -> Optional[int]:
    """Where the first UBI eraseblock with a valid header is, or None."""
    at = data.find(EC_MAGIC)
    while at >= 0:
        if _ec_header(data, at) is not None:
            return at
        at = data.find(EC_MAGIC, at + 4)
    return None


def read_ubi(data: bytes, start: int) -> Optional[UbiImage]:
    """Every volume of the UBI image starting at *start*, rebuilt from its eraseblocks.
    The eraseblock size is the smallest distance between valid erase-counter headers."""
    heads: List[int] = []
    at = start
    while at >= 0 and len(heads) < 65536:
        if _ec_header(data, at) is not None:
            heads.append(at)
        at = data.find(EC_MAGIC, at + 4)
    if len(heads) < 2:
        return None
    gaps = [b - a for a, b in zip(heads, heads[1:]) if b > a]
    peb = min(gaps)
    if peb < 1024 or peb & (peb - 1):
        return None
    blocks: Dict[int, Dict[int, Tuple[int, bytes]]] = {}       # vol -> lnum -> (sqnum, data)
    for head in heads:
        if (head - start) % peb:
            continue
        hdr = _ec_header(data, head)
        if hdr is None:
            continue
        vid_at, data_at = hdr
        v = head + vid_at
        if data[v:v + 4] != VID_MAGIC or v + 64 > len(data):
            continue                                     # an empty (erased) block
        if crc(data[v:v + 60]) != struct.unpack_from(">I", data, v + 60)[0]:
            continue
        vol_type = data[v + 5]
        vol_id, lnum = struct.unpack_from(">II", data, v + 8)
        data_size = struct.unpack_from(">I", data, v + 16)[0]
        sqnum = struct.unpack_from(">Q", data, v + 40)[0]
        body = data[head + data_at:head + peb]
        if vol_type == 2 and data_size:                  # static volume: only data_size used
            body = body[:data_size]
        old = blocks.setdefault(vol_id, {}).get(lnum)
        if old is None or sqnum > old[0]:
            blocks[vol_id][lnum] = (sqnum, body)
    names: Dict[int, str] = {}
    if LAYOUT_VOLUME in blocks and 0 in blocks[LAYOUT_VOLUME]:
        table = blocks[LAYOUT_VOLUME][0][1]
        for i in range(min(MAX_VOLUMES, len(table) // VTBL_RECORD)):
            rec = table[i * VTBL_RECORD:(i + 1) * VTBL_RECORD]
            if crc(rec[:-4]) != struct.unpack_from(">I", rec, VTBL_RECORD - 4)[0]:
                continue
            reserved, = struct.unpack_from(">I", rec, 0)
            nlen, = struct.unpack_from(">H", rec, 14)
            if reserved and 0 < nlen <= 127:
                names[i] = rec[16:16 + nlen].decode("utf-8", "replace")
    image = UbiImage(start, peb)
    for vol_id in sorted(v for v in blocks if v != LAYOUT_VOLUME and v < MAX_VOLUMES):
        lebs = blocks[vol_id]
        leb_size = max(len(b) for _, b in lebs.values())
        last = max(lebs)
        if (last + 1) * leb_size > MAX_VOLUME_BYTES:
            continue
        out = bytearray(b"\xff" * ((last + 1) * leb_size))
        for lnum, (_, body) in lebs.items():
            out[lnum * leb_size:lnum * leb_size + len(body)] = body
        image.volumes.append(Volume(names.get(vol_id, f"volume{vol_id}"), vol_id, bytes(out)))
    return image


# ------------------------------------------------------------ UBIFS

def is_ubifs(data: bytes, at: int = 0) -> Optional[int]:
    """The logical-block size of a UBIFS whose superblock node is at *at*, else None."""
    node = _node(data, at)
    if node is None or node[0] != SB:
        return None
    leb_size, = struct.unpack_from("<I", data, at + 36)
    return leb_size if 15 * 1024 <= leb_size <= 4 * 1024 * 1024 else None


def _node(data: bytes, at: int) -> Optional[Tuple[int, int, int]]:
    """(type, length, sequence number) of a UBIFS node with a right CRC at *at*."""
    if at + 24 > len(data):
        return None
    magic, ncrc, sqnum, length, kind = struct.unpack_from("<IIQIB", data, at)
    if magic != UBIFS_MAGIC or length < 24 or length > MAX_NODE or at + length > len(data):
        return None
    if crc(data[at + 8:at + length]) != ncrc:
        return None
    return kind, length, sqnum


def _inflate(kind: int, raw: bytes, size: int) -> Optional[bytes]:
    if kind == NONE:
        return raw[:size]
    if kind == ZLIB:
        return zlib.decompressobj(-15).decompress(raw, size)
    if kind == LZO:
        return lzo.decompress(raw, size)
    if kind == ZSTD:
        try:
            import zstandard  # type: ignore[import-not-found]
        except ImportError:
            return None
        return zstandard.ZstdDecompressor().decompress(raw, max_output_size=size)
    return None


@dataclass
class _Inode:
    sqnum: int
    size: int
    mode: int


def extract_ubifs(data: bytes, leb_size: int, dest: Path, offset: int = 0,
                  max_bytes: int = MAX_BYTES) -> Extracted:
    """Write the regular files of the UBIFS in *data* (its logical blocks back to back,
    each *leb_size* long) below *dest*."""
    result = Extracted(offset, "ubifs")
    inodes: Dict[int, _Inode] = {}
    names: Dict[Tuple[int, bytes], Tuple[int, int, int]] = {}      # -> sqnum, inum, type
    blocks: Dict[Tuple[int, int], Tuple[int, int, int, int]] = {}  # (inum, block) -> sqnum, at, len, size
    for leb in range(0, len(data), leb_size):
        at, end = leb, min(leb + leb_size, len(data))
        while at + 24 <= end:
            node = _node(data, at)
            if node is None:
                at += 8
                continue
            kind, length, sqnum = node
            if kind in (INO, DATA, DENT):
                inum, word = struct.unpack_from("<II", data, at + 24)
                if kind == INO:
                    size, = struct.unpack_from("<Q", data, at + 48)
                    mode, = struct.unpack_from("<I", data, at + 104)
                    old = inodes.get(inum)
                    if old is None or sqnum > old.sqnum:
                        inodes[inum] = _Inode(sqnum, size, mode)
                elif kind == DATA:
                    size, compr = struct.unpack_from("<IH", data, at + 40)
                    key = (inum, word & 0x1FFFFFFF)
                    old_b = blocks.get(key)
                    if old_b is None or sqnum > old_b[0]:
                        blocks[key] = (sqnum, at, length, (compr << 32) | size)
                else:
                    child, = struct.unpack_from("<Q", data, at + 40)
                    dtype, nlen = data[at + 49], struct.unpack_from("<H", data, at + 50)[0]
                    name = data[at + 56:at + 56 + nlen]
                    old_n = names.get((inum, name))
                    if old_n is None or sqnum > old_n[0]:
                        names[(inum, name)] = (sqnum, child, dtype)
            at += (length + 7) & ~7
    children: Dict[int, List[Tuple[str, int, int]]] = {}
    for (parent, name), (_s, child, dtype) in names.items():
        if child:
            children.setdefault(parent, []).append((name.decode("utf-8", "replace"), child, dtype))
    dest.mkdir(parents=True, exist_ok=True)
    seen: Set[int] = set()
    stack = [(ROOT, dest, 0)]
    unread = big = 0
    try:
        while stack:
            inum, here, depth = stack.pop()
            if inum in seen:
                continue
            seen.add(inum)
            for entry_name, child, dtype in sorted(children.get(inum, [])):
                if not _safe(entry_name):
                    continue
                if dtype == DENT_DIR:
                    if depth + 1 < MAX_DEPTH:
                        (here / entry_name).mkdir(exist_ok=True)
                        stack.append((child, here / entry_name, depth + 1))
                    continue
                ino = inodes.get(child)
                if dtype != DENT_REG or ino is None or ino.mode & S_IFMT != S_IFREG:
                    continue
                if ino.size > MAX_FILE:
                    big += 1
                    continue
                if result.files >= MAX_FILES:
                    result.skipped.append(f"more than {MAX_FILES} files")
                    return result
                if result.bytes + ino.size > max_bytes:
                    result.skipped.append(f"more than {max_bytes >> 20} MiB of files")
                    return result
                body = bytearray(ino.size)
                for block in range((ino.size + BLOCK - 1) // BLOCK):
                    entry = blocks.get((child, block))
                    if entry is None:
                        continue                         # a hole
                    _s, at, length, packed = entry
                    piece = _safe_inflate(packed >> 32, data[at + 48:at + length],
                                          packed & 0xFFFFFFFF)
                    if piece is None:
                        unread += 1
                        continue
                    start = block * BLOCK
                    stop = min(start + len(piece), ino.size)
                    body[start:stop] = piece[:stop - start]
                with open(here / entry_name, "wb") as fh:
                    fh.write(body)
                result.files += 1
                result.bytes += ino.size
    except OSError as exc:
        result.error = str(exc)
    if unread:
        result.skipped.append(f"{unread} data block(s) compressed with a scheme not read here")
    if big:
        result.skipped.append(f"{big} file(s) over {MAX_FILE >> 20} MiB")
    return result


def _safe_inflate(kind: int, raw: bytes, size: int) -> Optional[bytes]:
    if size > BLOCK:
        return None
    try:
        return _inflate(kind, raw, size)
    except Exception:          # each codec raises its own error type on corrupt input
        return None
