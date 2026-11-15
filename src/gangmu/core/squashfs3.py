"""Read SquashFS 2.x and 3.x file systems, as older firmware carries them.

Routers, set-top boxes and cameras built before about 2010 (OpenWrt Kamikaze and White
Russian, many vendor SDKs) used SquashFS 2.x or 3.x, little-endian on x86 and ARM and
big-endian on MIPS. The layout is that of squashfs-tools 3.4's ``squashfs_fs.h``:
inodes and directory entries are packed bit fields, which in a little-endian image
fill each structure from its least significant bit and in a big-endian image from its
most significant bit (``SQUASHFS_SWAP``).

Mainline SquashFS 2.x/3.x compresses with zlib, but most firmware patched in LZMA,
with no way in the superblock to say so, and in several framings: raw LZMA with the
encoder's default properties (OpenWrt Kamikaze and White Russian), an ``.lzma`` header
of 13 bytes, or five property bytes and no size; sqlzma images mix zlib and LZMA block
by block. The decoder is chosen by which framing turns the first metadata block into
an inode table, and a block that starts like zlib is always tried with zlib first.
Vendors also changed the magic number (``shsq``, ``qshs``, ``sqlz``, ``hsqt``, ``tqsh``);
those are accepted when the rest of the superblock is consistent. The limits and the
naming rules are those of ``squashfs``.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from .squashfs import MAX_BYTES, MAX_DEPTH, MAX_FILE, MAX_FILES, MAX_TABLE, Extracted, _safe

MAGICS = (b"hsqs", b"sqsh", b"shsq", b"qshs", b"sqlz", b"hsqt", b"tqsh")
METADATA_SIZE = 8192
DIR, REG, SYMLINK, LDIR, LREG = 1, 2, 3, 8, 9
CHECK = 4                                       # flag: a check byte after each header
INVALID_FRAG = 0xFFFFFFFF


@dataclass
class Superblock:
    offset: int
    big: bool
    major: int
    minor: int
    block_size: int
    block_log: int
    flags: int
    root_inode: int
    fragments: int
    bytes_used: int
    inode_table: int
    directory_table: int
    fragment_table: int
    ends: Tuple[int, ...]                       # table starts after the directory table
    magic: bytes

    @property
    def describe(self) -> str:
        order = "big-endian" if self.big else "little-endian"
        vendor = "" if self.magic in (b"hsqs", b"sqsh") else f", magic {self.magic.decode()}"
        return f"{self.major}.{self.minor}, {order}{vendor}"


def _parse(data: bytes, at: int, big: bool) -> Optional[Superblock]:
    e = ">" if big else "<"
    if at + 119 > len(data):
        return None
    (_magic, inodes, used2, uid2, guid2, inode2, dir2) = struct.unpack_from(e + "7I", data, at)
    major, minor, _bs1, block_log = struct.unpack_from(e + "4H", data, at + 28)
    flags = data[at + 36]
    root, = struct.unpack_from(e + "Q", data, at + 43)
    block_size, fragments, frag2 = struct.unpack_from(e + "3I", data, at + 51)
    ends: Tuple[int, ...]
    if major == 3 and minor <= 1:
        used, uid, guid, inode, dirt, frag, lookup = struct.unpack_from(e + "7q", data, at + 63)
        ends = (frag, lookup, uid, guid, used)
    elif major == 2 and minor <= 1:
        used, uid, guid, inode, dirt, frag = used2, uid2, guid2, inode2, dir2, frag2
        ends = (frag, uid, guid, used)
    else:
        return None
    if (not 12 <= block_log <= 20 or block_size != 1 << block_log or inodes == 0
            or not 0 < inode < dirt < used or at + used > len(data)):
        return None
    return Superblock(at, big, major, minor, block_size, block_log, flags, root, fragments,
                      used, inode, dirt, frag, tuple(v for v in ends if dirt < v <= used),
                      data[at:at + 4])


def superblock_at(data: bytes, at: int) -> Optional[Superblock]:
    """A SquashFS 2.x/3.x superblock at *at*, in whichever byte order makes it consistent."""
    if data[at:at + 4] not in MAGICS:
        return None
    for big in (data[at:at + 4] == b"sqsh", data[at:at + 4] != b"sqsh"):
        sb = _parse(data, at, big)
        if sb is not None:
            return sb
    return None


def find(data: bytes, limit: int = 8) -> List[Superblock]:
    out: List[Superblock] = []
    for magic in MAGICS:
        at = data.find(magic)
        while at >= 0 and len(out) < limit:
            sb = superblock_at(data, at)
            if sb is not None:
                out.append(sb)
            at = data.find(magic, at + 4)
    return sorted(out, key=lambda s: s.offset)


# ------------------------------------------------------------ decompression

Codec = Callable[[bytes, int], bytes]


def _raw(lc: int, lp: int, pb: int) -> Codec:
    filters = [{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": 1 << 23}]
    return lambda raw, most: lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters) \
        .decompress(raw, most)


def _alone(raw: bytes, most: int) -> bytes:
    return lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(raw, most)


def _props_only(raw: bytes, most: int) -> bytes:
    """Five property bytes (lc/lp/pb and the dictionary size), then the raw stream."""
    if len(raw) < 6 or raw[0] >= 225:
        raise ValueError("no LZMA properties")
    p = raw[0]
    lc, lp, pb = p % 9, (p // 9) % 5, p // 45
    dict_size, = struct.unpack_from("<I", raw, 1)
    filters = [{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb,
                "dict_size": max(dict_size, 4096)}]
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters).decompress(raw[5:], most)


def _zlib(raw: bytes, most: int) -> bytes:
    d = zlib.decompressobj()
    return d.decompress(raw, most)


# (name, codec), in the order tried on the first metadata block
CODECS: Tuple[Tuple[str, Codec], ...] = (
    ("zlib", _zlib),
    ("lzma", _raw(3, 0, 2)),                    # the encoder's defaults, no header
    ("lzma, .lzma header", _alone),
    ("lzma, properties", _props_only),
    ("lzma, lc=0 lp=0 pb=0", _raw(0, 0, 0)),
    ("lzma, lc=1 lp=2 pb=2", _raw(1, 2, 2)),
)


def _zlib_first(codec: Codec) -> Codec:
    """sqlzma images keep blocks LZMA would not shrink in zlib; their first byte says so."""
    def decode(raw: bytes, most: int) -> bytes:
        if raw[:1] == b"\x78":
            try:
                out = _zlib(raw, most)
                if out:
                    return out
            except zlib.error:
                pass
        return codec(raw, most)
    return decode


# ------------------------------------------------------------ reader

class _Bits:
    """The packed bit fields of one structure: from the least significant bit of a
    little-endian number, or from the most significant bit of a big-endian one."""

    def __init__(self, data: bytes, at: int, size: int, big: bool):
        self.n = int.from_bytes(data[at:at + size], "big" if big else "little")
        self.total = size * 8
        self.big = big

    def get(self, pos: int, width: int) -> int:
        shift = self.total - pos - width if self.big else pos
        return (self.n >> shift) & ((1 << width) - 1)


class SquashfsError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes, sb: Superblock):
        self.data, self.sb = data, sb
        self.base = sb.offset
        self.e = ">" if sb.big else "<"
        self.codec: Codec = self._choose()
        self.inodes, self.inode_at = self._table(sb.inode_table, sb.directory_table)
        end = min(self._directory_end(), sb.bytes_used)
        self.dirs, self.dir_at = self._table(sb.directory_table, end)
        self._fragments: Optional[List[Tuple[int, int]]] = None
        self._fragment_blocks: Dict[int, bytes] = {}

    # -- metadata
    def _header(self, at: int) -> Tuple[int, bool, int]:
        """(size, compressed, start of the bytes) of the metadata block at *at*."""
        pos = self.base + at
        word, = struct.unpack_from(self.e + "H", self.data, pos)
        size = word & 0x7FFF or 0x8000
        start = pos + 2 + (1 if self.sb.flags & CHECK else 0)
        return size, not word & 0x8000, start

    def _choose(self) -> Codec:
        size, compressed, start = self._header(self.sb.inode_table)
        raw = self.data[start:start + size]
        if not compressed:
            return _zlib_first(_raw(3, 0, 2))          # nothing to tell from: the usual pair
        for _name, codec in CODECS:
            try:
                out = codec(raw, METADATA_SIZE)
            except Exception:                           # each codec raises its own errors
                continue
            if out and self._looks_like_inode(out):
                self.codec_name = _name
                return codec if _name == "zlib" else _zlib_first(codec)
        raise SquashfsError("compressed with a scheme not read here")

    def _looks_like_inode(self, block: bytes) -> bool:
        kind = _Bits(block, 0, 2, self.sb.big).get(0, 4)
        return 1 <= kind <= 9

    def _metadata(self, at: int) -> Tuple[bytes, int]:
        size, compressed, start = self._header(at)
        raw = self.data[start:start + size]
        if len(raw) != size:
            raise SquashfsError("truncated metadata block")
        block = self.codec(raw, METADATA_SIZE) if compressed else raw
        if len(block) > METADATA_SIZE:
            raise SquashfsError("metadata block too large")
        return block, start - self.base + size

    def _table(self, start: int, end: int) -> Tuple[bytes, Dict[int, int]]:
        out = bytearray()
        where: Dict[int, int] = {}
        at = start
        while at < end:
            where[at - start] = len(out)
            block, at = self._metadata(at)
            out += block
            if len(out) > MAX_TABLE:
                raise SquashfsError("metadata table too large")
        return bytes(out), where

    def _directory_end(self) -> int:
        """The first metadata block of whichever table follows the directory table."""
        sb = self.sb
        ends = list(sb.ends)
        if sb.fragments and sb.directory_table < sb.fragment_table < sb.bytes_used:
            width = 8 if sb.major == 3 else 4
            first, = struct.unpack_from(self.e + ("Q" if width == 8 else "I"), self.data,
                                        self.base + sb.fragment_table)
            if sb.directory_table < first <= sb.fragment_table:
                ends.append(first)
        return min(ends) if ends else sb.bytes_used

    def _locate(self, table: bytes, where: Dict[int, int], block: int, offset: int) -> int:
        if block not in where:
            raise SquashfsError("reference to a metadata block that does not exist")
        pos = where[block] + offset
        if pos >= len(table):
            raise SquashfsError("reference past the end of a table")
        return pos

    def inode(self, ref: int) -> Tuple[int, int]:
        pos = self._locate(self.inodes, self.inode_at, ref >> 16, ref & 0xFFFF)
        return _Bits(self.inodes, pos, 2, self.sb.big).get(0, 4), pos

    # -- directories
    def _dir_inode(self, pos: int, kind: int) -> Tuple[int, int, int]:
        """(listing size, start block, offset) of a directory inode."""
        v3 = self.sb.major == 3
        if kind == DIR:
            b = _Bits(self.inodes, pos, 28 if v3 else 15, self.sb.big)
            if v3:
                return b.get(128, 19) - 3, b.get(160, 32), b.get(147, 13)
            return b.get(32, 19), b.get(96, 24), b.get(51, 13)
        b = _Bits(self.inodes, pos, 31 if v3 else 18, self.sb.big)
        if v3:
            return b.get(128, 27) - 3, b.get(168, 32), b.get(155, 13)
        return b.get(32, 27), b.get(104, 24), b.get(59, 13)

    def entries(self, pos: int, kind: int):
        size, start, offset = self._dir_inode(pos, kind)
        if size <= 0:
            return
        at = self._locate(self.dirs, self.dir_at, start, offset)
        end = at + size
        if end > len(self.dirs):
            raise SquashfsError("directory past the end of the directory table")
        v3 = self.sb.major == 3
        head, entry = (9, 5) if v3 else (4, 3)
        while at + head <= end:
            h = _Bits(self.dirs, at, head, self.sb.big)
            count, block = h.get(0, 8) + 1, h.get(8, 32 if v3 else 24)
            at += head
            for _ in range(count):
                if at + entry > end:
                    raise SquashfsError("truncated directory")
                d = _Bits(self.dirs, at, entry, self.sb.big)
                ioff, dtype, nsize = d.get(0, 13), d.get(13, 3), d.get(16, 8)
                at += entry
                name = self.dirs[at:at + nsize + 1]
                at += nsize + 1
                yield name.decode("utf-8", "replace"), (block << 16) | ioff, dtype

    # -- files
    def _fragment(self, index: int) -> Tuple[int, int]:
        if self._fragments is None:
            v3 = self.sb.major == 3
            size = 16 if v3 else 8
            per = METADATA_SIZE // size
            out: List[Tuple[int, int]] = []
            blocks = (self.sb.fragments + per - 1) // per
            for i in range(blocks):
                ptr, = struct.unpack_from(self.e + ("Q" if v3 else "I"), self.data,
                                          self.base + self.sb.fragment_table + i * (8 if v3 else 4))
                table, _ = self._metadata(ptr)
                for j in range(0, len(table) - size + 1, size):
                    if v3:
                        start, length = struct.unpack_from(self.e + "QI", table, j)
                    else:
                        start, length = struct.unpack_from(self.e + "II", table, j)
                    out.append((start, length))
            self._fragments = out
        if index >= len(self._fragments):
            raise SquashfsError("fragment index out of range")
        return self._fragments[index]

    def _data_block(self, start: int, word: int, want: int) -> bytes:
        size = word & 0xFFFFFF
        if size == 0:
            return bytes(want)
        if size > (1 << 20) + 64:
            raise SquashfsError("data block too large")
        raw = self.data[self.base + start:self.base + start + size]
        if len(raw) != size:
            raise SquashfsError("truncated data block")
        return raw if word & 0x1000000 else self.codec(raw, self.sb.block_size)

    def read_file(self, pos: int, kind: int) -> Tuple[int, Optional[bytes]]:
        v3 = self.sb.major == 3
        if kind == REG and v3:
            b = _Bits(self.inodes, pos, 32, self.sb.big)
            start, fragment, frag_off, size = b.get(96, 64), b.get(160, 32), b.get(192, 32), \
                b.get(224, 32)
            lists = pos + 32
        elif kind == REG:
            b = _Bits(self.inodes, pos, 24, self.sb.big)
            start, fragment, frag_off, size = b.get(64, 32), b.get(96, 32), b.get(128, 32), \
                b.get(160, 32)
            lists = pos + 24
        else:                                            # LREG, 3.x only
            b = _Bits(self.inodes, pos, 40, self.sb.big)
            start, fragment, frag_off, size = b.get(128, 64), b.get(192, 32), b.get(224, 32), \
                b.get(256, 64)
            lists = pos + 40
        if size > MAX_FILE:
            return size, None
        bs = self.sb.block_size
        has_fragment = fragment != INVALID_FRAG
        blocks = size // bs if has_fragment else (size + bs - 1) // bs
        if lists + 4 * blocks > len(self.inodes):
            raise SquashfsError("block list past the end of the inode table")
        out = bytearray()
        at = start
        for i in range(blocks):
            word, = struct.unpack_from(self.e + "I", self.inodes, lists + 4 * i)
            out += self._data_block(at, word, min(bs, size - len(out)))[:size - len(out)]
            at += word & 0xFFFFFF
        if has_fragment and len(out) < size:
            frag = self._fragment_blocks.get(fragment)
            if frag is None:
                if len(self._fragment_blocks) >= 16:
                    self._fragment_blocks.clear()
                fstart, fword = self._fragment(fragment)
                frag = self._data_block(fstart, fword, bs)
                self._fragment_blocks[fragment] = frag
            out += frag[frag_off:frag_off + size - len(out)]
        if len(out) != size:
            raise SquashfsError("file shorter than its inode says")
        return size, bytes(out)


def extract(data: bytes, sb: Superblock, dest: Path, max_bytes: int = MAX_BYTES) -> Extracted:
    """Write the regular files of the SquashFS 2.x/3.x file system at *sb* below *dest*."""
    result = Extracted(sb.offset, f"SquashFS {sb.describe}")
    try:
        reader = _Reader(data, sb)
        result.compression = getattr(reader, "codec_name", "uncompressed")
        kind, pos = reader.inode(sb.root_inode)
        if kind not in (DIR, LDIR):
            raise SquashfsError("the root inode is not a directory")
    except (SquashfsError, struct.error, zlib.error, lzma.LZMAError, ValueError,
            EOFError) as exc:
        result.error = str(exc) or type(exc).__name__
        return result
    dest.mkdir(parents=True, exist_ok=True)
    seen: Set[int] = set()
    big = 0
    stack: List[Tuple[int, int, Path, int]] = [(kind, pos, dest, 0)]
    try:
        while stack:
            kind, pos, here, depth = stack.pop()
            if pos in seen:
                continue
            seen.add(pos)
            for entry_name, ref, _ in reader.entries(pos, kind):
                if not _safe(entry_name):
                    continue
                child_kind, child_pos = reader.inode(ref)
                if child_kind in (DIR, LDIR):
                    if depth + 1 < MAX_DEPTH:
                        (here / entry_name).mkdir(exist_ok=True)
                        stack.append((child_kind, child_pos, here / entry_name, depth + 1))
                    continue
                if child_kind not in (REG, LREG) or (child_kind == LREG and sb.major != 3):
                    continue
                if result.files >= MAX_FILES:
                    result.skipped.append(f"more than {MAX_FILES} files")
                    return result
                size, body = reader.read_file(child_pos, child_kind)
                if body is None:
                    big += 1
                    continue
                if result.bytes + size > max_bytes:
                    result.skipped.append(f"more than {max_bytes >> 20} MiB of files")
                    return result
                with open(here / entry_name, "wb") as fh:
                    fh.write(body)
                result.files += 1
                result.bytes += size
    except (SquashfsError, struct.error, zlib.error, lzma.LZMAError, ValueError, EOFError,
            OSError) as exc:
        result.error = str(exc) or type(exc).__name__
    if big:
        result.skipped.append(f"{big} file(s) over {MAX_FILE >> 20} MiB")
    return result


def label(offset: int) -> str:
    return f"!squashfs@{offset:#x}"
