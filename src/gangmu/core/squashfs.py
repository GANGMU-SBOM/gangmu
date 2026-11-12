"""Read a SquashFS 4.0 file system out of a firmware image.

Most Linux-class firmware (OpenWrt, Yocto and Buildroot builds, IP cameras, gateways)
ships its root file system as SquashFS inside the flash image. What is installed is
written there: the package manager's database (``usr/lib/opkg/status``), the programs
and libraries with their version banners. None of it can be read until the file system
is: its data and metadata are compressed in independent blocks.

This module finds SquashFS 4.0 superblocks in a byte string and extracts the regular
files below a directory, so the rest of the scan reads them like any other tree. Only
the standard library is needed for gzip, xz and LZMA, which is what OpenWrt, Yocto and
Buildroot use by default; LZ4 and zstd are read when the ``lz4`` and ``zstandard``
packages are installed (``pip install 'gangmu-sbom[firmware]'``), LZO when
``python-lzo`` is. Older SquashFS versions (2.x, 3.x) and vendor variants with changed
magic numbers or LZMA settings are not read.

Every limit is enforced while reading, so a corrupt or hostile image cannot exhaust
memory or disk: total bytes written, files written, directory depth, and the size of any
one block. Names are written as plain path components: an entry named ``..`` or holding a
slash is skipped, and symbolic links, device nodes and the like are not created.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

MAGIC = b"hsqs"                       # SquashFS 4.0 is little-endian only
SUPERBLOCK = struct.Struct("<IIIIIHHHHHHQQQQQQQQ")   # 96 bytes
METADATA_SIZE = 8192
MAX_BLOCK = 1 << 20                   # SquashFS block sizes run from 4 KiB to 1 MiB

MAX_BYTES = 512 * 1024 * 1024         # written out of one image, all files together
MAX_FILE = 64 * 1024 * 1024           # one file; larger ones are skipped
MAX_FILES = 50_000
MAX_DEPTH = 32
MAX_TABLE = 64 * 1024 * 1024          # decompressed inode or directory table

GZIP, LZMA, LZO, XZ, LZ4, ZSTD = 1, 2, 3, 4, 5, 6
COMPRESSION_NAMES = {GZIP: "gzip", LZMA: "lzma", LZO: "lzo", XZ: "xz", LZ4: "lz4",
                     ZSTD: "zstd"}

DIR, REG, SYMLINK, LDIR, LREG = 1, 2, 3, 8, 9


class SquashfsError(ValueError):
    pass


@dataclass
class Superblock:
    offset: int                      # where the file system starts in the image
    inodes: int
    block_size: int
    fragments: int
    compression: int
    flags: int
    root_inode: int
    bytes_used: int
    inode_table: int
    directory_table: int
    fragment_table: int

    @property
    def compression_name(self) -> str:
        return COMPRESSION_NAMES.get(self.compression, f"#{self.compression}")


@dataclass
class Extracted:
    offset: int
    compression: str
    files: int = 0
    bytes: int = 0
    skipped: List[str] = field(default_factory=list)    # why some content was left out
    error: Optional[str] = None                          # why reading stopped early


def superblock_at(data: bytes, at: int) -> Optional[Superblock]:
    if at + SUPERBLOCK.size > len(data):
        return None
    (magic, inodes, _mtime, block_size, fragments, compression, block_log, flags, _ids,
     major, minor, root, used, _id_table, _xattr, inode_table, dir_table, frag_table,
     _lookup) = SUPERBLOCK.unpack_from(data, at)
    if (magic != 0x73717368 or major != 4 or minor != 0
            or not 12 <= block_log <= 20 or block_size != 1 << block_log
            or compression not in COMPRESSION_NAMES
            or not SUPERBLOCK.size < inode_table < dir_table <= used
            or at + used > len(data) or inodes == 0):
        return None
    return Superblock(at, inodes, block_size, fragments, compression, flags, root, used,
                      inode_table, dir_table, frag_table)


def find(data: bytes, limit: int = 8) -> List[Superblock]:
    """The SquashFS 4.0 file systems in *data*, by a superblock that is consistent with
    the bytes after it (version, block size, table order, length within the data)."""
    out: List[Superblock] = []
    at = data.find(MAGIC)
    while at >= 0 and len(out) < limit:
        sb = superblock_at(data, at)
        if sb is not None:
            out.append(sb)
            at = data.find(MAGIC, at + max(sb.bytes_used, 4))
        else:
            at = data.find(MAGIC, at + 4)
    return out


# ------------------------------------------------------------ decompression

def _optional(name: str):
    try:
        return __import__(name, fromlist=["_"])
    except ImportError:
        return None


def decompressor(compression: int) -> Optional[Callable[[bytes, int], bytes]]:
    """``f(block, most)`` for a compression id, or None when nothing installed reads it."""
    if compression == GZIP:
        def gz(block: bytes, most: int) -> bytes:
            d = zlib.decompressobj()
            out = d.decompress(block, most)
            if d.unconsumed_tail:
                raise SquashfsError("block larger than the file system allows")
            return out
        return gz
    if compression in (XZ, LZMA):
        fmt = lzma.FORMAT_XZ if compression == XZ else lzma.FORMAT_ALONE

        def xz(block: bytes, most: int) -> bytes:
            out = lzma.LZMADecompressor(fmt).decompress(block, most)
            return out
        return xz
    if compression == LZ4:
        lz4 = _optional("lz4.block")
        if lz4 is None:
            return None
        return lambda block, most: lz4.decompress(block, uncompressed_size=most)
    if compression == ZSTD:
        zstd = _optional("zstandard")
        if zstd is None:
            return None
        return lambda block, most: zstd.ZstdDecompressor().decompress(block, max_output_size=most)
    if compression == LZO:
        lzo = _optional("lzo")
        if lzo is None:
            return None
        return lambda block, most: lzo.decompress(block, False, most)
    return None


# ------------------------------------------------------------ reader

class _Reader:
    def __init__(self, data: bytes, sb: Superblock, inflate: Callable[[bytes, int], bytes]):
        self.data = data
        self.sb = sb
        self.base = sb.offset
        self.inflate = inflate
        self.inodes, self.inode_at = self._table(sb.inode_table, sb.directory_table)
        end = self._directory_table_end()
        self.dirs, self.dir_at = self._table(sb.directory_table, end)
        self._fragments: Optional[List[Tuple[int, int]]] = None
        self._fragment_blocks: Dict[int, bytes] = {}      # many small files share one

    # -- metadata
    def _metadata(self, at: int) -> Tuple[bytes, int]:
        """The decompressed metadata block at file-system offset *at*, and the offset
        of the next one."""
        pos = self.base + at
        if pos + 2 > len(self.data):
            raise SquashfsError("metadata block past the end")
        header = struct.unpack_from("<H", self.data, pos)[0]
        size = header & 0x7FFF
        raw = self.data[pos + 2:pos + 2 + size]
        if len(raw) != size or size == 0:
            raise SquashfsError("truncated metadata block")
        block = raw if header & 0x8000 else self.inflate(raw, METADATA_SIZE)
        if len(block) > METADATA_SIZE:
            raise SquashfsError("metadata block too large")
        return block, at + 2 + size

    def _table(self, start: int, end: int) -> Tuple[bytes, Dict[int, int]]:
        """A metadata table as one buffer, with where each block (by its offset from the
        table's start, which is what inode and directory references give) begins in it."""
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

    def _directory_table_end(self) -> int:
        """Where the directory table stops: at the first metadata block of whichever table
        follows it (fragments, export, ids or xattrs; each superblock field points at an
        index whose first entry is that block)."""
        sb = self.sb
        ends = []
        for field_at in (48, 56, 80, 88):          # id, xattr, fragment, export tables
            table = self._u64_at(field_at)
            if sb.directory_table < table < sb.bytes_used:
                first = self._u64_at(table)
                ends.append(first if sb.directory_table < first <= table else table)
        return min(ends) if ends else sb.bytes_used

    def _u64_at(self, at: int) -> int:
        pos = self.base + at
        if pos + 8 > len(self.data):
            return 0
        return struct.unpack_from("<Q", self.data, pos)[0]

    def _locate(self, table: bytes, where: Dict[int, int], ref_block: int, offset: int) -> int:
        if ref_block not in where:
            raise SquashfsError("reference to a metadata block that does not exist")
        pos = where[ref_block] + offset
        if pos >= len(table):
            raise SquashfsError("reference past the end of a table")
        return pos

    def inode(self, ref: int) -> Tuple[int, int]:
        """(inode type, position in the inode buffer) for an inode reference."""
        pos = self._locate(self.inodes, self.inode_at, ref >> 16, ref & 0xFFFF)
        return struct.unpack_from("<H", self.inodes, pos)[0], pos

    # -- directories
    def entries(self, pos: int, kind: int) -> Iterator[Tuple[str, int, int]]:
        """(name, inode reference, type) of each entry of the directory inode at *pos*."""
        body = pos + 16
        if kind == DIR:
            start, _nlink, size, offset, _parent = struct.unpack_from("<IIHHI", self.inodes, body)
        else:
            _nlink, size, start, _parent, _count, offset, _xattr = struct.unpack_from(
                "<IIIIHHI", self.inodes, body)
        if size <= 3:
            return
        at = self._locate(self.dirs, self.dir_at, start, offset)
        end = at + size - 3
        if end > len(self.dirs):
            raise SquashfsError("directory past the end of the directory table")
        while at + 12 <= end:
            count, block, _inode_base = struct.unpack_from("<IIi", self.dirs, at)
            at += 12
            for _ in range(count + 1):
                if at + 8 > end:
                    raise SquashfsError("truncated directory")
                offset, _delta, kind2, name_len = struct.unpack_from("<HhHH", self.dirs, at)
                at += 8
                name = self.dirs[at:at + name_len + 1]
                at += name_len + 1
                yield name.decode("utf-8", "replace"), (block << 16) | offset, kind2

    # -- files
    def _fragment(self, index: int) -> Tuple[int, int]:
        if self._fragments is None:
            entries: List[Tuple[int, int]] = []
            count = self.sb.fragments
            blocks = (count + 511) // 512
            for i in range(blocks):
                at = self._u64_at(self.sb.fragment_table + 8 * i)
                table = b""
                while len(table) < min(METADATA_SIZE, 16 * (count - len(entries))):
                    block, at = self._metadata(at)
                    table += block
                for j in range(0, len(table) - 15, 16):
                    start, size, _ = struct.unpack_from("<QII", table, j)
                    entries.append((start, size))
                    if len(entries) == count:
                        break
            self._fragments = entries
        if index >= len(self._fragments):
            raise SquashfsError("fragment index out of range")
        return self._fragments[index]

    def _data_block(self, start: int, word: int, want: int) -> bytes:
        size = word & 0xFFFFFF
        if size == 0:
            return bytes(want)                    # a sparse block
        if size > MAX_BLOCK + 64:
            raise SquashfsError("data block too large")
        pos = self.base + start
        raw = self.data[pos:pos + size]
        if len(raw) != size:
            raise SquashfsError("truncated data block")
        return raw if word & 0x1000000 else self.inflate(raw, self.sb.block_size)

    def read_file(self, pos: int, kind: int) -> Tuple[int, Optional[bytes]]:
        """(size, contents); contents is None when the file is larger than MAX_FILE."""
        body = pos + 16
        if kind == REG:
            start, fragment, frag_offset, size = struct.unpack_from("<IIII", self.inodes, body)
            body += 16
        else:
            start, size, _sparse, _nlink, fragment, frag_offset, _xattr = struct.unpack_from(
                "<QQQIIII", self.inodes, body)
            body += 40
        if size > MAX_FILE:
            return size, None
        bs = self.sb.block_size
        has_fragment = fragment != 0xFFFFFFFF
        blocks = size // bs if has_fragment else (size + bs - 1) // bs
        if body + 4 * blocks > len(self.inodes):
            raise SquashfsError("block list past the end of the inode table")
        out = bytearray()
        at = start
        for i in range(blocks):
            word = struct.unpack_from("<I", self.inodes, body + 4 * i)[0]
            out += self._data_block(at, word, min(bs, size - len(out)))[:size - len(out)]
            at += word & 0xFFFFFF
        if has_fragment and len(out) < size:
            frag = self._fragment_blocks.get(fragment)
            if frag is None:
                if len(self._fragment_blocks) >= 16:
                    self._fragment_blocks.clear()
                frag_start, frag_word = self._fragment(fragment)
                frag = self._data_block(frag_start, frag_word, bs)
                self._fragment_blocks[fragment] = frag
            out += frag[frag_offset:frag_offset + size - len(out)]
        if len(out) != size:
            raise SquashfsError("file shorter than its inode says")
        return size, bytes(out)


def _safe(name: str) -> bool:
    return bool(name) and name not in (".", "..") and "/" not in name and "\\" not in name \
        and "\0" not in name and ":" not in name


def extract(data: bytes, sb: Superblock, dest: Path, max_bytes: int = MAX_BYTES,
            only: Optional[Callable[[str], bool]] = None) -> Extracted:
    """Write the regular files of the file system at *sb* below *dest* (which is created).
    *only*, if given, is asked with each file's path (``usr/lib/opkg/status``) and the
    file is written only when it says yes. Reading stops at the first inconsistency;
    what was written by then stays, and ``error`` says why it stopped."""
    result = Extracted(sb.offset, sb.compression_name)
    inflate = decompressor(sb.compression)
    if inflate is None:
        result.error = (f"compressed with {sb.compression_name}, which needs an optional "
                        "package to read (pip install 'gangmu-sbom[firmware]')")
        return result
    try:
        reader = _Reader(data, sb, inflate)
        kind, pos = reader.inode(sb.root_inode)
        if kind not in (DIR, LDIR):
            raise SquashfsError("the root inode is not a directory")
    except (SquashfsError, struct.error, zlib.error, lzma.LZMAError, ValueError,
            EOFError, OSError) as exc:
        result.error = str(exc) or type(exc).__name__
        return result
    dest.mkdir(parents=True, exist_ok=True)
    seen: Set[int] = set()
    big = 0
    stack: List[Tuple[int, int, Path, str, int]] = [(kind, pos, dest, "", 0)]
    try:
        while stack:
            kind, pos, here, rel, depth = stack.pop()
            if pos in seen:
                continue
            seen.add(pos)
            for name, ref, _ in reader.entries(pos, kind):
                if not _safe(name):
                    continue
                child_kind, child_pos = reader.inode(ref)
                child_rel = f"{rel}/{name}" if rel else name
                if child_kind in (DIR, LDIR):
                    if depth + 1 < MAX_DEPTH:
                        (here / name).mkdir(exist_ok=True)
                        stack.append((child_kind, child_pos, here / name, child_rel, depth + 1))
                    continue
                if child_kind not in (REG, LREG):
                    continue
                if only is not None and not only(child_rel):
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
                with open(here / name, "wb") as fh:
                    fh.write(body)
                result.files += 1
                result.bytes += size
    except (SquashfsError, struct.error, zlib.error, lzma.LZMAError, ValueError,
            EOFError, OSError) as exc:
        result.error = str(exc) or type(exc).__name__
    if big:
        result.skipped.append(f"{big} file(s) over {MAX_FILE >> 20} MiB")
    return result


def label(offset: int) -> str:
    """The suffix that names an extracted file system beside the image it came from."""
    return f"!squashfs@{offset:#x}"
