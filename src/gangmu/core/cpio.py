"""Read cpio archives: a Linux kernel's initramfs, a ramdisk, a ``.cpio`` image.

An initramfs is the root file system a kernel unpacks into memory before anything else
runs; OpenWrt's initramfs images, recovery systems, Android boot images and many
vendor kernels carry the whole userland there. It is a cpio archive, usually compressed,
and several archives may follow each other. Four header formats are read: ``newc``
(``070701``, what the kernel writes and reads), ``crc`` (``070702``), the portable ASCII
``odc`` (``070707``), and the old binary format in either byte order.

Regular files are written; hard links get the data even when the archive stores it
under another name (``newc`` keeps it with the last link). Paths are cut into
components: ``.`` and empty ones are dropped, an entry with ``..`` is skipped, and
symbolic links and device nodes are not created. The limits are those of
``squashfs``.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .squashfs import MAX_BYTES, MAX_DEPTH, MAX_FILE, MAX_FILES, Extracted, _safe

TRAILER = b"TRAILER!!!"
S_IFMT, S_IFREG = 0o170000, 0o100000
_ASCII = re.compile(rb"07070[127]")
MIN_ENTRIES = 2                 # a header followed by a second one, or by the trailer


@dataclass
class Entry:
    name: str
    mode: int
    size: int
    data_at: int
    ino: Tuple[int, int]        # (device, inode), for hard links
    nlink: int
    end: int                    # where the next header starts


@dataclass
class Archive:
    offset: int
    kind: str                   # "newc", "crc", "odc", "binary-le", "binary-be"
    end: int


def _hex(b: bytes) -> int:
    return int(b, 16)


def _entry(data: bytes, at: int) -> Optional[Tuple[str, Entry]]:
    """The entry whose header is at *at*, and its format, or None."""
    head = data[at:at + 6]
    try:
        if head in (b"070701", b"070702"):
            if at + 110 > len(data):
                return None
            f = [_hex(data[at + 6 + 8 * i:at + 14 + 8 * i]) for i in range(13)]
            ino, mode, _uid, _gid, nlink, _mt, size, dmaj, dmin, _rmaj, _rmin, nsize, _c = f
            name_at = at + 110
            data_at = (name_at + nsize + 3) & ~3
            end = (data_at + size + 3) & ~3
            kind = "newc" if head == b"070701" else "crc"
            dev = (dmaj << 32) | dmin
        elif head == b"070707":
            if at + 76 > len(data):
                return None
            octal = data[at + 6:at + 76]
            fields = [int(octal[i:i + w], 8) for i, w in
                      ((0, 6), (6, 6), (12, 6), (18, 6), (24, 6), (30, 6), (36, 6),
                       (42, 11), (53, 6), (59, 11))]
            dev, ino, mode, _uid, _gid, nlink, _rdev, _mt, nsize, size = fields
            name_at = at + 76
            data_at = name_at + nsize
            end = data_at + size
            kind = "odc"
        else:
            magic = data[at:at + 2]
            if magic not in (b"\xc7\x71", b"\x71\xc7") or at + 26 > len(data):
                return None
            e = "<" if magic == b"\xc7\x71" else ">"
            (_m, dev, ino, mode, _uid, _gid, nlink, _rdev, _t1, _t2, nsize, s1, s2) = \
                struct.unpack_from(e + "13H", data, at)
            size = (s1 << 16) | s2
            name_at = at + 26
            data_at = name_at + nsize + (nsize & 1)
            end = data_at + size + (size & 1)
            kind = "binary-le" if e == "<" else "binary-be"
    except ValueError:
        return None
    if nsize == 0 or nsize > 4096 or end > len(data) or data[name_at + nsize - 1] != 0:
        return None
    name = data[name_at:name_at + nsize - 1].decode("utf-8", "replace")
    return kind, Entry(name, mode, size, data_at, (dev, ino), nlink, end)


def _walk(data: bytes, at: int) -> Tuple[str, List[Entry], int, bool]:
    """The format, the entries up to the trailer, where the archive ends, and whether
    it ended with the trailer."""
    first = _entry(data, at)
    if first is None:
        return "", [], at, False
    kind = first[0]
    entries: List[Entry] = []
    pos = at
    while True:
        got = _entry(data, pos)
        if got is None or got[0] != kind:
            break
        _, entry = got
        if entry.name == TRAILER.decode():
            return kind, entries, entry.end, True
        entries.append(entry)
        pos = entry.end
        if len(entries) > MAX_FILES * 2:
            break
    return kind, entries, pos, False


def find(data: bytes, limit: int = 8) -> List[Archive]:
    """cpio archives in *data*: a header followed by another one or by the trailer.
    Archives that follow each other (as an initramfs often is) are each found."""
    out: List[Archive] = []
    starts = [m.start() for m in _ASCII.finditer(data)]
    starts += [m.start() for m in re.finditer(rb"\xc7\x71|\x71\xc7", data) if m.start() % 2 == 0]
    for at in sorted(starts):
        if len(out) >= limit:
            break
        if out and at < out[-1].end:
            continue
        kind, entries, end, trailed = _walk(data, at)
        if len(entries) >= MIN_ENTRIES or (entries and trailed):
            out.append(Archive(at, kind, end))
    return out


def _parts(name: str) -> Optional[List[str]]:
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(not _safe(p) for p in parts) or len(parts) > MAX_DEPTH:
        return None
    return parts


def extract(data: bytes, archive: Archive, dest: Path, max_bytes: int = MAX_BYTES) -> Extracted:
    """Write the regular files of the cpio archive at *archive* below *dest*."""
    result = Extracted(archive.offset, f"cpio ({archive.kind})")
    _, entries, _, _ = _walk(data, archive.offset)
    # newc stores a hard-linked file's data with its last name: share it with every name
    bodies: Dict[Tuple[int, int], Tuple[int, int]] = {}
    for entry in entries:
        if entry.mode & S_IFMT == S_IFREG and entry.size and entry.nlink > 1:
            bodies[entry.ino] = (entry.data_at, entry.size)
    dest.mkdir(parents=True, exist_ok=True)
    big = 0
    try:
        for entry in entries:
            if entry.mode & S_IFMT != S_IFREG:
                continue
            parts = _parts(entry.name)
            if parts is None:
                continue
            at, size = entry.data_at, entry.size
            if size == 0 and entry.nlink > 1 and entry.ino in bodies:
                at, size = bodies[entry.ino]
            if size > MAX_FILE:
                big += 1
                continue
            if result.files >= MAX_FILES:
                result.skipped.append(f"more than {MAX_FILES} files")
                break
            if result.bytes + size > max_bytes:
                result.skipped.append(f"more than {max_bytes >> 20} MiB of files")
                break
            target = dest.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.parent.is_symlink() or target.is_symlink():
                continue
            with open(target, "wb") as fh:
                fh.write(data[at:at + size])
            result.files += 1
            result.bytes += size
    except OSError as exc:
        result.error = str(exc)
    if big:
        result.skipped.append(f"{big} file(s) over {MAX_FILE >> 20} MiB")
    return result
