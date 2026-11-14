"""File systems inside firmware images, extracted so the scan reads them as a tree.

A Linux-class firmware image (an OpenWrt sysupgrade file, a camera's flash dump) holds
its root file system as SquashFS, JFFS2 or UBIFS in UBI. The tree inside is what
shipped: the package manager's database, the programs and libraries. ``scan`` extracts
each file system it finds into a temporary directory named after the image, the kind
and the offset (``firmware.bin!squashfs@0x2ae934``, ``flash.bin!jffs2@0x7c0000``,
``nand.bin!ubi@0x0/rootfs``) and scans that directory like any other tree.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from functools import partial
from typing import Callable, Iterator, List, Optional, Tuple

from .binaries import SKIP_DIRS
from .core import jffs2, squashfs, ubi
from .core.squashfs import Extracted

# Files read whole and searched for a file system at any offset: flash images and the
# containers vendors wrap them in. Any other file is looked at only for a file system
# at its start (an extracted ``rootfs`` partition often has no suffix).
IMAGE_SUFFIXES = {".bin", ".img", ".squashfs", ".sqfs", ".sfs", ".trx", ".chk", ".fw",
                  ".ubi", ".ubifs", ".jffs2", ".itb", ".fit", ".pkg", ".upd", ".ota",
                  ".rom", ".dat"}
MIN_SIZE = 4096
MAX_IMAGE = 1024 * 1024 * 1024        # larger files are not searched
# A dump read off a NAND chip keeps each page's spare (OOB) bytes after it, so a 128 MiB
# chip with 2048-byte pages and 64 spare bytes gives a 132 MiB file. (page, spare) layouts
# of common chips; a file is taken for such a dump only when its size is a whole number of
# pages of one layout, those pages hold a power of two of at least 1 MiB, and the file
# itself is not a power of two.
NAND_LAYOUTS = ((2048, 64), (2048, 128), (4096, 128), (4096, 224), (4096, 256), (512, 16),
                (8192, 448), (8192, 512))
_START = (squashfs.MAGIC, b"\x85\x19", b"\x19\x85", ubi.EC_MAGIC,
          ubi.UBIFS_MAGIC.to_bytes(4, "little"))
# what names an extracted file system in a path: "!squashfs@0x2ae934", "!ubi@0x0"
LABEL = re.compile(r"!(?:squashfs|jffs2|ubifs|ubi|nand)@0x[0-9a-f]+")


@dataclass
class Job:
    kind: str                         # "SquashFS (xz)", "JFFS2", "UBIFS in UBI volume rootfs"
    offset: int
    where: str                        # the directory name, relative to the image's
    extract: Callable[[Path], Extracted]


def _candidates(root: Path) -> Iterator[Path]:
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            path = Path(here) / name
            if path.is_symlink():
                continue
            yield path


def _volume_name(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip(".") or "volume"
    return clean[:64]


def _squashfs(data: bytes, sb: squashfs.Superblock, dest: Path) -> Extracted:
    return squashfs.extract(data, sb, dest)


def nand_layouts(size: int) -> List[Tuple[int, int]]:
    """The (page, spare) layouts a NAND dump of *size* bytes could have. Layouts with the
    same ratio of spare to page bytes (512 + 16, 2048 + 64) fit the same sizes."""
    if size & (size - 1) == 0:
        return []
    out = []
    for page, spare in NAND_LAYOUTS:
        unit = page + spare
        if size % unit == 0:
            pages = size // unit * page
            if pages >= 1 << 20 and pages & (pages - 1) == 0:
                out.append((page, spare))
    return out


def _structure(data: bytes) -> int:
    """How much flash structure *data* shows: valid UBI eraseblock headers, plus JFFS2
    nodes (up to a cap). Spare bytes left in, or cut at the wrong page size, break both."""
    count = 0
    at = data.find(ubi.EC_MAGIC)
    while at >= 0 and count < 8192:
        head = ubi._ec_header(data, at)
        if head is not None:
            count += 1
            # the volume header sits a page or more further in: only the right page size
            # leaves it whole
            if ubi._vid_header(data, at + head[0]) is not None:
                count += 1
        at = data.find(ubi.EC_MAGIC, at + 4)
    for fs in jffs2.find(data, limit=2):
        for i, _ in enumerate(jffs2._nodes(data, fs.offset, fs.little)):
            if i >= 4096:
                break
            count += 1
    return count


def nand_layout(data: bytes) -> Optional[Tuple[int, int]]:
    """The (page, spare) layout of a NAND dump, chosen by which layout's page data shows
    the most flash structure, or None."""
    best: Optional[Tuple[int, int]] = None
    best_score = 0
    for page, spare in nand_layouts(len(data)):
        score = _structure(strip_spare(data, page, spare))
        if score > best_score:
            best, best_score = (page, spare), score
    return best


def strip_spare(data: bytes, page: int, spare: int) -> bytes:
    """The page data of a NAND dump, without the spare bytes after each page."""
    unit = page + spare
    return b"".join(data[at:at + page] for at in range(0, len(data), unit))


def _write(body: bytes, name: str, dest: Path) -> Extracted:
    dest.mkdir(parents=True, exist_ok=True)
    with open(dest / name, "wb") as fh:
        fh.write(body)
    result = Extracted(0, "file")
    result.files, result.bytes = 1, len(body)
    return result


def jobs(name: str, data: bytes, whole: bool) -> List[Job]:
    """The file systems in one file's bytes. *whole*: search the whole file, not only
    its start."""
    layout = nand_layout(data) if whole and nand_layouts(len(data)) else None
    if layout is not None:
        page, spare = layout
        pages = strip_spare(data, page, spare)
        if jobs(name, pages, True):
            # the dump's page data is written out as a file of its own, which the next
            # pass reads; the bytes with spare areas in them say nothing reliable
            return [Job(f"NAND dump with {spare} spare bytes per {page}-byte page", 0,
                        f"{name}!nand@0x0", partial(_write, pages, name))]
    out: List[Job] = []
    start = ubi.find_ubi(data) if whole else (0 if data[:4] == ubi.EC_MAGIC else None)
    image = ubi.read_ubi(data, start) if start is not None else None
    # Inside UBI the data is cut by eraseblock headers: a file system there is read from
    # its rebuilt volume, never from the raw bytes.
    end = image.offset if image is not None else len(data)
    sbs = squashfs.find(data[:end]) if whole else \
        [sb for sb in [squashfs.superblock_at(data, 0)] if sb is not None]
    for sb in sbs:
        out.append(Job(f"SquashFS ({sb.compression_name})", sb.offset,
                       name + squashfs.label(sb.offset),
                       partial(_squashfs, data, sb)))
    leb = ubi.is_ubifs(data, 0)
    if leb is not None:
        out.append(Job("UBIFS", 0, f"{name}!ubifs@0x0",
                       partial(ubi.extract_ubifs, data, leb)))
    if image is not None and image.volumes:
        out.append(Job(f"UBI image ({len(image.volumes)} volume(s), "
                       f"{image.peb_size >> 10} KiB eraseblocks)", image.offset,
                       f"{name}!ubi@{image.offset:#x}",
                       partial(_extract_ubi, image)))
    # JFFS2 last: its nodes could only be mistaken inside another file system's data
    # by a run of correct CRCs, but an image holding UBI holds no JFFS2
    if image is None and leb is None:
        found = jffs2.find(data) if whole else \
            [f for f in jffs2.find(data[:jffs2.MAX_NODE * 4], limit=1) if f.offset == 0]
        for fs in found:
            out.append(Job("JFFS2" + (" (big-endian)" if not fs.little else ""), fs.offset,
                           f"{name}!jffs2@{fs.offset:#x}",
                           partial(jffs2.extract, data, fs)))
    return out


def _extract_ubi(image: ubi.UbiImage, dest: Path) -> Extracted:
    """A UBIFS volume is extracted into a directory named after the volume; any other
    volume (a kernel, a FIT image, a SquashFS) is written whole as ``<volume>.bin``, so
    the scan reads it as a firmware image and the next pass finds what it holds."""
    total = Extracted(image.offset, "ubi")
    dest.mkdir(parents=True, exist_ok=True)
    for volume in image.volumes:
        name = _volume_name(volume.name)
        leb = ubi.is_ubifs(volume.data, 0)
        if leb is not None:
            got = ubi.extract_ubifs(volume.data, leb, dest / name)
            total.files += got.files
            total.bytes += got.bytes
            total.skipped += [f"{volume.name}: {s}" for s in got.skipped]
            if got.error:
                total.skipped.append(f"{volume.name}: reading stopped early ({got.error})")
            continue
        body = volume.data.rstrip(b"\xff")
        if len(body) < MIN_SIZE:
            continue
        with open(dest / f"{name}.bin", "wb") as fh:
            fh.write(body)
        total.files += 1
        total.bytes += len(body)
    return total


def find_images(root: Path) -> Iterator[Tuple[Path, List[Job]]]:
    """Every file below *root* that holds a file system this module reads."""
    for path in _candidates(root):
        try:
            size = path.stat().st_size
            if size < MIN_SIZE or size > MAX_IMAGE:
                continue
            whole = path.suffix.lower() in IMAGE_SUFFIXES
            if not whole:
                with open(path, "rb") as fh:
                    head = fh.read(4)
                if not any(head.startswith(m) for m in _START):
                    continue
            data = path.read_bytes()
        except OSError:
            continue
        found = jobs(path.name, data, whole)
        if found:
            yield path, found


def extract_into(root: Path, dest_root: Path) -> Tuple[List[str], List[str]]:
    """Extract every file system found below *root* into *dest_root*, at the image's
    relative directory. Returns (the extracted directories relative to *dest_root*,
    notes for the report)."""
    extracted: List[str] = []
    notes: List[str] = []
    for path, found in find_images(root):
        rel = path.relative_to(root)
        for job in found:
            where = (rel.parent / job.where).as_posix()
            result = job.extract(dest_root / rel.parent / job.where)
            if result.files:
                extracted.append(where)
            what = (f"{rel.as_posix()}: {job.kind} at {job.offset:#x}, "
                    f"{result.files} file(s) read and scanned as {where}")
            if result.error:
                what += (f"; reading stopped early ({result.error}), so files after that "
                         "point are not in this scan")
            if result.skipped:
                what += "; left out: " + ", ".join(result.skipped)
            notes.append(what)
    return extracted, notes
