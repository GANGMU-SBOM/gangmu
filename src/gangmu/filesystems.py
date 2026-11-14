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
from typing import Callable, Iterator, List, Tuple

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
MAX_DEPTH = 2                         # a file system inside an image inside a file system
_START = (squashfs.MAGIC, b"\x85\x19", b"\x19\x85", ubi.EC_MAGIC,
          ubi.UBIFS_MAGIC.to_bytes(4, "little"))
# what names an extracted file system in a path: "!squashfs@0x2ae934", "!ubi@0x0"
LABEL = re.compile(r"!(?:squashfs|jffs2|ubifs|ubi)@0x[0-9a-f]+")


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


def jobs(name: str, data: bytes, whole: bool) -> List[Job]:
    """The file systems in one file's bytes. *whole*: search the whole file, not only
    its start."""
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
