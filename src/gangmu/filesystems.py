"""File systems inside firmware images, extracted so the scan reads them as a tree.

A Linux-class firmware image (an OpenWrt sysupgrade file, a camera's flash dump) holds
its root file system as SquashFS. The tree inside is what shipped: the package
manager's database, the programs and libraries. ``scan`` extracts each file system it
finds into a temporary directory named after the image and the offset
(``firmware.bin!squashfs@0x2ae934``) and scans that directory like any other tree.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, List, Tuple

from .binaries import SKIP_DIRS
from .core import squashfs

# Files read whole and searched for a superblock at any offset: flash images and the
# containers vendors wrap them in. Any other file is looked at only for a superblock at
# its start (an extracted ``rootfs`` partition often has no suffix).
IMAGE_SUFFIXES = {".bin", ".img", ".squashfs", ".sqfs", ".sfs", ".trx", ".chk", ".fw",
                  ".ubi", ".itb", ".fit", ".pkg", ".upd", ".ota", ".rom", ".dat"}
MIN_SIZE = 4096
MAX_IMAGE = 1024 * 1024 * 1024        # larger files are not searched
MAX_DEPTH = 2                         # a file system inside an image inside a file system


def _candidates(root: Path) -> Iterator[Path]:
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            path = Path(here) / name
            if path.is_symlink():
                continue
            yield path


def find_images(root: Path) -> Iterator[Tuple[Path, bytes, List[squashfs.Superblock]]]:
    """Every file below *root* that holds a SquashFS 4.0 file system, with its bytes."""
    for path in _candidates(root):
        try:
            size = path.stat().st_size
            if size < MIN_SIZE or size > MAX_IMAGE:
                continue
            whole = path.suffix.lower() in IMAGE_SUFFIXES
            if not whole:
                with open(path, "rb") as fh:
                    if fh.read(4) != squashfs.MAGIC:
                        continue
            data = path.read_bytes()
        except OSError:
            continue
        if whole:
            found = squashfs.find(data)
        else:
            first = squashfs.superblock_at(data, 0)
            found = [first] if first is not None else []
        if found:
            yield path, data, found


def extract_into(root: Path, dest_root: Path) -> Tuple[List[str], List[str]]:
    """Extract every file system found below *root* into *dest_root*, at the image's
    relative directory, named ``<image>!squashfs@<offset>``. Returns (the extracted
    directories relative to *dest_root*, notes for the report)."""
    extracted: List[str] = []
    notes: List[str] = []
    for path, data, superblocks in find_images(root):
        rel = path.relative_to(root)
        for sb in superblocks:
            name = rel.name + squashfs.label(sb.offset)
            dest = dest_root / rel.parent / name
            result = squashfs.extract(data, sb, dest)
            where = (rel.parent / name).as_posix()
            if result.files:
                extracted.append(where)
            what = (f"{rel.as_posix()}: SquashFS ({result.compression}) at {sb.offset:#x}, "
                    f"{result.files} file(s) read and scanned as {where}")
            if result.error:
                what += (f"; reading stopped early ({result.error}), so files after that "
                         "point are not in this scan")
            if result.skipped:
                what += "; left out: " + ", ".join(result.skipped)
            notes.append(what)
    return extracted, notes
