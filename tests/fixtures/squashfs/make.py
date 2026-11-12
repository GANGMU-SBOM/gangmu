"""Rebuild the SquashFS fixtures (needs mksquashfs from squashfs-tools 4.x).

    python tests/fixtures/squashfs/make.py

The tree is small but reaches every part of the reader: a file over several data
blocks with a tail in a fragment, a file only in a fragment, an all-zero file (sparse
blocks), an empty file, a symbolic link, nested directories, and an opkg database.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

STATUS = """Package: zlib
Version: 1.3.1-1
Status: install user installed
Architecture: mipsel_24kc

Package: busybox
Version: 1.36.1-1
Status: install user installed
Architecture: mipsel_24kc
"""


def tree(root: Path) -> None:
    (root / "usr/lib/opkg").mkdir(parents=True)
    (root / "usr/lib/opkg/status").write_text(STATUS)
    (root / "usr/share/doc").mkdir(parents=True)
    text = "".join(f"line {i:05d} of a file that spans several 4 KiB blocks\n" for i in range(400))
    (root / "usr/share/doc/long.txt").write_text(text)
    (root / "usr/share/doc/zeros.bin").write_bytes(bytes(3 * 4096))
    (root / "usr/share/doc/empty").write_bytes(b"")
    noise, block = b"", b"seed"
    while len(noise) < 6000:                  # incompressible: stored uncompressed
        block = hashlib.sha256(block).digest()
        noise += block
    (root / "usr/share/doc/noise.bin").write_bytes(noise[:6000])
    (root / "lib").mkdir()
    (root / "lib/libz.so.1.3.1").write_bytes(b"\0" * 64 + b"inflate 1.3.1 Copyright 1995-2024 Mark Adler \0" + b"\0" * 64)
    os.symlink("libz.so.1.3.1", root / "lib/libz.so.1")
    (root / "etc/deep/er/still").mkdir(parents=True)
    (root / "etc/deep/er/still/here.conf").write_text("x=1\n")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "rootfs"
        src.mkdir()
        tree(src)
        for comp in ("gzip", "xz"):
            out = HERE / f"rootfs-{comp}.sqfs"
            if out.exists():
                out.unlink()
            subprocess.run(["mksquashfs", str(src), str(out), "-comp", comp, "-b", "4096",
                            "-noappend", "-all-root", "-mkfs-time", "0", "-all-time", "0",
                            "-no-progress", "-quiet"], check=True)
    # A flash image: a header and padding, the file system at an offset that is not a
    # multiple of anything, and erased flash after it.
    fs = (HERE / "rootfs-xz.sqfs").read_bytes()
    head = b"FWHEADER" + bytes(range(256)) * 20
    (HERE / "firmware.bin").write_bytes(head + b"\x01\x02\x03" + fs + b"\xff" * 4096)


if __name__ == "__main__":
    shutil.which("mksquashfs") or exit("mksquashfs not found")
    main()
