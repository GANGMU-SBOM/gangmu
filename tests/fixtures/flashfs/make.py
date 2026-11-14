"""Rebuild the JFFS2, UBIFS and UBI fixtures (needs mtd-utils and squashfs-tools).

    python tests/fixtures/flashfs/make.py

The tree is the SquashFS fixtures' (see ../squashfs/make.py). Each image is stored
gzipped: flash images are mostly erased (0xff) blocks.
"""

import gzip
import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SQUASHFS = HERE.parent / "squashfs"


def _tree(root: Path) -> None:
    spec = importlib.util.spec_from_file_location("make_squashfs", SQUASHFS / "make.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.tree(root)


def run(*cmd: str, cwd: Path) -> None:
    subprocess.run(cmd, check=True, cwd=cwd, stdout=subprocess.DEVNULL)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "rootfs").mkdir()
        _tree(t / "rootfs")
        jffs2 = ("mkfs.jffs2", "-r", "rootfs", "-e", "0x4000", "-n", "--squash")
        run(*jffs2, "-l", "-o", "le.jffs2", cwd=t)                       # zlib, rtime
        run(*jffs2, "-b", "-x", "zlib", "-o", "be.jffs2", cwd=t)         # rtime only
        run(*jffs2, "-l", "-X", "lzo", "-x", "zlib", "-o", "lzo.jffs2", cwd=t)
        ubifs = ("mkfs.ubifs", "-r", "rootfs", "-m", "512", "-e", "15872", "-c", "64")
        run(*ubifs, "-x", "zlib", "-o", "zlib.ubifs", cwd=t)
        run(*ubifs, "-x", "lzo", "-o", "lzo.ubifs", cwd=t)
        run(*ubifs, "-x", "zstd", "-o", "zstd.ubifs", cwd=t)
        shutil.copy(SQUASHFS / "rootfs-xz.sqfs", t / "rootfs.sqfs")
        (t / "ubi.cfg").write_text(
            "[data]\nmode=ubi\nimage=zlib.ubifs\nvol_id=0\nvol_type=dynamic\n"
            "vol_name=rootfs_data\n\n"
            "[rootfs]\nmode=ubi\nimage=rootfs.sqfs\nvol_id=1\nvol_type=static\n"
            "vol_name=rootfs\n")
        run("ubinize", "-o", "nand.ubi", "-p", "16KiB", "-m", "512", "-s", "512", "ubi.cfg",
            cwd=t)
        for name in ("le.jffs2", "be.jffs2", "lzo.jffs2", "zlib.ubifs", "lzo.ubifs",
                     "zstd.ubifs", "nand.ubi"):
            with gzip.GzipFile(HERE / f"{name}.gz", "wb", mtime=0) as fh:
                fh.write((t / name).read_bytes())


if __name__ == "__main__":
    for tool in ("mkfs.jffs2", "mkfs.ubifs", "ubinize"):
        shutil.which(tool) or exit(f"{tool} not found (mtd-utils)")
    main()
