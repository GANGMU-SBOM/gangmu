"""Rebuild the cramfs fixtures (needs mkfs.cramfs from util-linux).

    python tests/fixtures/cramfs/make.py

The tree is the SquashFS fixtures' (see ../squashfs/make.py), in both byte orders,
stored gzipped.
"""

import gzip
import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> None:
    spec = importlib.util.spec_from_file_location("make_squashfs",
                                                  HERE.parent / "squashfs" / "make.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "rootfs"
        root.mkdir()
        module.tree(root)
        for order in ("little", "big"):
            out = Path(tmp) / f"{order}.cramfs"
            subprocess.run(["mkfs.cramfs", "-N", order, str(root), str(out)], check=True,
                           stdout=subprocess.DEVNULL)
            with gzip.GzipFile(HERE / f"{order}.cramfs.gz", "wb", mtime=0) as fh:
                fh.write(out.read_bytes())


if __name__ == "__main__":
    shutil.which("mkfs.cramfs") or exit("mkfs.cramfs not found (util-linux)")
    main()
