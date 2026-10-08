#!/usr/bin/env python3
"""Build the binary-identification corpus: real Cortex-M firmware of known releases.

    python benchmarks/binary/build_corpus.py --out /tmp/corpus [--cache /tmp/checkouts]
        [--lib zlib --lib cjson] [--opt Os --opt O2]

Needs git, network (or a --cache of checkouts named <lib>-<tag>) and a cross compiler:
arm-none-eabi-gcc (--target arm), riscv64-unknown-elf-gcc with newlib headers (--target
riscv32) or aarch64-linux-gnu-gcc with its libc headers (--target aarch64) or xtensa-esp32-elf-gcc
(--target xtensa, ESP32).
Writes ``<out>/<lib>/<tag>/<opt>.elf`` (with symbols: a reference build) and
``<opt>.strip.elf`` (stripped: the image a scanner meets), plus ``corpus.json`` giving each
library's release order. ``gangmu binary-eval --corpus <out>`` reads that.
"""

import argparse
import glob
import json
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
OPTS = ["Os", "O2", "O1", "O0"]

# What differs between the targets. Both link only the library's code (see build()).
TARGETS = {
    "arm": {"cc": "arm-none-eabi-gcc", "strip": "arm-none-eabi-strip",
            "flags": ["-mcpu=cortex-m3", "-mthumb"], "ld": "fw.ld", "start": "start.c",
            "include": []},
    "riscv32": {"cc": "riscv64-unknown-elf-gcc", "strip": "riscv64-unknown-elf-strip",
                "flags": ["-march=rv32imac", "-mabi=ilp32"], "ld": "fw-riscv.ld",
                "start": "start-riscv.c", "include": ["/usr/include/newlib"]},
    "aarch64": {"cc": "aarch64-linux-gnu-gcc", "strip": "aarch64-linux-gnu-strip",
                "flags": ["-march=armv8-a", "-ffreestanding", "-fno-pic", "-fno-pie",
                          "-fno-asynchronous-unwind-tables"],
                "ld": "fw-aarch64.ld", "start": "start-aarch64.c", "include": [],
                "link": ["-static", "-no-pie"]},
    # Espressif's crosstool-NG toolchain must be on PATH (idf_tools.py install xtensa-esp32-elf).
    # -mtext-section-literals keeps each function's literal pool beside it, in .text.
    "xtensa": {"cc": "xtensa-esp32-elf-gcc", "strip": "xtensa-esp32-elf-strip",
               "flags": ["-mlongcalls", "-mtext-section-literals", "-ffunction-sections"],
               "ld": "fw-xtensa.ld", "start": "start-xtensa.c", "include": []},
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def checkout(url: str, tag: str, dest: Path) -> bool:
    if dest.is_dir():
        return True
    r = run(["git", "clone", "-q", "--depth", "1", "--branch", tag, url, str(dest)])
    return r.returncode == 0


def sources(spec: dict, root: Path):
    files = set()
    for pat in spec["sources"]:
        files |= {Path(p) for p in glob.glob(str(root / pat))}
    for pat in spec.get("exclude", []):
        files -= {Path(p) for p in glob.glob(str(root / pat))}
    return sorted(files)


def build(lib: str, spec: dict, tag: str, root: Path, opt: str, out: Path,
          relink: bool = False, target: str = "arm") -> str:
    """Returns "" on success, else why it failed."""
    work = out.parent / f".{opt}.build"
    work.mkdir(parents=True, exist_ok=True)
    t = TARGETS[target]
    flags = [*t["flags"], f"-{opt}", "-fno-tree-loop-distribute-patterns", "-w"] \
        + [f"-I{root / i}" for i in spec.get("include", ["."])] \
        + [f"-I{d}" for d in t["include"]] + [f"-D{d}" for d in spec.get("defines", [])]
    objects, skipped = [], 0
    for i, src in enumerate(sources(spec, root)):
        obj = work / f"{i}-{src.stem}.o"
        if relink and obj.exists():
            objects.append(str(obj))
            continue
        r = run([t["cc"], *flags, "-c", str(src), "-o", str(obj)])
        if r.returncode == 0:
            objects.append(str(obj))
        else:
            skipped += 1
    if not objects:
        return "no source compiled"
    start = work / "start.o"
    r = run([t["cc"], *flags, "-c", str(HERE / t["start"]), "-o", str(start)])
    if r.returncode:
        return "start.c: " + r.stderr[-200:]
    # No libc, no libgcc: a reference must hold the library's own code and nothing else,
    # or functions every program shares (printf, strtod) become part of its fingerprint.
    # The images are never run, so unresolved references are fine.
    r = run([t["cc"], *t["flags"], *t.get("link", []), "-nostartfiles", "-nostdlib",
             "-T", str(HERE / t["ld"]), "-Wl,--unresolved-symbols=ignore-all",
             "-o", str(out), str(start), *objects])
    if r.returncode:
        return "link: " + r.stderr[-300:]
    run([t["strip"], "-s", "-o", str(out.with_suffix(".strip.elf")), str(out)])
    return f"({skipped} file(s) did not compile)" if skipped else ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--target", choices=sorted(TARGETS), default="arm",
                    help="arm: Cortex-M3 Thumb (default); riscv32: rv32imac; "
                         "aarch64: ARMv8-A, freestanding; xtensa: ESP32")
    ap.add_argument("--cache", help="checkouts named <lib>-<tag>, reused if present")
    ap.add_argument("--lib", action="append", help="build only these libraries")
    ap.add_argument("--relink", action="store_true",
                    help="reuse the object files of an earlier run and only link again")
    ap.add_argument("--opt", action="append", help=f"optimisation levels (default {OPTS})")
    args = ap.parse_args(argv)
    libs = yaml.safe_load((HERE / "libs.yaml").read_text())
    out = Path(args.out)
    cache = Path(args.cache or out / ".checkouts")
    cache.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for lib, spec in libs.items():
        if args.lib and lib not in args.lib:
            continue
        built = []
        for tag in spec["tags"]:
            root = cache / f"{lib}-{tag}"
            if not checkout(spec["url"], tag, root):
                print(f"{lib} {tag}: cannot fetch", file=sys.stderr)
                continue
            ok = []
            for opt in args.opt or OPTS:
                dest = out / lib / tag / f"{opt}.elf"
                dest.parent.mkdir(parents=True, exist_ok=True)
                why = build(lib, spec, tag, root, opt, dest, args.relink, args.target)
                if dest.exists():
                    ok.append(opt)
                    if why:
                        print(f"{lib} {tag} -{opt}: {why}", file=sys.stderr)
                else:
                    print(f"{lib} {tag} -{opt}: FAILED {why}", file=sys.stderr)
            if ok:
                built.append({"tag": tag, "opts": ok})
        if built:
            manifest[lib] = built
    (out / "corpus.json").write_text(json.dumps(manifest, indent=2))
    print(f"built {sum(len(v) for v in manifest.values())} release(s) of "
          f"{len(manifest)} librar{'y' if len(manifest) == 1 else 'ies'} in {out}")
    return 0 if manifest else 1


if __name__ == "__main__":
    sys.exit(main())
