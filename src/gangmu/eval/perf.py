"""Whole-scan performance: a reproducible baseline and a regression check.

Accuracy has a benchmark (``gangmu eval``); speed needs one too, or every new
capability quietly makes the tool slower until nobody runs it in CI. This
module measures a full scan the way a user runs one and records what decides
whether it stays usable on a real SDK:

* **wall time**, cold (nothing cached) and warm (the incremental cache from the
  cold run), normalised by a calibration loop so a laptop and a CI runner can
  be compared;
* **peak memory** of the scanning process and its workers;
* **work counters** that do not depend on the machine at all: how many files
  were tokenised and hashed, and how many (rule, directory) pairs the engine
  actually evaluated. A regression in these is a regression on every machine,
  and they are what a CI check can hold exactly;
* how cost grows with the **size of the rule base**, by replicating the loaded
  rules with salted hashes so the replicas match nothing real.

The default tree is synthetic and seeded, so the CI check needs no network and
measures the same thing every time. Point it at a real SDK for the numbers in
docs/PERFORMANCE.md.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..fingerprint import Signature
from ..fnsig import FunctionSignature
from ..rules.loader import RuleBase

_KEYWORDS = ["if", "for", "while", "return", "switch", "case", "break"]
_TYPES = ["int", "uint32_t", "uint8_t", "size_t", "void *", "const char *"]


# --------------------------------------------------------------- synthetic tree

def synthetic_tree(dest: Path, seed: int = 0, components: int = 48,
                   files_per_component: int = 24, functions_per_file: int = 10,
                   embed: Sequence[Path] = ()) -> Dict[str, int]:
    """Write a deterministic SDK-shaped tree of generated C.

    Components carry a LICENSE (which is what makes discovery pick them up),
    a fifth of them vendor a nested component of their own -- the shape that
    used to make the engine tokenise the same files twice -- and a few are
    byte-identical copies of each other, as vendored code usually is. *embed*
    copies real directories in, so a run can also assert on what it finds.
    """
    rng = random.Random(seed)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    stats = {"components": 0, "files": 0, "bytes": 0}
    words = [_word(rng) for _ in range(400)]

    def write_component(path: Path, n_files: int) -> None:
        path.mkdir(parents=True, exist_ok=True)
        (path / "LICENSE").write_text("Synthetic licence for benchmarking.\n")
        stats["components"] += 1
        for i in range(n_files):
            sub = path / ("src" if i % 3 else "include")
            sub.mkdir(exist_ok=True)
            suffix = ".c" if i % 3 else ".h"
            text = _c_file(rng, words, functions_per_file)
            target = sub / f"{_word(rng)}_{i}{suffix}"
            target.write_text(text)
            stats["files"] += 1
            stats["bytes"] += len(text)

    made: List[Path] = []
    for c in range(components):
        path = dest / "components" / f"comp_{c:03d}"
        if c and c % 9 == 0:
            # A verbatim second copy of an earlier component.
            shutil.copytree(made[c // 2], path)
            stats["components"] += 1
        else:
            write_component(path, files_per_component)
        if c % 5 == 0:
            write_component(path / "third_party" / f"lib_{c:03d}",
                            max(4, files_per_component // 2))
        made.append(path)
    for i, source in enumerate(embed):
        shutil.copytree(source, dest / "vendor" / Path(source).name)
        stats["components"] += 1
    return stats


def _word(rng: random.Random) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(3, 9)))


def _c_file(rng: random.Random, words: List[str], functions: int) -> str:
    lines = ["#include <stdint.h>", ""]
    for _ in range(functions):
        name = f"{rng.choice(words)}_{rng.choice(words)}"
        args = ", ".join(f"{rng.choice(_TYPES)} {rng.choice(words)}"
                         for _ in range(rng.randint(0, 3))) or "void"
        lines.append(f"static int {name}({args})")
        lines.append("{")
        for _ in range(rng.randint(4, 18)):
            a, b = rng.choice(words), rng.choice(words)
            kind = rng.random()
            if kind < 0.3:
                lines.append(f"    {rng.choice(_TYPES)} {a} = {b} + {rng.randint(0, 999)};")
            elif kind < 0.5:
                lines.append(f"    if ({a} > {b}) {{ {a} = {b}({rng.randint(0, 9)}); }}")
            elif kind < 0.7:
                lines.append(f"    for (int i = 0; i < {rng.randint(2, 64)}; i++) {{ {a}[i] ^= {b}; }}")
            else:
                lines.append(f"    {a} = {b}({a}, 0x{rng.randint(0, 0xffff):04x}u);")
        lines.append(f"    return {rng.choice(words)};")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------ scaled rule base

def scaled_rulebase(base: RuleBase, factor: int) -> RuleBase:
    """The loaded rules plus ``factor - 1`` salted replicas of each.

    A replica keeps every structural property of its original -- the number
    of functions, versions, sketch values, anchors and globs -- but its hashes
    are XORed with a per-replica salt, so it matches nothing a real rule
    matches. That isolates what the *number* of rules costs, which is the
    question a growing community rule base asks.
    """
    out = RuleBase(rules=list(base.rules), errors=list(base.errors))
    for replica in range(1, max(1, factor)):
        salt = random.Random(replica).getrandbits(64) | 1
        for rule in base.rules:
            clone = copy.copy(rule)
            clone.id = f"{rule.id}#replica{replica}"
            if rule.functions is not None:
                try:
                    sig = rule.functions.load()
                except Exception:                     # noqa: BLE001
                    sig = None
                spec = copy.copy(rule.functions)
                if sig is not None:
                    exact = sorted(zip((h ^ salt for h in sig.hashes),
                                       sig.bitmaps, sig.flags))
                    abstract = sorted(zip((h ^ salt for h in sig.abstract_hashes),
                                          sig.abstract_bitmaps))
                    spec._loaded = FunctionSignature(
                        versions=list(sig.versions),
                        hashes=[e[0] for e in exact], bitmaps=[e[1] for e in exact],
                        flags=[e[2] for e in exact],
                        abstract_hashes=[a[0] for a in abstract],
                        abstract_bitmaps=[a[1] for a in abstract])
                clone.functions = spec
            if rule.signature is not None:
                old = rule.signature.signature
                clone.signature = dataclasses.replace(
                    rule.signature, fileset_sha256=None,
                    signature=Signature(values=sorted({v ^ salt for v in old.values}),
                                        k=old.k, window=old.window, size=old.size))
            clone.anchors = tuple(dataclasses.replace(a, sha256={
                v: hashlib.sha256(f"{replica}:{h}".encode()).hexdigest()
                for v, h in a.sha256.items()}) for a in rule.anchors)
            out.rules.append(clone)
    return out


# ------------------------------------------------------------------ measuring

def calibrate(rounds: int = 3) -> float:
    """Seconds for a fixed, single-core analysis workload on this machine.

    Scan times are reported divided by this, so a regression check compares
    "how many calibration units a scan costs" rather than raw seconds that a
    faster or busier runner would move.
    """
    from ..analysis import analyse_bytes
    rng = random.Random(1234)
    words = [_word(rng) for _ in range(300)]
    corpus = [_c_file(rng, words, 12).encode() for _ in range(40)]
    best = float("inf")
    for _ in range(rounds):
        t0 = time.perf_counter()
        for data in corpus:
            analyse_bytes(data, 16, 8)
        best = min(best, time.perf_counter() - t0)
    return best


def measure_in_child(root: Path, rules_dirs: Sequence[Path], jobs: int = 1,
                     cache_dir: Optional[Path] = None, scale: int = 1,
                     python: Optional[str] = None) -> Dict[str, Any]:
    """One scan in a fresh interpreter, so peak memory is the scan's own."""
    args = json.dumps({"root": str(root), "rules": [str(r) for r in rules_dirs],
                       "jobs": jobs,
                       "cache": str(cache_dir) if cache_dir else None,
                       "scale": scale})
    env = dict(os.environ)
    src = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([python or sys.executable, "-m", "gangmu.eval.perf", args],
                          capture_output=True, text=True, env=env, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"perf child failed: {proc.stderr.strip()[-2000:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _child(spec: Dict[str, Any]) -> Dict[str, Any]:
    from ..rules.loader import load_rules
    from ..scan import ScanOptions, scan

    t0 = time.perf_counter()
    rules = RuleBase()
    for directory in spec["rules"]:
        loaded = load_rules(Path(directory), strict=False)
        rules.rules.extend(loaded.rules)
        rules.errors.extend(loaded.errors)
    if spec.get("scale", 1) > 1:
        rules = scaled_rulebase(rules, int(spec["scale"]))
    t1 = time.perf_counter()
    stats: Dict[str, int] = {}
    result = scan(Path(spec["root"]), rules,
                  options=ScanOptions(jobs=int(spec["jobs"]),
                                      cache_dir=Path(spec["cache"]) if spec["cache"] else None,
                                      stats=stats))
    t2 = time.perf_counter()
    own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    kids = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    scale = 1024 if sys.platform == "darwin" else 1      # macOS reports bytes
    return {
        "rules": len(rules),
        "load_s": round(t1 - t0, 3),
        "scan_s": round(t2 - t1, 3),
        "peak_rss_mb": round(own / scale / 1024, 1),
        "worker_peak_rss_mb": round(kids / scale / 1024, 1),
        "candidates": (len(result.findings) + len(result.possible)
                       + len(result.unidentified)),
        "findings": sorted(f"{f.directory}={f.upstream_name}@{f.version}"
                           for f in result.findings),
        **stats,
    }


def numpy_available() -> bool:
    from ..fingerprint import numpy_module
    return numpy_module() is not None


def run_suite(root: Path, rules_dirs: Sequence[Path], jobs: int = 1,
              scales: Sequence[int] = (1,), warm: bool = True) -> Dict[str, Any]:
    """Cold scan, warm rescan, and the rule-count curve, each in its own process."""
    out: Dict[str, Any] = {"jobs": jobs, "numpy": numpy_available(),
                           "calibration_s": round(calibrate(), 4), "runs": []}
    with tempfile.TemporaryDirectory(prefix="gangmu-perf-cache-") as cache:
        for scale in scales:
            cold = measure_in_child(root, rules_dirs, jobs=jobs, scale=scale,
                                    cache_dir=Path(cache) / f"x{scale}" if warm else None)
            cold["mode"] = "cold"
            cold["scale"] = scale
            out["runs"].append(cold)
            if warm and scale == scales[0]:
                again = measure_in_child(root, rules_dirs, jobs=jobs, scale=scale,
                                         cache_dir=Path(cache) / f"x{scale}")
                again["mode"] = "warm"
                again["scale"] = scale
                out["runs"].append(again)
    for run in out["runs"]:
        run["scan_units"] = round(run["scan_s"] / out["calibration_s"], 2)
    return out


# ------------------------------------------------------------- regression check

# Counters are exact properties of the algorithm; times and memory are not, so
# they get room for a noisy runner. A real regression -- tokenising files twice,
# evaluating every rule on every directory -- moves the counters by integer
# factors, far outside these margins.
TIME_TOLERANCE = 1.6
MEMORY_TOLERANCE = 1.35
# A warm rescan's memory depends on whether the stat cache hits, which depends
# on file mtimes: a baseline recorded on a developer's machine and a fresh CI
# checkout can differ by about 1.4x for the same code. Cold runs, whose memory
# does not, keep the tight margin.
WARM_MEMORY_TOLERANCE = 1.6
COUNTERS = ("files_tokenised", "files_hashed", "rule_checks")


def check(current: Dict[str, Any], baseline: Dict[str, Any]) -> List[str]:
    """Problems with *current* against *baseline*; empty when it holds."""
    problems: List[str] = []
    base_runs = {(r["mode"], r["scale"]): r for r in baseline.get("runs", [])}
    compare_time = current.get("numpy") == baseline.get("numpy")
    for run in current.get("runs", []):
        key = (run["mode"], run["scale"])
        ref = base_runs.get(key)
        if ref is None:
            continue
        label = f"{run['mode']} x{run['scale']}"
        if run.get("findings") != ref.get("findings"):
            problems.append(f"{label}: findings differ from the baseline")
        for counter in COUNTERS:
            if counter in ref and run.get(counter, 0) > ref[counter]:
                problems.append(f"{label}: {counter} {run.get(counter)} > baseline "
                                f"{ref[counter]}")
        if compare_time and run["scan_units"] > ref["scan_units"] * TIME_TOLERANCE:
            problems.append(f"{label}: scan cost {run['scan_units']} calibration units "
                            f"> {TIME_TOLERANCE} x baseline {ref['scan_units']}")
        memory_tolerance = (WARM_MEMORY_TOLERANCE if run["mode"] == "warm"
                            else MEMORY_TOLERANCE)
        if run["peak_rss_mb"] > ref["peak_rss_mb"] * memory_tolerance:
            problems.append(f"{label}: peak memory {run['peak_rss_mb']} MB > "
                            f"{memory_tolerance} x baseline {ref['peak_rss_mb']} MB")
    return problems


if __name__ == "__main__":                              # the child process
    print(json.dumps(_child(json.loads(sys.argv[1]))))
