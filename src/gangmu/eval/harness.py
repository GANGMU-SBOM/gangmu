"""A reproducible benchmark for component identification.

Why this exists
---------------
The cross-tool SBOM benchmarks that exist -- sbomify's, and the quality scores
behind sbombenchmark.dev -- cover Python, JavaScript, Java, Go, Rust and Docker.
Every one of those ecosystems has a lock file. **None of them covers C/C++ or
embedded**, which is precisely the case where generation is hard and where a
number would therefore mean something.

So this harness measures the two things that actually decide whether an embedded
SBOM is usable, on real upstream releases rather than a curated corpus:

1. **Version accuracy.** Given N real release trees of a component, how often is
   the reported version right? This is the number that decides whether a CVE
   range match is meaningful.
2. **Robustness to vendor modification.** A silicon vendor renames symbols,
   deletes the ports it does not need, reformats, and adds its own code. The
   harness applies each of those at a controlled rate and reports the point at
   which identification degrades. This is the methodology the CENTRIS and V1SCAN
   papers use, run against this tool.

Everything is seeded, so a run is reproducible and the numbers can be checked by
whoever is being asked to believe them.
"""

from __future__ import annotations

import random
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_directory

_IDENT = re.compile(rb"\b([a-z_][a-z0-9_]{5,})\b")


@dataclass
class Mutation:
    rename_ratio: float = 0.0        # share of identifiers renamed
    delete_ratio: float = 0.0        # share of files removed
    add_ratio: float = 0.0           # vendor files added, as a share of the tree
    reformat: bool = False           # collapse whitespace and strip comments


def mutate_tree(source: Path, dest: Path, mutation: Mutation,
                seed: int = 0) -> Dict[str, int]:
    """Copy *source* to *dest*, applying a vendor-like modification.

    The mutations are the ones silicon vendors actually make, in the proportions
    that matter: renaming is what defeats a naive hash, deletion is what a port
    layer does to the parts it does not need, and additions are the vendor's own
    code.
    """
    rng = random.Random(seed)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(source, dest)

    files = sorted(p for p in dest.rglob("*")
                   if p.is_file() and p.suffix in {".c", ".h", ".cc", ".cpp"})
    stats = {"files": len(files), "deleted": 0, "renamed": 0, "added": 0}

    if mutation.delete_ratio > 0:
        victims = rng.sample(files, int(len(files) * mutation.delete_ratio))
        for path in victims:
            path.unlink()
            stats["deleted"] += 1
        files = [p for p in files if p.exists()]

    if mutation.rename_ratio > 0 or mutation.reformat:
        names: set = set()
        for path in files:
            names.update(m.group(1) for m in _IDENT.finditer(path.read_bytes()))
        chosen = set(rng.sample(sorted(names),
                                int(len(names) * mutation.rename_ratio))) \
            if mutation.rename_ratio > 0 else set()
        stats["renamed"] = len(chosen)
        for path in files:
            data = path.read_bytes()
            if chosen:
                data = _IDENT.sub(
                    lambda m: (b"vnd_" + m.group(1)) if m.group(1) in chosen
                    else m.group(1), data)
            if mutation.reformat:
                data = data.replace(b"\n", b"\r\n").replace(b"    ", b"\t")
            path.write_bytes(data)

    if mutation.add_ratio > 0:
        for i in range(int(len(files) * mutation.add_ratio)):
            extra = dest / f"vendor_port_{i}.c"
            extra.write_bytes(
                b"/* vendor addition */\n"
                + b"".join(f"int vendor_helper_{i}_{j}(int a) {{ "
                           f"int b = a * {j + 1}; while (b > 0) {{ b--; }} "
                           f"return b; }}\n".encode() for j in range(20)))
            stats["added"] += 1
    return stats


@dataclass
class VersionResult:
    tree: str
    truth: Optional[str]
    reported: Optional[str]
    exact: bool
    in_range: bool
    containment: float = 0.0
    multi_version: bool = False
    detail: str = ""


@dataclass
class MutationResult:
    label: str
    mutation: Mutation
    identified: bool
    containment: float
    version: Optional[str]
    version_ok: bool
    stats: Dict[str, int] = field(default_factory=dict)
    exact_containment: float = 0.0
    abstract_containment: float = 0.0
    used_abstraction: bool = False


def evaluate_versions(signature, trees: Sequence[Tuple[str, Path, str]],
                      include: Sequence[str] = DEFAULT_INCLUDE,
                      exclude: Sequence[str] = DEFAULT_EXCLUDE,
                      jobs: int = 1) -> List[VersionResult]:
    from ..fnsig import infer_version

    out: List[VersionResult] = []
    for label, path, truth in trees:
        dirprint = print_directory(path, include, exclude, jobs=jobs)
        verdict = infer_version(signature, dirprint.functions)
        containment, _, _ = _containment(signature, dirprint, verdict.best_index)
        reported = verdict.label
        exact = verdict.best == truth
        in_range = bool(reported and truth and (
            exact or (verdict.low and verdict.high
                      and _between(truth, verdict.low, verdict.high))))
        out.append(VersionResult(
            tree=label, truth=truth, reported=reported, exact=exact,
            in_range=in_range, containment=containment,
            multi_version=verdict.multi_version, detail=verdict.detail))
    return out


def _containment(signature, dirprint, best_index: int) -> Tuple[float, float, float]:
    """(effective, exact, abstract) -- the engine's own rule, so the benchmark
    measures the tool rather than one of its layers."""
    own = (signature.version_application_hashes(best_index)
           if best_index >= 0 else set())
    exact = len(dirprint.functions & own) / len(own) if own else 0.0
    abstract = 0.0
    if signature.abstract_hashes and best_index >= 0:
        own_abs = signature.version_abstract_hashes(best_index)
        if own_abs:
            abstract = len(dirprint.abstract_functions & own_abs) / len(own_abs)
    return max(exact, abstract), exact, abstract


def _between(value: str, low: str, high: str) -> bool:
    from ..vuln.version import compare
    lo = compare(value, low)
    hi = compare(value, high)
    return lo is not None and hi is not None and lo >= 0 and hi <= 0


def run_mutation_eval(signature, pristine: Path, truth: str, workdir: Path,
                      mutations: Sequence[Tuple[str, Mutation]],
                      include: Sequence[str] = DEFAULT_INCLUDE,
                      exclude: Sequence[str] = DEFAULT_EXCLUDE,
                      floor: float = 0.20, jobs: int = 1,
                      seed: int = 1234) -> List[MutationResult]:
    from ..fnsig import infer_version

    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    results: List[MutationResult] = []
    for label, mutation in mutations:
        target = workdir / re.sub(r"[^A-Za-z0-9._-]+", "_", label)
        stats = mutate_tree(pristine, target, mutation, seed=seed)
        dirprint = print_directory(target, include, exclude, jobs=jobs)
        verdict = infer_version(signature, dirprint.functions)
        containment, exact, abstract = _containment(signature, dirprint,
                                                    verdict.best_index)
        results.append(MutationResult(
            label=label, mutation=mutation, identified=containment >= floor,
            containment=containment, version=verdict.label,
            version_ok=verdict.best == truth, stats=stats,
            exact_containment=exact, abstract_containment=abstract,
            used_abstraction=abstract > exact))
        shutil.rmtree(target, ignore_errors=True)
    return results
