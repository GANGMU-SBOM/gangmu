"""Benchmark for identifying a library, and its release, inside compiled firmware.

The corpus is real code: each library built for Cortex-M at several optimisation levels,
once per release (``benchmarks/binary/build_corpus.py``). For every library, reference
fingerprints are built from the builds at one optimisation level and used to identify the
builds at another, so a reference never meets the image it was made from. Each cell has
one of four outcomes:

``exact``  the reported release is the true one and no tie widens it
``range``  a ``low~high`` span that contains the true release
``wrong``  a release, or span, that does not contain the true one
``none``   the library was not recognised

Negative controls pair a library's fingerprints with another library's images; any match
there is a false positive.

Choosing the two thresholds on the same data they are reported on says nothing about
unseen libraries, so ``leave_one_library_out`` picks them on all libraries but one and
scores the one left out. Only that figure is evidence of generalisation, and it is only as
good as the corpus is varied.
"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

GRID = [(k, t) for k in (2, 3) for t in (0.95, 0.9, 0.85, 0.8)]
OUTCOMES = ("exact", "range", "wrong", "none")


@dataclass
class Build:
    ref: List[Set[int]]       # features from the build with symbols
    img: List[Set[int]]       # features from the stripped build


@dataclass
class Corpus:
    arch: str = ""            # what the images were decoded as
    # lib -> ordered releases; builds[lib][tag][opt]
    releases: Dict[str, List[str]] = field(default_factory=dict)
    builds: Dict[str, Dict[str, Dict[str, Build]]] = field(default_factory=dict)

    def opts(self, lib: str) -> List[str]:
        seen: List[str] = []
        for per_opt in self.builds[lib].values():
            seen += [o for o in per_opt if o not in seen]
        return seen


@dataclass
class Cell:
    lib: str
    ref_opt: str
    img_opt: str
    tag: str
    outcome: str
    reported: str = ""
    coverage: float = 0.0       # share of the reported release's fingerprints that matched
    matched: int = 0


@dataclass
class Report:
    min_features: int
    tie_share: float
    cells: List[Cell] = field(default_factory=list)
    negatives: List[Tuple[str, str, str]] = field(default_factory=list)   # (prints of, image of, hit)
    negative_total: int = 0

    def counts(self, lib: Optional[str] = None, cross_opt_only: bool = False) -> Dict[str, int]:
        out = {o: 0 for o in OUTCOMES}
        for c in self.cells:
            if (lib is None or c.lib == lib) and not (cross_opt_only and c.ref_opt == c.img_opt):
                out[c.outcome] += 1
        return out

    def false_positives(self, lib: Optional[str] = None) -> int:
        return sum(1 for a, b, _ in self.negatives if lib is None or lib in (a, b))

    def to_dict(self) -> dict:
        libs = sorted({c.lib for c in self.cells})
        return {"min_features": self.min_features, "tie_share": self.tie_share,
                "overall": self.counts(), "cross_optimisation": self.counts(cross_opt_only=True),
                "per_library": {l: self.counts(l) for l in libs},
                "negative_controls": {"pairs": self.negative_total,
                                      "false_positives": len(self.negatives)},
                "cells": [vars(c) for c in self.cells]}


# ----------------------------------------------------------------------- corpus

FEATURES_CACHE = ".features.pickle"


def load_corpus(directory: Path, use_cache: bool = True) -> Corpus:
    """Read ``corpus.json`` and extract features from every ELF (cached beside it)."""
    from ..fprint import image_features
    root = Path(directory)
    manifest = json.loads((root / "corpus.json").read_text())
    cache_path = root / FEATURES_CACHE
    cache: Dict[str, Tuple[int, int, List[Set[int]], str]] = {}
    if use_cache and cache_path.exists():
        try:
            cache = pickle.loads(cache_path.read_bytes())
        except Exception:                                  # noqa: BLE001 - a bad cache is a miss
            cache = {}

    arches: List[str] = []

    def features(path: Path) -> List[Set[int]]:
        stat = path.stat()
        key = str(path.relative_to(root))
        hit = cache.get(key)
        if hit and len(hit) == 4 and hit[:2] == (stat.st_mtime_ns, stat.st_size):
            arches.append(hit[3])
            return hit[2]
        feats, arch = image_features(path.read_bytes(), min_features=1)
        cache[key] = (stat.st_mtime_ns, stat.st_size, feats, arch or "")
        arches.append(arch or "")
        return feats

    corpus = Corpus()
    for lib, releases in manifest.items():
        corpus.releases[lib] = [r["tag"] for r in releases]
        corpus.builds[lib] = {}
        for rel in releases:
            corpus.builds[lib][rel["tag"]] = {}
            for opt in rel["opts"]:
                base = root / lib / rel["tag"]
                ref, img = base / f"{opt}.elf", base / f"{opt}.strip.elf"
                if ref.exists() and img.exists():
                    corpus.builds[lib][rel["tag"]][opt] = Build(features(ref), features(img))
    corpus.arch = max(set(arches), key=arches.count) if arches else ""
    if use_cache:
        try:
            cache_path.write_bytes(pickle.dumps(cache))
        except OSError:
            pass
    return corpus


# ----------------------------------------------------------------------- evaluation

def _filter(sets: Iterable[Set[int]], k: int) -> List[Set[int]]:
    return [s for s in sets if len(s) >= k]


def _classify(hit, tags: Sequence[str], truth: str) -> Tuple[str, str]:
    if hit is None:
        return "none", ""
    best, _, _, _, tied = hit
    if not tied:
        return ("exact" if best == truth else "wrong"), best
    low, high = tied.split("~")
    span = tags[tags.index(low):tags.index(high) + 1]
    return ("range" if truth in span else "wrong"), tied


def _prints_for(corpus: Corpus, lib: str, ref_opt: str, k: int):
    from ..fprint import FunctionPrints
    tags = [t for t in corpus.releases[lib] if ref_opt in corpus.builds[lib][t]]
    if len(tags) < 2:
        return None, tags
    return FunctionPrints.build(
        [(t, _filter(corpus.builds[lib][t][ref_opt].ref, k)) for t in tags], min_features=k,
        arch=corpus.arch), tags


def evaluate(corpus: Corpus, min_features: int = 2, tie_share: float = 0.85,
             images: Optional[Corpus] = None) -> Report:
    """Score *corpus*. With *images* (a corpus of the same libraries built for another
    architecture) the references come from *corpus* and the images from *images*, which
    is how a rule author's references meet firmware for a different CPU."""
    report = Report(min_features, tie_share)
    target = images or corpus
    prints: Dict[Tuple[str, str], object] = {}
    for lib in corpus.builds:
        if lib not in target.builds:
            continue
        for ref_opt in corpus.opts(lib):
            built, tags = _prints_for(corpus, lib, ref_opt, min_features)
            if built is None:
                continue
            prints[(lib, ref_opt)] = (built, tags)
            for img_opt in target.opts(lib):
                for tag in tags:
                    build = target.builds[lib].get(tag, {}).get(img_opt)
                    if build is None:
                        continue
                    hit = built.match(_filter(build.img, min_features), min_features, tie_share,
                                      target.arch)
                    outcome, reported = _classify(hit, tags, tag)
                    report.cells.append(Cell(lib, ref_opt, img_opt, tag, outcome, reported,
                                             hit[3] if hit else 0.0, hit[1] if hit else 0))
    for (lib, ref_opt), (built, _) in prints.items():
        for other in target.builds:
            if other == lib:
                continue
            for tag, per_opt in target.builds[other].items():
                for img_opt, build in per_opt.items():
                    report.negative_total += 1
                    hit = built.match(_filter(build.img, min_features), min_features, tie_share,
                                      target.arch)
                    if hit is not None:
                        report.negatives.append((lib, other, hit[0]))
    return report


# ----------------------------------------------------------------------- generalisation

@dataclass
class Fold:
    held_out: str
    chosen: Tuple[int, float]
    held: Dict[str, int]
    false_positives: int
    in_sample_best: Tuple[int, float] = (0, 0.0)
    default_held: Dict[str, int] = field(default_factory=dict)


def _score(report: Report, libs: Sequence[str]):
    """Lower is better: wrong answers and false positives first, then misses, then how
    often an exact release was named."""
    c = {o: sum(report.counts(l)[o] for l in libs) for o in OUTCOMES}
    fp = sum(1 for a, b, _ in report.negatives if a in libs and b in libs)
    return (c["wrong"] + fp, c["none"], -(c["exact"] + c["range"]), -c["exact"])


def leave_one_library_out(corpus: Corpus, grid: Sequence[Tuple[int, float]] = GRID,
                          default: Tuple[int, float] = (2, 0.85)) -> List[Fold]:
    reports = {p: evaluate(corpus, *p) for p in set(grid) | {default}}
    libs = sorted(corpus.builds)
    folds = []
    for held in libs:
        rest = [l for l in libs if l != held]
        chosen = min(grid, key=lambda p: (_score(reports[p], rest), grid.index(p)))
        r = reports[chosen]
        folds.append(Fold(
            held_out=held, chosen=chosen, held=r.counts(held),
            false_positives=r.false_positives(held),
            in_sample_best=min(grid, key=lambda p: (_score(reports[p], libs), grid.index(p))),
            default_held=reports[default].counts(held)))
    return folds


def format_report(report: Report) -> str:
    libs = sorted({c.lib for c in report.cells})
    lines = [f"min_features={report.min_features} tie_share={report.tie_share}",
             f"{'library':<12}" + "".join(f"{o:>7}" for o in OUTCOMES)]
    for lib in libs:
        lines.append(f"{lib:<12}" + "".join(f"{report.counts(lib)[o]:>7}" for o in OUTCOMES))
    lines.append(f"{'all':<12}" + "".join(f"{report.counts()[o]:>7}" for o in OUTCOMES))
    lines.append(f"{'cross-opt':<12}" + "".join(
        f"{report.counts(cross_opt_only=True)[o]:>7}" for o in OUTCOMES))
    lines.append(f"negative controls: {len(report.negatives)} false positive(s) in "
                 f"{report.negative_total} pairs")
    return "\n".join(lines)


def format_folds(folds: Sequence[Fold]) -> str:
    lines = [f"{'held out':<12}{'chosen on the rest':<22}" + "".join(f"{o:>7}" for o in OUTCOMES)
             + f"{'FP':>5}"]
    for f in folds:
        lines.append(f"{f.held_out:<12}{str(f.chosen):<22}"
                     + "".join(f"{f.held[o]:>7}" for o in OUTCOMES) + f"{f.false_positives:>5}")
    total = {o: sum(f.held[o] for f in folds) for o in OUTCOMES}
    lines.append(f"{'total':<12}{'':<22}" + "".join(f"{total[o]:>7}" for o in OUTCOMES)
                 + f"{sum(f.false_positives for f in folds):>5}")
    return "\n".join(lines)
