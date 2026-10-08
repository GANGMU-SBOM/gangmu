"""A rule author's self-test for per-function fingerprints.

``gangmu rules binary-prints`` does not just write a sidecar. It first asks whether the
fingerprints it is about to ship can do their job, using only what the author supplied:

* the author gives each release built more than once (say ``-Os`` and ``-O2``);
* every build is turned into references, and every *other* build of every release is
  turned into a stripped image to identify, so a reference never meets its own image;
* images of unrelated firmware (``--negative``) must match nothing.

The outcome is stored in the sidecar and copied into the rule's ``calibration`` block.
The rule loader refuses a rule whose block says it failed, is missing, or disagrees with
the sidecar (the sidecar's digest is in the rule, so the figures cannot be edited by hand).

What this does and does not show: it shows the fingerprints recognise their own library
across builds the author made, and do not fire on the firmware the author tried. It does
not show they hold on the compiler, flags and architecture of a build the author never
saw. The scanner repeats the author's figures in its evidence so a reader sees how much
was checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import fprint
from .eval import binary as ev

MIN_RELEASES = 2          # one release has nothing to be told apart from
MIN_FINGERPRINTS = 10     # twice the matches a claim needs, so a build-to-build wobble survives
SELF = "self"


@dataclass
class Calibration:
    releases: int
    builds_per_release: int
    fingerprintable: int
    cross_build: Optional[Dict[str, int]]
    same_build: Dict[str, int]
    negative_pairs: int
    false_positives: int
    min_features: int
    tie_share: float
    reasons: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.reasons

    def to_meta(self) -> dict:
        return {"version": 1, "releases": self.releases,
                "builds_per_release": self.builds_per_release,
                "fingerprintable": self.fingerprintable,
                "cross_build": self.cross_build, "same_build": self.same_build,
                "negative_pairs": self.negative_pairs,
                "false_positives": self.false_positives,
                "min_features": self.min_features, "tie_share": self.tie_share,
                "passed": self.passed}


def _counts(cells) -> Dict[str, int]:
    out = {o: 0 for o in ev.OUTCOMES}
    for c in cells:
        out[c.outcome] += 1
    return out


def calibrate(builds: Dict[str, Dict[str, bytes]], negatives: Sequence[bytes] = (),
              min_features: Optional[int] = None, tie_share: Optional[float] = None
              ) -> Tuple[fprint.FunctionPrints, Calibration]:
    """*builds*: ``{release label: {build name: ELF bytes}}``, releases oldest first."""
    k = fprint.MIN_FEATURES if min_features is None else min_features
    share = fprint.TIE_SHARE if tie_share is None else tie_share
    corpus = ev.Corpus()
    corpus.releases[SELF] = list(builds)
    corpus.builds[SELF] = {}
    merged: List[Tuple[str, List[set]]] = []
    archs: set = set()
    for label, per_build in builds.items():
        corpus.builds[SELF][label] = {}
        union: List[set] = []
        for name, data in per_build.items():
            ref, ref_arch = fprint.image_features(data, min_features=1)
            img = fprint.image_function_features(data, min_features=1, ignore_symbols=True)
            archs.add(ref_arch or "")
            corpus.builds[SELF][label][name] = ev.Build(ref, img)
            union += [s for s in ref if len(s) >= k]
        merged.append((label, union))
    for i, data in enumerate(negatives):
        corpus.releases[f"neg{i}"] = ["n"]
        corpus.builds[f"neg{i}"] = {"n": {"x": ev.Build(
            [], fprint.image_function_features(data, min_features=1))}}

    arch = archs.pop() if len(archs) == 1 else ""
    prints = fprint.FunctionPrints.build(merged, min_features=k, arch=arch)
    per_release = min((len(b) for b in builds.values()), default=0)
    report = ev.evaluate(corpus, k, share) if len(builds) >= 2 else ev.Report(k, share)
    mine = [c for c in report.cells if c.lib == SELF]
    cross = [c for c in mine if c.ref_opt != c.img_opt]
    cal = Calibration(
        releases=len(builds), builds_per_release=per_release,
        fingerprintable=len(prints.functions),
        cross_build=_counts(cross) if cross else None,
        same_build=_counts([c for c in mine if c.ref_opt == c.img_opt]),
        negative_pairs=report.negative_total,
        false_positives=len(report.negatives), min_features=k, tie_share=share)
    if cal.releases < MIN_RELEASES:
        cal.reasons.append(f"need at least {MIN_RELEASES} releases to tell versions apart")
    if cal.fingerprintable < MIN_FINGERPRINTS:
        cal.reasons.append(f"only {cal.fingerprintable} fingerprintable functions "
                           f"(need {MIN_FINGERPRINTS}): the library has too few strings and "
                           f"constants for this method")
    if cal.cross_build is None:
        cal.reasons.append("give each release at least two builds (for example -Os and -O2) "
                           "so the fingerprints can be tested on a build they were not made from")
    else:
        if cal.cross_build["wrong"]:
            cal.reasons.append(f"{cal.cross_build['wrong']} cross-build answer(s) named a "
                               f"release that is not the true one")
        if cal.cross_build["none"]:
            cal.reasons.append(f"{cal.cross_build['none']} cross-build image(s) were not "
                               f"recognised as this library")
    if cal.false_positives:
        cal.reasons.append(f"{cal.false_positives} of {cal.negative_pairs} negative-control "
                           f"pairs matched")
    prints.meta = cal.to_meta()
    return prints, cal


def format_calibration(cal: Calibration) -> str:
    lines = [f"releases {cal.releases}, builds per release {cal.builds_per_release}, "
             f"fingerprintable functions {cal.fingerprintable}"]
    if cal.cross_build is not None:
        c = cal.cross_build
        lines.append(f"cross-build: exact {c['exact']}, range {c['range']}, wrong {c['wrong']}, "
                     f"none {c['none']}")
    lines.append(f"negative controls: {cal.false_positives} false positive(s) in "
                 f"{cal.negative_pairs} pairs")
    lines.append("PASSED" if cal.passed else "FAILED:\n  - " + "\n  - ".join(cal.reasons))
    return "\n".join(lines)
