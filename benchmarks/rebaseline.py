"""Rebuild benchmarks/perf-baseline.json from the ``perf.json`` artifacts of several CI runs.

    gh api repos/<owner>/gangmu/actions/artifacts/<id>/zip > a.zip     # once per CI run, unzip each
    python benchmarks/rebaseline.py benchmarks/perf-baseline.json run1/perf.json run2/perf.json ...

The CI runners are not one machine: their calibration varies from about 0.033 s to 0.06 s, and
a scan has a fixed cost of around half a second that does not shrink with the CPU, so the same
code reads 20 to 30% dearer in calibration units on the fast runners. A baseline recorded on a
developer's laptop sits outside that spread, and the 1.6x limit was crossed once by a run that
was 1.61x. So the baseline is the median over several CI runs (times and memory), and the largest
count seen (the work counters may not grow). The last file named supplies every other field and
should come from the newest code. Run it again when the rule base or the synthetic tree changes.
"""

import copy
import json
import statistics
import sys
from pathlib import Path


def rebaseline(paths):
    runs = [json.loads(Path(p).read_text()) for p in paths]
    base = copy.deepcopy(runs[-1])
    base["calibration_s"] = round(statistics.median(r["calibration_s"] for r in runs), 4)
    base.pop("calibration_drift", None)

    def rows(key):
        return [next(x for x in r["runs"] if (x["mode"], x["scale"]) == key) for r in runs]

    for ref in base["runs"]:
        found = rows((ref["mode"], ref["scale"]))
        for field in ("scan_s", "load_s"):
            ref[field] = round(statistics.median(x[field] for x in found), 3)
        for field in ("peak_rss_mb", "worker_peak_rss_mb"):
            ref[field] = round(statistics.median(x[field] for x in found), 1)
        ref["scan_units"] = round(statistics.median(x["scan_units"] for x in found), 2)
        for field in ("files_tokenised", "files_hashed", "rule_checks"):
            ref[field] = max(x[field] for x in found)
    return base


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    Path(sys.argv[1]).write_text(json.dumps(rebaseline(sys.argv[2:]), indent=2) + "\n")
    print(f"wrote {sys.argv[1]} from {len(sys.argv) - 2} runs")
