"""`gangmu sbom-score`, `eval`, `binary-eval`, `binary-functions`, `perf`, `bench`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from ..eval import CISA_2026, NTIA_2021, score_sbom
from ..dirprint import (DEFAULT_INCLUDE, print_directory)

from .common import (_resolve_jobs, _rule_roots, _write, _load_json)


_STANDARDS = {"ntia-2021": (NTIA_2021, "NTIA 2021 minimum elements"),
              "cisa-2026": (CISA_2026, "CISA 2026 minimum elements")}


def cmd_sbom_score(args: argparse.Namespace) -> int:
    """Score an SBOM against the published minimum-element standards."""
    bom = _load_json(args.sbom, "SBOM")
    if bom is None:
        return 2
    wanted = args.standard or ["ntia-2021", "cisa-2026"]
    reports = []
    for key in wanted:
        elements, title = _STANDARDS[key]
        reports.append(score_sbom(bom, elements, title))

    if args.format == "json":
        _write(json.dumps([r.to_dict() for r in reports], indent=2,
                          ensure_ascii=False), args.output)
    else:
        lines = []
        for report in reports:
            lines.append(f"{report.standard}  —  {report.out_of_ten}/10 "
                         f"over {report.components} component(s)")
            lines.append("")
            for score in report.scores:
                mark = "ok  " if score.ratio == 1.0 else (
                    "FAIL" if score.ratio == 0.0 else "part")
                lines.append(f"  {mark} {score.element.name:38s} "
                             f"{score.passed}/{score.total}")
                if score.failures and score.ratio < 1.0:
                    shown = ", ".join(score.failures[:5])
                    more = f" (+{len(score.failures) - 5})" if len(score.failures) > 5 else ""
                    lines.append(f"       missing on: {shown}{more}")
                    lines.append(f"       {score.element.why}")
            lines.append("")
        _write("\n".join(lines), args.output)

    if args.fail_under is not None:
        worst = min(r.out_of_ten for r in reports)
        if worst < args.fail_under:
            print(f"error: score {worst}/10 is below {args.fail_under}",
                  file=sys.stderr)
            return 1
    return 0


def disasm_arches():
    from ..disasm import ARCHES
    return list(ARCHES)


def cmd_binary_eval(args: argparse.Namespace) -> int:
    """Score library and release identification on a corpus of real firmware builds."""
    from .. import disasm
    from ..eval import binary as ev
    if not disasm.available():
        print("error: this needs Capstone: pip install 'gangmu-sbom[disasm]'", file=sys.stderr)
        return 2
    try:
        corpus = ev.load_corpus(Path(args.corpus), use_cache=not args.no_cache)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read the corpus in {args.corpus}: {exc} "
              f"(build one with benchmarks/binary/build_corpus.py)", file=sys.stderr)
        return 2
    images = None
    if args.images:
        try:
            images = ev.load_corpus(Path(args.images), use_cache=not args.no_cache)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read the corpus in {args.images}: {exc}", file=sys.stderr)
            return 2
    report = ev.evaluate(corpus, args.min_features, args.tie_share, images)
    folds = ev.leave_one_library_out(corpus) if args.loo and images is None else None
    if args.format == "json":
        out = report.to_dict()
        if folds is not None:
            out["leave_one_library_out"] = [vars(f) for f in folds]
        print(json.dumps(out, indent=2, default=list))
    else:
        print(ev.format_report(report))
        if folds is not None:
            print("\nleave one library out (thresholds chosen on the other libraries):")
            print(ev.format_folds(folds))
    return 0


def cmd_binary_functions(args: argparse.Namespace) -> int:
    """List the function boundaries recovered from a firmware image."""
    from .. import disasm
    from ..elf import parse_elf
    if not disasm.available():
        print("error: this needs Capstone: pip install 'gangmu-sbom[disasm]'", file=sys.stderr)
        return 2
    try:
        data = Path(args.image).read_bytes()
    except OSError as exc:
        print(f"error: cannot read {args.image}: {exc}", file=sys.stderr)
        return 2
    elf = parse_elf(data)
    if elf is not None:
        rec = disasm.recover_elf(data, elf)
    else:
        rec = disasm.recover_raw(data, args.arch, int(args.base, 0) if args.base else None,
                                 int(args.code_size, 0) if args.code_size else None,
                                 int(args.offset, 0) if args.offset else None)
    if rec is None or not rec.functions:
        print(f"error: no functions recovered: {rec.note if rec else 'no decoder'}",
              file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps({"arch": rec.arch, "functions": [
            {"address": f.address, "size": f.size, "name": f.name, "source": f.source}
            for f in rec.functions]}, indent=2))
    else:
        print(f"# {rec.arch}: {len(rec.functions)} function(s), "
              f"{rec.from_symbols} from symbols" + (f"; {rec.note}" if rec.note else ""))
        for f in rec.functions:
            print(f"{f.address:#010x}  {f.size:>6}  {f.source:<13} {f.name}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """Run the reproducible identification benchmark."""
    from ..eval import Mutation, evaluate_versions, run_mutation_eval
    from ..fnsig import FunctionSignature

    try:
        signature = FunctionSignature.read(Path(args.signature))
    except (OSError, ValueError) as exc:
        print(f"error: cannot read {args.signature}: {exc}", file=sys.stderr)
        return 2
    include = args.include or list(DEFAULT_INCLUDE)
    jobs = _resolve_jobs(args.jobs)
    out: Dict[str, Any] = {"signature": {"versions": signature.versions,
                                         "exact": len(signature.hashes),
                                         "abstract": len(signature.abstract_hashes)}}

    if args.tree:
        trees = []
        for item in args.tree:
            if "=" not in item:
                print(f"error: --tree takes PATH=VERSION, got {item!r}",
                      file=sys.stderr)
                return 2
            path, truth = item.rsplit("=", 1)
            trees.append((Path(path).name, Path(path), truth))
        results = evaluate_versions(signature, trees, include, jobs=jobs)
        out["versions"] = [vars(r) | {"tree": r.tree} for r in results]
        exact = sum(r.exact for r in results)
        within = sum(r.in_range for r in results)
        print(f"{'tree':30s} {'truth':10s} {'reported':14s} {'exact':6s} "
              f"{'in-range':9s} containment")
        for r in results:
            print(f"{r.tree:30s} {r.truth:10s} {str(r.reported):14s} "
                  f"{str(r.exact):6s} {str(r.in_range):9s} {r.containment:.3f}")
        print(f"\nexact {exact}/{len(results)} = {exact / len(results):.0%}   "
              f"within range {within}/{len(results)} = {within / len(results):.0%}")
        out["summary"] = {"exact": exact, "inRange": within, "total": len(results)}

    if args.mutate:
        mutations = [
            ("pristine", Mutation()),
            ("reformat (CRLF and tabs)", Mutation(reformat=True)),
            ("rename 10% of identifiers", Mutation(rename_ratio=0.10)),
            ("rename 25%", Mutation(rename_ratio=0.25)),
            ("rename 50%", Mutation(rename_ratio=0.50)),
            ("delete 20% of files", Mutation(delete_ratio=0.20)),
            ("delete 50% of files", Mutation(delete_ratio=0.50)),
            ("add 30% vendor code", Mutation(add_ratio=0.30)),
            ("vendor-like: rename 15%, delete 25%, add 20%, reformat",
             Mutation(rename_ratio=0.15, delete_ratio=0.25, add_ratio=0.20,
                      reformat=True)),
        ]
        path, truth = args.mutate.rsplit("=", 1)
        import tempfile
        with tempfile.TemporaryDirectory(prefix="gangmu-eval-") as tmp:
            mutation_results = run_mutation_eval(signature, Path(path), truth, Path(tmp),
                                        mutations, include, jobs=jobs)
        print(f"\n{'mutation':56s} {'exact':>7s} {'abstract':>9s} "
              f"{'used':>7s} {'ident':>6s}  version")
        for m in mutation_results:
            print(f"{m.label:56s} {m.exact_containment:7.3f} "
                  f"{m.abstract_containment:9.3f} {m.containment:7.3f} "
                  f"{str(m.identified):>6s}  {m.version}")
        kept = sum(m.identified for m in mutation_results)
        vok = sum(m.version_ok for m in mutation_results)
        print(f"\nidentified under {kept}/{len(mutation_results)} mutations; "
              f"version correct {vok}/{len(mutation_results)}")
        out["mutations"] = [
            {"label": m.label, "identified": m.identified,
             "containment": round(m.containment, 4),
             "exactContainment": round(m.exact_containment, 4),
             "abstractContainment": round(m.abstract_containment, 4),
             "usedAbstraction": m.used_abstraction,
             "version": m.version, "versionOk": m.version_ok,
             "stats": m.stats} for m in mutation_results]

    if args.output:
        Path(args.output).write_text(json.dumps(out, indent=2, ensure_ascii=False),
                                     encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    return 0


def cmd_perf(args: argparse.Namespace) -> int:
    """Whole-scan performance: baseline, rule-count curve, regression check."""
    import tempfile
    from ..eval.perf import check, run_suite, synthetic_tree

    scales = sorted({int(x) for x in str(args.scale).split(",") if x.strip()}) or [1]
    rules = [r.path for r in _rule_roots(args.rules)]
    jobs = args.jobs if args.jobs > 0 else 1

    with tempfile.TemporaryDirectory(prefix="gangmu-perf-") as tmp:
        tree: Dict[str, Any]
        if args.root:
            root = Path(args.root)
            tree = {"root": str(root)}
        else:
            root = Path(tmp) / "synthetic"
            tree = {"synthetic": synthetic_tree(root, seed=args.seed,
                                                embed=[Path(e) for e in args.embed or []]),
                    "seed": args.seed}
        result = run_suite(root, rules, jobs=jobs, scales=scales,
                           warm=not args.no_warm)
    result["tree"] = tree

    print(f"{'run':10s} {'rules':>6s} {'scan s':>8s} {'units':>7s} {'peak MB':>8s} "
          f"{'tokenised':>10s} {'rule checks':>12s} {'skipped':>8s}")
    for run in result["runs"]:
        print(f"{run['mode'] + ' x' + str(run['scale']):10s} {run['rules']:6d} "
              f"{run['scan_s']:8.2f} {run['scan_units']:7.1f} {run['peak_rss_mb']:8.1f} "
              f"{run.get('files_tokenised', 0):10d} {run.get('rule_checks', 0):12d} "
              f"{run.get('rule_checks_skipped', 0):8d}")
    print(f"\ncalibration {result['calibration_s']}s; numpy "
          f"{'on' if result['numpy'] else 'off'}; jobs {jobs}")

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n",
                                     encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    if args.check:
        try:
            baseline = json.loads(Path(args.check).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read baseline {args.check}: {exc}", file=sys.stderr)
            return 2
        if baseline.get("numpy") != result["numpy"]:
            print("note: numpy differs from the baseline run; times are not "
                  "compared, counters and memory still are", file=sys.stderr)
        problems = check(result, baseline)
        if problems and all(" calibration units " in p for p in problems):
            # Time alone is noisy on a shared runner; a real regression
            # survives a second measurement, a busy neighbour does not.
            print("time over the margin; measuring once more", file=sys.stderr)
            with tempfile.TemporaryDirectory(prefix="gangmu-perf-") as tmp:
                if not args.root:
                    root = Path(tmp) / "synthetic"
                    synthetic_tree(root, seed=args.seed,
                                   embed=[Path(e) for e in args.embed or []])
                problems = check(run_suite(root, rules, jobs=jobs, scales=scales,
                                           warm=not args.no_warm), baseline)
        for problem in problems:
            print(f"regression: {problem}", file=sys.stderr)
        if problems:
            return 1
        print("performance holds against the baseline", file=sys.stderr)
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """Measure the two passes separately, because only one of them usually runs."""
    import time

    include = args.include or list(DEFAULT_INCLUDE)
    jobs = _resolve_jobs(args.jobs)
    rows = []
    for target in args.directory:
        path = Path(target)
        t0 = time.perf_counter()
        dp = print_directory(path, include, jobs=jobs)
        fileset = dp.fileset_sha256
        t1 = time.perf_counter()
        fps = dp.fingerprints
        t2 = time.perf_counter()
        sig = dp.signature(size=args.size)
        t3 = time.perf_counter()
        rows.append((path.name, dp.file_count, len(fps), t1 - t0, t2 - t1, t3 - t2,
                     fileset[:8], sig))

    print(f"{'tree':24s} {'files':>6s} {'fprints':>9s} "
          f"{'pass1(s)':>9s} {'pass2(s)':>9s} {'sketch(s)':>10s}")
    for name, files, nfp, p1, p2, p3, _, _ in rows:
        print(f"{name:24s} {files:6d} {nfp:9d} {p1:9.3f} {p2:9.3f} {p3:10.3f}")
    print(f"\njobs={jobs}, sketch size={args.size}")
    print("pass1 = walk + sha256 (always runs); pass2 = tokenise + winnow "
          "(skipped when the fileset hash already matches a rule)")

    if len(rows) > 1:
        print("\nsimilarity matrix")
        names = [r[0] for r in rows]
        print(" " * 24 + " ".join(f"{n[:10]:>10s}" for n in names))
        for name, *_rest in rows:
            sig_a = next(r[7] for r in rows if r[0] == name)
            cells = " ".join(f"{sig_a.similarity(r[7]):10.3f}" for r in rows)
            print(f"{name:24s} {cells}")
    return 0
