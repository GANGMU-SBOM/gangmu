"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .build.facts import collect_build_facts
from .build.kconfig import find_kconfig, read_kconfig
from .config import CONFIG_NAMES, write_template
from .cra import REPORT_STAGES, build_evidence_bundle, check_cra, draft_report
from .cn import check_dual_regime, draft_miit_report
from .build.projects import parse_project
from .build.wrap import default_compilers, wrap_build
from .core.plugins import register_commands
from .sbom import to_cyclonedx, to_spdx, to_spdx3
from .scan import POSSIBLE_BELOW, ScanOptions, scan

from .commands.common import (  # noqa: F401 - re-exported for plug-ins and tests
    DEFAULT_CACHE,
    _resolve_jobs,
    _resolve_cache,
    _rule_roots,
    _load_rulebase,
    _roots_text,
    _write,
    _table,
    _config,
    _from_config,
    _load_json)
from .commands.rules import (  # noqa: F401 - re-exported for plug-ins and tests
    cmd_rules_lint,
    cmd_rules_index,
    cmd_rules_fingerprint,
    cmd_rules_import,
    cmd_rules_functions,
    cmd_rules_binary_prints,
    cmd_rules_cpe_evidence,
    cmd_rules_verify)
from .commands.vuln import (  # noqa: F401 - re-exported for plug-ins and tests
    cmd_vuln,
    _apply_patches,
    cmd_patch_verify,
    cmd_patch_build,
    _fix_from_advisory,
    _apply_reachability,
    _cn_keeper,
    cmd_cn_db_check,
    cmd_vuln_coverage,
    cmd_vuln_fetch)
from .commands.boms import (  # noqa: F401 - re-exported for plug-ins and tests
    _identified_components,
    cmd_cbom,
    cmd_aibom,
    cmd_policy_check)
from .commands.evals import (  # noqa: F401 - re-exported for plug-ins and tests
    _STANDARDS,
    cmd_sbom_score,
    disasm_arches,
    cmd_binary_eval,
    cmd_binary_functions,
    cmd_eval,
    cmd_perf,
    cmd_bench)


def cmd_scan(args: argparse.Namespace) -> int:
    config = _config(args)
    args.root = args.root or config.get("build.root") or "."
    args.compile_db = _from_config(args, "compile_db", "build.compile_db", config)
    args.link_map = _from_config(args, "link_map", "build.link_map", config)
    args.project = _from_config(args, "project", "build.project", config)
    args.rules = _from_config(args, "rules", "build.rules", config)
    if args.app_name == "firmware" and config.product_name:
        args.app_name = config.product_name
    if not args.app_version and config.product_version:
        args.app_version = config.product_version
    rulebase = _load_rulebase(args.rules)
    for err in rulebase.errors:
        print(f"warning: {err}", file=sys.stderr)
    for note in rulebase.overridden:
        print(f"note: rule {note}", file=sys.stderr)
    if not rulebase.rules:
        print(f"error: no usable rules in {_roots_text(rulebase)}", file=sys.stderr)
        return 2

    facts = None
    db = None
    if args.project:
        try:
            parsed = parse_project(Path(args.project), args.configuration)
        except (ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for note in parsed.notes:
            print(f"note: {note}", file=sys.stderr)
        print(f"{parsed.kind} project '{parsed.project.name}'"
              + (f" [{parsed.configuration}]" if parsed.configuration else "")
              + f": {len(parsed.sources)} source(s) built, "
                f"{len(parsed.excluded)} excluded from this configuration",
              file=sys.stderr)
        db = parsed.to_compile_db()

    if db is not None or args.compile_db or args.link_map:
        facts = collect_build_facts(Path(args.root),
                                    Path(args.compile_db) if args.compile_db else None,
                                    Path(args.link_map) if args.link_map else None,
                                    db=db)
        print(f"build facts: {facts.summary()}", file=sys.stderr)
        if not facts.compiled and (db is not None or args.compile_db):
            print("error: the compile database or project lists no source file "
                  f"under {args.root}, so every component would be reported as "
                  "not linked. Check that it came from a build of this tree "
                  "(for `gangmu wrap`, pass --compiler with the exact compiler "
                  "name the build uses).", file=sys.stderr)
            return 2
        if facts.ambiguous_objects:
            print(f"warning: {len(facts.ambiguous_objects)} object basename(s) are "
                  f"ambiguous and were kept conservatively", file=sys.stderr)

    kconfig = None
    if not args.no_kconfig:
        kc_path = Path(args.kconfig) if args.kconfig else find_kconfig(Path(args.root))
        if kc_path is not None:
            try:
                kconfig = read_kconfig(kc_path)
            except OSError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print(f"build configuration: {kc_path} ({len(kconfig)} option(s))",
                  file=sys.stderr)
    support = None
    if args.support:
        from .support import SupportError, load_overrides
        try:
            support = load_overrides(Path(args.support))
        except (OSError, SupportError) as exc:
            print(f"error: --support: {exc}", file=sys.stderr)
            return 2
    result = scan(Path(args.root), rulebase, facts,
                  ScanOptions(deep=args.deep, kconfig=kconfig, min_confidence=args.min_confidence,
                              jobs=_resolve_jobs(args.jobs),
                              cache_dir=_resolve_cache(args),
                              support=support,
                              declared=not args.no_declared,
                              licenses=not args.no_licenses,
                              binaries=not args.no_binaries,
                              possible_below=0.0 if args.include_possible
                              else POSSIBLE_BELOW))

    if args.format != "table":
        for note in result.notes:
            print(f"note: {note}", file=sys.stderr)
    if args.format == "table":
        _write(_table(result), args.output)
    elif args.format == "json":
        _write(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), args.output)
    elif args.format == "spdx":
        _write(json.dumps(to_spdx(result, args.app_name, args.app_version),
                          indent=2, ensure_ascii=False), args.output)
    elif args.format == "spdx3":
        _write(json.dumps(to_spdx3(result, args.app_name, args.app_version),
                          indent=2, ensure_ascii=False), args.output)
    else:
        _write(json.dumps(to_cyclonedx(result, args.app_name, args.app_version),
                          indent=2, ensure_ascii=False), args.output)

    if args.fail_under is not None:
        weak = [f for f in result.findings if f.confidence < args.fail_under]
        if weak:
            print(f"error: {len(weak)} component(s) below confidence "
                  f"{args.fail_under}", file=sys.stderr)
            return 1
    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    """Join CycloneDX documents (ours, the vendor's, a Yocto or Conan SBOM) into one."""
    from .sbom.merge import MergeError, merge_boms
    documents = []
    for path in args.files:
        try:
            documents.append((Path(path).name,
                              json.loads(Path(path).read_text(encoding="utf-8"))))
        except (OSError, ValueError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return 2
    try:
        merged, report = merge_boms(documents)
    except MergeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _write(json.dumps(merged, indent=2, ensure_ascii=False), args.output)
    print(f"merged {report.inputs} documents: {report.components_in} components in, "
          f"{report.components_out} out ({report.duplicates} duplicates joined), "
          f"{report.vulnerabilities_out} vulnerabilities", file=sys.stderr)
    for name, versions in report.disagreements:
        print(f"  disagreement: {name} is {' and '.join(versions)}", file=sys.stderr)
    for text in report.state_conflicts:
        print(f"  vulnerability state: {text} (kept the more cautious)", file=sys.stderr)
    if report.dangling_dependencies:
        print(f"  {report.dangling_dependencies} dependency references pointed at "
              "components no document lists and were dropped", file=sys.stderr)
    return 1 if args.fail_on_disagreement and (
        report.disagreements or report.state_conflicts) else 0


def cmd_license_check(args: argparse.Namespace) -> int:
    """Triage the licences in a CycloneDX SBOM: copyleft, possible incompatibilities, gaps."""
    from .licensecheck import check_licenses, render
    try:
        bom = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: {args.sbom}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        print(f"error: {args.sbom}: not a CycloneDX JSON document", file=sys.stderr)
        return 2
    report = check_licenses(bom)
    if args.format == "json":
        print(json.dumps({
            "counts": report.counts, "copyleft": report.copyleft, "network": report.network,
            "possibleConflicts": [{"a": a, "b": b, "why": w}
                                  for a, b, w in report.possible_conflicts],
            "noLicence": report.unlicensed,
            "prebuiltBinariesWithoutLicence": report.unlicensed_files},
            indent=2, ensure_ascii=False))
    else:
        print(render(report))
    failing = {"copyleft": bool(report.copyleft or report.network),
               "incompatible": bool(report.possible_conflicts),
               "unlicensed": bool(report.unlicensed or report.unlicensed_files)}
    return 1 if any(failing[k] for k in args.fail_on) else 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two CycloneDX files, e.g. ours against the vendor's own SBOM."""
    def load(path: str) -> dict:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def index(bom: dict) -> dict:
        out = {}
        for comp in bom.get("components", []):
            key = (comp.get("name", "").lower(), comp.get("version") or "")
            out[key] = comp
        return out

    a, b = index(load(args.left)), index(load(args.right))
    names_a = {k[0] for k in a}
    names_b = {k[0] for k in b}

    only_a = sorted(names_a - names_b)
    only_b = sorted(names_b - names_a)
    both = sorted(names_a & names_b)

    version_mismatch = []
    for name in both:
        va = {k[1] for k in a if k[0] == name}
        vb = {k[1] for k in b if k[0] == name}
        if va != vb:
            version_mismatch.append((name, sorted(va), sorted(vb)))

    print(f"left  : {args.left}  ({len(names_a)} component names)")
    print(f"right : {args.right}  ({len(names_b)} component names)")
    print(f"\nin both            : {len(both)}")
    print(f"only on the left   : {len(only_a)}" + (f"  {only_a}" if only_a else ""))
    print(f"only on the right  : {len(only_b)}" + (f"  {only_b}" if only_b else ""))
    if version_mismatch:
        print("\nversion disagreements:")
        for name, left_versions, right_versions in version_mismatch:
            print(f"  {name}: left={left_versions} right={right_versions}")
    recall = len(both) / len(names_b) if names_b else 1.0
    print(f"\nrecall against right: {recall:.2%}")
    if args.fail_under is not None and recall < args.fail_under:
        return 1
    return 0


# ------------------------------------------------------------------- main

def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.directory or ".") / CONFIG_NAMES[0]
    if target.exists() and not args.force:
        print(f"{target} already exists; pass --force to overwrite", file=sys.stderr)
        return 1
    try:
        write_template(target)
    except OSError as exc:
        print(f"error: cannot write {target}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    print(f"wrote {target}")
    print("Fill in the REQUIRED fields, then run `gangmu cra-check` to see which "
          "obligations they unblock.")
    return 0


_VERDICT_MARK = {"met": "ok  ", "partial": "part", "not met": "FAIL",
                 "declared": "decl", "out of scope": "----"}


def cmd_cra_check(args: argparse.Namespace) -> int:
    config = _config(args)
    if config.path:
        print(f"configuration: {config.path}", file=sys.stderr)
    else:
        print("warning: no gangmu.yaml found. Several obligations can only be "
              "satisfied by a declaration; run `gangmu init` first.",
              file=sys.stderr)
    result = check_cra(
        config,
        bom=_load_json(args.sbom, "SBOM"),
        vex=_load_json(args.vex, "VEX"),
        scan=_load_json(args.scan, "scan"),
        evidence_bundle=Path(args.evidence) if args.evidence else None)

    if args.format == "json":
        _write(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), args.output)
    else:
        lines = []
        for finding in result.findings:
            mark = _VERDICT_MARK.get(finding.verdict.value, "?")
            lines.append(f"{mark} {finding.requirement.id:9s} "
                         f"{finding.requirement.clause:24s} "
                         f"{finding.requirement.title}")
            for item in finding.evidence:
                lines.append(f"         + {item}")
            for item in finding.gaps:
                lines.append(f"         ! {item}")
            if finding.next_step:
                lines.append(f"         -> {finding.next_step}")
        counts = result.counts()
        lines += ["", "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))]
        if result.blocking:
            lines.append("")
            lines.append("Blocking: " + ", ".join(f.requirement.id
                                                  for f in result.blocking))
        lines.append("")
        lines.append("'out of scope' means the obligation is real and this tool "
                     "does not address it. Those are yours to document.")
        _write("\n".join(lines), args.output)
    return 1 if (result.blocking and not args.no_fail) else 0


def cmd_report(args: argparse.Namespace) -> int:
    config = _config(args)
    if args.regime == "cn-miit":
        miit = draft_miit_report(
            config, args.advisory, vex=_load_json(args.vex, "VEX"),
            found_at=args.aware_at, impact=args.summary or "",
            scope=args.scope or "", measures=args.corrective_measure or "",
            stage="report" if args.stage == "early-warning" else "update")
        _write(json.dumps(miit.to_dict(), indent=2, ensure_ascii=False)
               if args.format == "json" else miit.to_markdown(), args.output)
        if miit.missing:
            print(f"{len(miit.missing)} 个必填字段尚未填写："
                  + "、".join(f.label for f in miit.missing), file=sys.stderr)
            return 1
        return 0

    for note in check_dual_regime(config):
        print(f"note: {note.splitlines()[0]}", file=sys.stderr)
    draft = draft_report(
        args.stage, config, args.advisory,
        vex=_load_json(args.vex, "VEX"),
        aware_at=args.aware_at, summary=args.summary or "",
        corrective_measure=args.corrective_measure or "",
        exploited=not args.incident)
    if args.format == "json":
        _write(json.dumps(draft.to_dict(), indent=2, ensure_ascii=False), args.output)
    else:
        _write(draft.to_markdown(), args.output)
    if draft.missing:
        print(f"{len(draft.missing)} required field(s) are still empty: "
              + ", ".join(f.label for f in draft.missing), file=sys.stderr)
        return 1
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    config = _config(args)
    verification = None
    if args.verification and Path(args.verification).exists():
        verification = Path(args.verification).read_text(encoding="utf-8")
    cra = None
    if args.sbom or args.vex:
        cra = check_cra(config, bom=_load_json(args.sbom, "SBOM"),
                        vex=_load_json(args.vex, "VEX"),
                        evidence_bundle=Path(args.out)).to_dict()
    bundle = build_evidence_bundle(
        Path(args.out), config,
        sbom=Path(args.sbom) if args.sbom else None,
        vex=Path(args.vex) if args.vex else None,
        scan_json=Path(args.scan) if args.scan else None,
        rules_dirs=[r.path for r in _rule_roots(args.rules)] if not args.no_rules else None,
        verification=verification, cra_check=cra,
        compile_db=Path(args.compile_db) if args.compile_db else None,
        link_map=Path(args.link_map) if args.link_map else None)
    print(f"{len(bundle.entries)} file(s) -> {args.out}")
    for note in bundle.notes:
        print(f"note: {note}", file=sys.stderr)
    print(f"Keep this for {config.get('retention.years', 10)} years "
          f"(Article 13(14)). manifest.json holds a sha256 for every file.")
    return 0


def cmd_wrap(args: argparse.Namespace) -> int:
    command = [a for a in args.command if a != "--"]
    if not command:
        print("error: give the build command after --, e.g. "
              "gangmu wrap -o cc.json -- make -j8", file=sys.stderr)
        return 2
    compilers = args.compiler or default_compilers()
    try:
        result = wrap_build(command, compilers, Path(args.out),
                            workdir=Path(args.directory) if args.directory else None)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{result.invocations} compile step(s) recorded -> {args.out}",
          file=sys.stderr)
    if result.invocations == 0:
        print("warning: nothing was recorded. Either the build was already up to "
              "date (try a clean build) or it invokes the compiler by an absolute "
              "path, which a PATH shim cannot intercept -- pass --compiler with "
              "the exact name the build uses.", file=sys.stderr)
    return result.returncode


def cmd_keygen(args: argparse.Namespace) -> int:
    from .core.signing import SigningError, generate_keypair
    try:
        priv, pub = generate_keypair(Path(args.out), args.name)
    except SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"private key: {priv} (keep it secret and backed up)\npublic key:  {pub}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    from .core.signing import SigningError, sign_file
    try:
        out = sign_file(Path(args.file), Path(args.key),
                        Path(args.output) if args.output else None)
    except (SigningError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"signed {args.file} -> {out}")
    return 0


def cmd_sign_verify(args: argparse.Namespace) -> int:
    from .core.signing import SigningError, verify_file
    try:
        result = verify_file(Path(args.file), Path(args.sig) if args.sig else None,
                             Path(args.pubkey) if args.pubkey else None)
    except SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not result.valid:
        print(f"FAILED: {result.problem}", file=sys.stderr)
        return 1
    if result.trusted is False:
        print(f"FAILED: {result.problem} (key {result.key_id})", file=sys.stderr)
        return 1
    print(f"OK: signature valid, key {result.key_id}, signed {result.signed_at}")
    if result.trusted is None:
        print("note: no --pubkey given, so this only shows the file matches the key "
              "inside the signature file; compare the key id with one you trust.",
              file=sys.stderr)
    return 0


RULES_HELP = ("rule directory; repeat to overlay several (a later directory's "
              "rule replaces an earlier one with the same id). Default: the "
              "installed rule packs")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gangmu",
        description="Build-time SBOM for embedded C/C++, with a community rule base.")
    p.add_argument("--version", action="version", version=f"gangmu-sbom {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="identify components in a source tree")
    s.add_argument("root", nargs="?",
                   help="source tree to scan (default: build.root from the config)")
    s.add_argument("--rules", action="append", help=RULES_HELP)
    s.add_argument("--config", help=f"project configuration "
                                    f"(default: nearest {CONFIG_NAMES[0]})")
    s.add_argument("--compile-db", help="compile_commands.json from the real build")
    s.add_argument("--link-map", help="linker .map file from the real build (GNU ld, lld, IAR ilink or Arm armlink)")
    s.add_argument("--kconfig",
                   help="sdkconfig or Zephyr .config of the real build; components whose "
                        "options it turns off are left out (default: sdkconfig, "
                        "build/sdkconfig, build/zephyr/.config or .config under the root)")
    s.add_argument("--no-kconfig", action="store_true",
                   help="do not read a build configuration, list every component in the tree")
    s.add_argument("--project",
                   help="IAR .ewp, Keil .uvprojx or CCS project to read the "
                        "built file list from, when there is no compile database")
    s.add_argument("--configuration",
                   help="IDE configuration or target name (default: the first)")
    s.add_argument("--format",
                   choices=["cyclonedx", "spdx", "spdx3", "json", "table"],
                   default="table",
                   help="spdx is SPDX 2.3; spdx3 is SPDX 3.0.1 JSON-LD")
    s.add_argument("--support", metavar="FILE",
                   help="JSON or YAML naming each component's maintenance status "
                        "and end-of-support date (status: maintained, limited, "
                        "no_longer_maintained, abandoned). Overrides the rules' "
                        "own upstream.support; components nobody names are "
                        "written as 'unknown'")
    s.add_argument("--output", "-o")
    s.add_argument("--deep", action="store_true",
                   help="also consider directories with no manifest or licence file")
    s.add_argument("--no-declared", action="store_true",
                   help="ignore RT-Thread .config / packages and OpenHarmony "
                        "README.OpenSource declarations")
    s.add_argument("--no-licenses", action="store_true",
                   help="do not read SPDX-License-Identifier headers and LICENSE files "
                        "of the components found (the SBOM then carries only the "
                        "licence the rule records)")
    s.add_argument("--min-confidence", type=float, default=0.35)
    s.add_argument("--no-binaries", action="store_true",
                   help="do not inventory prebuilt .a/.lib/.so files")
    s.add_argument("--include-possible", action="store_true",
                   help="put weak identifications (identity below 0.60) into the "
                        "SBOM too, as earlier versions did")
    s.add_argument("--fail-under", type=float,
                   help="exit non-zero if any component falls below this confidence")
    s.add_argument("--app-name", default="firmware")
    s.add_argument("--app-version")
    s.add_argument("--jobs", "-j", type=int, default=0,
                   help="worker processes for fingerprinting; 0 = auto, 1 = serial")
    s.add_argument("--cache-dir", help=f"sketch cache (default {DEFAULT_CACHE})")
    s.add_argument("--no-cache", action="store_true")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="work on the rule base")
    rsub = r.add_subparsers(dest="rules_command", required=True)

    rl = rsub.add_parser("lint", help="parse and validate every rule")
    rl.add_argument("--rules", action="append", help=RULES_HELP)
    rl.set_defaults(func=cmd_rules_lint)

    ri = rsub.add_parser(
        "index",
        help="precompile a rule directory so it loads without parsing YAML "
             "(run it when a rule pack is built; entries are checked by hash)")
    ri.add_argument("directory", nargs="+")
    ri.set_defaults(func=cmd_rules_index)

    rf = rsub.add_parser("fingerprint",
                         help="print the identity block for a pristine upstream tree")
    rf.add_argument("directory")
    rf.add_argument("--version", help="the upstream version this tree is")
    rf.add_argument("--anchor", action="append",
                    help="path (relative to DIRECTORY) to pin by hash; repeatable")
    rf.add_argument("--include", action="append")
    rf.add_argument("--exclude", action="append")
    rf.add_argument("--jobs", "-j", type=int, default=0)
    rf.set_defaults(func=cmd_rules_fingerprint)

    ri = rsub.add_parser(
        "import",
        help="derive draft rules from a vendor SDK's own pins "
             "(git submodules, or a west manifest)")
    ri.add_argument("sdk_repo", help="SDK git URL, or a local clone")
    ri.add_argument("--manifest", choices=["gitmodules", "west"],
                    default="gitmodules",
                    help="how the SDK pins its third-party code")
    ri.add_argument("--manifest-file", help="west manifest name (default west.yml)")
    ri.add_argument("--group", action="append",
                    help="west group to re-enable, e.g. optional; repeatable")
    ri.add_argument("--vendor", required=True)
    ri.add_argument("--sdk", required=True)
    ri.add_argument("--sdk-version")
    ri.add_argument("--out", required=True, help="directory to write rules into")
    ri.add_argument("--only", action="append",
                    help="submodule path to import; repeatable")
    ri.add_argument("--skip", action="append",
                    help="glob of submodule paths to skip; repeatable")
    ri.add_argument("--date", help="value for review.added (default: today)")
    ri.add_argument("--jobs", "-j", type=int, default=0)
    ri.add_argument("--recursive", action="store_true",
                    help="also import submodules nested inside submodules "
                         "(gitmodules), or follow west `import:` entries")
    ri.add_argument("--dry-run", action="store_true")
    ri.add_argument("--verbose", "-v", action="store_true")
    ri.set_defaults(func=cmd_rules_import)

    rfn = rsub.add_parser(
        "functions",
        help="build a multi-version function signature from upstream releases")
    rfn.add_argument("url", help="the upstream repository")
    rfn.add_argument("--out", required=True, help="path for the .fnsig sidecar")
    rfn.add_argument("--tag", action="append", help="explicit tag; repeatable. LABEL=<40-hex commit> pins an untagged release")
    rfn.add_argument("--tag-pattern", help="regex selecting release tags")
    rfn.add_argument("--limit", type=int, default=12,
                     help="how many of the most recent releases to cover")
    rfn.add_argument("--subdir", action="append",
                     help="component root inside the repository; repeat to give "
                          "fallbacks for releases that kept it elsewhere (first "
                          "present wins, '.' is the repository root)")
    rfn.add_argument("--include", action="append")
    rfn.add_argument("--exclude", action="append")
    rfn.add_argument("--strings", action="store_true",
                     help="fingerprint string constants instead of function bodies, "
                          "for recognising the component inside compiled images "
                          "(identity.binary_strings)")
    rfn.add_argument("--jobs", "-j", type=int, default=0)
    rfn.add_argument("--verbose", "-v", action="store_true")
    rfn.set_defaults(func=cmd_rules_functions)

    rbp = rsub.add_parser(
        "binary-prints",
        help="build per-function fingerprints from reference builds (needs capstone)")
    rbp.add_argument("--ref", action="append", required=True,
                     help="LABEL[:BUILD]=PATH to an ELF built from that release; repeatable, "
                          "oldest release first. Give every release at least two builds "
                          "(1.2.11:Os=a.elf 1.2.11:O2=b.elf): they are tested against each "
                          "other. Build for the architecture you will scan, with only the "
                          "library's own code linked in (no libc)")
    rbp.add_argument("--negative", action="append",
                     help="an ELF of unrelated firmware that must match nothing; repeatable")
    rbp.add_argument("--out", required=True, help="path for the .fnprint sidecar")
    rbp.set_defaults(func=cmd_rules_binary_prints)

    rce = rsub.add_parser(
        "cpe-evidence",
        help="find the NVD vendor:product each rule's upstream is filed under")
    rce.add_argument("--nvd", required=True,
                     help="directory of NVD feeds (2.0, 1.1 or the fkie-cad mirror; "
                          ".json, .json.xz or .json.gz)")
    rce.add_argument("--rules", action="append", help=RULES_HELP)
    rce.add_argument("--rule", action="append", help="rule id; repeatable")
    rce.add_argument("--all", action="store_true",
                     help="also check rules that already have a CPE")
    rce.add_argument("--top", type=int, default=3)
    rce.add_argument("--format", choices=["table", "json"], default="table")
    rce.add_argument("--jobs", "-j", type=int, default=0)
    rce.set_defaults(func=cmd_rules_cpe_evidence)

    rv = rsub.add_parser("verify",
                         help="re-derive each rule's evidence from upstream")
    rv.add_argument("--rules", action="append", help=RULES_HELP)
    rv.add_argument("--rule", action="append", help="rule id; repeatable")
    rv.add_argument("--checkout", help="use this local pristine tree instead of fetching")
    rv.add_argument("--tolerance", type=float, default=0.0)
    rv.set_defaults(func=cmd_rules_verify)

    be = sub.add_parser(
        "binary-eval",
        help="score library/release identification on a corpus of real firmware builds")
    be.add_argument("--corpus", required=True,
                    help="directory made by benchmarks/binary/build_corpus.py")
    be.add_argument("--images", metavar="CORPUS",
                    help="a corpus of the same libraries built for another architecture: "
                         "references come from --corpus, images from this one, and only "
                         "string literals are compared")
    be.add_argument("--min-features", type=int, default=2)
    be.add_argument("--tie-share", type=float, default=None,
                    help="score releases by the share of matched functions they explain "
                         "(the older rule) instead of by contradiction")
    be.add_argument("--loo", action="store_true",
                    help="also choose the thresholds with one library held out, per library")
    be.add_argument("--no-cache", action="store_true", help="re-extract every feature")
    be.add_argument("--format", choices=["table", "json"], default="table")
    be.set_defaults(func=cmd_binary_eval)

    bf = sub.add_parser(
        "binary-functions",
        help="recover function boundaries from a firmware image (needs capstone)")
    bf.add_argument("image", help="an ELF, or a raw .bin with a Cortex-M vector table")
    bf.add_argument("--arch", choices=disasm_arches(), help="for a raw image that is not Cortex-M")
    bf.add_argument("--base", help="load address of a raw image, e.g. 0x08000000")
    bf.add_argument("--code-size", help="bytes of code at the start of a raw image, when known "
                                        "(constant tables after it otherwise decode as code)")
    bf.add_argument("--format", choices=["table", "json"], default="table")
    bf.set_defaults(func=cmd_binary_functions)

    i = sub.add_parser("init", help="write a gangmu.yaml for this project")
    i.add_argument("directory", nargs="?")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    cc = sub.add_parser(
        "cra-check",
        help="audit what is in hand against the CRA clauses this tool can address")
    cc.add_argument("--config")
    cc.add_argument("--sbom")
    cc.add_argument("--vex")
    cc.add_argument("--scan", help="the JSON output of `gangmu scan --format json`")
    cc.add_argument("--evidence", help="path to an evidence bundle")
    cc.add_argument("--format", choices=["table", "json"], default="table")
    cc.add_argument("--output", "-o")
    cc.add_argument("--no-fail", action="store_true",
                    help="always exit 0, even with blocking findings")
    cc.set_defaults(func=cmd_cra_check)

    rp = sub.add_parser(
        "report",
        help="draft an Article 14 notification for the ENISA platform")
    rp.add_argument("advisory", help="the CVE or advisory id being reported")
    rp.add_argument("--stage", choices=list(REPORT_STAGES), default="early-warning")
    rp.add_argument("--regime", choices=["eu-cra", "cn-miit"], default="eu-cra",
                    help="eu-cra: CRA Article 14 (ENISA). "
                         "cn-miit: 《网络产品安全漏洞管理规定》第七条 "
                         "(2 days, cstis.cn) -- a wider trigger than CRA's")
    rp.add_argument("--scope", help="cn-miit: 影响范围")
    rp.add_argument("--config")
    rp.add_argument("--vex")
    rp.add_argument("--aware-at", help="ISO timestamp of becoming aware")
    rp.add_argument("--summary")
    rp.add_argument("--corrective-measure")
    rp.add_argument("--incident", action="store_true",
                    help="a severe incident rather than an exploited vulnerability")
    rp.add_argument("--format", choices=["markdown", "json"], default="markdown")
    rp.add_argument("--output", "-o")
    rp.set_defaults(func=cmd_report)

    ev = sub.add_parser(
        "evidence", help="assemble the technical-documentation bundle")
    ev.add_argument("--out", required=True)
    ev.add_argument("--config")
    ev.add_argument("--sbom")
    ev.add_argument("--vex")
    ev.add_argument("--scan")
    ev.add_argument("--rules", action="append", help=RULES_HELP)
    ev.add_argument("--no-rules", action="store_true")
    ev.add_argument("--verification",
                    help="saved output of `gangmu rules verify`")
    ev.add_argument("--compile-db")
    ev.add_argument("--link-map")
    ev.set_defaults(func=cmd_evidence)

    v = sub.add_parser(
        "vuln", help="match an SBOM against advisories and emit CycloneDX VEX")
    v.add_argument("sbom", help="a CycloneDX document from `gangmu scan`")
    v.add_argument("--db", required=True,
                   help="directory of NVD 2.0 and/or OSV JSON files")
    v.add_argument("--format",
                   choices=["table", "cyclonedx", "openvex", "csaf", "json"],
                   default="table",
                   help="cyclonedx: the SBOM with vulnerabilities and analysis; "
                        "openvex: OpenVEX 0.2.0; csaf: CSAF 2.0 csaf_vex "
                        "(draft). openvex and csaf need --publisher")
    v.add_argument("--publisher", metavar="NAME",
                   help="who stands behind the statements: OpenVEX author, CSAF "
                        "publisher name. Never invented by the tool")
    v.add_argument("--publisher-url", metavar="URL",
                   help="CSAF publisher namespace, the issuing party's own URL")
    v.add_argument("--output", "-o")
    v.add_argument("--cn-db",
                   help="目录：CNNVD / CNVD / 工信部 NVDB 的 JSON 导出。"
                        "NVD 与 OSV 都不收国内厂商自报的漏洞")
    v.add_argument("--unlinked-vex", action="store_true",
                   help="components the link map shows are not in the image: write "
                        "their findings as not_affected (code_not_present) instead "
                        "of leaving them in_triage. Off by default: a map cannot "
                        "see LTO or code loaded another way")
    v.add_argument("--include-not-affected", action="store_true",
                   help="also report advisories ruled out by version")
    v.add_argument("--fail-on", action="append",
                   choices=["exploitable", "in_triage", "kev"],
                   help="exit non-zero if any finding is in this state, or "
                        "('kev') is on the CISA known-exploited list and not "
                        "ruled out; repeatable")
    v.add_argument("--no-threat", action="store_true",
                   help="ignore the KEV/EPSS files under <db>/threat/")
    v.add_argument("--source", metavar="DIR",
                   help="the tree that was scanned: report, per finding, whether "
                        "the advisory's vulnerable function is absent, defined "
                        "but unreferenced, or reachable from the product's code")
    v.add_argument("--symbols", action="append", metavar="FILE",
                   help="JSON {\"CVE-...\": [\"function\", ...]} naming the "
                        "vulnerable functions; without it they are guessed from "
                        "the advisory text. Repeatable")
    v.add_argument("--config", action="append", metavar="FILE",
                   help="with --source: the build's configuration, a Kconfig answer file "
                        "(sdkconfig, .config) or a C header (mbedtls_config.h, "
                        "sdkconfig.h). Branches it rules out are not counted, "
                        "and a function only in such a branch is absent. "
                        "Default: the sdkconfig/.config and sdkconfig.h/"
                        "autoconf.h found under --source. Repeatable")
    v.add_argument("--compile-db", metavar="FILE",
                   help="with --source: compile_commands.json of the real build. "
                        "A .c/.cpp file it does not list was not compiled, so "
                        "functions only defined there are absent; each compiled "
                        "file's own -D/-U flags are applied to its #if. Ignored "
                        "(with a note) when it names none of the tree's files")
    v.add_argument("--define", "-D", action="append", metavar="NAME[=VALUE]",
                   help="with --source: a macro the build defines on its "
                        "command line; repeatable")
    v.add_argument("--assume-undefined-off", action="store_true",
                   help="with --source: treat a macro that nothing in the tree, "
                        "--config or --define mentions as off. Right when the "
                        "product's config header is named with --config (Mbed "
                        "TLS mbedtls_config.h); wrong when the toolchain "
                        "defines it")
    v.add_argument("--reachability-vex", action="store_true",
                   help="with --source: mark findings whose function is absent or "
                        "unreferenced not_affected (code_not_present / "
                        "code_not_reachable). Off by default: a source-level "
                        "call graph cannot see binary blobs or assembly")
    v.add_argument("--patches", action="append", metavar="FILE",
                   help="patch records (from `gangmu patch-build`); with --source, "
                        "tests whether each advisory's fix is in the code: the "
                        "fixed body present resolves the finding, the vulnerable "
                        "one confirms it, an edited one is left for a person. "
                        "Repeatable")
    v.add_argument("--no-pack-patches", action="store_true",
                   help="do not load the patch records installed rule packs ship "
                        "(patches/*.json); only --patches files are used")
    v.add_argument("--rules", action="append", metavar="DIR",
                   help="rule directory whose patches/ holds patch records "
                        "(default: the installed rule packs); repeatable")
    v.add_argument("--patch-near-vex", action="store_true",
                   help="with --patches: let an edited function that is a close "
                        "variant of the fixed (or the vulnerable) code change "
                        "the state too. Off by default: only a byte-identical "
                        "body does, a near match is reported for a person to "
                        "confirm")
    v.set_defaults(func=cmd_vuln)

    pb = sub.add_parser(
        "patch-build",
        help="record the functions an advisory's fix changed, for `vuln --patches`")
    pb.add_argument("cve", help="the advisory id the record is for")
    pb.add_argument("--repo", help="the upstream repository: a local clone or a URL")
    pb.add_argument("--fix", action="append", metavar="COMMIT",
                    help="the commit that fixed it (a single non-merge commit); "
                         "repeat for a fix made in several. Omit to read it from "
                         "the advisory in --db")
    pb.add_argument("--db", help="advisory directory to read the repository and "
                                 "fix commit from (OSV GIT ranges)")
    pb.add_argument("--function", action="append", metavar="NAME",
                    help="record only this function (required when the commit "
                         "changes more than 40)")
    pb.add_argument("--first-parent", action="store_true",
                    help="a fix merged as a pull request: take the merge's net "
                         "change against its first parent (it may carry more "
                         "than the fix, so check the functions it names)")
    pb.add_argument("--output", "-o", default="patches.json",
                    help="record file; an existing one is added to (default: "
                         "patches.json)")
    pb.set_defaults(func=cmd_patch_build)

    pv = sub.add_parser(
        "patch-verify",
        help="rebuild patch records from their upstream commits and compare")
    pv.add_argument("files", nargs="+", help="patch record files")
    pv.set_defaults(func=cmd_patch_verify)

    cc = sub.add_parser(
        "cn-db-check",
        help="report what a CNNVD / CNVD export directory yields, file by file")
    cc.add_argument("db", help="directory given to `gangmu vuln --cn-db`")
    cc.set_defaults(func=cmd_cn_db_check)

    vf = sub.add_parser(
        "vuln-fetch",
        help="download advisories into the directory `gangmu vuln --db` reads "
             "(the only command here that needs the network)")
    vf.add_argument("--db", required=True, help="directory to fill or refresh")
    vf.add_argument("--sbom", help="fetch only what this CycloneDX SBOM can match")
    vf.add_argument("--product", action="append",
                    help="part:vendor:product, e.g. a:lwip_project:lwip; repeatable")
    vf.add_argument("--purl", action="append",
                    help="package URL to query OSV for; repeatable")
    vf.add_argument("--all", action="store_true",
                    help="the entire NVD, sharded by year; incremental on re-run")
    vf.add_argument("--since", metavar="YYYY-MM-DD",
                    help="only records modified since (overrides the stored "
                         "watermark)")
    vf.add_argument("--api-key", help="NVD API key (default: $NVD_API_KEY)")
    vf.add_argument("--threat", action="store_true",
                    help="also download CISA KEV and EPSS into <db>/threat/ "
                         "(used by `gangmu vuln` to rank findings)")
    vf.add_argument("--no-nvd", action="store_true")
    vf.add_argument("--no-osv", action="store_true")
    vf.add_argument("--verbose", "-v", action="store_true")
    vf.set_defaults(func=cmd_vuln_fetch)

    vc = sub.add_parser(
        "vuln-coverage",
        help="count the findings a CPE-only scanner would miss on this SBOM")
    vc.add_argument("sbom", help="a CycloneDX document from `gangmu scan`")
    vc.add_argument("--db", required=True,
                    help="directory of NVD 2.0 and OSV JSON files (as for `vuln`)")
    vc.add_argument("--cutoff", default="2026-04-15", metavar="YYYY-MM-DD",
                    help="split NVD records by published date around this day "
                         "(default 2026-04-15, when NVD moved to risk-based enrichment)")
    vc.add_argument("--output", "-o")
    vc.set_defaults(func=cmd_vuln_coverage)

    w = sub.add_parser(
        "wrap",
        help="run a build behind compiler shims and write a compile database")
    w.add_argument("--out", "-o", default="compile_commands.json")
    w.add_argument("--compiler", action="append",
                   help="compiler name to shim; repeatable (default: cc, gcc, "
                        "g++, clang, clang++ and every <triple>-gcc / -g++ / "
                        "-clang found on PATH, e.g. arm-none-eabi-gcc)")
    w.add_argument("--directory", "-C", help="run the command here")
    w.add_argument("command", nargs=argparse.REMAINDER,
                   help="-- then the build command, e.g. -- make -j8")
    w.set_defaults(func=cmd_wrap)

    kg = sub.add_parser("keygen", help="make an Ed25519 key pair for `gangmu sign`")
    kg.add_argument("--out", default=".", help="directory for the key pair")
    kg.add_argument("--name", default="gangmu-signing")
    kg.set_defaults(func=cmd_keygen)

    sg = sub.add_parser(
        "sign", help="detached Ed25519 signature for an SBOM or an evidence manifest "
                     "(needs gangmu-sbom[sign])")
    sg.add_argument("file")
    sg.add_argument("--key", required=True, help="PEM private key (see `gangmu keygen`)")
    sg.add_argument("--output", "-o", help="signature file (default FILE.gangmu-sig)")
    sg.set_defaults(func=cmd_sign)

    sv = sub.add_parser("sign-verify", help="check a signature made by `gangmu sign`")
    sv.add_argument("file")
    sv.add_argument("--sig", help="signature file (default FILE.gangmu-sig)")
    sv.add_argument("--pubkey", help="PEM public key you trust; without it the "
                                      "result is only 'matches the embedded key'")
    sv.set_defaults(func=cmd_sign_verify)

    cb = sub.add_parser(
        "cbom",
        help="list the cryptographic algorithms in a tree or firmware (CycloneDX 1.6 CBOM)")
    cb.add_argument("root", nargs="?", default=".")
    cb.add_argument("--compile-db", help="count only source files this build compiled")
    cb.add_argument("--link-map", help="count only what the link map kept")
    cb.add_argument("--format", choices=["table", "cyclonedx", "readiness"], default="table",
                    help="readiness: a Markdown post-quantum migration summary")
    cb.add_argument("--output", "-o")
    cb.add_argument("--app-name", default="firmware")
    cb.add_argument("--app-version", default="")
    cb.add_argument("--include-tests", action="store_true",
                    help="also read test and fixture directories")
    cb.add_argument("--no-binaries", action="store_true",
                    help="do not read prebuilt libraries and firmware images")
    cb.add_argument("--rules", action="append", metavar="DIR",
                    help="a rule pack directory whose algorithms/*.yaml add to or replace the "
                         "built-in algorithm table (default: installed packs of kind 'cbom'); "
                         "repeatable")
    cb.add_argument("--libraries", action="store_true",
                    help="also run the SBOM scan and add the algorithms that the identified "
                         "libraries' capability tables list (needs a cbom rule pack with "
                         "libraries/*.yaml)")
    cb.add_argument("--fail-on", action="append", choices=["quantum-vulnerable", "legacy"],
                    help="exit 1 when a counted algorithm is in this class (repeatable)")
    cb.set_defaults(func=cmd_cbom)

    ai = sub.add_parser(
        "aibom",
        help="list the ML models and inference runtimes in a tree or firmware "
             "(CycloneDX 1.6 AIBOM)")
    ai.add_argument("root", help="source tree or firmware directory to read")
    ai.add_argument("--format", choices=["table", "cyclonedx"], default="table")
    ai.add_argument("--output", "-o")
    ai.add_argument("--app-name", default="firmware")
    ai.add_argument("--app-version", default="")
    ai.add_argument("--include-tests", action="store_true",
                    help="also read test and fixture directories")
    ai.add_argument("--rules", action="append", metavar="DIR",
                    help="a rule pack directory whose formats/*.yaml and runtimes/*.yaml add to "
                         "or replace the built-in tables (default: installed packs of kind "
                         "'aibom'); repeatable")
    ai.add_argument("--declarations", metavar="FILE",
                    help="declaration file with training data, licence and intended use "
                         "(default: gangmu-aibom.yaml in the tree, if present)")
    ai.add_argument("--require-declarations", action="store_true",
                    help="exit 1 when a model has no declared licence or training data")
    ai.set_defaults(func=cmd_aibom)

    po = sub.add_parser("policy", help="read a CBOM or AIBOM against a written policy")
    psub = po.add_subparsers(dest="policy_command", required=True)
    pc = psub.add_parser(
        "check", help="scan a tree and report what each policy check finds, and when it is due")
    pc.add_argument("root", help="source tree or firmware directory to read")
    pc.add_argument("--policy", action="append", metavar="DIR",
                    help="a policy pack directory with policies/*.yaml (default: installed "
                         "packs of kind 'policy'); repeatable")
    pc.add_argument("--id", action="append", metavar="POLICY",
                    help="only this policy id; repeatable")
    pc.add_argument("--as-of", metavar="YYYY-MM-DD",
                    help="judge deadlines as of this date (default: today)")
    pc.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    pc.add_argument("--output", "-o")
    pc.add_argument("--fail-on", action="append", choices=["due", "deprecated", "fail"],
                    help="exit 1 when a check is at or above this status (default: fail)")
    pc.add_argument("--compile-db", help="compile_commands.json from the real build")
    pc.add_argument("--link-map", help="linker .map file from the real build")
    pc.add_argument("--declarations", metavar="FILE",
                    help="AIBOM declaration file (default: gangmu-aibom.yaml in the tree)")
    pc.set_defaults(func=cmd_policy_check)

    sc = sub.add_parser(
        "sbom-score",
        help="score an SBOM against the NTIA 2021 and CISA 2026 minimum elements")
    sc.add_argument("sbom")
    sc.add_argument("--standard", action="append", choices=list(_STANDARDS))
    sc.add_argument("--format", choices=["table", "json"], default="table")
    sc.add_argument("--output", "-o")
    sc.add_argument("--fail-under", type=float)
    sc.set_defaults(func=cmd_sbom_score)

    ev2 = sub.add_parser(
        "eval", help="reproducible identification benchmark against real releases")
    ev2.add_argument("--signature", required=True, help="a .fnsig to evaluate")
    ev2.add_argument("--tree", action="append",
                     help="PATH=VERSION of a tree with known truth; repeatable")
    ev2.add_argument("--mutate", help="PATH=VERSION of a pristine tree to mutate")
    ev2.add_argument("--include", action="append")
    ev2.add_argument("--jobs", "-j", type=int, default=0)
    ev2.add_argument("--output", "-o")
    ev2.set_defaults(func=cmd_eval)

    b = sub.add_parser("bench", help="time the fingerprint passes on one or more trees")
    b.add_argument("directory", nargs="+")
    b.add_argument("--include", action="append")
    b.add_argument("--jobs", "-j", type=int, default=0)
    b.add_argument("--size", type=int, default=256)
    b.set_defaults(func=cmd_bench)

    pf = sub.add_parser("perf", help="whole-scan performance baseline and "
                                     "regression check")
    pf.add_argument("root", nargs="?",
                    help="tree to scan (default: a seeded synthetic SDK)")
    pf.add_argument("--rules", action="append",
                    help="rule directory; repeat to combine several")
    pf.add_argument("--scale", default="1",
                    help="rule-base multipliers, e.g. 1,4,16 (replicas match nothing)")
    pf.add_argument("--jobs", "-j", type=int, default=1)
    pf.add_argument("--seed", type=int, default=0)
    pf.add_argument("--embed", action="append",
                    help="copy a real directory into the synthetic tree")
    pf.add_argument("--no-warm", action="store_true",
                    help="skip the warm (incremental cache) rescan")
    pf.add_argument("--check", metavar="BASELINE",
                    help="fail if this run regresses against a baseline JSON")
    pf.add_argument("--output", "-o", help="write the measurements as JSON")
    pf.set_defaults(func=cmd_perf)

    d = sub.add_parser("diff", help="compare two CycloneDX documents")
    d.add_argument("left")
    d.add_argument("right")
    d.add_argument("--fail-under", type=float)
    d.set_defaults(func=cmd_diff)

    mg = sub.add_parser("merge", help="join CycloneDX documents (ours, the vendor's, "
                                      "a Yocto or Conan SBOM) into one")
    mg.add_argument("files", nargs="+", metavar="FILE",
                    help="CycloneDX JSON documents; the first wins on every field it has")
    mg.add_argument("--output", "-o", help="write the merged document here (default stdout)")
    mg.add_argument("--fail-on-disagreement", action="store_true",
                    help="exit 1 when documents give one component different versions or "
                         "one vulnerability different states")
    mg.set_defaults(func=cmd_merge)

    lc = sub.add_parser("license-check", help="triage the licences in a CycloneDX SBOM "
                                              "(copyleft, possible incompatibilities, gaps)")
    lc.add_argument("sbom", help="CycloneDX JSON document")
    lc.add_argument("--format", choices=["text", "json"], default="text")
    lc.add_argument("--fail-on", action="append", default=[],
                    choices=["copyleft", "incompatible", "unlicensed"],
                    help="exit 1 when this is found (repeatable)")
    lc.set_defaults(func=cmd_license_check)

    register_commands(sub)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
