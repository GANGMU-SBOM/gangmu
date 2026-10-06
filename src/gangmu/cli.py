"""Command line interface."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from . import __version__
from .build.facts import collect_build_facts
from .cbom import cbom_table, failing, scan_cbom, to_cbom
from .build.kconfig import find_kconfig, read_kconfig
from .config import CONFIG_NAMES, Config, load_config, write_template
from .cra import REPORT_STAGES, build_evidence_bundle, check_cra, draft_report
from .cn import MIIT_STAGES, check_dual_regime, draft_miit_report
from .eval import CISA_2026, NTIA_2021, score_sbom
from .build.projects import parse_project
from .build.wrap import default_compilers, wrap_build
from .dirprint import (DEFAULT_EXCLUDE, DEFAULT_INCLUDE, SketchCache,
                       print_directory, sha256_file)
from .fingerprint import ALGO
from .model import ScanResult
from .rules.loader import RuleBase, load_rule_roots, load_rules
from .rules.schema import RuleError
from .plugins import register_commands
from .rules.packs import RulePackError, RuleRoot, default_roots
from .sbom import to_cyclonedx, to_spdx, to_spdx3
from .globbing import matches_suffix
from .importers import (build_function_signature, dump_rule, import_gitmodules,
                        import_west, list_tags, pick_releases, tag_to_version)
from .scan import POSSIBLE_BELOW, ScanOptions, scan
from .vuln.model import VexState
from .vuln import (apply_linkage, candidates_from_cyclonedx, enrich as cn_enrich, load_cn_report,
                   load_database, match as match_vulns, wanted_for, summary as vex_summary,
                   to_vex, unmatched_components, without_cpe)
from .verify import verify_rule, verify_with_fetch

DEFAULT_CACHE = Path(
    os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "gangmu"


# ----------------------------------------------------------------- helpers

def _resolve_jobs(value: int) -> int:
    """0 means auto. Capped at 8: beyond that the walk and the disk dominate."""
    if value and value > 0:
        return value
    return max(1, min(8, os.cpu_count() or 1))


def _resolve_cache(args) -> Optional[Path]:
    if getattr(args, "no_cache", False):
        return None
    return Path(getattr(args, "cache_dir", None) or DEFAULT_CACHE)

def _rule_roots(arg) -> List[RuleRoot]:
    """``--rules`` (repeatable) replaces the defaults; later roots overlay earlier."""
    given = [arg] if isinstance(arg, str) else list(arg or [])
    if given:
        for path in given:
            if not Path(path).is_dir():
                raise SystemExit(f"rule base not found: {path}")
        return [RuleRoot(Path(p), "--rules") for p in given]
    roots = default_roots(fallback=[Path.cwd() / "rules"])
    missing = [r.path for r in roots if not r.path.is_dir()]
    if missing:
        raise SystemExit(f"rule base not found: {missing[0]} (from GANGMU_RULES)")
    if not roots:
        raise SystemExit(
            "no rule base found. Install it with `pip install gangmu-rules`, "
            "pass --rules PATH, or set GANGMU_RULES to a checkout of the rules.")
    return roots


def _load_rulebase(arg) -> RuleBase:
    try:
        return load_rule_roots(_rule_roots(arg), strict=False)
    except RulePackError as exc:
        raise SystemExit(f"error: {exc}")


def _roots_text(rulebase: RuleBase) -> str:
    return ", ".join(str(r.path) for r in rulebase.roots)


def _write(data: str, out: Optional[str]) -> None:
    if out and out != "-":
        Path(out).write_text(data, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(data)


def _table(result: ScanResult) -> str:
    rows = [("CONF", "COMPONENT", "VERSION", "SRC", "DIRECTORY", "NOTES")]
    for f in result.findings:
        notes = []
        if f.vendor_patched:
            # Not a known release: a vendor fork, or simply a commit newer than the recorded versions.
            notes.append("vendor-modified (or newer than known releases)")
        if f.linked is False:
            notes.append("not linked")
        if f.alternatives:
            notes.append(f"{len(f.alternatives)} alt")
        rows.append((
            f"{f.confidence:.2f}",
            f.upstream_name[:28],
            (f.version or "-")[:14],
            (f.version_source or "-")[:9],
            f.directory[:44],
            ", ".join(notes),
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
             for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    if result.binaries:
        named = sum(1 for b in result.binaries if b.embedded)
        lines.append("")
        lines.append(f"{len(result.binaries)} prebuilt binar(ies) with no source "
                     f"({named} with a version banner); listed in the SBOM, "
                     "not analysable here")
    if result.possible:
        lines.append("")
        lines.append("POSSIBLE (resemble a known component, not enough to assert; "
                     "left out of the SBOM -- use --include-possible to keep them)")
        for f in result.possible:
            lines.append(f"  {f.identity_confidence:.2f}  {f.upstream_name}  "
                         f"{f.version or '-'}  {f.directory}")
    tail = [
        "",
        f"{len(result.findings)} component(s) identified from "
        f"{result.rules_loaded} rule(s)"
        + ("; build facts used" if result.build_facts_used else "; no build facts"),
    ]
    for note in result.notes:
        tail.append(f"note: {note}")
    if result.unidentified:
        tail.append(f"{len(result.unidentified)} candidate director(ies) unidentified: "
                    + ", ".join(result.unidentified[:8])
                    + (" ..." if len(result.unidentified) > 8 else ""))
    return "\n".join(lines + tail)


# ------------------------------------------------------------- subcommands

def _config(args) -> Config:
    try:
        return load_config(Path(args.config) if getattr(args, "config", None) else None)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"warning: could not read configuration: {exc}", file=sys.stderr)
        return Config()


def _from_config(args, attr: str, key: str, config: Config):
    """Command line wins; configuration fills the gap; neither is an error."""
    if getattr(args, attr, None):
        return getattr(args, attr)
    return config.get(key)


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


def cmd_rules_lint(args: argparse.Namespace) -> int:
    rulebase = _load_rulebase(args.rules)
    for root in rulebase.roots:
        print(f"root {root.label}: {root.path}")
    for note in rulebase.overridden:
        print(f"over {note}")
    for err in rulebase.errors:
        print(f"FAIL {err}")
    for rule in rulebase:
        if rule.binary_functions is not None:
            try:
                rule.binary_functions.load()
            except (RuleError, OSError, ValueError) as exc:
                print(f"FAIL {rule.id}: {exc}")
                rulebase.errors.append(f"{rule.id}: {exc}")
                continue
        flag = "" if rule.cpe else ("  [no CPE: " +
                                    (rule.cpe_status or "no reason recorded") .split(":")[0] + "]")
        print(f"ok   {rule.id}  ({rule.source_path}){flag}")

    no_cpe = [r for r in rulebase if not r.cpe]
    unexplained = [r for r in no_cpe if not r.cpe_status]
    print(f"\n{len(rulebase)} rule(s) ok, {len(rulebase.errors)} broken")
    if rulebase.rules:
        print(f"{len(rulebase) - len(no_cpe)}/{len(rulebase)} rule(s) carry a CPE "
              f"({len(no_cpe)} do not).")
    if unexplained:
        print(f"\n{len(unexplained)} rule(s) have neither a CPE nor a cpe_status "
              f"saying why. A reader cannot tell 'nobody looked' from 'none "
              f"exists', and those are very different facts:")
        for rule in unexplained:
            print(f"  {rule.id}")
    return 1 if (rulebase.errors or unexplained) else 0


def cmd_rules_index(args: argparse.Namespace) -> int:
    from .rules.loader import INDEX_NAME, build_index
    for directory in args.directory:
        root = Path(directory)
        if not root.is_dir():
            print(f"error: {root} is not a directory", file=sys.stderr)
            return 2
        counts = build_index(root)
        print(f"{root / INDEX_NAME}: {counts['indexed']} rule file(s) indexed"
              + (f", {counts['skipped']} left to the YAML parser" if counts["skipped"] else ""))
    return 0


def cmd_rules_fingerprint(args: argparse.Namespace) -> int:
    """Author-side helper: print the YAML block for a pristine upstream tree."""
    directory = Path(args.directory)
    include = args.include or list(DEFAULT_INCLUDE)
    exclude = args.exclude or list(DEFAULT_EXCLUDE)
    dp = print_directory(directory, include, exclude,
                         jobs=_resolve_jobs(getattr(args, "jobs", 0)))
    sig = dp.signature()
    lines = [
        "identity:",
        "  include: [" + ", ".join(f'"{p}"' for p in include) + "]",
    ]
    if exclude != list(DEFAULT_EXCLUDE):
        lines.append("  exclude: [" + ", ".join(f'"{p}"' for p in exclude) + "]")
    if args.anchor:
        lines.append("  anchors:")
        for rel in args.anchor:
            path = directory / rel
            if not path.is_file():
                print(f"error: anchor not found: {rel}", file=sys.stderr)
                return 2
            lines += [f"    - path: {rel}",
                      "      sha256:",
                      f'        "{args.version or "UNKNOWN"}": "{sha256_file(path)}"']
    lines += [
        "  signature:",
        f"    algo: {ALGO}",
        f"    k: {sig.k}",
        f"    window: {sig.window}",
        f"    size: {sig.size}",
        f'    reference_version: "{args.version}"' if args.version else
        "    reference_version: null",
        f'    fileset_sha256: "{dp.fileset_sha256}"',
        f"    values: >-",
        f"      {sig.to_hex()}",
    ]
    print("\n".join(lines))
    print(f"\n# {dp.file_count} files, {len(dp.fingerprints)} fingerprints, "
          f"fileset {dp.fileset_sha256[:16]}...", file=sys.stderr)
    return 0


def cmd_rules_import(args: argparse.Namespace) -> int:
    """Derive draft rules from a vendor SDK's own pins."""
    out_dir = Path(args.out)
    skip = args.skip or []
    log = ((lambda m: print(f"  .. {m}", file=sys.stderr)) if args.verbose
           else (lambda m: None))
    common = dict(vendor=args.vendor, sdk=args.sdk, sdk_version=args.sdk_version,
                  only=args.only, jobs=_resolve_jobs(args.jobs), log=log)
    if args.manifest == "west":
        results = import_west(args.sdk_repo, enable_groups=args.group or (),
                              manifest_file=args.manifest_file or "west.yml",
                              recursive=args.recursive,
                              **common)
    else:
        results = import_gitmodules(args.sdk_repo, recursive=args.recursive,
                                    **common)

    written = skipped = failed = needs_cpe = 0
    for result in results:
        if skip and matches_suffix(result.project.path, skip):
            print(f"skip {result.project.path}  (matched --skip)")
            skipped += 1
            continue
        if result.status != "ok":
            marker = "----" if result.status == "no-source" else "FAIL"
            print(f"{marker} {result.project.path}  {result.detail}")
            skipped += result.status == "no-source"
            failed += result.status == "error"
            continue
        rule = dict(result.rule)
        rule["review"]["added"] = args.date or _dt.date.today().isoformat()
        text = dump_rule(rule)
        target = out_dir / f"{Path(result.project.path).name}.yaml"
        flag = "  [NEEDS CPE]" if result.needs_cpe else ""
        if args.dry_run:
            print(f"would write {target}  ({result.detail}){flag}")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            print(f"ok   {target}  ({result.detail}){flag}")
        written += 1
        needs_cpe += result.needs_cpe

    print(f"\n{written} rule(s) {'planned' if args.dry_run else 'written'}, "
          f"{skipped} skipped, {failed} failed")
    if needs_cpe:
        print(f"{needs_cpe} rule(s) have no CPE and are marked for review. "
              f"Do not merge them until a human has looked one up: a missing CPE "
              f"matches no CVE and the SBOM still looks clean.")
    return 1 if failed else 0


def cmd_rules_functions(args: argparse.Namespace) -> int:
    """Build the multi-version function signature a rule points at."""
    tags = args.tag or []
    if not tags:
        try:
            found = list_tags(args.url, args.tag_pattern)
        except Exception as exc:                      # noqa: BLE001
            print(f"error: cannot list tags of {args.url}: {exc}", file=sys.stderr)
            return 2
        if not found:
            print(f"error: no tags matched. Pass --tag explicitly.", file=sys.stderr)
            return 2
        tags = pick_releases(found, args.limit)
    for entry in tags:
        rev = entry.partition("=")[2]
        if rev and not re.fullmatch(r"[0-9a-f]{40}", rev):
            print(f"error: --tag {entry}: a pinned revision must be a full "
                  f"40-hex commit id, never a branch or abbreviated id",
                  file=sys.stderr)
            return 2
    print(f"building from {len(tags)} release(s): {', '.join(tags)}", file=sys.stderr)

    report = build_function_signature(
        args.url, tags,
        include=args.include or list(DEFAULT_INCLUDE),
        exclude=args.exclude or list(DEFAULT_EXCLUDE),
        subdir=args.subdir, label=tag_to_version, strings=args.strings,
        jobs=_resolve_jobs(args.jobs),
        log=(lambda m: print(f"  .. {m}", file=sys.stderr)) if args.verbose
            else (lambda m: None))
    for tag, why in report.skipped:
        print(f"skipped {tag}: {why}", file=sys.stderr)
    if not report.tags:
        print("error: no release yielded functions", file=sys.stderr)
        return 2

    out = Path(args.out)
    digest = report.signature.write(out)
    sig = report.signature
    print(f"wrote {out}  ({len(sig.hashes)} {'string constants' if args.strings else 'functions'} across {len(sig.versions)} "
          f"versions, {len(sig.to_bytes()) / 1024:.1f} KB, "
          f"{len(sig.discriminating())} version-discriminating)", file=sys.stderr)
    block = [
        "  binary_strings:" if args.strings else "  functions:",
        f"    file: {out.name}",
        f'    sha256: "{digest}"',
        f"    count: {len(sig.hashes)}",
        "    versions: [" + ", ".join(f'"{v}"' for v in sig.versions) + "]",
    ]
    print("\n".join(block))
    return 0


def cmd_rules_binary_prints(args: argparse.Namespace) -> int:
    """Build identity.binary_functions from reference builds, after testing it."""
    from . import disasm
    from .calibrate import calibrate, format_calibration
    if not disasm.available():
        print("error: this needs Capstone: pip install 'gangmu-sbom[disasm]'", file=sys.stderr)
        return 2
    builds: Dict[str, Dict[str, bytes]] = {}
    for item in args.ref:
        spec, _, path = item.partition("=")
        label, _, name = spec.partition(":")
        if not label or not path:
            print(f"error: --ref {item}: expected LABEL[:BUILD]=PATH", file=sys.stderr)
            return 2
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        per_release = builds.setdefault(label, {})
        name = name or f"build{len(per_release) + 1}"
        if name in per_release:
            print(f"error: --ref {item}: release {label} already has a build called {name}",
                  file=sys.stderr)
            return 2
        per_release[name] = data
    negatives = []
    for path in args.negative or []:
        try:
            negatives.append(Path(path).read_bytes())
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
    prints, cal = calibrate(builds, negatives)
    print(format_calibration(cal), file=sys.stderr)
    if not cal.passed:
        print("not written: a rule may only carry fingerprints that passed their self-test",
              file=sys.stderr)
        return 1
    out = Path(args.out)
    digest = prints.write(out)
    print(f"wrote {out}  ({len(prints.functions)} functions across {len(prints.versions)} "
          f"versions, {out.stat().st_size / 1024:.1f} KB)", file=sys.stderr)
    print(yaml.safe_dump({"identity": {"binary_functions": {
        "file": out.name, "sha256": digest, "count": len(prints.functions),
        "versions": prints.versions, "calibration": prints.meta}}},
        sort_keys=False, default_flow_style=None).rstrip())
    return 0


def cmd_rules_cpe_evidence(args: argparse.Namespace) -> int:
    """Rank the NVD vendor:product pairs each rule's upstream is filed under."""
    from .vuln.evidence import find_evidence, terms_for
    rulebase = _load_rulebase(args.rules)
    selected = [r for r in rulebase
                if ((r.id in args.rule) if args.rule else (args.all or not r.cpe))]
    if not selected:
        print("nothing to look up: every selected rule already has a CPE "
              "(use --all to check those too)", file=sys.stderr)
        return 0
    try:
        found = find_evidence(Path(args.nvd), [terms_for(r) for r in selected],
                              jobs=_resolve_jobs(args.jobs))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({rule_id: [{"cpe": c.cpe, "by_reference": c.by_reference,
                                     "by_name": c.by_name} for c in cands]
                          for rule_id, cands in found.items()}, indent=2))
        return 0
    for rule in selected:
        cands = found.get(rule.id, [])
        current = f" (rule has {rule.cpe})" if rule.cpe else ""
        print(f"{rule.id}{current}")
        if not cands:
            print("    no NVD record cites the upstream or names it")
        for cand in cands[:args.top]:
            refs = ", ".join(cand.by_reference[:4]) + (
                " ..." if len(cand.by_reference) > 4 else "")
            print(f"    {cand.cpe_key:45s} reference {len(cand.by_reference):4d}"
                  f"  name {len(cand.by_name):4d}  {refs}")
    print("\nOnly a vendor:product cited by reference is evidence. Read the CVEs "
          "before writing a CPE into a rule.", file=sys.stderr)
    return 0


def cmd_rules_verify(args: argparse.Namespace) -> int:
    rulebase = _load_rulebase(args.rules)
    for err in rulebase.errors:
        print(f"FAIL {err}")
    selected = [r for r in rulebase if not args.rule or r.id in args.rule]
    if args.rule and not selected:
        print(f"error: no rule matches {args.rule}", file=sys.stderr)
        return 2

    failures = 0
    for rule in selected:
        if args.checkout:
            report = verify_rule(rule, Path(args.checkout), args.tolerance)
        else:
            report = verify_with_fetch(rule, tolerance=args.tolerance)
        status = "ok  " if report.ok else "FAIL"
        print(f"{status} {rule.id}")
        for line in report.checked:
            print(f"       + {line}")
        for line in report.problems:
            print(f"       ! {line}")
        failures += 0 if report.ok else 1
    print(f"\n{len(selected) - failures}/{len(selected)} rule(s) verified")
    return 1 if (failures or rulebase.errors) else 0


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
        for name, va, vb in version_mismatch:
            print(f"  {name}: left={va} right={vb}")
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


def _load_json(path, what: str):
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: cannot read {what} {path}: {exc}", file=sys.stderr)
        return None


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
        draft = draft_miit_report(
            config, args.advisory, vex=_load_json(args.vex, "VEX"),
            found_at=args.aware_at, impact=args.summary or "",
            scope=args.scope or "", measures=args.corrective_measure or "",
            stage="report" if args.stage == "early-warning" else "update")
        _write(json.dumps(draft.to_dict(), indent=2, ensure_ascii=False)
               if args.format == "json" else draft.to_markdown(), args.output)
        if draft.missing:
            print(f"{len(draft.missing)} 个必填字段尚未填写："
                  + "、".join(f.label for f in draft.missing), file=sys.stderr)
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


def cmd_vuln(args: argparse.Namespace) -> int:
    try:
        bom = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read SBOM {args.sbom}: {exc}", file=sys.stderr)
        return 2
    if bom.get("bomFormat") != "CycloneDX":
        print("error: --sbom must be a CycloneDX document "
              "(gangmu scan --format cyclonedx)", file=sys.stderr)
        return 2
    candidates = candidates_from_cyclonedx(bom)
    try:
        # Only records naming one of this SBOM's products are built: a full
        # NVD mirror is a third of a million records.
        advisories = load_database(Path(args.db), wanted_for(candidates),
                                   jobs=_resolve_jobs(0))
    except FileNotFoundError as exc:
        print(f"error: {exc}\n"
              f"Point --db at a directory of NVD 2.0 or OSV JSON files. The "
              f"lookup is deliberately offline: a report you cannot produce "
              f"without the public internet is one you cannot produce inside a "
              f"factory network, or in the 24 hours after a disclosure.",
              file=sys.stderr)
        return 2

    matches = match_vulns(candidates, advisories,
                          include_not_affected=args.include_not_affected)
    if any(c.subsystem_advisories for c in candidates):
        n = apply_linkage(matches, [c for c in candidates if c.subsystem_advisories])
        if n:
            print(f"{n} finding(s) on an OS/SDK tree lowered from exploitable to in_triage: "
                  "the advisory names one subsystem, check it against the build",
                  file=sys.stderr)
    if any(c.linked is False for c in candidates):
        n = apply_linkage(matches, candidates, mark_not_affected=args.unlinked_vex)
        print(f"{sum(1 for c in candidates if c.linked is False)} component(s) are in "
              f"the tree but not linked into the image (link map); "
              + (f"{n} finding(s) recorded as not_affected (code_not_present)"
                 if args.unlinked_vex else
                 f"{n} finding(s) lowered from exploitable to in_triage. "
                 "--unlinked-vex records them as not_affected once you have confirmed"),
              file=sys.stderr)

    threat = None
    if not args.no_threat:
        from .vuln.threat import annotate, load_threat, risk_key
        threat = load_threat(Path(args.db))
        if threat:
            n_kev = annotate(matches, threat)
            matches.sort(key=risk_key)
            print(f"EPSS/KEV: {len(threat.kev)} KEV entries, {len(threat.epss)} "
                  f"EPSS scores{' (' + threat.epss_date + ')' if threat.epss_date else ''}; "
                  f"{n_kev} finding(s) are known to be exploited", file=sys.stderr)
        else:
            threat = None

    if args.patches or args.source:
        rc = _apply_patches(args, matches)
        if rc:
            return rc

    if args.source:
        rc = _apply_reachability(args, matches)
        if rc:
            return rc

    cn = None
    if args.cn_db:
        try:
            cn_report = load_cn_report(Path(args.cn_db), keep=_cn_keeper(candidates, matches))
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        cn_entries = cn_report.entries
        for problem in cn_report.problems:
            print(f"warning: 国内漏洞库: {problem}", file=sys.stderr)
        if not cn_report.parsed:
            print(f"warning: --cn-db {args.cn_db} yielded no advisories, so the "
                  f"domestic channel found nothing to report. This is not a clean "
                  f"result; run `gangmu cn-db-check {args.cn_db}` to see why.",
                  file=sys.stderr)
        cn = cn_enrich(candidates, cn_entries, matches)
        print(f"读取 {cn_report.parsed} 条国内漏洞库条目；{len(cn.merged)} 条与已有匹配"
              f"合并，{len(cn.candidates)} 条按产品名命中需人工确认",
              file=sys.stderr)
        for cve, intl, local in cn.disagreements[:10]:
            print(f"note: {cve} 定级不一致 —— 国际 {intl} / 国内 {local}",
                  file=sys.stderr)
    blind = [c.name for c in unmatched_components(candidates)]
    no_cpe = [c.name for c in without_cpe(candidates)]

    counts = vex_summary(matches)
    print(f"{len(advisories)} advisory record(s) name these components, "
          f"{len(candidates)} component(s)",
          file=sys.stderr)

    if args.format == "table":
        rows = [("STATE", "ID", "SEV", "COMPONENT", "VERSION", "VIA", "WHY")]
        if threat:
            rows[0] = rows[0][:3] + ("KEV", "EPSS") + rows[0][3:]
        for m in matches:
            row = (m.state.value, m.advisory.id[:20],
                   (m.advisory.severity or "-")[:8], m.component[:18],
                   (m.version or "-")[:14], m.channel, m.detail[:58])
            if threat:
                row = row[:3] + ("YES" if m.kev else "-",
                                 f"{m.epss[0]:.3f}" if m.epss else "-") + row[3:]
            rows.append(row)
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows]
        lines.insert(1, "  ".join("-" * w for w in widths))
        tail = ["", "  ".join(f"{k}={v}" for k, v in counts.items() if v) or "no findings"]
        if no_cpe:
            tail.append(f"{len(no_cpe)}/{len(candidates)} component(s) have no CPE "
                        f"and were reachable only by PURL: "
                        + ", ".join(no_cpe[:6])
                        + (" ..." if len(no_cpe) > 6 else ""))
        if cn is not None and cn.candidates:
            tail.append(f"{len(cn.candidates)} 条国内库条目按产品名命中，"
                        f"没有 CVE 编号可对齐，需人工确认：")
            for name, entry in cn.candidates[:5]:
                tail.append(f"    {entry.id}  {entry.title[:40]}  -> {name}")
            tail.append("    关键字命中不是匹配。国内库条目常无 CPE/PURL，"
                        "无法做版本区间判断。")
        if blind:
            tail.append(f"{len(blind)} component(s) could not be looked up at all "
                        f"(no CPE and no PURL): {', '.join(blind[:6])}"
                        + (" ..." if len(blind) > 6 else ""))
            tail.append("Absence of findings for those is absence of evidence.")
        _write("\n".join(lines + tail), args.output)
    elif args.format == "json":
        _write(json.dumps({"matches": [m.to_dict() for m in matches],
                           "summary": counts, "notLookedUp": blind},
                          indent=2, ensure_ascii=False), args.output)
    elif args.format in ("openvex", "csaf"):
        from .vuln.csaf import to_csaf
        from .vuln.openvex import to_openvex
        try:
            if args.format == "openvex":
                doc = to_openvex(matches, bom, author=args.publisher or "")
            else:
                doc = to_csaf(matches, bom,
                              app_name=(bom.get("metadata", {}).get("component", {})
                                        .get("name") or "firmware"),
                              publisher=args.publisher or "",
                              publisher_url=args.publisher_url or "")
        except ValueError as exc:
            print(f"error: {exc}" if matches else f"note: {exc}", file=sys.stderr)
            return 2 if matches else 0
        _write(json.dumps(doc, indent=2, ensure_ascii=False), args.output)
    else:
        _write(json.dumps(to_vex(matches, bom, blind_spots=blind),
                          indent=2, ensure_ascii=False), args.output)

    if args.fail_on:
        bad = sum(counts.get(state, 0) for state in args.fail_on if state != "kev")
        if "kev" in args.fail_on:
            bad += sum(1 for m in matches if m.kev is not None
                       and m.state.value in ("exploitable", "in_triage"))
        if bad:
            print(f"error: {bad} finding(s) in state(s) {args.fail_on}",
                  file=sys.stderr)
            return 1
    return 0


def _apply_patches(args: argparse.Namespace, matches) -> int:
    """Test the code, not the version, for every advisory that has a patch record."""
    from .patchtest import (PatchError, assess, load_pack_patches, load_patches,
                            near_names, records_for)
    if not args.source:
        print("error: --patches needs --source: the patch test reads the tree "
              "that was scanned", file=sys.stderr)
        return 2
    root = Path(args.source)
    if not root.is_dir():
        print(f"error: --source {root} is not a directory", file=sys.stderr)
        return 2
    records: dict = {}
    if not args.no_pack_patches:
        # Records the installed rule packs ship (patches/*.json): the community
        # pack first, so a private pack or a --patches file overrides it.
        given = args.rules or None
        roots = [Path(p) for p in given] if given else [
            r.path for r in default_roots(fallback=[Path.cwd() / "rules"])]
        try:
            records.update(load_pack_patches(roots))
        except PatchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    for path in args.patches or []:
        try:
            records.update(load_patches(Path(path)))
        except PatchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if not records:
        return 0
    cache: dict = {}
    tally: dict = {}
    near = near_names(records.values())
    for match in matches:
        adv = match.advisory
        record = records_for(adv.id, adv.aliases, records)
        if record is None:
            continue
        match.patch = verdict = assess(record, root, match.directory, cache, near)
        tally[verdict.status] = tally.get(verdict.status, 0) + 1
        if match.state.value not in ("in_triage", "exploitable"):
            continue
        near_ok = args.patch_near_vex
        if verdict.status == "fixed" or (near_ok and verdict.status == "likely_fixed"):
            match.state = VexState.RESOLVED
        elif verdict.status in ("vulnerable", "partial") or (
                near_ok and verdict.status == "likely_vulnerable"):
            match.state = VexState.EXPLOITABLE
        else:
            # modified / absent: the version said "maybe" and the code does not
            # settle it either way, so the state is left for a person.
            match.detail = f"{match.detail} [patch test: {verdict.detail}]".strip()
            continue
        match.detail = f"patch test: {verdict.detail}"
    print(f"patch presence: {len(records)} record(s) loaded; "
          + (", ".join(f"{k} {v}" for k, v in sorted(tally.items()))
             if tally else "none applied to a match"), file=sys.stderr)
    return 0


def cmd_patch_verify(args: argparse.Namespace) -> int:
    from .patchtest import PatchError, load_patches, verify_record
    bad = total = 0
    for path in args.files:
        try:
            records = load_patches(Path(path))
        except PatchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for key, record in sorted(records.items()):
            total += 1
            problems = verify_record(record)
            if problems:
                bad += 1
                print(f"FAIL {key} ({path})", file=sys.stderr)
                for p in problems:
                    print(f"     {p}", file=sys.stderr)
            else:
                print(f"ok   {key}: {len(record.functions)} function(s) re-derived "
                      f"from {', '.join(c[:12] for c in record.commits)}",
                      file=sys.stderr)
    print(f"{total - bad} of {total} record(s) reproduce", file=sys.stderr)
    return 1 if bad else 0


def cmd_patch_build(args: argparse.Namespace) -> int:
    from .patchtest import PatchError, build_record, load_patches, save_patches
    repo, commits = args.repo, list(args.fix or [])
    if not commits or not repo:
        if not args.db:
            print("error: give --repo and --fix, or --db to read them from the "
                  "advisory", file=sys.stderr)
            return 2
        try:
            found_repo, found = _fix_from_advisory(args.cve, Path(args.db))
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not found:
            print(f"error: {args.cve} in {args.db} records no fix commit "
                  f"(an OSV GIT range with a `fixed` event); pass --repo and "
                  f"--fix", file=sys.stderr)
            return 2
        repo, commits = repo or found_repo, commits or found
        print(f"{args.cve}: fix {', '.join(c[:12] for c in commits)} in {repo}",
              file=sys.stderr)
    out = Path(args.output)
    try:
        existing = load_patches(out) if out.exists() else {}
        record = build_record(args.cve, repo, commits, only=args.function,
                             first_parent=args.first_parent)
    except PatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    existing[record.advisory] = record
    save_patches(out, existing)
    print(f"{record.advisory}: {len(record.functions)} function(s) recorded in {out}: "
          + ", ".join(sorted({f.function for f in record.functions})[:8])
          + (" ..." if len({f.function for f in record.functions}) > 8 else ""),
          file=sys.stderr)
    return 0


def _fix_from_advisory(cve: str, db: Path):
    """(repository, fix commits) from an OSV GIT range in a local advisory directory."""
    from .vuln.sources import load_database
    wanted_id = cve.upper()
    for adv in load_database(db):
        if wanted_id not in [adv.id.upper(), *[a.upper() for a in adv.aliases]]:
            continue
        for rng in adv.osv_ranges:
            if rng.get("type") == "GIT" and rng.get("fixed_commits"):
                return rng.get("repo") or "", list(rng["fixed_commits"])
    return "", []


def _apply_reachability(args: argparse.Namespace, matches) -> int:
    from .reach import assess, build_graph, load_symbols, mine_symbols
    root = Path(args.source)
    if not root.is_dir():
        print(f"error: --source {root} is not a directory", file=sys.stderr)
        return 2
    curated = {}
    for path in args.symbols or []:
        try:
            curated.update(load_symbols(Path(path)))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read --symbols {path}: {exc}", file=sys.stderr)
            return 2
    graph = build_graph(root)
    print(f"reachability: read {graph.files} source file(s), "
          f"{len(graph.defined)} function(s)", file=sys.stderr)
    cache: dict = {}
    tally: dict = {}
    for match in matches:
        adv = match.advisory
        names = None
        basis = ""
        for key in [adv.id] + list(adv.aliases):
            if str(key).upper() in curated:
                names, basis = curated[str(key).upper()], "curated"
                break
        if names is None:
            names, basis = mine_symbols(adv.summary), "advisory text"
        match.reach = assess(graph, match.directory, names, basis, cache)
        tally[match.reach.status] = tally.get(match.reach.status, 0) + 1
        if args.reachability_vex and match.state.value in ("in_triage", "exploitable"):
            if match.reach.status == "absent":
                match.state, match.justification = VexState.NOT_AFFECTED, "code_not_present"
            elif match.reach.status == "unreachable":
                match.state, match.justification = VexState.NOT_AFFECTED, "code_not_reachable"
            else:
                continue
            match.detail = f"{match.detail} [reachability: {match.reach.detail}]".strip()
    print("reachability: " + ", ".join(f"{k} {v}" for k, v in sorted(tally.items())),
          file=sys.stderr)
    return 0


def _cn_keeper(candidates, matches):
    """Which domestic entries one SBOM can use: those carrying a CVE it already
    matched (to be merged) and those with no CVE that name one of its components
    (to be offered as candidates). Everything else is parsed and let go."""
    wanted = set()
    for match in matches:
        wanted.add(match.advisory.id.upper())
        wanted.update(str(alias).upper() for alias in match.advisory.aliases)
    names = [(c.name or "").lower() for c in candidates if len(c.name or "") >= 3]

    def keep(entry) -> bool:
        if entry.cve_ids:
            return any(cve.upper() in wanted for cve in entry.cve_ids)
        haystack = f"{entry.title} {entry.affected_text}".lower()
        return any(name in haystack for name in names)
    return keep


def cmd_cn_db_check(args: argparse.Namespace) -> int:
    """Say what a CNNVD / CNVD export directory actually yields."""
    from .vuln.cn_sources import load_cn_report
    try:
        report = load_cn_report(Path(args.db), keep=lambda entry: False)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not report.files:
        print(f"{args.db}: no .json / .xml / .csv files found", file=sys.stderr)
        return 1
    width = max(len(str(f.path.relative_to(args.db))) for f in report.files)
    print(f"{'FILE'.ljust(width)}  FMT  RECORDS  PARSED  CVE  SEVERITY  AFFECTED")
    for f in report.files:
        name = str(f.path.relative_to(args.db)).ljust(width)
        if f.error:
            print(f"{name}  {f.format.ljust(3)}  {f.error}")
        else:
            print(f"{name}  {f.format.ljust(3)}  {f.records:>7}  {f.parsed:>6}  "
                  f"{f.with_cve:>3}  {f.with_severity:>8}  {f.with_affected:>8}")
    print(f"\n{report.parsed} advisory(ies): "
          + (", ".join(f"{k} {v}" for k, v in sorted(report.sources.items())) or "none"))
    no_cve = report.no_cve
    if no_cve:
        print(f"{no_cve} have no CVE id: they can only be offered as candidates "
              f"by product name, never matched to a version.")
    for problem in report.problems:
        print(f"warning: {problem}", file=sys.stderr)
    return 0 if report.parsed and not report.problems else 1


def cmd_vuln_fetch(args: argparse.Namespace) -> int:
    """Fill (or refresh) a local advisory directory; the one online step."""
    from datetime import datetime, timezone
    from .vuln.fetch import FetchError, fetch_nvd, fetch_osv
    dest = Path(args.db)
    log = ((lambda m: print(m, file=sys.stderr)) if args.verbose
           else (lambda m: None))
    products: list = list(args.product or [])
    purls: list = list(args.purl or [])
    if args.sbom:
        try:
            bom = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read SBOM {args.sbom}: {exc}", file=sys.stderr)
            return 2
        wanted = wanted_for(candidates_from_cyclonedx(bom))
        products += sorted(wanted.cpe_keys)
        purls += sorted(wanted.purl_keys)
    scoped = bool(products or purls)
    if args.threat and not scoped and not args.all:
        from .vuln.threat import fetch_threat
        try:
            kev_n, epss_n = fetch_threat(dest, log=log)
        except (OSError, ValueError, FetchError) as exc:
            print(f"error: cannot fetch KEV/EPSS: {exc}", file=sys.stderr)
            return 1
        print(f"{kev_n} KEV entries, {epss_n} EPSS scores written under "
              f"{dest / 'threat'}")
        return 0
    if not scoped and not args.all:
        print("error: say what to fetch: --sbom FILE, --product part:vendor:product, "
              "--purl PURL, or --all for the entire NVD (hundreds of MB; "
              "incremental after the first run)", file=sys.stderr)
        return 2
    since = None
    if args.since:
        try:
            since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"error: --since wants YYYY-MM-DD, got {args.since!r}",
                  file=sys.stderr)
            return 2
    api_key = args.api_key or os.environ.get("NVD_API_KEY")
    try:
        nvd_new = 0
        if not args.no_nvd and (products or args.all):
            nvd_new = fetch_nvd(dest, products=products if scoped else (),
                                api_key=api_key, since=since, log=log)
        osv_new = 0
        if not args.no_osv and purls:
            osv_new = fetch_osv(dest, purls, log=log)
        if args.threat:
            from .vuln.threat import fetch_threat
            try:
                kev_n, epss_n = fetch_threat(dest, log=log)
            except (OSError, ValueError) as exc:
                raise FetchError(f"cannot fetch KEV/EPSS: {exc}") from exc
            print(f"{kev_n} KEV entries, {epss_n} EPSS scores written under "
                  f"{dest / 'threat'}")
    except FetchError as exc:
        print(f"error: {exc}\nNothing here is a partial result: shards are "
              f"replaced atomically, so the directory is still usable.",
              file=sys.stderr)
        return 1
    print(f"{nvd_new} NVD record(s) new or changed, {osv_new} OSV record(s) "
          f"written under {dest}")
    if not api_key and not scoped:
        print("note: no NVD API key; a full download is paced at 5 requests per "
              "30 s. Set NVD_API_KEY to go roughly ten times faster.",
              file=sys.stderr)
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


_STANDARDS = {"ntia-2021": (NTIA_2021, "NTIA 2021 minimum elements"),
              "cisa-2026": (CISA_2026, "CISA 2026 minimum elements")}


def cmd_keygen(args: argparse.Namespace) -> int:
    from .signing import SigningError, generate_keypair
    try:
        priv, pub = generate_keypair(Path(args.out), args.name)
    except SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"private key: {priv} (keep it secret and backed up)\npublic key:  {pub}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    from .signing import SigningError, sign_file
    try:
        out = sign_file(Path(args.file), Path(args.key),
                        Path(args.output) if args.output else None)
    except (SigningError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"signed {args.file} -> {out}")
    return 0


def cmd_sign_verify(args: argparse.Namespace) -> int:
    from .signing import SigningError, verify_file
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


def cmd_cbom(args: argparse.Namespace) -> int:
    """Inventory the cryptographic algorithms in a source tree or firmware as a CBOM."""
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return 2
    facts = None
    if args.compile_db or args.link_map:
        facts = collect_build_facts(root,
                                    Path(args.compile_db) if args.compile_db else None,
                                    Path(args.link_map) if args.link_map else None)
        print(f"build facts: {facts.summary()}", file=sys.stderr)
    result = scan_cbom(root, facts, include_tests=args.include_tests,
                       binaries=not args.no_binaries)
    if args.format == "table":
        _write(cbom_table(result), args.output)
    else:
        for note in result.notes:
            print(f"note: {note}", file=sys.stderr)
        _write(json.dumps(to_cbom(result, args.app_name, args.app_version),
                          indent=2, ensure_ascii=False), args.output)
    if args.fail_on:
        bad = failing(result, args.fail_on)
        if bad:
            print("error: " + ", ".join(sorted(a.name for a in bad))
                  + f" ({len(bad)} asset(s)) match --fail-on", file=sys.stderr)
            return 1
    return 0


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
    from .disasm import ARCHES
    return list(ARCHES)


def cmd_binary_eval(args: argparse.Namespace) -> int:
    """Score library and release identification on a corpus of real firmware builds."""
    from . import disasm
    from .eval import binary as ev
    if not disasm.available():
        print("error: this needs Capstone: pip install 'gangmu-sbom[disasm]'", file=sys.stderr)
        return 2
    try:
        corpus = ev.load_corpus(Path(args.corpus), use_cache=not args.no_cache)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read the corpus in {args.corpus}: {exc} "
              f"(build one with benchmarks/binary/build_corpus.py)", file=sys.stderr)
        return 2
    report = ev.evaluate(corpus, args.min_features, args.tie_share)
    folds = ev.leave_one_library_out(corpus) if args.loo else None
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
    from . import disasm
    from .elf import parse_elf
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
                                 int(args.code_size, 0) if args.code_size else None)
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
              f"{rec.from_symbols} from symbols")
        for f in rec.functions:
            print(f"{f.address:#010x}  {f.size:>6}  {f.source:<13} {f.name}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """Run the reproducible identification benchmark."""
    from .eval import Mutation, evaluate_versions, run_mutation_eval
    from .fnsig import FunctionSignature

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
            results = run_mutation_eval(signature, Path(path), truth, Path(tmp),
                                        mutations, include, jobs=jobs)
        print(f"\n{'mutation':56s} {'exact':>7s} {'abstract':>9s} "
              f"{'used':>7s} {'ident':>6s}  version")
        for r in results:
            print(f"{r.label:56s} {r.exact_containment:7.3f} "
                  f"{r.abstract_containment:9.3f} {r.containment:7.3f} "
                  f"{str(r.identified):>6s}  {r.version}")
        kept = sum(r.identified for r in results)
        vok = sum(r.version_ok for r in results)
        print(f"\nidentified under {kept}/{len(results)} mutations; "
              f"version correct {vok}/{len(results)}")
        out["mutations"] = [
            {"label": r.label, "identified": r.identified,
             "containment": round(r.containment, 4),
             "exactContainment": round(r.exact_containment, 4),
             "abstractContainment": round(r.abstract_containment, 4),
             "usedAbstraction": r.used_abstraction,
             "version": r.version, "versionOk": r.version_ok,
             "stats": r.stats} for r in results]

    if args.output:
        Path(args.output).write_text(json.dumps(out, indent=2, ensure_ascii=False),
                                     encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    return 0


def cmd_perf(args: argparse.Namespace) -> int:
    """Whole-scan performance: baseline, rule-count curve, regression check."""
    import tempfile
    from .eval.perf import check, run_suite, synthetic_tree

    scales = sorted({int(x) for x in str(args.scale).split(",") if x.strip()}) or [1]
    rules = [r.path for r in _rule_roots(args.rules)]
    jobs = args.jobs if args.jobs > 0 else 1

    with tempfile.TemporaryDirectory(prefix="gangmu-perf-") as tmp:
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
    be.add_argument("--min-features", type=int, default=2)
    be.add_argument("--tie-share", type=float, default=0.85)
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
    cb.add_argument("--format", choices=["table", "cyclonedx"], default="table")
    cb.add_argument("--output", "-o")
    cb.add_argument("--app-name", default="firmware")
    cb.add_argument("--app-version", default="")
    cb.add_argument("--include-tests", action="store_true",
                    help="also read test and fixture directories")
    cb.add_argument("--no-binaries", action="store_true",
                    help="do not read prebuilt libraries and firmware images")
    cb.add_argument("--fail-on", action="append", choices=["quantum-vulnerable", "legacy"],
                    help="exit 1 when a counted algorithm is in this class (repeatable)")
    cb.set_defaults(func=cmd_cbom)

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

    register_commands(sub)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
