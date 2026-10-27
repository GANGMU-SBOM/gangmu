"""`gangmu rules ...`: lint, index, fingerprint, import, bundled, verify."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import Dict

import yaml

from ..dirprint import (DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_directory, sha256_file)
from ..fingerprint import ALGO
from ..rules.schema import RuleError
from ..core.globbing import matches_suffix
from ..importers import (build_function_signature, dump_rule, import_candidates,
                         import_gitmodules, import_west, list_tags, pick_releases,
                         tag_to_version)
from ..verify import verify_rule, verify_with_fetch

from .common import (_resolve_jobs, _load_rulebase)


def cmd_rules_lint(args: argparse.Namespace) -> int:
    rulebase = _load_rulebase(args.rules)
    for root in rulebase.roots:
        print(f"root {root.label}: {root.path}")
    for note in rulebase.overridden:
        print(f"over {note}")
    for err in rulebase.errors:
        print(f"FAIL {err}")
    for rule in rulebase:
        broken = False
        arches: dict = {}
        for spec in rule.binary_function_specs():
            try:
                arch = spec.load().arch
            except (RuleError, OSError, ValueError) as exc:
                print(f"FAIL {rule.id}: {exc}")
                rulebase.errors.append(f"{rule.id}: {exc}")
                broken = True
                break
            if arch in arches:
                msg = (f"{rule.id}: {spec.file} and {arches[arch]} are both built for "
                       f"{arch or 'an unrecorded architecture'}; list one sidecar per architecture")
                print(f"FAIL {msg}")
                rulebase.errors.append(msg)
                broken = True
                break
            arches[arch] = spec.file
        if broken:
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
    from ..rules.loader import INDEX_NAME, build_index
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
        "    values: >-",
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
    if args.manifest != "candidates" and not (args.vendor and args.sdk):
        print("error: --vendor and --sdk are required for gitmodules and west", file=sys.stderr)
        return 2
    common = dict(vendor=args.vendor, sdk=args.sdk, sdk_version=args.sdk_version,
                  only=args.only, jobs=_resolve_jobs(args.jobs), log=log)
    if args.manifest == "candidates":
        if args.dry_run:
            print("error: --dry-run is not supported with candidates (the function "
                  "signature is written while the rule is built)", file=sys.stderr)
            return 2
        results = import_candidates(Path(args.sdk_repo), out_dir, limit=args.limit,
                                    only=args.only, jobs=common["jobs"], log=log,
                                    date=args.date or _dt.date.today().isoformat())
    elif args.manifest == "west":
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
        assert result.rule is not None      # status "ok" carries the rule
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
            print("error: no tags matched. Pass --tag explicitly.", file=sys.stderr)
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
    from .. import disasm
    from ..calibrate import calibrate, format_calibration
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
    from ..vuln.evidence import find_evidence, terms_for
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


def cmd_rules_bundled(args: argparse.Namespace) -> int:
    """List the rules whose signature holds another rule's whole release, or, with
    --rule and --tree, find where that host keeps the copies."""
    from ..rules.bundles import exclude_globs, find_bundles, locate
    rulebase = _load_rulebase(args.rules)
    if args.tree:
        if not args.rule:
            print("error: --tree needs --rule (the host whose checkout it is)",
                  file=sys.stderr)
            return 2
        host = next((r for r in rulebase if r.id == args.rule), None)
        if host is None:
            print(f"error: no rule {args.rule}", file=sys.stderr)
            return 2
        found = locate(Path(args.tree), rulebase, host.id)
        if args.format == "json":
            print(json.dumps({"rule": host.id, "found": [
                {"directory": c.directory, "rule_id": c.rule_id, "version": c.version,
                 "files": c.files} for c in found],
                "exclude": exclude_globs(found, host.source.subdir or "")}, indent=2))
            return 0
        if not found:
            print(f"{host.id}: no other component found in {args.tree}")
            return 0
        for c in found:
            where = c.directory + ("" if c.files is None else f" ({len(c.files)} file(s))")
            print(f"{where:50s} {c.rule_id} {c.version or ''}")
        print("\nidentity.exclude:")
        for glob in exclude_globs(found, host.source.subdir or ""):
            print(f"  - '{glob}'")
        return 0
    bundles = find_bundles(rulebase.rules)
    if args.rule:
        bundles = [b for b in bundles if args.rule in (b.host, b.bundled)]
    if args.format == "json":
        print(json.dumps([{"host": b.host, "bundled": b.bundled, "release": b.release,
                           "inside": b.inside, "size": b.size,
                           "host_share": round(b.host_share, 4), "state": b.state}
                          for b in bundles], indent=2))
        return 0
    for b in bundles:
        print(f"{b.state:7s} {b.host:40s} bundles {b.bundled:35s} {b.release:>12s} "
              f"{b.inside}/{b.size}  {b.host_share:6.1%} of host")
    lost = sum(b.state == "lost" for b in bundles)
    if lost:
        print(f"\n{lost} bundled copie(s) are too large a part of their host for "
              f"segmentation to keep them the bundled library's. Exclude the copy in "
              f"the host's rule (gangmu rules bundled --rule HOST --tree CHECKOUT) and "
              f"rebuild its signature.", file=sys.stderr)
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
