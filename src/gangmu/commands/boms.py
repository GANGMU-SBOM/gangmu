"""`gangmu cbom`, `aibom` and `policy check`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..build.facts import collect_build_facts
from ..aibom import (AibomRuleError, aibom_roots, aibom_table, load_aibom_roots, scan_aibom,
                     to_aibom)
from ..aibom_decl import DeclarationError, find_declarations, load_declarations
from ..cbom import (CbomRuleError, cbom_roots, cbom_table, failing, load_algo_roots,
                    readiness_report, scan_cbom, to_cbom)
from ..core.packs import RulePackError
from ..scan import scan

from .common import (_build_macros, _load_rulebase, _write)


def _identified_components(root: Path, facts) -> list:
    """The components the SBOM scan identifies in *root*, for the CBOM's library tables."""
    rulebase = _load_rulebase(None)
    for err in rulebase.errors:
        print(f"warning: {err}", file=sys.stderr)
    if not rulebase.rules:
        print("warning: no SBOM rules are installed, so no library was identified",
              file=sys.stderr)
        return []
    return list(scan(root, rulebase, facts).findings)


def cmd_cbom(args: argparse.Namespace) -> int:
    """Inventory the cryptographic algorithms in a source tree or firmware as a CBOM."""
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return 2
    facts = None
    if args.compile_db:
        facts = collect_build_facts(root, Path(args.compile_db),
                                    Path(args.link_map) if args.link_map else None)
        print(f"build facts: {facts.summary()}", file=sys.stderr)
    elif args.link_map:
        print("note: a link map joins to sources through a compile database; without "
              "--compile-db it is used only for function-level evidence", file=sys.stderr)
    components = None
    if args.libraries:
        components = _identified_components(root, facts)
    try:
        algos = load_algo_roots(cbom_roots(args.rules or []))
    except (CbomRuleError, RulePackError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    macros = _build_macros(args, root)
    image = None
    if args.link_map or args.elf:
        from ..image import load_image
        try:
            image = load_image(Path(args.link_map) if args.link_map else None,
                               Path(args.elf) if args.elf else None)
        except OSError as exc:
            print(f"error: cannot read the image: {exc}", file=sys.stderr)
            return 2
        for note in image.notes:
            print(f"image: {note}", file=sys.stderr)
        if not image.informative():
            image = None
    result = scan_cbom(root, facts, include_tests=args.include_tests,
                       binaries=not args.no_binaries, algos=algos, components=components,
                       macros=macros, image=image)
    if args.format == "table":
        _write(cbom_table(result), args.output)
    elif args.format == "readiness":
        _write(readiness_report(result), args.output)
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


def cmd_aibom(args: argparse.Namespace) -> int:
    """List the machine-learning models and inference runtimes in a tree as an AIBOM."""
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return 2
    decl_path = Path(args.declarations) if args.declarations else find_declarations(root)
    declarations = None
    if decl_path is not None:
        try:
            declarations = load_declarations(decl_path)
        except DeclarationError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    elif args.require_declarations:
        print("error: --require-declarations needs a declaration file "
              "(gangmu-aibom.yaml in the tree, or --declarations FILE)", file=sys.stderr)
        return 2
    try:
        rules = load_aibom_roots(aibom_roots(args.rules or []))
    except (AibomRuleError, RulePackError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = scan_aibom(root, include_tests=args.include_tests, declarations=declarations,
                        rules=rules)
    if args.format == "table":
        _write(aibom_table(result), args.output)
    else:
        for note in result.notes:
            print(f"note: {note}", file=sys.stderr)
        _write(json.dumps(to_aibom(result, args.app_name, args.app_version),
                          indent=2, ensure_ascii=False), args.output)
    for entry in result.declared_only:
        print(f"warning: {declarations.source if declarations else '-'}: {entry.label} matches no model in the tree; "
              "kept as a declared-only component", file=sys.stderr)
    if args.require_declarations:
        gaps = result.gaps()
        if gaps:
            for gap in gaps:
                print(f"error: {gap}", file=sys.stderr)
            return 1
    return 0


def cmd_policy_check(args: argparse.Namespace) -> int:
    """Read the CBOM and AIBOM of a tree against written policies and say what is due."""
    import datetime as dt
    from .. import policy as pol
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return 2
    try:
        as_of = (dt.date.fromisoformat(args.as_of) if args.as_of else dt.date.today())
    except ValueError:
        print(f"error: --as-of '{args.as_of}' is not a date (write YYYY-MM-DD)", file=sys.stderr)
        return 2
    try:
        policies = pol.load_policy_roots(pol.policy_roots(args.policy or []))
    except (pol.PolicyError, RulePackError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.id:
        policies = [p for p in policies if p.id in set(args.id)]
    if not policies:
        print("error: no policy found; install a policy pack or pass --policy DIR "
              "(and --id to pick one)", file=sys.stderr)
        return 2
    need_cbom, need_aibom = pol.needs(policies)
    cbom_result = aibom_result = None
    try:
        if need_cbom:
            facts = None
            if args.compile_db or args.link_map:
                facts = collect_build_facts(root,
                                            Path(args.compile_db) if args.compile_db else None,
                                            Path(args.link_map) if args.link_map else None)
            algos = load_algo_roots(cbom_roots([]))
            cbom_result = scan_cbom(root, facts, algos=algos)
        if need_aibom:
            decl_path = Path(args.declarations) if args.declarations else find_declarations(root)
            declarations = load_declarations(decl_path) if decl_path else None
            aibom_result = scan_aibom(root, declarations=declarations,
                                      rules=load_aibom_roots(aibom_roots([])))
        reports = [pol.evaluate(p, as_of, cbom_result, aibom_result) for p in policies]
    except (pol.PolicyError, CbomRuleError, AibomRuleError, DeclarationError,
            RulePackError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    render = {"table": pol.policy_table, "markdown": pol.policy_markdown,
              "json": pol.policy_json}[args.format]
    _write(render(reports), args.output)
    bad = pol.failing(reports, args.fail_on or ["fail"])
    if bad:
        print("error: " + ", ".join(f"{p.id}/{c.check.id}" for p, c in bad)
              + f" ({len(bad)} check(s)) at or above --fail-on", file=sys.stderr)
        return 1
    return 0
