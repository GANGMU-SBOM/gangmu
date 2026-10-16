"""`gangmu vuln`, `vuln-fetch`, `vuln-coverage`, `cn-db-check`, `patch-*`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Tuple

from ..core.packs import default_roots
from ..vuln.model import VexState
from ..vuln import (apply_linkage, candidates_from_cyclonedx, enrich as cn_enrich, load_cn_report,
                    load_database, match as match_vulns, wanted_for, summary as vex_summary,
                    to_vex, unmatched_components, without_cpe)

from .common import (_resolve_jobs, _write)


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
        from ..vuln.threat import annotate, load_threat, risk_key
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
        rows: List[Tuple[str, ...]] = [("STATE", "ID", "SEV", "COMPONENT", "VERSION", "VIA", "WHY")]
        if threat:
            rows[0] = rows[0][:3] + ("KEV", "EPSS") + rows[0][3:]
        for m in matches:
            row: Tuple[str, ...] = (m.state.value, m.advisory.id[:20],
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
        from ..vuln.csaf import to_csaf
        from ..vuln.openvex import to_openvex
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
    from ..patchtest import (PatchError, assess, load_pack_patches, load_patches,
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
    from ..patchtest import PatchError, load_patches, verify_record
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
    from ..patchtest import PatchError, build_record, load_patches, save_patches
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
    from ..vuln.sources import load_database
    wanted_id = cve.upper()
    for adv in load_database(db):
        if wanted_id not in [adv.id.upper(), *[a.upper() for a in adv.aliases]]:
            continue
        for rng in adv.osv_ranges:
            if rng.get("type") == "GIT" and rng.get("fixed_commits"):
                return rng.get("repo") or "", list(rng["fixed_commits"])
    return "", []


def _build_macros(args: argparse.Namespace, root: Path):
    """The configuration to evaluate ``#if`` with, or None when none was given."""
    from ..build.kconfig import find_kconfig, read_kconfig
    from ..ifdef import Macros, collect_tree_defines, find_config_headers
    paths = [Path(p) for p in (args.config or [])]
    headers = [p for p in paths if p.suffix in (".h", ".hpp", ".hh")]
    paths = [p for p in paths if p not in headers]
    if not args.config:
        found = find_kconfig(root)
        paths = [found] if found else []
        headers = find_config_headers(root)
    defines = list(args.define or [])
    if not (paths or headers or defines or args.assume_undefined_off):
        return None
    macros = Macros(assume_undefined=args.assume_undefined_off)
    for path in paths:
        try:
            macros.add_kconfig(read_kconfig(path).values)
        except OSError as exc:
            print(f"warning: cannot read --config {path}: {exc}", file=sys.stderr)
    for item in defines:
        name, _, text = item.partition("=")
        macros.define(name, text if "=" in item else "1")
    collect_tree_defines(root, macros, headers)
    return macros


def _apply_reachability(args: argparse.Namespace, matches) -> int:
    from ..reach import assess, build_graph, load_symbols, mine_symbols
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
    macros = _build_macros(args, root)
    db = None
    if args.compile_db:
        from ..build.compile_db import load_compile_db
        try:
            db = load_compile_db(Path(args.compile_db))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read --compile-db {args.compile_db}: {exc}",
                  file=sys.stderr)
            return 2
    graph = build_graph(root, macros, db)
    if db is not None and not graph.compile_db_used:
        print("reachability: --compile-db names none of the files under --source; "
              "ignored", file=sys.stderr)
    print(f"reachability: read {graph.files} source file(s), "
          f"{len(graph.defined)} function(s)", file=sys.stderr)
    if graph.inactive_lines or graph.uncompiled_files:
        print(f"reachability: the build rules out {graph.inactive_lines} line(s) and "
              f"{graph.uncompiled_files} uncompiled file(s); {len(graph.compiled_out)} "
              f"function(s) compiled out", file=sys.stderr)
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
    from ..vuln.cn_sources import load_cn_report
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


def cmd_vuln_coverage(args: argparse.Namespace) -> int:
    """What a CPE-only scanner would have missed on this SBOM, from local data."""
    from ..vuln.coverage import coverage
    try:
        bom = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read SBOM {args.sbom}: {exc}", file=sys.stderr)
        return 2
    if bom.get("bomFormat") != "CycloneDX":
        print("error: the SBOM must be a CycloneDX document", file=sys.stderr)
        return 2
    try:
        report = coverage(candidates_from_cyclonedx(bom), Path(args.db), args.cutoff)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_vuln_fetch(args: argparse.Namespace) -> int:
    """Fill (or refresh) a local advisory directory; the one online step."""
    from datetime import datetime, timezone
    from ..vuln.fetch import FetchError, fetch_nvd, fetch_osv
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
        from ..vuln.threat import fetch_threat
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
            from ..vuln.threat import fetch_threat
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
