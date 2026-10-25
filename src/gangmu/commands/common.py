"""Helpers shared by the subcommands."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from ..config import Config, load_config
from ..model import ScanResult
from ..rules.loader import RuleBase, load_rule_roots
from ..core.packs import RulePackError, RuleRoot, default_roots

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
        raise SystemExit(f"error: {exc}") from exc


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
        older = any("may be older than any release" in e.summary for e in f.evidence)
        if f.vendor_patched:
            # Not a known release: a vendor fork, a commit newer than the recorded
            # versions, or (when the closest match is the oldest recorded) a release
            # older than any the rule records.
            notes.append("vendor-modified (or older than known releases)" if older
                         else "vendor-modified (or newer than known releases)")
        elif older:
            notes.append("may be older than known releases")
        if f.linked is False:
            notes.append("not linked")
        if f.alternatives:
            notes.append(f"{len(f.alternatives)} alt")
        if f.files:
            notes.append(f"{len(f.files)} file(s) among others")
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
        top = [b for b in result.binaries if b.container is None]
        inside = len(result.binaries) - len(top)
        named = sum(1 for b in result.binaries if b.embedded)
        lines.append("")
        lines.append(f"{len(top)} prebuilt binar(ies) with no source "
                     + (f"(plus {inside} found inside them) " if inside else "")
                     + f"({named} with a version banner); listed in the SBOM, "
                     "not analysable here")
    if result.possible:
        lines.append("")
        lines.append("POSSIBLE (resemble a known component, not enough to assert; "
                     "left out of the SBOM -- use --include-possible to keep them)")
        for f in result.possible:
            lines.append(f"  {f.identity_confidence:.2f}  {f.upstream_name}  "
                         f"{f.version or '-'}  {f.directory}")
    if result.unknown:
        lines.append("")
        lines.append("UNKNOWN (looks vendored, no rule names it; not in the SBOM)")
        for u in result.unknown:
            where = u.directory if u.kind == "directory" else f"{len(u.files)} file(s) in {u.directory}"
            lines.append(f"  {u.score:4.1f}  {u.name_hint or '?'}  {u.version_hint or '-'}  {where}"
                         + (f"  (resembles {', '.join(u.resembles)})" if u.resembles else ""))
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


def _load_json(path, what: str):
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: cannot read {what} {path}: {exc}", file=sys.stderr)
        return None


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
