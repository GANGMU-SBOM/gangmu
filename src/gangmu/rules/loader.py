"""Loading the rule base from disk.

Rules live in a directory tree, one YAML file per rule, laid out as
``rules/<vendor>/<sdk>/<component>.yaml``.  The layout is for humans; nothing
in the code depends on it, so a rule may sit anywhere under the root.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

import yaml

from ..core.globbing import matches_suffix
from ..core.packs import RuleRoot, check_manifest, read_manifest
from .schema import Rule, RuleError, rule_from_dict


@dataclass
class RuleBase:
    rules: List[Rule] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    roots: List[RuleRoot] = field(default_factory=list)
    # "<id>: <later root> replaces <earlier root>" for every overlaid rule
    overridden: List[str] = field(default_factory=list)
    # rule id -> (pack, version) of the root whose rule is in force: the later root
    # when a rule was overlaid. The version is "" when the root has no manifest.
    provenance: Dict[str, Tuple[str, str]] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def for_directory(self, rel_path: str, dir_name: str) -> List[Rule]:
        """Rules worth trying against this directory.

        Every rule is a candidate. A copied component is very often *not* where
        the SDK normally puts it -- that is the whole problem -- so the path is
        a ranking hint (see :meth:`path_matches`), never a gate.
        """
        return list(self.rules)

    def path_matches(self, rule: Rule, rel_path: str, dir_name: str) -> bool:
        if rule.path_globs and matches_suffix(rel_path, rule.path_globs):
            return True
        return bool(rule.ships_as and dir_name == rule.ships_as)


INDEX_NAME = ".rule-index.json"
INDEX_FORMAT = 1


def _read_index(root: Path) -> Dict[str, dict]:
    """The precompiled parse of each rule file, keyed by relative path.

    An entry is only ever used when the sha256 of the file's current bytes is
    the one recorded, so a stale, partial or hand-edited index can cost speed
    and nothing else: the YAML is parsed as before.
    """
    try:
        data = json.loads((root / INDEX_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("format") != INDEX_FORMAT:
        return {}
    files = data.get("files")
    return files if isinstance(files, dict) else {}


def build_index(root: Path) -> Dict[str, int]:
    """Write ``<root>/.rule-index.json``; returns counts of indexed/skipped files.

    Parsing YAML is most of what loading a rule base costs, and it is the same
    parse on every run. A file whose parse does not survive a JSON round trip
    unchanged (an unquoted date, a non-string key) is left out and parsed from
    YAML at load time, as before.
    """
    root = Path(root)
    files: Dict[str, dict] = {}
    skipped = 0
    for path in sorted(root.rglob("*.y*ml")):
        if path.name.startswith("."):
            continue
        data = path.read_bytes()
        try:
            raw = yaml.safe_load(data.decode("utf-8"))
            if raw is None or json.loads(json.dumps(raw)) != raw:
                raise ValueError("not JSON-stable")
        except (yaml.YAMLError, ValueError, TypeError):
            skipped += 1
            continue
        files[path.relative_to(root).as_posix()] = {
            "sha256": hashlib.sha256(data).hexdigest(), "raw": raw}
    (root / INDEX_NAME).write_text(
        json.dumps({"format": INDEX_FORMAT, "files": files},
                   sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return {"indexed": len(files), "skipped": skipped}


def load_rules(root: Path, strict: bool = False) -> RuleBase:
    """Parse every ``*.yaml`` under *root*.

    With ``strict`` the first bad rule raises; otherwise bad rules are collected
    in ``RuleBase.errors`` so a scan is not taken down by one broken file --
    which matters once the rule base is community-maintained.
    """
    root = Path(root)
    base = RuleBase()
    seen: Dict[str, str] = {}
    if not root.exists():
        raise FileNotFoundError(f"rule root not found: {root}")

    index = _read_index(root)
    for path in sorted(root.rglob("*.y*ml")):
        if path.name.startswith("."):
            continue
        rel = path.relative_to(root).as_posix()
        try:
            data = path.read_bytes()
            entry = index.get(rel)
            if isinstance(entry, dict) and "raw" in entry and \
                    entry.get("sha256") == hashlib.sha256(data).hexdigest():
                raw = entry["raw"]
            else:
                raw = yaml.safe_load(data.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            msg = f"{rel}: YAML parse error: {exc}"
            if strict:
                raise RuleError(msg) from exc
            base.errors.append(msg)
            continue
        if raw is None:
            continue
        try:
            rule = rule_from_dict(raw, source_path=rel)
        except RuleError as exc:
            if strict:
                raise
            base.errors.append(str(exc))
            continue
        if rule.id in seen:
            msg = f"{rel}: duplicate rule id '{rule.id}' (also in {seen[rule.id]})"
            if strict:
                raise RuleError(msg)
            base.errors.append(msg)
            continue
        if rule.functions is not None:
            rule.functions.base_dir = str(path.parent)
        if rule.binary_strings is not None:
            rule.binary_strings.base_dir = str(path.parent)
        if rule.binary_functions is not None:
            rule.binary_functions.base_dir = str(path.parent)
        seen[rule.id] = rel
        base.rules.append(rule)
    return base


def load_rule_roots(roots: Sequence[Union[RuleRoot, Path, str]],
                    strict: bool = False) -> RuleBase:
    """Load several rule roots in order; a later root's rule replaces an
    earlier one with the same id.

    Each root's ``rulebase.json`` is checked first, and a root this build is
    too old for raises :class:`~gangmu.rules.packs.RulePackError` -- that is
    never downgraded to a warning, because the scan would quietly miss what
    the newer rules describe.
    """
    combined = RuleBase()
    position: Dict[str, int] = {}
    origin: Dict[str, str] = {}
    for item in roots:
        root = item if isinstance(item, RuleRoot) else RuleRoot(Path(item), "--rules")
        if root.manifest is None:
            root.manifest = read_manifest(root.path)
        check_manifest(root.path, root.manifest)
        loaded = load_rules(root.path, strict=strict)
        combined.roots.append(root)
        pack = root.pack_name
        version = str((root.manifest or {}).get("version") or "")
        combined.errors.extend(f"[{root.label}] {e}" if len(roots) > 1 else e
                               for e in loaded.errors)
        for rule in loaded.rules:
            if rule.id in position:
                combined.rules[position[rule.id]] = rule
                combined.overridden.append(
                    f"{rule.id}: {root.label} replaces {origin[rule.id]}")
            else:
                position[rule.id] = len(combined.rules)
                combined.rules.append(rule)
            origin[rule.id] = root.label
            combined.provenance[rule.id] = (pack, version)
    return combined
