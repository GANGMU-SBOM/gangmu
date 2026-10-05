"""Where rules come from: rule roots, installed rule packs and their manifests.

A *rule root* is a directory of rule YAML files.  Several roots can be loaded
together, in order; when two roots define the same rule id, the later one wins.
That is what lets a private rule pack (your own BSP, a vendor's pre-release SDK)
sit on top of the community rule base without forking it.

A *rule pack* is an installed Python distribution that advertises a rule root
through the ``gangmu.rule_packs`` entry-point group.  The community rule base is
published that way as ``gangmu-rules``; anyone can publish another.  The entry
point names a callable that returns the root directory::

    [project.entry-points."gangmu.rule_packs"]
    community = "gangmu_rules:path"

A root may carry a ``rulebase.json`` manifest saying which rule-format version it
uses and the oldest gangmu that reads it.  A root the running tool is too old
for is refused outright: silently loading it would produce an SBOM that looks
complete and is not.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .. import __version__
from ..plugins import entry_points as _entry_points

MANIFEST_NAME = "rulebase.json"
RULE_FORMAT = 1                 # the rule-format version this build reads
PACK_GROUP = "gangmu.rule_packs"
COMMUNITY_PACK = "community"    # loaded first, so every other pack overlays it


class RulePackError(RuntimeError):
    """A rule root this build must not load."""


@dataclass
class RuleRoot:
    path: Path
    origin: str                         # "--rules", "GANGMU_RULES", "pack:<name>", ...
    manifest: Optional[dict] = None

    @property
    def label(self) -> str:
        name = (self.manifest or {}).get("name")
        version = (self.manifest or {}).get("version")
        tag = f"{name} {version}" if name and version else (name or self.path.name)
        return f"{tag} ({self.origin})"


def _version_tuple(text: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for piece in str(text).split("."):
        match = re.match(r"\d+", piece)
        if not match:
            break
        parts.append(int(match.group()))
        if match.end() != len(piece):       # 0.6.0rc1 -> (0, 6, 0)
            break
    return tuple(parts)


def read_manifest(root: Path) -> Optional[dict]:
    path = Path(root) / MANIFEST_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RulePackError(f"{path}: unreadable manifest: {exc}") from exc
    if not isinstance(data, dict):
        raise RulePackError(f"{path}: manifest must be a JSON object")
    return data


def check_manifest(root: Path, manifest: Optional[dict],
                   tool_version: str = __version__) -> None:
    if not manifest:
        return
    fmt = manifest.get("format", RULE_FORMAT)
    if not isinstance(fmt, int) or fmt > RULE_FORMAT:
        raise RulePackError(
            f"{root}: rule format {fmt} is newer than this gangmu reads "
            f"(format {RULE_FORMAT}). Upgrade: pip install -U gangmu-sbom")
    needed = manifest.get("requires_gangmu")
    if needed and _version_tuple(tool_version) < _version_tuple(needed):
        raise RulePackError(
            f"{root}: these rules need gangmu {needed} or later, this is "
            f"{tool_version}. Upgrade: pip install -U gangmu-sbom")


def installed_packs() -> List[Tuple[str, Path]]:
    """Rule roots advertised by installed distributions, community first."""
    found: Dict[str, Path] = {}
    for ep in _entry_points(PACK_GROUP):
        if ep.name in found:
            continue
        try:
            target = ep.load()
            path = Path(target() if callable(target) else target)
        except Exception as exc:            # a broken pack must not stop a scan
            print(f"warning: rule pack '{ep.name}' could not be loaded: {exc}",
                  file=sys.stderr)
            continue
        if path.is_dir():
            found[ep.name] = path
        else:
            print(f"warning: rule pack '{ep.name}' points at a missing "
                  f"directory: {path}", file=sys.stderr)
    order = sorted(found, key=lambda n: (n != COMMUNITY_PACK, n))
    return [(name, found[name]) for name in order]


def default_roots(fallback: Sequence[Path] = (),
                  packs: Optional[List[Tuple[str, Path]]] = None) -> List[RuleRoot]:
    """The rule roots used when the command line names none.

    ``GANGMU_RULES`` (one or more directories, separated like ``PATH``) replaces
    everything else.  Otherwise every installed rule pack, community first.
    ``fallback`` (the current directory's ``rules/``) is used only when no pack
    is installed, so an unrelated project folder never shadows the real rule
    base.
    """
    env = os.environ.get("GANGMU_RULES")
    if env:
        return [RuleRoot(Path(p), "GANGMU_RULES") for p in env.split(os.pathsep) if p]
    roots: List[RuleRoot] = []
    for name, path in (installed_packs() if packs is None else packs):
        roots.append(RuleRoot(path, f"pack:{name}"))
    if not roots:
        for path in fallback:
            if Path(path).is_dir():
                roots.append(RuleRoot(Path(path), "./rules"))
                break
    return roots
