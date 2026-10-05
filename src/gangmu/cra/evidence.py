"""The evidence bundle.

Article 13(14) says the technical documentation is kept at the disposal of
market surveillance authorities for ten years. Ten years is longer than most of
these tools will exist, so the bundle is written to be readable without them: a
directory of plain files, a manifest of sha256 digests, and a README that
explains what each file is and how it was produced.

What goes in is only what was actually established. The rule base and its
verification report are included because an auditor's first question about an
SBOM is "how do you know", and the answer is reproducible: every rule names the
upstream release it was derived from.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__
from ..config import Config

README = """\
# CRA technical documentation — component evidence

Produced by gangmu-sbom {version} on {date}.

This directory is the component part of the technical documentation required by
Article 13(8) and Annex VII of Regulation (EU) 2024/2847, to be kept available
to market surveillance authorities for {years} years{from_date}.

## What is here

{inventory}

## How the SBOM was produced

{provenance}

## How to check it

Every digest in `manifest.json` can be re-computed with sha256. Every rule in
`rules/` names the upstream release it was derived from; re-deriving them
reproduces the evidence:

    gangmu rules verify --rules rules/

That command fetches each named upstream release and recomputes the hashes and
sketches. It needs network access, not this tool's authors.

## What this does not cover

A component inventory is one obligation among several. Security testing
(Annex I Part II(3)), the update distribution mechanism (points 7 and 8) and the
coordinated disclosure policy (point 5) are documented elsewhere.
"""


@dataclass
class BundleEntry:
    path: str
    sha256: str
    bytes: int
    description: str


@dataclass
class Bundle:
    directory: Path
    entries: List[BundleEntry] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": {"name": "gangmu-sbom", "version": __version__},
            "created": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": [{"path": e.path, "sha256": e.sha256, "bytes": e.bytes,
                       "description": e.description} for e in self.entries],
            "notes": self.notes,
        }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy(src: Path, dest_dir: Path, name: str, description: str,
          bundle: Bundle) -> None:
    dest = dest_dir / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        for file in sorted(dest.rglob("*")):
            if file.is_file():
                bundle.entries.append(BundleEntry(
                    path=file.relative_to(dest_dir).as_posix(),
                    sha256=_sha256(file), bytes=file.stat().st_size,
                    description=description))
    else:
        shutil.copy2(src, dest)
        bundle.entries.append(BundleEntry(
            path=dest.relative_to(dest_dir).as_posix(), sha256=_sha256(dest),
            bytes=dest.stat().st_size, description=description))


def build_evidence_bundle(out_dir: Path, config: Config,
                          sbom: Optional[Path] = None,
                          vex: Optional[Path] = None,
                          scan_json: Optional[Path] = None,
                          rules_dir: Optional[Path] = None,
                          rules_dirs: Optional[Sequence[Path]] = None,
                          verification: Optional[str] = None,
                          cra_check: Optional[dict] = None,
                          compile_db: Optional[Path] = None,
                          link_map: Optional[Path] = None) -> Bundle:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle = Bundle(directory=out_dir)

    wanted = [
        (sbom, "sbom.json", "The software bill of materials (Annex I Part II(1))."),
        (vex, "vex.json", "Vulnerability analysis in CycloneDX VEX form."),
        (scan_json, "scan.json",
         "The scan's own findings, including directories that were NOT identified."),
        (compile_db, "build/compile_commands.json",
         "The compile database the SBOM was derived from: what the build compiled."),
        (link_map, "build/link.map",
         "The linker map: what survived into the image."),
    ]
    for src, name, description in wanted:
        if src and Path(src).exists():
            _copy(Path(src), out_dir, name, description, bundle)
        else:
            bundle.notes.append(f"{name} was not supplied")

    roots = [Path(d) for d in (rules_dirs or ([rules_dir] if rules_dir else []))
             if Path(d).is_dir()]
    for index, root in enumerate(roots):
        # one root keeps the old layout; several are kept apart, in load order
        name = "rules" if len(roots) == 1 else f"rules/{index + 1}-{root.name}"
        _copy(root, out_dir, name,
              "The identification rules in force when the SBOM was produced. "
              "Each names the upstream release it was derived from.", bundle)
    if not roots:
        bundle.notes.append("the rule base was not included, so the SBOM's "
                            "provenance cannot be re-derived from this bundle")

    if config.path and Path(config.path).exists():
        _copy(Path(config.path), out_dir, "gangmu.yaml",
              "Project declaration: product, manufacturer, markets, support "
              "period, disclosure policy.", bundle)

    if verification:
        path = out_dir / "rules-verification.txt"
        path.write_text(verification, encoding="utf-8")
        bundle.entries.append(BundleEntry(
            path="rules-verification.txt", sha256=_sha256(path),
            bytes=path.stat().st_size,
            description="Output of `gangmu rules verify`: each rule re-derived "
                        "from the upstream release it names."))

    if cra_check is not None:
        path = out_dir / "cra-check.json"
        path.write_text(json.dumps(cra_check, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        bundle.entries.append(BundleEntry(
            path="cra-check.json", sha256=_sha256(path),
            bytes=path.stat().st_size,
            description="Self-check against the CRA clauses this tool can "
                        "address, including the ones it cannot."))

    # Collapse directories so the inventory reads as a list of artefacts, not
    # a file listing: a reader wants to know what is here, not every filename.
    grouped: Dict[str, List[BundleEntry]] = {}
    for entry in bundle.entries:
        head = entry.path.split("/", 1)[0] if "/" in entry.path else entry.path
        grouped.setdefault(head, []).append(entry)
    inventory_lines = []
    for head, entries in grouped.items():
        if len(entries) == 1 and entries[0].path == head:
            inventory_lines.append(f"- `{head}` — {entries[0].description}")
        else:
            inventory_lines.append(
                f"- `{head}/` — {len(entries)} file(s). {entries[0].description}")
    inventory = "\n".join(inventory_lines) or "- (nothing was supplied)"

    provenance_bits = []
    if compile_db:
        provenance_bits.append(
            "Components were attributed from the build's own compile database, "
            "so files present in the tree but never compiled are not listed.")
    else:
        provenance_bits.append(
            "No compile database was supplied: the SBOM was derived from the "
            "source tree and may over-report.")
    if link_map:
        provenance_bits.append(
            "The linker map was used, so objects the linker discarded are "
            "marked as not linked into the image.")
    provenance_bits.append(
        "Identification is by anchor hashes, winnowed k-gram sketches and "
        "version probes, each recorded as evidence on the component.")

    placed = config.get("market.placed_on_market")
    readme = README.format(
        version=__version__,
        date=_dt.date.today().isoformat(),
        years=config.get("retention.years", 10),
        from_date=f", counted from {placed}" if placed else
                  " (no placing-on-market date declared)",
        inventory=inventory,
        provenance="\n".join(f"- {b}" for b in provenance_bits),
    )
    (out_dir / "README.md").write_text(readme, encoding="utf-8")
    manifest = out_dir / "manifest.json"
    manifest.write_text(json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False),
                        encoding="utf-8")
    return bundle
