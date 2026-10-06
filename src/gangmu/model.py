"""Core data types shared by every layer.

Design note
-----------
Identity (*which upstream project is this?*) and version (*which release?*)
are tracked separately and carry their own confidence.  A vendor fork very
often has a recognisable identity and an unknowable version, and an SBOM that
collapses the two into one number cannot express that.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Technique(str, Enum):
    """How a claim was arrived at.

    The names are chosen to line up with CycloneDX
    ``evidence.identity.methods[].technique`` so that serialisation is a
    rename-free mapping.
    """

    HASH_COMPARISON = "hash-comparison"
    SOURCE_CODE_ANALYSIS = "source-code-analysis"
    AST_FINGERPRINT = "ast-fingerprint"
    MANIFEST_ANALYSIS = "manifest-analysis"
    FILENAME = "filename"
    INSTRUMENTATION = "instrumentation"
    OTHER = "other"


@dataclass(frozen=True)
class Evidence:
    """One reason to believe a claim, re-checkable by a third party."""

    technique: Technique
    confidence: float
    summary: str
    locator: Optional[str] = None  # file path, glob or build artefact

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "technique": self.technique.value,
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
        }
        if self.locator:
            out["locator"] = self.locator
        return out


@dataclass
class Finding:
    """A candidate identification of one directory as one upstream component."""

    directory: str                      # relative to the scan root
    rule_id: str
    upstream_name: str
    purl: Optional[str] = None
    cpe: Optional[str] = None
    homepage: Optional[str] = None
    declared_license: Optional[str] = None

    version: Optional[str] = None
    version_source: Optional[str] = None  # "anchor" | "probe" | "manifest" | None

    identity_confidence: float = 0.0
    version_confidence: float = 0.0

    vendor_patched: bool = False
    vendor_name: Optional[str] = None
    supplier: Optional[str] = None
    renamed_from: Optional[str] = None    # the name the vendor ships it under
    patch_hint: Optional[str] = None
    fork_url: Optional[str] = None

    evidence: List[Evidence] = field(default_factory=list)
    alternatives: List["Finding"] = field(default_factory=list)

    rule_pack: Optional[str] = None
    """The rule pack whose rule identified this component (``gangmu-rules``, a
    vendor's pack, a private one). None for findings that come from a build
    declaration or a binary string, not from a rule."""
    rule_pack_version: Optional[str] = None
    """That pack's version from its manifest, when it has one."""

    # Build facts, when a build was supplied.
    compiled_files: int = 0
    linked: Optional[bool] = None
    config_off: List[str] = field(default_factory=list)
    """Kconfig symbols the build configuration has switched off for this component."""

    observed_licenses: List[str] = field(default_factory=list)
    """``SPDX-License-Identifier`` expressions found in the component's source
    headers, most common first. Evidence from the tree, not the rule's licence."""
    license_files: Dict[str, str] = field(default_factory=dict)
    """Top-level LICENSE / COPYING files and the licence recognised in each
    ("" when the text is not one of the few recognised exactly)."""

    content_hash: Optional[str] = None
    """sha256 over the directory's (path, file digest) pairs.

    CISA's 2026 minimum elements add a component hash so a reader can check that
    the bytes shipped are the bytes the SBOM describes. For a vendored source
    component there is no package archive to hash, so the fileset digest -- the
    same one the exact-copy test uses -- is the honest equivalent.
    """

    component_name: Optional[str] = None
    """The ecosystem's own name for this component (OpenHarmony
    ``component.name``), which other components' declared dependencies use."""
    depends_on: List[str] = field(default_factory=list)
    """Component names this one declares it depends on (OpenHarmony
    ``bundle.json`` deps). Resolved to SBOM references where they were found."""

    path_match: int = 0
    """2 = the directory is where the rule says the component lives, 1 = only the
    directory name agrees, 0 = neither. Ranked above rule specificity: a narrow
    rule firing in the wrong place should not beat a general rule firing in the
    right one."""

    @property
    def confidence(self) -> float:
        """The number a reader should act on.

        A component whose identity is certain but whose version is a guess is
        not a certain component for vulnerability-matching purposes, so the
        overall figure is held down by the weaker of the two.  Identity alone
        is still worth something, hence the floor at half the identity score.
        """
        if self.version is None:
            return round(self.identity_confidence * 0.5, 3)
        return round(min(self.identity_confidence, self.version_confidence), 3)

    def to_dict(self) -> Dict[str, Any]:
        out = dataclasses.asdict(self)
        out["evidence"] = [e.to_dict() for e in self.evidence]
        out["alternatives"] = [a.to_dict() for a in self.alternatives]
        out["confidence"] = self.confidence
        return out


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    unidentified: List[str] = field(default_factory=list)
    rules_loaded: int = 0
    build_facts_used: bool = False
    notes: List[str] = field(default_factory=list)
    binaries: List[Any] = field(default_factory=list)
    """Prebuilt archives and shared libraries (``gangmu.binaries.Binary``)."""
    not_built: List[Finding] = field(default_factory=list)
    """Components found in the tree that the build configuration turns off
    (``sdkconfig`` / ``.config``). Kept out of ``findings`` so they do not reach
    the SBOM; each carries the Kconfig symbols that excluded it in ``config_off``."""
    possible: List[Finding] = field(default_factory=list)
    """Directories that resemble a known component but not well enough to assert
    it. Kept out of ``findings`` so no SBOM, VEX or CVE match is built on them."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "rulesLoaded": self.rules_loaded,
            "buildFactsUsed": self.build_facts_used,
            "findings": [f.to_dict() for f in self.findings],
            "possible": [f.to_dict() for f in self.possible],
            "notBuilt": [f.to_dict() for f in self.not_built],
            "binaries": [b.to_dict() for b in self.binaries],
            "unidentified": self.unidentified,
            "notes": self.notes,
        }
