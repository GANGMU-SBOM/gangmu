"""How a claim was arrived at, and the proof behind it.

Shared by every bill of materials: a component in an SBOM, an algorithm in a
CBOM and a model in an AIBOM each rest on evidence a third party can re-check.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


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
