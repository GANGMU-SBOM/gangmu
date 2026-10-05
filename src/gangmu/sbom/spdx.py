"""SPDX 2.3 JSON output.

SPDX is the lowest common denominator some buyers and authorities still ask
for.  It has no place to put a confidence score or a fork relationship, so
those are written into ``comment`` rather than dropped -- an SBOM that silently
loses the hedging is the failure mode this project exists to avoid.
"""

from __future__ import annotations

import datetime as _dt
import re
import uuid
from typing import Any, Dict, List, Optional

from .. import __version__
from ..licenses import differs, observed_ids, spdx_license_declared
from ..model import Finding, ScanResult

_SAFE = re.compile(r"[^A-Za-z0-9.\-]+")


def _spdx_id(prefix: str, value: str) -> str:
    return f"SPDXRef-{prefix}-{_SAFE.sub('-', value).strip('-')}"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _package(finding: Finding) -> Dict[str, Any]:
    pkg_id = _spdx_id("Package", f"{finding.upstream_name}-{finding.directory}")
    comment_lines = [
        f"identified by gangmu rule {finding.rule_id}",
        f"directory: {finding.directory}",
        f"identity confidence: {finding.identity_confidence:.3f}",
        f"version confidence: {finding.version_confidence:.3f}"
        f" (source: {finding.version_source or 'none'})",
    ]
    if finding.vendor_patched:
        comment_lines.append(
            f"VENDOR-MODIFIED copy of upstream {finding.upstream_name}"
            + (f" -- {finding.patch_hint}" if finding.patch_hint else "")
        )
    if finding.renamed_from:
        comment_lines.append(f"shipped by the vendor as '{finding.renamed_from}'")
    observed = observed_ids(finding)
    if observed:
        comment_lines.append("licences seen in the files: " + "; ".join(observed)
                             + (" -- differs from the rule's licence"
                                if differs(finding.declared_license, observed) else ""))
    for ev in finding.evidence:
        comment_lines.append(f"evidence[{ev.technique.value}]: {ev.summary}")
    for alt in finding.alternatives:
        comment_lines.append(
            f"alternative: {alt.upstream_name} ({alt.identity_confidence:.2f})")

    refs: List[Dict[str, str]] = []
    if finding.purl:
        refs.append({"referenceCategory": "PACKAGE-MANAGER",
                     "referenceType": "purl", "referenceLocator": finding.purl})
    if finding.cpe:
        refs.append({"referenceCategory": "SECURITY",
                     "referenceType": "cpe23Type", "referenceLocator": finding.cpe})

    pkg: Dict[str, Any] = {
        "SPDXID": pkg_id,
        "name": finding.upstream_name,
        "versionInfo": finding.version or "NOASSERTION",
        "downloadLocation": finding.homepage or "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": spdx_license_declared(
            finding.declared_license, finding.observed_licenses, finding.license_files),
        "copyrightText": "NOASSERTION",
        "comment": "\n".join(comment_lines),
        "supplier": (f"Organization: {finding.supplier or finding.vendor_name}"
                     if (finding.supplier or finding.vendor_name)
                     else "NOASSERTION"),
    }
    if refs:
        pkg["externalRefs"] = refs
    return pkg


def to_spdx(result: ScanResult, app_name: str = "firmware",
            app_version: Optional[str] = None,
            timestamp: Optional[str] = None,
            namespace: Optional[str] = None) -> Dict[str, Any]:
    root_id = _spdx_id("Package", app_name)
    packages = [{
        "SPDXID": root_id,
        "name": app_name,
        "versionInfo": app_version or "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }]
    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }]
    by_name = {}
    for finding in result.findings:
        pkg = _package(finding)
        packages.append(pkg)
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": pkg["SPDXID"],
        })
        if finding.component_name:
            by_name.setdefault(finding.component_name, []).append(pkg["SPDXID"])
    for blob in result.binaries:
        pkg = {
            "SPDXID": _spdx_id("Binary", blob.path),
            "name": blob.path,
            "versionInfo": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": blob.sha256}],
            "comment": ("prebuilt " + blob.kind + ", no source available"
                        + (f"; embeds {', '.join((e.display_name + ' ' + e.version).strip() for e in blob.embedded)}"
                           if blob.embedded else "")),
        }
        packages.append(pkg)
        relationships.append({"spdxElementId": root_id,
                              "relationshipType": "CONTAINS",
                              "relatedSpdxElement": pkg["SPDXID"]})
    # Declared dependencies (OpenHarmony bundle.json), where both ends were found.
    for finding, pkg in zip(result.findings, packages[1:]):
        for name in finding.depends_on:
            for target in by_name.get(name, []):
                if target != pkg["SPDXID"]:
                    relationships.append({
                        "spdxElementId": pkg["SPDXID"],
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": target,
                    })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{app_name}-sbom",
        "documentNamespace": namespace or f"https://gangmu.dev/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": timestamp or _now(),
            "creators": [f"Tool: gangmu-sbom-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }
