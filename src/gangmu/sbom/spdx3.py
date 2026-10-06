"""SPDX 3.0.1 JSON-LD output (Software profile).

SPDX 2.3 packs everything it cannot model into one ``comment``. 3.0 has places for
several things 2.3 does not: a supplier agent per package, a hash that verifies the
files, a support level and an end-of-support time, and licences as elements linked
by relationship. Those are used where they fit; what still has no home (identity
and version confidence, the fork relationship, the evidence) goes into ``comment``
as in the 2.3 writer, so nothing the scan knew is lost by choosing this format.

The document is validated against the published 3.0.1 JSON schema in the tests.
"""

from __future__ import annotations

import datetime as _dt
import re
import uuid
from typing import Any, Dict, List, Optional

from .. import __version__
from ..licenses import differs, observed_ids, spdx_license_declared
from ..model import Finding, ScanResult
from ..support import UNKNOWN, describe as describe_support

CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPEC_VERSION = "3.0.1"

_SAFE = re.compile(r"[^A-Za-z0-9.\-]+")

# gangmu's status vocabulary -> SPDX 3 ``supportLevel``
_SUPPORT_LEVEL = {
    "maintained": "support",
    "limited": "limitedSupport",
    "no_longer_maintained": "noSupport",
    "abandoned": "noSupport",
    "unknown": "noAssertion",
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Doc:
    """Collects elements and hands out stable IRIs under one namespace."""

    def __init__(self, namespace: str, created: str) -> None:
        self.ns = namespace.rstrip("/")
        self.created = created
        self.elements: List[Dict[str, Any]] = []
        self._agents: Dict[str, str] = {}
        self._licenses: Dict[str, str] = {}

    def iri(self, kind: str, value: str) -> str:
        return f"{self.ns}/{kind}/{_SAFE.sub('-', value).strip('-') or 'x'}"

    def add(self, element: Dict[str, Any]) -> str:
        element.setdefault("creationInfo", "_:creationinfo")
        self.elements.append(element)
        return element["spdxId"]

    def agent(self, name: str) -> str:
        if name not in self._agents:
            self._agents[name] = self.add({
                "type": "Organization", "spdxId": self.iri("agent", name), "name": name})
        return self._agents[name]

    def license(self, expression: str) -> str:
        if expression not in self._licenses:
            self._licenses[expression] = self.add({
                "type": "simplelicensing_LicenseExpression",
                "spdxId": self.iri("license", expression),
                "simplelicensing_licenseExpression": expression})
        return self._licenses[expression]

    def relate(self, source: str, kind: str, targets: List[str]) -> None:
        self.add({"type": "Relationship",
                  "spdxId": self.iri("rel", f"{kind}-{len(self.elements)}"),
                  "from": source, "relationshipType": kind, "to": targets})


def _comment(finding: Finding) -> str:
    lines = [
        f"identified by gangmu rule {finding.rule_id}",
        f"directory: {finding.directory}",
        f"identity confidence: {finding.identity_confidence:.3f}",
        f"version confidence: {finding.version_confidence:.3f}"
        f" (source: {finding.version_source or 'none'})",
    ]
    if finding.vendor_patched:
        lines.append(f"VENDOR-MODIFIED copy of upstream {finding.upstream_name}"
                     + (f" -- {finding.patch_hint}" if finding.patch_hint else ""))
    if finding.renamed_from:
        lines.append(f"shipped by the vendor as '{finding.renamed_from}'")
    observed = observed_ids(finding)
    if observed:
        lines.append("licences seen in the files: " + "; ".join(observed)
                     + (" -- differs from the rule's licence"
                        if differs(finding.declared_license, observed) else ""))
    lines.append(describe_support(finding.support))
    for ev in finding.evidence:
        lines.append(f"evidence[{ev.technique.value}]: {ev.summary}")
    for alt in finding.alternatives:
        lines.append(f"alternative: {alt.upstream_name} ({alt.identity_confidence:.2f})")
    return "\n".join(lines)


def _package(doc: _Doc, finding: Finding) -> str:
    pkg: Dict[str, Any] = {
        "type": "software_Package",
        "spdxId": doc.iri("package", f"{finding.upstream_name}-{finding.directory}"),
        "name": finding.upstream_name,
        "software_packageVersion": finding.version or "NOASSERTION",
        "software_primaryPurpose": ("framework"
                                    if finding.rule_id.startswith("declared/vendor-sdk/")
                                    else "library"),
        "comment": _comment(finding),
    }
    if finding.purl:
        pkg["software_packageUrl"] = finding.purl
    if finding.homepage:
        pkg["software_homePage"] = finding.homepage
    if finding.cpe:
        pkg["externalIdentifier"] = [{"type": "ExternalIdentifier",
                                      "externalIdentifierType": "cpe23",
                                      "identifier": finding.cpe}]
    if finding.content_hash:
        # Same fileset digest as the CycloneDX writer: a vendored tree has no archive.
        pkg["verifiedUsing"] = [{"type": "Hash", "algorithm": "sha256",
                                 "hashValue": finding.content_hash}]
    supplier = finding.supplier or finding.vendor_name
    if supplier:
        pkg["suppliedBy"] = doc.agent(supplier)
    support = finding.support or UNKNOWN
    pkg["supportLevel"] = [_SUPPORT_LEVEL[support.status]]
    if support.end_of_support:
        pkg["validUntilTime"] = f"{support.end_of_support}T00:00:00Z"
    pkg_id = doc.add(pkg)
    declared = spdx_license_declared(finding.declared_license, finding.observed_licenses,
                                     finding.license_files)
    if declared != "NOASSERTION" and "LicenseRef-" not in declared:
        doc.relate(pkg_id, "hasDeclaredLicense", [doc.license(declared)])
    return pkg_id


def to_spdx3(result: ScanResult, app_name: str = "firmware",
             app_version: Optional[str] = None,
             timestamp: Optional[str] = None,
             namespace: Optional[str] = None) -> Dict[str, Any]:
    created = timestamp or _now()
    doc = _Doc(namespace or f"https://gangmu.dev/spdx/{uuid.uuid4()}", created)

    tool = doc.add({"type": "Tool", "spdxId": doc.iri("tool", "gangmu-sbom"),
                    "name": f"gangmu-sbom-{__version__}"})
    agent = doc.add({"type": "SoftwareAgent", "spdxId": doc.iri("agent", "gangmu-sbom"),
                     "name": "gangmu-sbom"})
    creation_info = {"type": "CreationInfo", "@id": "_:creationinfo",
                     "specVersion": SPEC_VERSION, "created": created,
                     "createdBy": [agent], "createdUsing": [tool]}

    root = doc.add({"type": "software_Package", "spdxId": doc.iri("package", app_name),
                    "name": app_name,
                    "software_packageVersion": app_version or "NOASSERTION",
                    "software_primaryPurpose": "firmware"})
    members: List[str] = []
    by_name: Dict[str, List[str]] = {}
    ids: List[str] = []
    for finding in result.findings:
        pkg_id = _package(doc, finding)
        ids.append(pkg_id)
        members.append(pkg_id)
        if finding.component_name:
            by_name.setdefault(finding.component_name, []).append(pkg_id)
    for blob in result.binaries:
        comment = ("prebuilt " + blob.kind + ", no source available"
                   + (f"; embeds {', '.join((e.display_name + ' ' + e.version).strip() for e in blob.embedded)}"
                      if blob.embedded else ""))
        members.append(doc.add({
            "type": "software_Package", "spdxId": doc.iri("binary", blob.path),
            "name": blob.path, "software_packageVersion": "NOASSERTION",
            "software_primaryPurpose": "file",
            "verifiedUsing": [{"type": "Hash", "algorithm": "sha256",
                               "hashValue": blob.sha256}],
            "comment": comment}))
    if members:
        doc.relate(root, "contains", members)
    for finding, pkg_id in zip(result.findings, ids):
        for name in finding.depends_on:
            targets = [t for t in by_name.get(name, []) if t != pkg_id]
            if targets:
                doc.relate(pkg_id, "dependsOn", targets)

    sbom = doc.add({
        "type": "software_Sbom", "spdxId": doc.iri("sbom", app_name),
        "name": f"{app_name}-sbom",
        "software_sbomType": ["build" if result.build_facts_used else "source"],
        "rootElement": [root],
        "element": [e["spdxId"] for e in doc.elements
                    if e["type"] not in ("software_Sbom",) and e["spdxId"] != root],
    })
    cc0 = doc.license("CC0-1.0")
    document = {
        "type": "SpdxDocument", "spdxId": doc.iri("document", app_name),
        "name": f"{app_name}-sbom", "dataLicense": cc0,
        "profileConformance": ["core", "software"],
        "rootElement": [sbom],
    }
    doc.add(document)
    document["element"] = [e["spdxId"] for e in doc.elements
                           if e["spdxId"] != document["spdxId"]]
    return {"@context": CONTEXT, "@graph": [creation_info] + doc.elements}
