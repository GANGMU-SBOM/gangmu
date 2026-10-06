"""CycloneDX 1.6 output.

Two fields carry the weight here, and they are the reason CycloneDX is the
primary format rather than an afterthought:

``pedigree``
    A vendor fork is not upstream.  ``pedigree.ancestors`` names what it was
    derived from and ``pedigree.patches`` records that the vendor changed it, so
    a consumer can tell "lwIP 2.2.0" from "Espressif's lwIP, based on 2.2.0".

``evidence.identity``
    Every claim carries the techniques that produced it and a confidence in
    [0, 1].  An SBOM that states "lwIP 2.2.0" with no hedge, when the truth is a
    0.95-similarity fork, is worse than useless under audit.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any, Dict, List, Optional

from .. import __version__
from ..licenses import cyclonedx_licenses, differs, observed_ids
from ..support import support_properties
from ..model import Finding, ScanResult

SPEC_VERSION = "1.6"
_IDENTITY_FIELD_FOR = {"purl": "purl", "cpe": "cpe"}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _identity_entries(finding: Finding) -> List[Dict[str, Any]]:
    methods = [
        {
            "technique": ev.technique.value,
            "confidence": round(ev.confidence, 3),
            "value": ev.summary,
        }
        for ev in finding.evidence
    ]
    entries: List[Dict[str, Any]] = []
    for field_name, value in (("purl", finding.purl), ("cpe", finding.cpe)):
        if not value:
            continue
        entry: Dict[str, Any] = {
            "field": _IDENTITY_FIELD_FOR[field_name],
            "confidence": finding.confidence,
            "concludedValue": value,
        }
        if methods:
            entry["methods"] = methods
        entries.append(entry)
    if not entries:
        # No purl or cpe to assert. The name and the confidence are still worth
        # stating -- a consumer that cannot match a CVE should at least be told
        # how sure we are about what this is.
        fallback = {"field": "name", "confidence": finding.confidence,
                    "concludedValue": finding.upstream_name}
        if methods:
            fallback["methods"] = methods
        entries.append(fallback)
    return entries


def _pedigree(finding: Finding) -> Optional[Dict[str, Any]]:
    if not finding.vendor_patched:
        return None
    ancestor: Dict[str, Any] = {
        "type": "library",
        "name": finding.upstream_name,
        "bom-ref": f"upstream/{finding.upstream_name}",
    }
    if finding.version:
        ancestor["version"] = finding.version
    if finding.purl:
        ancestor["purl"] = finding.purl
    if finding.homepage:
        ancestor["externalReferences"] = [{"type": "website", "url": finding.homepage}]

    notes = [finding.patch_hint or
             f"This copy is not byte-identical to pristine {finding.upstream_name}."]
    if finding.fork_url:
        notes.append(f"Upstream of this fork: {finding.fork_url}")
    notes.append("A CVE lookup on the ancestor's CPE is therefore approximate: "
                 "the vendor's changes are not reflected in NVD.")

    # 'unofficial' is CycloneDX's word for a patch not accepted upstream, which
    # is what a vendor fork is. No 'diff' is emitted: we do not have one, and a
    # homepage URL in that field would be a lie dressed as metadata.
    pedigree: Dict[str, Any] = {
        "ancestors": [ancestor],
        "patches": [{"type": "unofficial"}],
        "notes": " ".join(notes),
    }
    return pedigree


def _properties(finding: Finding) -> List[Dict[str, str]]:
    props = [
        {"name": "gangmu:rule", "value": finding.rule_id},
        {"name": "gangmu:directory", "value": finding.directory},
        {"name": "gangmu:identityConfidence",
         "value": f"{finding.identity_confidence:.3f}"},
        {"name": "gangmu:versionConfidence",
         "value": f"{finding.version_confidence:.3f}"},
    ]
    if finding.rule_pack:
        props.append({"name": "gangmu:rulePack", "value": finding.rule_pack})
        if finding.rule_pack_version:
            props.append({"name": "gangmu:rulePackVersion", "value": finding.rule_pack_version})
    if finding.version_source:
        props.append({"name": "gangmu:versionSource", "value": finding.version_source})
    if finding.version and "~" in finding.version:
        props.append({"name": "gangmu:versionRange", "value": finding.version})
    if finding.renamed_from:
        props.append({"name": "gangmu:shippedAs", "value": finding.renamed_from})
    if finding.component_name:
        props.append({"name": "gangmu:ecosystemComponent", "value": finding.component_name})
    if finding.vendor_name:
        props.append({"name": "gangmu:vendor", "value": finding.vendor_name})
    observed = observed_ids(finding)
    if observed:
        props.append({"name": "gangmu:observedLicenses", "value": "; ".join(observed)})
        if differs(finding.declared_license, observed):
            props.append({"name": "gangmu:licenseDiffersFromRule", "value": "true"})
    if finding.compiled_files:
        props.append({"name": "gangmu:compiledFiles", "value": str(finding.compiled_files)})
    if finding.linked is not None:
        props.append({"name": "gangmu:linkedIntoImage",
                      "value": "true" if finding.linked else "false"})
    if finding.advisory_scope:
        props.append({"name": "gangmu:advisoryScope", "value": finding.advisory_scope})
    for alt in finding.alternatives:
        props.append({"name": "gangmu:alternative",
                      "value": f"{alt.upstream_name} ({alt.identity_confidence:.2f}, "
                               f"rule {alt.rule_id})"})
    props.extend(support_properties(finding.support))
    return props


def _component(finding: Finding) -> Dict[str, Any]:
    ref = f"{finding.directory}#{finding.rule_id}"
    comp: Dict[str, Any] = {
        "bom-ref": ref,
        # a vendor SDK is a framework the product is built on, not a library
        "type": ("framework" if finding.rule_id.startswith("declared/vendor-sdk/")
                 else "library"),
        "name": finding.upstream_name,
        # CycloneDX: "excluded" documents what is in the tree but not in the image.
        "scope": "excluded" if finding.linked is False else "required",
    }
    if finding.version:
        comp["version"] = finding.version
    if finding.purl:
        comp["purl"] = finding.purl
    if finding.cpe:
        comp["cpe"] = finding.cpe
    supplier = finding.supplier or (
        f"{finding.vendor_name}" if finding.vendor_name else None)
    if supplier:
        comp["supplier"] = {"name": supplier}
    if finding.content_hash:
        # CISA 2026 minimum elements: a component hash. A vendored source tree
        # has no archive to hash, so this is the digest of its (path, file
        # digest) pairs -- reproducible with `gangmu scan` on the same tree.
        comp["hashes"] = [{"alg": "SHA-256", "content": finding.content_hash}]
    licenses = cyclonedx_licenses(finding.declared_license, finding.observed_licenses,
                                  finding.license_files)
    if licenses:
        comp["licenses"] = licenses
    if finding.homepage:
        comp["externalReferences"] = [{"type": "website", "url": finding.homepage}]
    pedigree = _pedigree(finding)
    if pedigree:
        comp["pedigree"] = pedigree
    identity = _identity_entries(finding)
    if identity:
        comp["evidence"] = {"identity": identity}
    comp["properties"] = _properties(finding)
    return comp


def _binary_component(blob) -> Dict[str, Any]:
    """A prebuilt binary: named and hashed even when nothing inside is identified."""
    props = [
        {"name": "gangmu:binary", "value": blob.kind},
        {"name": "gangmu:sourceAvailable", "value": "false"},
        {"name": "gangmu:sizeBytes", "value": str(blob.size)},
    ]
    if blob.linked is not None:
        props.append({"name": "gangmu:linkedIntoImage",
                      "value": "true" if blob.linked else "false"})
    if blob.stripped is not None:
        props.append({"name": "gangmu:stripped", "value": "true" if blob.stripped else "false"})
    if blob.functions:
        props.append({"name": "gangmu:functionsRecovered",
                      "value": f"{blob.functions} ({blob.function_source}, {blob.arch})"})
    if blob.layers > 1:
        props.append({"name": "gangmu:unpackedLayers", "value": str(blob.layers)})
    if blob.toolchain:
        props.append({"name": "gangmu:toolchain", "value": blob.toolchain})
    for emb in blob.embedded:
        props.append({"name": ("gangmu:vendorComponent" if emb.vendor_component
                               else "gangmu:embeddedLibrary"),
                      "value": f"{emb.display_name} {emb.version}".strip()})
    return {
        "bom-ref": f"binary:{blob.path}",
        "type": "file",
        "name": blob.path,
        "scope": "excluded" if blob.linked is False else "required",
        "hashes": [{"alg": "SHA-256", "content": blob.sha256}],
        "properties": props,
    }


def to_cyclonedx(result: ScanResult, app_name: str = "firmware",
                 app_version: Optional[str] = None,
                 timestamp: Optional[str] = None,
                 serial: Optional[str] = None) -> Dict[str, Any]:
    root_component: Dict[str, Any] = {
        "bom-ref": "root-application",
        "type": "application",
        "name": app_name,
    }
    if app_version:
        root_component["version"] = app_version

    components = [_component(f) for f in result.findings]
    dependencies = _dependency_graph(result.findings, components)
    components.extend(_binary_component(b) for b in result.binaries)
    bom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or _now(),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "gangmu-sbom",
                    "version": __version__,
                }]
            },
            "component": root_component,
            "properties": [
                # CISA 2026: SBOM generation context.
                {"name": "gangmu:generationContext",
                 "value": ("build" if result.build_facts_used else "source")},
                {"name": "gangmu:generationContextNote",
                 "value": ("Derived from the build's own compile database"
                           if result.build_facts_used else
                           "Derived from the source tree only; may over-report "
                           "code that is never compiled or never linked")},
                {"name": "gangmu:rulesLoaded", "value": str(result.rules_loaded)},
                {"name": "gangmu:buildFactsUsed",
                 "value": "true" if result.build_facts_used else "false"},
                {"name": "gangmu:unidentifiedDirectories",
                 "value": str(len(result.unidentified))},
                *({"name": "gangmu:possibleComponent",
                   "value": (f"{f.upstream_name} {f.version or ''} at {f.directory} "
                             f"(identity {f.identity_confidence:.2f}, rule {f.rule_id})"
                             ).replace("  ", " ")}
                  for f in result.possible),
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    return bom


def _dependency_graph(findings, components) -> List[Dict[str, Any]]:
    """Real nesting, not a flat list under the application.

    A component vendored *inside* another component is a transitive dependency,
    and CRA's "at the very least the top-level dependencies" only means anything
    if the document distinguishes the two. ESP-IDF's Mbed TLS carries
    tf-psa-crypto; Zephyr's mbedTLS module wraps Mbed TLS itself. Reporting all
    of them as direct dependencies of the firmware would be a flat list wearing
    a graph's clothes.

    Containment is decided by directory nesting, which is how vendored code is
    actually arranged on disk.
    """
    # One directory can hold several components (an OpenHarmony
    # README.OpenSource may declare more than one), so refs are kept per
    # directory as lists rather than one-to-one.
    refs: Dict[str, List[str]] = {}
    for f, c in zip(findings, components):
        refs.setdefault(f.directory.rstrip("/"), []).append(c["bom-ref"])

    parent: Dict[str, Optional[str]] = {}
    for here in refs:
        best: Optional[str] = None
        for other in refs:
            if other == here or not (other == "." or here.startswith(other + "/")):
                continue                           # "." is the scan root: it holds everything
            if best is None or len(other) > len(best):
                best = other                       # the nearest enclosing one
        parent[here] = best

    children: Dict[str, List[str]] = {}
    for here, enclosing in parent.items():
        key = enclosing if enclosing is not None else "root-application"
        children.setdefault(key, []).extend(refs[here])

    # Declared dependencies (OpenHarmony bundle.json) are edges the directory
    # layout cannot show: hilog_lite sits in base/hiviewdfx and uses
    # third_party/bounds_checking_function.
    by_name: Dict[str, List[str]] = {}
    for f, c in zip(findings, components):
        if f.component_name:
            by_name.setdefault(f.component_name, []).append(c["bom-ref"])

    graph = [{"ref": "root-application",
              "dependsOn": sorted(children.get("root-application", []))}]
    for f, c in zip(findings, components):
        here = f.directory.rstrip("/")
        depends = set(children.get(here, []))
        missing = []
        for name in f.depends_on:
            refs_for = [r for r in by_name.get(name, []) if r != c["bom-ref"]]
            depends.update(refs_for)
            if not refs_for:
                missing.append(name)
        if missing:
            # Declared but not in this tree (or not identified): say so rather
            # than drop the edge silently.
            c.setdefault("properties", []).append(
                {"name": "gangmu:declaredDependencyNotFound",
                 "value": ", ".join(missing)})
        graph.append({"ref": c["bom-ref"], "dependsOn": sorted(depends)})
    return graph
