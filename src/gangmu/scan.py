"""Orchestration: source tree + rules (+ build facts) -> findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .build.facts import BuildFacts
from .licenses import observe
from .globbing import matches_suffix
from .build.kconfig import KconfigValues, disabled_by
from .declared import Declaration, collect_declarations
from .binaries import collect_binaries
from .discover import discover_roots, empty_submodules
from .analysis import AnalysisStore
from .fingerprint import DEFAULT_K, DEFAULT_WINDOW
from .match.engine import MatchEngine, PrintCache
from .model import Evidence, Finding, ScanResult, Technique
from .rules.loader import RuleBase
from .rules.resolve import resolve
from .rules.schema import Rule

DECLARED_CONFIDENCE = 0.90
POSSIBLE_BELOW = 0.60       # the engine's "weak" band starts here


@dataclass
class ScanOptions:
    deep: bool = False
    min_confidence: float = 0.35
    possible_below: float = POSSIBLE_BELOW   # identity under this is "possible", not a component; 0 keeps all
    min_sources: int = 3
    jobs: int = 1
    cache_dir: Optional[Path] = None
    binaries: bool = True           # inventory prebuilt .a/.lib/.so and read their banners
    declared: bool = True           # read RT-Thread / OpenHarmony declarations
    licenses: bool = True           # read SPDX headers and LICENSE files of what is identified
    kconfig: Optional[KconfigValues] = None  # sdkconfig / .config: drop components it turns off
    stats: Optional[Dict[str, int]] = None   # filled with work counters if given


def scan(root: Path, rulebase: RuleBase,
         build_facts: Optional[BuildFacts] = None,
         options: Optional[ScanOptions] = None) -> ScanResult:
    options = options or ScanOptions()
    root = Path(root).resolve()
    with AnalysisStore(root, *_store_params(rulebase), jobs=options.jobs,
                       cache_dir=options.cache_dir) as store:
        result = _scan(root, rulebase, build_facts, options, store)
        if options.stats is not None:
            options.stats.update(store.stats)
    return result


def _store_params(rulebase: RuleBase):
    """The (k, window) most rules use; any rule using others falls back to its
    own directory prints, which is correct and merely slower."""
    counts: Dict[tuple, int] = {}
    for rule in rulebase:
        if rule.signature is not None:
            key = (rule.signature.signature.k, rule.signature.signature.window)
            counts[key] = counts.get(key, 0) + 1
    if not counts:
        return DEFAULT_K, DEFAULT_WINDOW
    return max(counts, key=lambda key: (counts[key], key))


def _scan(root: Path, rulebase: RuleBase, build_facts: Optional[BuildFacts],
          options: ScanOptions, store: AnalysisStore) -> ScanResult:
    engine = MatchEngine(rulebase=rulebase,
                         cache=PrintCache(jobs=options.jobs, store=store),
                         min_confidence=options.min_confidence)

    roots = discover_roots(root, rulebase, build_facts,
                           deep=options.deep, min_sources=options.min_sources)
    declarations = collect_declarations(root) if options.declared else []
    # A declared directory is always worth fingerprinting too: an RT-Thread
    # package declares only the wrapper's tag, and the rule base is what says
    # which upstream release is inside it.
    extra = {d.directory for d in declarations
             if d.present and not d.manifest_only and d.directory != root and root in d.directory.parents
             and not (build_facts and build_facts.compiled
                      and not build_facts.sources_under(d.directory))}
    roots = sorted(set(roots) | extra)
    specificity = {r.id: r.specificity for r in rulebase}

    engine.prefetch(roots)
    if options.stats is not None:
        options.stats["candidate_directories"] = len(roots)
    raw: List[Finding] = []
    unidentified: List[str] = []
    for directory in roots:
        found = engine.identify_directory(root, directory)
        engine.forget(directory)
        if found:
            raw.extend(found)
        else:
            unidentified.append(directory.relative_to(root).as_posix())

    if options.stats is not None:
        options.stats.update(engine.stats)
    findings = resolve(raw, specificity)
    findings = _drop_nested_duplicates(findings)

    notes: List[str] = []
    if options.declared:
        findings, notes = _apply_declarations(root, findings, rulebase,
                                              declarations, build_facts)

    # A directory inside an identified component is part of that component, not
    # a separate unknown. Reporting it would bury the unknowns that matter.
    identified = [f.directory.rstrip('/') + '/' for f in findings]
    unidentified = [u for u in unidentified
                    if not any((u + '/').startswith(prefix) for prefix in identified)]

    if build_facts:
        for finding in findings:
            directory = root / finding.directory
            compiled = build_facts.sources_under(directory)
            finding.compiled_files = len(compiled)
            if build_facts.have_link_map:
                finding.linked = bool(build_facts.linked_under(directory))

    if options.licenses:
        for finding in findings:
            _observe_licenses(root, finding)

    missing = empty_submodules(root)
    if missing:
        shown = ", ".join(missing[:8]) + (f" and {len(missing) - 8} more"
                                          if len(missing) > 8 else "")
        notes.append(f"{len(missing)} git submodule(s) declared in .gitmodules are "
                     f"empty, so anything they hold is not in this scan: {shown}. "
                     f"Run `git submodule update --init --recursive` and scan again.")

    findings.sort(key=lambda f: (-f.confidence, f.directory))
    binaries = []
    if options.binaries:
        facts_map = build_facts is not None and build_facts.have_link_map
        binaries = collect_binaries(
            root, build_facts.linked_archives if facts_map else None,
            _string_signatures(rulebase), _function_prints(rulebase))
        findings.extend(_binary_findings(binaries, rulebase))
        unlinked = [b for b in binaries if b.linked is False and b.embedded
                    and any(not e.vendor_component for e in b.embedded)]
        if unlinked:
            notes.append(
                f"{len(unlinked)} prebuilt archive(s) carry a library banner but the link "
                f"map does not name them, so they are listed as files (linked=false) and "
                f"not reported as components: "
                + ", ".join(b.path for b in unlinked[:6])
                + (f" and {len(unlinked) - 6} more" if len(unlinked) > 6 else "") + ".")
        findings.sort(key=lambda f: (-f.confidence, f.directory))
    not_built: List[Finding] = []
    if options.kconfig is not None and len(options.kconfig):
        findings, not_built = _apply_kconfig(findings, rulebase, options.kconfig)
        if not_built:
            notes.append(
                f"{len(not_built)} component(s) are in the tree but switched off in "
                f"{options.kconfig.path or 'the build configuration'}, so they are left "
                f"out: " + ", ".join(f"{f.upstream_name} ({f.directory})"
                                     for f in not_built[:6])
                + (f" and {len(not_built) - 6} more" if len(not_built) > 6 else "")
                + ". Use --no-kconfig to list them.")
    possible = [f for f in findings if f.identity_confidence < options.possible_below]
    if possible:
        findings = [f for f in findings if f.identity_confidence >= options.possible_below]
    return ScanResult(root=str(root), findings=findings, possible=possible,
                      not_built=not_built,
                      binaries=binaries,
                      unidentified=sorted(unidentified),
                      rules_loaded=len(rulebase),
                      build_facts_used=build_facts is not None,
                      notes=notes)


def _observe_licenses(root: Path, finding: Finding) -> None:
    directory = root / finding.directory
    if not directory.is_dir():
        return
    headers, files = observe(directory)
    finding.observed_licenses = headers
    finding.license_files = files

def _apply_kconfig(findings: List[Finding], rulebase: RuleBase,
                   config: KconfigValues):
    by_id = {r.id: r for r in rulebase}
    kept: List[Finding] = []
    dropped: List[Finding] = []
    for finding in findings:
        rule = by_id.get(finding.rule_id)
        off = None
        if rule is not None:
            for gate in rule.config_gates:
                if gate.path is None or matches_suffix(finding.directory, [gate.path]):
                    off = disabled_by(gate.symbols, config)
                    break
        if off:
            finding.config_off = off
            dropped.append(finding)
        else:
            kept.append(finding)
    return kept, dropped


BINARY_IDENTITY = 0.70      # a banner proves the library is inside, not that it is unmodified
BINARY_VERSION = 0.60
BINARY_SYMBOLS_IDENTITY = 0.65   # an exported API names the library, but every release exports it


def _string_signatures(rulebase: RuleBase):
    return [(r.upstream_name, _norm(r.ships_as or r.upstream_name), r.binary_strings.load())
            for r in rulebase if r.binary_strings is not None]


def _function_prints(rulebase: RuleBase):
    return [(r.upstream_name, _norm(r.ships_as or r.upstream_name), r.binary_functions.load())
            for r in rulebase if r.binary_functions is not None]


def _binary_summary(emb, version: Optional[str]) -> str:
    if emb.method == "functions":
        return (f"{emb.banner} were matched by the strings and constants they use; the "
                "library is inside this binary, but a modified function can keep both, so "
                "this is not proof of unmodified upstream code")
    if emb.method == "strings":
        return (f"{emb.banner} appear in this prebuilt binary; the library is inside it, "
                "but string constants survive a modified copy, so this is not proof of "
                "unmodified upstream code")
    if version:
        return (f"the string {emb.banner!r} is compiled into this prebuilt binary; the "
                "library is inside it, but its code cannot be compared with upstream")
    return (f"{emb.banner} are exported by this prebuilt binary; the library is inside "
            "it, but no release can be named from an API that every release exports")


def _binary_findings(binaries, rulebase: RuleBase) -> List[Finding]:
    """One finding per (library, version) banner found inside a prebuilt binary.

    An archive the link map does not name never reached the image, so it stays in the
    file inventory (``linked=false``) but yields no component: a component would be
    matched against advisories for code that does not ship."""
    from .declared_linux import KNOWN
    out: List[Finding] = []
    for blob in binaries:
        if blob.linked is False:
            continue
        for emb in blob.embedded:
            if emb.vendor_component:
                continue                      # a vendor's own component: no upstream to name
            rule = _rule_by_name(rulebase, emb.display_name)
            known = KNOWN.get(emb.name)
            version = emb.version or None         # "": found by API symbols, no release
            purl = (rule.purl_with_version(version) if rule
                    else f"pkg:generic/{emb.name}"
                    + (f"@{version}" if version and "~" not in version else ""))
            cpe = (rule.cpe_with_version(version) if rule
                   else _spliced(known[1], version) if known else None)
            out.append(Finding(
                directory=blob.path,
                rule_id=f"binary/{emb.name}",
                upstream_name=rule.upstream_name if rule else emb.display_name,
                purl=purl, cpe=cpe,
                homepage=rule.homepage if rule else None,
                declared_license=rule.license if rule else None,
                version=version,
                version_source="binary-string" if version else "unknown",
                identity_confidence=BINARY_IDENTITY if version else BINARY_SYMBOLS_IDENTITY,
                version_confidence=BINARY_VERSION if version else 0.0,
                supplier=rule.supplier if rule else None,
                evidence=[Evidence(
                    technique=Technique.OTHER,
                    confidence=BINARY_IDENTITY if version else BINARY_SYMBOLS_IDENTITY,
                    summary=_binary_summary(emb, version),
                    locator=blob.path)],
                content_hash=blob.sha256,
                linked=blob.linked,
            ))
    return out


def _apply_declarations(root: Path, findings: List[Finding], rulebase: RuleBase,
                        declarations: List[Declaration],
                        build_facts: Optional[BuildFacts]):
    """Fold package-manager declarations into the fingerprint findings.

    A declaration on a directory a rule already identified becomes evidence on
    that finding (and supplies the version when it is an upstream version and
    nothing stronger did). A declaration nobody's rule covers becomes a finding
    of its own -- that is the case package managers exist for.
    """
    notes: List[str] = []
    by_dir = {f.directory: f for f in findings}
    out = list(findings)
    for decl in declarations:
        if not decl.present:
            notes.append(f"{decl.ecosystem}: package {decl.name}"
                         + (f" {decl.version}" if decl.version else "")
                         + f" is selected in {decl.source} but not downloaded; "
                           "it is not in this SBOM until it is on disk")
            continue
        try:
            rel = decl.directory.relative_to(root).as_posix() or "."
        except ValueError:
            continue
        if (not decl.manifest_only and build_facts and build_facts.compiled
                and not build_facts.sources_under(decl.directory)):
            # Same test discovery applies to every other candidate.
            continue
        evidence = Evidence(
            technique=Technique.MANIFEST_ANALYSIS,
            confidence=DECLARED_CONFIDENCE,
            summary=_declaration_summary(decl),
            locator=decl.source,
        )
        existing = None if decl.manifest_only else by_dir.get(rel)
        if existing is not None and _same_component(existing, decl):
            existing.evidence.append(evidence)
            _take_dependencies(existing, decl)
            if decl.version_is_upstream and decl.version == existing.version:
                # Two independent sources agree on the release.
                existing.version_confidence = max(existing.version_confidence,
                                                  DECLARED_CONFIDENCE)
            if (decl.version_is_upstream and decl.version
                    and existing.version != decl.version):
                if existing.version is None or existing.version_source in (
                        None, "signature-reference"):
                    rule = _rule_by_id(rulebase, existing.rule_id)
                    existing.version = decl.version
                    existing.version_source = "declared"
                    existing.version_confidence = DECLARED_CONFIDENCE
                    if rule is not None:
                        existing.purl = rule.purl_with_version(decl.version)
                        existing.cpe = rule.cpe_with_version(decl.version)
                else:
                    existing.evidence.append(Evidence(
                        technique=Technique.OTHER, confidence=0.0,
                        summary=(f"{decl.source} declares {decl.version} but the "
                                 f"code reads as {existing.version} "
                                 f"({existing.version_source}); a reviewer should "
                                 "decide which is true"),
                        locator=decl.source))
            continue
        finding = _declared_finding(rel, decl, rulebase, evidence)
        _take_dependencies(finding, decl)
        out.append(finding)
        if existing is None and not decl.manifest_only:
            by_dir[rel] = finding
    return out, notes


def _take_dependencies(finding: Finding, decl: Declaration) -> None:
    if decl.component and not finding.component_name:
        finding.component_name = decl.component
    for dep in decl.depends_on:
        if dep not in finding.depends_on:
            finding.depends_on.append(dep)


def _declared_finding(rel: str, decl: Declaration, rulebase: RuleBase,
                      evidence: Evidence) -> Finding:
    rule = _rule_by_name(rulebase, decl.name) if decl.version_is_upstream else None
    version = decl.version
    purl = decl.purl
    cpe = _spliced(decl.cpe, version)
    if rule is not None:
        # The upstream version is declared, so the rule's upstream identifiers
        # apply as they are. (An RT-Thread package version never reaches here:
        # splicing a wrapper's tag into the upstream CPE would match the wrong
        # CVEs, or none.)
        purl = rule.purl_with_version(version) or purl
        cpe = rule.cpe_with_version(version)
    return Finding(
        directory=rel,
        rule_id=f"declared/{decl.ecosystem}/{decl.name}",
        upstream_name=rule.upstream_name if rule else (decl.display_name or decl.name),
        purl=purl,
        cpe=cpe,
        homepage=decl.upstream_url or (rule.homepage if rule else None),
        declared_license=(rule.license if rule and rule.license else
                          _spdx_or_none(decl.license)),
        version=version,
        version_source="declared" if version else None,
        identity_confidence=DECLARED_CONFIDENCE,
        version_confidence=DECLARED_CONFIDENCE if version else 0.0,
        supplier=rule.supplier if rule else decl.supplier,
        evidence=[evidence],
        path_match=2,
        vendor_patched=decl.forked,
        patch_hint=decl.fork_note,
    )


def _spliced(cpe: Optional[str], version: Optional[str]) -> Optional[str]:
    if not cpe:
        return None
    parts = cpe.split(":")
    if version and "~" not in version and len(parts) > 5:
        parts[5] = version
    return ":".join(parts)


def _declaration_summary(decl: Declaration) -> str:
    what = decl.name + (f" {decl.version}" if decl.version else "")
    if decl.ecosystem == "vendor-sdk":
        return (f"{decl.source} states {what}, released by {decl.supplier}; the "
                "vendor's own HAL and drivers in this tree belong to this release")
    if decl.ecosystem in ("buildroot", "openwrt"):
        return (f"{decl.ecosystem} package {what} is selected in {decl.source}; "
                "the recipe pins this upstream version")
    if decl.ecosystem == "yocto":
        return (f"Yocto: {decl.source} lists {what}"
                + (f" ({decl.description})" if decl.description else ""))
    if decl.ecosystem in ("conan", "bazel"):
        return (decl.description if decl.description and not decl.version
                else f"{decl.ecosystem} dependency {what} declared in {decl.source}")
    if decl.ecosystem == "platformio":
        return (decl.description if decl.manifest_only and decl.description
                else f"PlatformIO library {what} installed per {decl.source}")
    if decl.ecosystem == "kbuild":
        return f"{decl.source} states {what}" + (
            f" ({decl.fork_note})" if decl.fork_note else "")
    if decl.ecosystem == "rt-thread":
        return (f"RT-Thread package {what} selected in {decl.source}; the version "
                "is the package's tag, not necessarily the upstream release")
    if decl.supplier and not decl.upstream_url:
        return (f"OpenHarmony {decl.source} declares component {what}"
                + (f", depending on {', '.join(decl.depends_on)}"
                   if decl.depends_on else ""))
    return f"OpenHarmony {decl.source} declares {what}" + (
        f" from {decl.upstream_url}" if decl.upstream_url else "")


def _same_component(finding: Finding, decl: Declaration) -> bool:
    if decl.ecosystem == "rt-thread":
        return True        # package names are RT-Thread's; the rule's identity wins
    return _norm(finding.upstream_name) == _norm(decl.name) or \
        _norm(finding.renamed_from or "") == _norm(decl.name)


def _rule_by_id(rulebase: RuleBase, rule_id: str) -> Optional[Rule]:
    return next((r for r in rulebase if r.id == rule_id), None)


def _rule_by_name(rulebase: RuleBase, name: str) -> Optional[Rule]:
    """An upstream rule for this name, preferring one that is not a vendor fork."""
    matches = [r for r in rulebase
               if _norm(r.upstream_name) == _norm(name)
               or _norm(r.ships_as or "") == _norm(name)]
    matches.sort(key=lambda r: (r.patched, r.id))
    return matches[0] if matches else None


def _norm(name: str) -> str:
    return "".join(c for c in name.lower() if c.isalnum())


_SPDX_ALIASES = {
    "mit license": "MIT", "mit": "MIT",
    "apache license 2.0": "Apache-2.0", "apache license v2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0", "apache 2.0": "Apache-2.0",
    "bsd 3-clause license": "BSD-3-Clause", "bsd-3-clause": "BSD-3-Clause",
    "bsd 2-clause license": "BSD-2-Clause", "bsd-2-clause": "BSD-2-Clause",
    "zlib license": "Zlib", "zlib": "Zlib",
    "isc license": "ISC", "isc": "ISC",
    "openssl license": "OpenSSL",
}


def _spdx_or_none(license_text: Optional[str]) -> Optional[str]:
    """Only an unambiguous SPDX id goes into the SBOM's licence field.

    OpenHarmony writes licences as prose ("MIT License", "GPL V2.0 and LGPL
    V2.1"). Guessing an id from a compound phrase is how licence fields go
    wrong, so anything not in a short, exact table is left out.
    """
    if not license_text:
        return None
    return _SPDX_ALIASES.get(license_text.strip().lower())


def _drop_nested_duplicates(findings: List[Finding]) -> List[Finding]:
    """A wrapper directory and the component inside it are one component.

    ESP-IDF's ``components/lwip`` wraps ``components/lwip/lwip``; Mbed TLS
    contains ``tf-psa-crypto``, which matches the Mbed TLS rule too. Reporting
    both would double-count.

    Which one survives is decided by confidence, not by depth. An earlier
    version always preferred the deeper directory and so reported Mbed TLS as
    its own sub-library at 0.75 while silently dropping the 0.95 match on the
    real component root.
    """
    def is_ancestor(a: str, b: str) -> bool:
        return b != a and b.startswith(a.rstrip("/") + "/")

    dropped = set()
    for i, outer in enumerate(findings):
        for j, inner in enumerate(findings):
            if i == j or outer.upstream_name != inner.upstream_name:
                continue
            if not is_ancestor(outer.directory, inner.directory):
                continue
            # Same component, one inside the other. Keep the stronger claim;
            # on a tie keep the deeper one, which is the more specific path.
            if inner.confidence > outer.confidence:
                dropped.add(outer.directory)
            elif outer.confidence > inner.confidence:
                dropped.add(inner.directory)
            else:
                dropped.add(outer.directory)
    return [f for f in findings if f.directory not in dropped]
