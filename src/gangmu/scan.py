"""Orchestration: source tree + rules (+ build facts) -> findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .build.facts import BuildFacts
from .licenses import observe
from .core.globbing import matches_suffix
from .build.kconfig import KconfigValues, disabled_by
from .declared import Declaration, collect_declarations
from .binaries import collect_binaries
from .discover import discover_roots, empty_submodules
from .analysis import AnalysisStore
from .fingerprint import DEFAULT_K, DEFAULT_WINDOW
from .match.engine import MatchEngine, PrintCache
from .match.loose import find_loose
from .model import Evidence, Finding, ScanResult, Technique
from .rules.loader import RuleBase
from .rules.resolve import resolve
from .rules.schema import Rule
from .support import stamp as stamp_support
from .unknown import discover_unknown
from .core.cpe import escape_value, join_cpe, split_cpe

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
    loose: bool = True              # identify components copied in as loose files among others
    unknown: bool = True            # report code that looks vendored and that no rule names
    support: Optional[List[Any]] = None     # support.Override entries from --support
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


def _store_params(rulebase: RuleBase) -> Tuple[int, int]:
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
             if d.directory is not None and not d.manifest_only and d.directory != root
             and root in d.directory.parents
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
    raw = _drop_shadowing_ancestors(raw)
    findings = resolve(raw, specificity)
    findings = _drop_nested_duplicates(findings)

    notes: List[str] = []
    if options.declared:
        findings, notes = _apply_declarations(root, findings, rulebase,
                                              declarations, build_facts)

    absorbed: List[Tuple[str, List[str], str]] = []
    if options.loose:
        # What no directory explains: a component's files dropped in among the
        # project's own (app/lwprintf.c beside app/main.c).
        loose = find_loose(root, engine, store, findings,
                           build_facts.compiled if build_facts and build_facts.compiled else None,
                           asserted=options.possible_below, absorbed=absorbed)
        # A resemblance at a directory gives way to the component's own files in it.
        placed = {(f.rule_id, f.directory) for f in loose}
        findings = [f for f in findings if f.identity_confidence >= options.possible_below
                    or not any(rid == f.rule_id and _within(d, f.directory) for rid, d in placed)]
        findings.extend(loose)
        # A rule that lost a directory to another is no alternative to it once it
        # has its own files there.
        for f in findings:
            f.alternatives = [a for a in f.alternatives if (a.rule_id, f.directory) not in placed]
        if options.stats is not None:
            options.stats["loose_findings"] = len(loose)

    # A directory inside an identified component is part of that component, not
    # a separate unknown. Reporting it would bury the unknowns that matter.
    identified = [f.directory.rstrip('/') + '/' for f in findings if not f.files]
    unidentified = [u for u in unidentified
                    if not any((u + '/').startswith(prefix) for prefix in identified)]

    if build_facts:
        for finding in findings:
            directory = root / finding.directory
            if finding.files:
                mine = {(root / f).resolve() for f in finding.files}
                finding.compiled_files = len(mine & build_facts.compiled)
                if build_facts.have_link_map:
                    finding.linked = bool(mine & build_facts.linked)
                continue
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
        facts_map = build_facts if build_facts is not None and build_facts.have_link_map \
            else None
        binaries = collect_binaries(
            root, facts_map.linked_archives if facts_map else None,
            _string_signatures(rulebase), _function_prints(rulebase),
            facts_map.link_map_stem if facts_map else "",
            _banner_patterns(rulebase))
        findings.extend(_binary_findings(binaries, rulebase))
        opaque = [b.path for b in binaries if b.opaque and b.linked is not False]
        if opaque:
            shown = ", ".join(opaque[:4]) + (f" and {len(opaque) - 4} more"
                                             if len(opaque) > 4 else "")
            notes.append(
                f"{len(opaque)} raw image(s) are high-entropy ({shown}): encrypted, compressed "
                "with a scheme the scan cannot unwrap, or not code at all. Nothing could be "
                "read from them, so any component inside is missing from this SBOM; unwrap or "
                "decrypt them first (the vendor's update tool, binwalk, unblob) and scan the result")
        unlinked = sum(1 for b in binaries if b.linked is False and b.container is None)
        if unlinked:
            notes.append(
                f"{unlinked} prebuilt binar(ies) in the tree are not named by the link map; "
                "they stay in the SBOM with scope 'excluded' (CycloneDX) so a monorepo's "
                "other boards do not read as shipped. --no-binaries leaves them out")
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
    _stamp_rule_packs(rulebase, findings, possible, not_built)
    stamp_support({r.id: r for r in rulebase}, options.support or [],
                            findings, possible, not_built)
    if options.support is not None and findings:
        gaps = sum(1 for f in findings if f.support is not None and f.support.status == "unknown")
        if gaps:
            notes.append(f"{gaps} of {len(findings)} component(s) have no support "
                         "status in the rules or the --support file; the SBOM says "
                         "'unknown' for them. FDA asks for the level of support and "
                         "the end-of-support date of every component")
    unknown = []
    if options.unknown:
        unknown = discover_unknown(
            root, [(f.directory, f.files, f.upstream_name) for f in findings + not_built
                   if not f.rule_id.startswith("binary/")] + absorbed,
            [(f.directory, f.files, f.rule_id) for f in possible], store)
        if unknown:
            notes.append(
                f"{len(unknown)} piece(s) of code look vendored but no rule names them "
                f"(own licence, copyright holder, manifest or function prefix): "
                + ", ".join(f"{u.name_hint or '?'} ({u.directory})" for u in unknown[:5])
                + (f" and {len(unknown) - 5} more" if len(unknown) > 5 else "")
                + ". They are not in the SBOM; see 'unknown' in the JSON output")
    return ScanResult(root=str(root), findings=findings, possible=possible,
                      not_built=not_built, unknown=unknown,
                      binaries=binaries,
                      unidentified=sorted(unidentified),
                      rules_loaded=len(rulebase),
                      build_facts_used=build_facts is not None,
                      notes=notes)


def _stamp_rule_packs(rulebase: RuleBase, *groups: List[Finding]) -> None:
    """Record, on each finding, which rule pack supplied the rule that matched.

    Without it an SBOM cannot say which part of the rule base a component's identity
    came from, so a team cannot tell what a vendor pack, or its subscription, is
    actually buying them. Findings from build declarations and binaries match no rule
    and are left unmarked.
    """
    if not rulebase.provenance:
        return
    for group in groups:
        for finding in group:
            for item in [finding] + list(finding.alternatives):
                known = rulebase.provenance.get(item.rule_id)
                if known:
                    item.rule_pack = known[0]
                    item.rule_pack_version = known[1] or None


def _within(path: str, directory: str) -> bool:
    return directory in ("", ".") or path == directory or path.startswith(directory.rstrip("/") + "/")


def _observe_licenses(root: Path, finding: Finding) -> None:
    directory = root / finding.directory
    if not directory.is_dir():
        return
    if finding.files:
        # The directory's licence files and other sources are the project's.
        finding.observed_licenses, _ = observe(directory, [root / f for f in finding.files])
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
BINARY_METADATA = 0.90      # the toolchain recorded the dependency list on purpose (Go, Rust)
BINARY_IMPORT_IDENTITY = 0.50    # an import is a run-time dependency, not code inside the file
BINARY_SIDECAR = 0.85       # a .deps.json is exact but a separate file, so it can be stale
BINARY_FILE_NAME = 0.55     # the release in a library's file name (version only): the packager's choice, not the code's
BINARY_ASSEMBLY = 0.50      # a .NET assembly named like a NuGet package; nobody confirmed it
METADATA_METHODS = ("go-buildinfo", "cargo-auditable", "package-note")
WEAK_DEPENDENCY_METHODS = ("imports", "dotnet-reference")   # needed at run time, release unknown


def _string_signatures(rulebase: RuleBase):
    return [(r.upstream_name, _norm(r.ships_as or r.upstream_name), r.binary_strings.load())
            for r in rulebase if r.binary_strings is not None]


def _banner_patterns(rulebase: RuleBase):
    """The version banners rules supply for their component (``identity.binary_banners``)."""
    return [(_norm(r.ships_as or r.upstream_name), r.upstream_name, re.compile(pattern.encode()))
            for r in rulebase for pattern in r.binary_banners]


def _function_prints(rulebase: RuleBase):
    # a rule may carry one sidecar per architecture; the matcher tries the one built for the
    # image's CPU first (binaries._by_functions)
    return [(r.upstream_name, _norm(r.ships_as or r.upstream_name), spec.load())
            for r in rulebase for spec in r.binary_function_specs()]


def _binary_summary(emb, version: Optional[str]) -> str:
    if emb.method == "package-note":
        return (f"{emb.banner}: the packaging metadata its distribution's build wrote into "
                "this file (the ELF .note.package), so it is the package the file was built "
                "for; the version includes the distribution's revision and may carry fixes "
                "backported from later upstream releases, so it is not compared with upstream "
                "advisories as an upstream release")
    if emb.method in METADATA_METHODS:
        return (f"{emb.banner}: the toolchain recorded this dependency list in the binary, so it "
                "is the version the build resolved" + (
                    "; a replace directive means the code compiled in is not that release"
                    if emb.modified else
                    "; a patch applied after resolution would not show here"))
    if emb.method == "file-name":
        return (f"{emb.banner}: the release is in the library's file name, which agrees with its "
                "own SONAME; the packager chose that name, the code was not compared with "
                "upstream, and the release it names may carry the distribution's backported "
                "fixes")
    if emb.method == "deps-json":
        return (f"{emb.banner}: listed in the program's .deps.json, which the .NET SDK writes at "
                "build time with the package versions it restored; it is a separate file, so it "
                "can differ from the DLLs actually shipped")
    if emb.method == "dotnet-reference":
        return (f"{emb.banner}: this assembly refers to it, so it is needed at run time, but "
                "the package and release cannot be named from a reference, because an assembly "
                "version often stays the same across package releases")
    if emb.method == "dotnet-assembly":
        return (f"{emb.banner}; the name and version are the author's own text and nothing here "
                "shows the file was published as that NuGet package, so a reviewer should "
                "confirm before treating it as one")
    if emb.method == "version-info":
        return (f"the Windows version resource of this binary states {emb.banner}; its author "
                "wrote that text, so it names the library but can be stale or copied by a "
                "wrapper, and it is not proof of an unmodified copy")
    if emb.method == "imports":
        return (f"{emb.banner}: this binary needs the library at run time, but the library "
                "is a separate file and not part of this one, and a DLL name never says "
                "which release is installed")
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
    """One finding per (library, version) banner found inside a prebuilt binary."""
    from .declared_linux import KNOWN
    out: List[Finding] = []
    for blob in binaries:
        for emb in blob.embedded:
            if emb.vendor_component:
                continue                      # a vendor's own component: no upstream to name
            exact = emb.method in METADATA_METHODS
            rule = None if emb.purl else _rule_by_name(rulebase, emb.display_name)
            known = KNOWN.get(emb.name)
            version = emb.version or None         # "": found by API symbols, no release
            purl = emb.purl or (rule.purl_with_version(version) if rule
                                else f"pkg:generic/{emb.name}"
                                + (f"@{version}" if version and "~" not in version else ""))
            cpe = emb.cpe or (rule.cpe_with_version(version) if rule
                              else _spliced(known[1], version) if known else None)
            if exact and version:
                identity = version_conf = BINARY_METADATA
            elif emb.method in WEAK_DEPENDENCY_METHODS:
                identity, version_conf = BINARY_IMPORT_IDENTITY, 0.0
            elif emb.method == "deps-json":
                identity = version_conf = BINARY_SIDECAR
            elif emb.method == "dotnet-assembly":
                identity = version_conf = BINARY_ASSEMBLY
            elif emb.method == "file-name" and version:
                identity, version_conf = BINARY_IDENTITY, BINARY_FILE_NAME
            elif version:
                identity, version_conf = BINARY_IDENTITY, BINARY_VERSION
            else:
                identity, version_conf = BINARY_SYMBOLS_IDENTITY, 0.0
            out.append(Finding(
                directory=blob.path,
                rule_id=f"binary/{emb.name}",
                upstream_name=rule.upstream_name if rule else emb.display_name,
                purl=purl, cpe=cpe,
                homepage=rule.homepage if rule else None,
                declared_license=rule.license if rule else None,
                version=version,
                version_source=("binary-metadata" if exact else
                                "binary-sidecar" if emb.method == "deps-json" else
                                "binary-version-info" if emb.method == "version-info" else
                                "binary-file-name" if emb.method == "file-name" else
                                "binary-string" if version else "unknown"),
                identity_confidence=identity,
                version_confidence=version_conf,
                vendor_patched=emb.modified,
                patch_hint="go.mod replace directive" if emb.modified else None,
                supplier=rule.supplier if rule else None,
                evidence=[Evidence(
                    technique=Technique.OTHER,
                    confidence=identity,
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
    ignored = 0
    by_dir = {f.directory: f for f in findings}
    out = list(findings)
    for decl in declarations:
        if decl.directory is None:
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
        if _is_sample_of_component(rel, findings):
            ignored += 1
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
    if ignored:
        notes.append(f"{ignored} declaration(s) under example, test or doc "
                     "directories of an identified component were not reported "
                     "as components of their own: they describe how that "
                     "component is demonstrated, not what this firmware ships")
    return out, notes


# Directories that hold a component's demonstrations rather than its product.
_NON_SHIPPING = frozenset({"example", "examples", "sample", "samples", "demo",
                           "demos", "test", "tests", "doc", "docs"})


def _is_sample_of_component(rel: str, findings: List[Finding]) -> bool:
    """Is *rel* an example or test directory inside an identified component?

    nanopb's tree carries a ``conanfile.py`` and a ``platformio.ini`` under
    ``examples/``; reading them as dependencies of the firmware reported nanopb
    a second time, at a different version, under a path that is not shipped.
    Only a directory inside a component the scan already identified qualifies,
    so a project's own ``examples`` folder is still read.
    """
    for f in findings:
        if f.directory in (".", "") or rel == f.directory \
                or not rel.startswith(f.directory.rstrip("/") + "/"):
            continue
        inside = rel[len(f.directory.rstrip("/")) + 1:].split("/")
        if any(part.lower() in _NON_SHIPPING for part in inside):
            return True
    return False


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
    parts = split_cpe(cpe)
    if version and "~" not in version and len(parts) > 5:
        parts[5] = escape_value(version)
    return join_cpe(parts)


def _declaration_summary(decl: Declaration) -> str:
    what = decl.name + (f" {decl.version}" if decl.version else "")
    if decl.ecosystem == "vendor-sdk":
        return (f"{decl.source} states {what}, released by {decl.supplier}; the "
                "vendor's own HAL and drivers in this tree belong to this release")
    if decl.ecosystem in ("buildroot", "openwrt"):
        return (f"{decl.ecosystem} package {what} is selected in {decl.source}; "
                "the recipe pins this upstream version")
    if decl.ecosystem in ("dpkg", "opkg", "apk"):
        return (decl.description if decl.description and not decl.version_is_upstream
                else f"{decl.ecosystem} package {what} is installed per {decl.source}")
    if decl.ecosystem == "yocto":
        return (f"Yocto: {decl.source} lists {what}"
                + (f" ({decl.description})" if decl.description else ""))
    if decl.ecosystem in ("conan", "bazel", "cmake", "vcpkg", "meson", "cargo"):
        return (decl.description if decl.description and not decl.version
                else f"{decl.ecosystem} dependency {what} declared in {decl.source}")
    if decl.ecosystem in ("stm32cube", "cmsis-pack"):
        return (decl.description if decl.description and not decl.version
                else f"{decl.supplier} package {what} states its own release in {decl.source}")
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


def _explains(inner: Finding, outer: Finding) -> bool:
    """Does the nested claim say everything the enclosing one does?

    Identity must be at least as strong. The version must be the same one (or
    the enclosing claim has none): which evidence produced it is not a reason to
    keep the parent, or a probe at 0.85 loses to a function match at 0.88 for
    the very same release. Where the versions differ, the more confident claim
    wins, so an exact release at the root is not traded for an inner range.
    """
    if inner.identity_confidence < outer.identity_confidence:
        return False
    if outer.version is None or inner.version == outer.version:
        return True
    return inner.confidence >= outer.confidence


def _drop_shadowing_ancestors(candidates: List[Finding]) -> List[Finding]:
    """Remove a claim made at a parent directory that a child already explains.

    Function containment looks at everything under a directory, so a component
    that lives in ``os/components/dfs/elmfat`` also fires, as strongly, at ``os``
    and at every directory between. ``resolve`` keeps one winner per directory,
    so that second claim used to take ``os`` away from the RT-Thread kernel that
    owns it, and the later duplicate pass then removed the correct, deeper
    location. The claim is dropped per candidate, before resolving, and only
    when the descendant is at least as confident, version included: a weaker
    nested match (Mbed TLS's ``tf-psa-crypto``) never displaces the real root,
    and a root that pins an exact release is not traded for an inner range.
    """
    by_name: dict = {}
    for finding in candidates:
        by_name.setdefault(finding.upstream_name, []).append(finding)
    shadowed = set()
    for group in by_name.values():
        if len(group) < 2:
            continue
        for outer in group:
            prefix = outer.directory.rstrip("/") + "/"
            for inner in group:
                if (inner is not outer and inner.directory != outer.directory
                        and (outer.directory in (".", "")
                             or inner.directory.startswith(prefix))
                        and _explains(inner, outer)):
                    shadowed.add(id(outer))
                    break
    return [f for f in candidates if id(f) not in shadowed]


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
