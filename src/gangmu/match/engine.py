"""The identification engine.

Three tiers, strongest first.  They do *not* short-circuit each other wholesale:
identity and version are decided separately, because a vendor fork routinely has
an obvious identity and an unknowable version.

    tier 1  anchor hashes       exact, pins identity *and* version
    tier 2  MinHash similarity  identity only -- see the calibration note
    tier 3  version probes      version only
    (plus)  vendor manifests    identity and version, when the vendor declares them
    (plus)  path and name       a nudge, never a decision

Calibration note
----------------
Measured on real trees:

    upstream lwIP 2.2.0  vs  upstream 2.2.2          0.984
    upstream lwIP 2.2.0  vs  Espressif's fork        0.945
    upstream lwIP 2.2.0  vs  upstream 2.1.3          0.859
    upstream lwIP 2.2.0  vs  cJSON                   0.000

A vendor fork and a neighbouring upstream release land close enough together
that similarity cannot tell them apart.  That is precisely why version never
comes from similarity alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..analysis import AnalysisStore
from ..dirprint import (DEFAULT_EXCLUDE, DEFAULT_INCLUDE, DirectoryPrint,
                        SketchCache, print_directory, print_from_store, sha256_file)
from ..fingerprint import DEFAULT_K as DEFAULT_K_FALLBACK
from ..fingerprint import DEFAULT_WINDOW as DEFAULT_WINDOW_FALLBACK
from ..fnsig import infer_version, infer_version_subset, intersects
from ..globbing import matches_suffix
from ..manifest import ManifestFacts, read_manifest
from ..model import Evidence, Finding, Technique
from ..rules.loader import RuleBase
from ..rules.schema import Rule

VERSION_CONFIDENCE = {
    "anchor": 0.98,
    "manifest": 0.90,
    "probe": 0.85,
    "functions": 0.88,
    "signature-reference": 0.70,
}

# A partial copy (``functions.subset``) is accepted when at least this many of its
# functions are the component's and at least this share of its functions are.
SUBSET_MIN_FUNCTIONS = 40
SUBSET_MIN_SHARE = 0.90
SUBSET_IDENTITY = 0.75      # below a full copy: most of the component is not here
# A modified derivative (``functions.derivative``): at least this many of the
# directory's functions, and at least this share of them, are byte-identical to
# some recorded release. Weaker than a partial copy, so it is reported at the
# weak band's confidence, as a fork, with no version.
DERIVATIVE_MIN_FUNCTIONS = 300
DERIVATIVE_MIN_SHARE = 0.30
DERIVATIVE_IDENTITY = 0.50


class PrintCache:
    """One DirectoryPrint per (directory, include, exclude, k, window).

    Several rules routinely look at the same directory with the same globs; the
    expensive half of a DirectoryPrint is lazy, so sharing the object means the
    tokenising happens at most once even when five rules ask for it.
    """

    def __init__(self, jobs: int = 1, disk: Optional[SketchCache] = None,
                 store: Optional[AnalysisStore] = None) -> None:
        self._cache: Dict[Tuple[str, Tuple[str, ...], Tuple[str, ...], int, int],
                          DirectoryPrint] = {}
        self.jobs = jobs
        self.disk = disk
        self.store = store

    def get(self, directory: Path, include: Sequence[str], exclude: Sequence[str],
            k: int, window: int) -> DirectoryPrint:
        key = (str(directory), tuple(include), tuple(exclude), k, window)
        if key not in self._cache:
            if self.store is not None and (k, window) == (self.store.k,
                                                          self.store.window):
                self._cache[key] = print_from_store(self.store, directory, include,
                                                    exclude, k, window)
            else:
                self._cache[key] = print_directory(directory, include, exclude, k,
                                                   window, jobs=self.jobs,
                                                   cache=self.disk)
        return self._cache[key]

    def release(self, directory: Path) -> None:
        """Forget a directory's prints once it has been matched."""
        prefix = str(directory)
        for key in [key for key in self._cache if key[0] == prefix]:
            del self._cache[key]


@dataclass
class MatchEngine:
    rulebase: RuleBase
    cache: PrintCache = field(default_factory=PrintCache)
    min_confidence: float = 0.35
    segment: bool = True
    prefilter: bool = True
    _segmented: bool = field(default=False, repr=False)
    _fn_index: Optional[Dict[str, Tuple[List[int], List[int]]]] = field(
        default=None, repr=False)
    _sketch_index: Optional[Dict[str, frozenset]] = field(default=None, repr=False)
    stats: Dict[str, int] = field(default_factory=lambda: {
        "rule_checks": 0, "rule_checks_skipped": 0}, repr=False)

    def __post_init__(self) -> None:
        if self.segment:
            self.segment_rule_base()
        if self.prefilter:
            self._build_index()

    # ------------------------------------------------------------ indexing

    def _build_index(self) -> None:
        """Per-rule evidence sets, so a rule that shares nothing with a
        directory is skipped without running it.

        A rule can only fire on a directory through a function it records, a
        sketch value it shares, an anchor file, or a byte-identical file set.
        Testing the first two is a disjointness check against the rule's sorted
        hash list (``fnsig.intersects``), which costs about the size of the
        smaller side rather than a full tiered match. Neither a global
        hash-to-rule index nor a set per rule is held in memory: at a few
        hundred rules either cost more than the scan itself. Rules that could
        fire some other way (an anchor file that exists, a zero floor) are never
        filtered.
        """
        fn: Dict[str, Tuple[List[int], List[int]]] = {}
        sk: Dict[str, frozenset] = {}
        for rule in self.rulebase:
            if rule.functions is not None:
                try:
                    signature = rule.functions.load()
                except Exception:                       # noqa: BLE001
                    signature = None
                if signature is not None:
                    fn[rule.id] = (signature.ordered_hashes,
                                   signature.ordered_abstract)
            if rule.signature is not None:
                sk[rule.id] = frozenset(rule.signature.signature.values)
        self._fn_index = fn
        self._sketch_index = sk

    def _always_checked(self, directory: Path, rule: Rule) -> bool:
        # An anchor can only fire through a file that exists.
        if any((directory / anchor.path).is_file() for anchor in rule.anchors):
            return True
        if rule.functions is not None and rule.functions.thresholds["floor"] <= 0:
            return True
        if rule.signature is not None and rule.thresholds["floor"] <= 0:
            return True
        return False

    def _could_fire(self, directory: Path, rule: Rule) -> bool:
        if self._fn_index is None or self._always_checked(directory, rule):
            return True
        include = rule.include or DEFAULT_INCLUDE
        exclude = rule.exclude or DEFAULT_EXCLUDE
        dp = self.cache.get(directory, include, exclude, spec_k(rule),
                            spec_window(rule))
        if rule.functions is not None:
            sets = self._fn_index.get(rule.id)
            if sets is not None and (intersects(dp.functions, sets[0])
                                     or intersects(dp.abstract_functions, sets[1])):
                return True
        if rule.signature is not None:
            spec = rule.signature
            if spec.fileset_sha256 and dp.fileset_sha256 == spec.fileset_sha256:
                return True
            values = self._sketch_index.get(rule.id) if self._sketch_index else None
            if values is None:
                return True
            sketch = dp.signature(spec.signature.k, spec.signature.window,
                                  spec.signature.size)
            if not values.isdisjoint(sketch.values):
                return True
        return False

    def forget(self, directory: Path) -> None:
        """Drop everything held for a directory that has been matched."""
        self.cache.release(directory)

    def prefetch(self, directories: Sequence[Path]) -> None:
        """Hash and analyse every file the scan will need, in one batch.

        With a process pool, one batch over the whole scan keeps every worker
        busy; directory by directory, the many small components each ran
        serially below the parallel threshold. Only files a rule would analyse
        anyway are included: a sketch rule whose recorded file set matches the
        directory byte for byte never needs its files tokenised.
        """
        store = self.cache.store
        if store is None:
            return
        groups: Dict[Tuple, List[Rule]] = {}
        for rule in self.rulebase:
            key = (tuple(rule.include or DEFAULT_INCLUDE),
                   tuple(rule.exclude or DEFAULT_EXCLUDE),
                   spec_k(rule), spec_window(rule))
            groups.setdefault(key, []).append(rule)
        wanted: List[str] = []
        for directory in directories:
            for (include, exclude, k, window), rules in groups.items():
                dp = self.cache.get(directory, include, exclude, k, window)
                if dp.store is None:
                    continue
                if any(r.functions is not None or (
                        r.signature is not None and not (
                            r.signature.fileset_sha256
                            and r.signature.fileset_sha256 == dp.fileset_sha256))
                       for r in rules):
                    wanted.extend(dp.rels)
        store.ensure(wanted)

    def segment_rule_base(self) -> int:
        """CENTRIS code segmentation, applied across the loaded rules.

        If component A vendors component B, B's functions are present in A, and
        detecting B in a firmware would also "detect" A. CENTRIS removes such
        borrowed code from A's signature before matching.

        The direction of borrowing cannot be read off the signatures alone, so
        this takes the conservative symmetric form: **a function that appears in
        more than one rule is application code for none of them.** That is
        weaker than CENTRIS -- it also discards genuinely shared algorithmic
        code, costing a little recall -- but it cannot invent a dependency that
        is not there, and a false component in an SBOM is the costlier error.
        """
        if self._segmented:
            return 0
        self._segmented = True
        specs = []
        counted = []          # (family, signature), one per distinct sidecar
        seen = set()
        for rule in self.rulebase:
            if rule.functions is None:
                continue
            # Rules for one component in different directory layouts point at
            # the same sidecar (by content); that is one signature, not shared code.
            try:
                signature = rule.functions.load()
            except Exception:                           # noqa: BLE001
                continue
            specs.append((rule, signature))
            key = rule.functions.sha256
            if key not in seen:
                seen.add(key)
                counted.append((rule.functions.family, signature))
        # Rules of one family (sibling ports of a code base) count as one
        # contributor: what they share is the family's own code.
        families: dict = {}
        contributors = []     # (exact hashes, abstract hashes) per contributor
        for family, sig in counted:
            if not family:
                contributors.append((sig.hashes, set(sig.abstract_hashes)))
                continue
            exact, abstract = families.setdefault(family, (set(), set()))
            exact.update(sig.hashes)
            abstract.update(sig.abstract_hashes)
        contributors.extend(families.values())
        # A signature's hashes are distinct within it, so "in more than one
        # rule" is "repeated in the concatenation". Sorting one flat list and
        # comparing neighbours needs a fraction of the memory a counting dict
        # does, which matters once the rule base runs to hundreds of rules.
        shared = _repeated(h for exact, _ in contributors for h in exact)
        abstract_shared = _repeated(h for _, abstract in contributors
                                    for h in abstract)
        marked = 0
        for _, signature in specs:
            if shared:
                marked += signature.segment(shared)
            if abstract_shared:
                marked += signature.segment_abstract(abstract_shared)
        return marked

    def identify_directory(self, root: Path, directory: Path) -> List[Finding]:
        """Every rule that plausibly fires on this directory, unranked."""
        rel = directory.relative_to(root).as_posix() or "."
        manifest = read_manifest(directory)
        out: List[Finding] = []
        for rule in self.rulebase.for_directory(rel, directory.name):
            if self.prefilter and not self._could_fire(directory, rule):
                self.stats["rule_checks_skipped"] += 1
                continue
            self.stats["rule_checks"] += 1
            finding = self._apply(root, directory, rel, rule, manifest)
            if finding and finding.identity_confidence >= self.min_confidence:
                out.append(finding)
        return out

    # ---------------------------------------------------------------- tiers

    def _apply(self, root: Path, directory: Path, rel: str, rule: Rule,
               manifest: Optional[ManifestFacts]) -> Optional[Finding]:
        evidence: List[Evidence] = []
        identity = 0.0
        version: Optional[str] = None
        version_source: Optional[str] = None

        # --- tier 1: anchor hashes -------------------------------------
        anchor_hit = self._check_anchors(directory, rule, evidence)
        if anchor_hit:
            identity = max(identity, 0.98)
            version, version_source = anchor_hit, "anchor"

        # --- tier 2a: function containment (preferred) ------------------
        # CENTRIS: a component is identified by how much of its own application
        # code is present, not by how similar two trees look overall. TIVER: the
        # versions those functions come from give a range, not a point.
        version_range = None
        if rule.functions is not None:
            outcome = self._by_functions(directory, rule, rel, evidence)
            if outcome is not None:
                fn_identity, fn_version, version_range = outcome
                identity = max(identity, fn_identity)
                if fn_version and version_source != "anchor":
                    version, version_source = fn_version, "functions"

        # --- tier 2b: whole-tree similarity (fallback) ------------------
        similarity = None
        exact_copy = None
        if rule.signature is not None and (rule.functions is None or identity == 0.0):
            similarity, exact_copy = self._similarity(directory, rule)
            band_conf, band_name = _band(similarity, rule.thresholds)
            if band_conf:
                identity = max(identity, band_conf)
                evidence.append(Evidence(
                    technique=Technique.AST_FINGERPRINT,
                    confidence=band_conf,
                    summary=(f"winnowed MinHash similarity {similarity:.3f} to "
                             f"{rule.upstream_name}"
                             + (f" {rule.signature.reference_version}"
                                if rule.signature.reference_version else "")
                             + f" ({band_name})"),
                    locator=rel,
                ))
                if (version is None and band_name == "exact"
                        and rule.signature.reference_version):
                    version = rule.signature.reference_version
                    version_source = "signature-reference"
            if exact_copy is True:
                identity = max(identity, 0.98)
                evidence.append(Evidence(
                    technique=Technique.HASH_COMPARISON,
                    confidence=0.98,
                    summary=(f"every file matches the reference release "
                             f"byte for byte"),
                    locator=rel,
                ))

        # --- an anchor is evidence about a FILE, the sketch about the TREE --
        # Two forks of the same upstream often share a file byte for byte, so an
        # anchor can match a directory that is not this component at all. When
        # the two disagree the tree wins: a single shared header is much weaker
        # evidence than the shape of several hundred files.
        if anchor_hit and similarity is not None:
            if similarity < rule.thresholds["floor"]:
                return None
            if similarity < rule.thresholds["weak"]:
                identity = min(identity, 0.50)
                version, version_source = None, None
                evidence.append(Evidence(
                    technique=Technique.OTHER,
                    confidence=0.5,
                    summary=(f"an anchor file matched but the directory as a whole "
                             f"is only {similarity:.3f} similar to "
                             f"{rule.upstream_name}: the file is probably shared "
                             f"with another fork rather than this being that "
                             f"component"),
                    locator=rel))

        # --- tier 3: version probes ------------------------------------
        if identity > 0.0:
            probed = self._probe_version(directory, rule, evidence, rel)
            if probed and version_source != "anchor":
                version, version_source = probed, "probe"

        # --- vendor manifest -------------------------------------------
        if manifest and identity > 0.0:
            if manifest.version and version_source in (None, "signature-reference"):
                version, version_source = manifest.version, "manifest"
            if manifest.version or manifest.name:
                evidence.append(Evidence(
                    technique=Technique.MANIFEST_ANALYSIS,
                    confidence=VERSION_CONFIDENCE["manifest"],
                    summary=(f"vendor manifest declares "
                             f"{manifest.name or rule.upstream_name}"
                             + (f" {manifest.version}" if manifest.version else "")),
                    locator=f"{rel}/{manifest.source}",
                ))

        if identity <= 0.0:
            return None

        # --- path and name: a nudge, not a decision --------------------
        path_match = 0
        if rule.path_globs and matches_suffix(rel, rule.path_globs):
            path_match = 2
        elif rule.ships_as and Path(directory).name == rule.ships_as:
            path_match = 1
        if path_match:
            identity = min(identity + 0.02, 1.0)
            evidence.append(Evidence(
                technique=Technique.FILENAME,
                confidence=0.3,
                summary=(f"directory sits where rule {rule.id} expects it"
                         if path_match == 2 else
                         f"directory is named as rule {rule.id} expects, but is "
                         f"not where that rule says the component lives"),
                locator=rel,
            ))

        identity = min(identity, rule.confidence_ceiling)
        version_conf = VERSION_CONFIDENCE.get(version_source or "", 0.0)

        # A rule for one vendor's copy that fires outside the place it says that
        # copy lives (another SDK's tree) still tells us which upstream this is, but
        # not who supplied *this* directory: do not hand it that vendor's name.
        foreign = bool(rule.vendor and rule.path_globs and path_match != 2)
        if foreign:
            evidence.append(Evidence(
                technique=Technique.OTHER,
                confidence=0.0,
                summary=(f"rule {rule.id} describes {rule.vendor}'s copy and this "
                         f"directory is not where that rule says it lives (a matching name alone is not it), so the "
                         f"supplier is not asserted"),
                locator=rel))

        return Finding(
            directory=rel,
            rule_id=rule.id,
            upstream_name=rule.upstream_name,
            purl=rule.purl_with_version(version),
            cpe=rule.cpe_with_version(version),
            homepage=rule.homepage,
            declared_license=rule.license,
            version=version,
            version_source=version_source,
            identity_confidence=round(identity, 3),
            version_confidence=round(min(version_conf, identity), 3),
            vendor_patched=_is_patched(rule, exact_copy, version,
                                       version_range),
            vendor_name=None if foreign else rule.vendor,
            supplier=None if foreign else rule.supplier,
            renamed_from=(rule.ships_as if rule.ships_as
                          and rule.ships_as.lower() != rule.upstream_name.lower()
                          else None),
            patch_hint=None if foreign else rule.fork_note,
            fork_url=rule.fork_url,
            evidence=evidence,
            path_match=path_match,
            advisory_scope=rule.advisory_scope,
            content_hash=self._content_hash(directory, rule),
        )

    def _check_anchors(self, directory: Path, rule: Rule,
                       evidence: List[Evidence]) -> Optional[str]:
        for anchor in rule.anchors:
            path = directory / anchor.path
            if not path.is_file():
                continue
            try:
                digest = sha256_file(path)
            except OSError:
                continue
            for ver, expected in anchor.sha256.items():
                if digest == expected:
                    evidence.append(Evidence(
                        technique=Technique.HASH_COMPARISON,
                        confidence=VERSION_CONFIDENCE["anchor"],
                        summary=(f"{anchor.path} matches, byte for byte, the hash "
                                 f"rule {rule.id} records for "
                                 f"{rule.upstream_name} {ver}"),
                        locator=f"{directory.name}/{anchor.path}",
                    ))
                    return ver
        return None

    def _content_hash(self, directory: Path, rule: Rule) -> Optional[str]:
        include = rule.include or DEFAULT_INCLUDE
        exclude = rule.exclude or DEFAULT_EXCLUDE
        try:
            return self.cache.get(directory, include, exclude,
                                  spec_k(rule), spec_window(rule)).fileset_sha256
        except OSError:
            return None

    def _by_functions(self, directory: Path, rule: Rule, rel: str,
                      evidence: List[Evidence]):
        """Containment of the component's application code, plus its version."""
        spec = rule.functions
        assert spec is not None
        try:
            signature = spec.load()
        except Exception as exc:                      # noqa: BLE001
            evidence.append(Evidence(
                technique=Technique.OTHER, confidence=0.0,
                summary=f"function signature unusable: {exc}", locator=rel))
            return None

        include = rule.include or DEFAULT_INCLUDE
        exclude = rule.exclude or DEFAULT_EXCLUDE
        candidate = self.cache.get(directory, include, exclude,
                                   spec_k(rule), spec_window(rule))
        present = candidate.functions
        if not present:
            return None

        verdict = infer_version(signature, present)
        own = (signature.version_application_hashes(verdict.best_index)
               if verdict.best_index >= 0 else signature.application_hashes)
        if not own:
            return None
        containment = len(present & own) / len(own)
        matched = len(present & own)

        # A vendor who renames symbols -- prefixing a whole library with their
        # own tag is routine -- defeats exact hashing: renaming a tenth of the
        # identifiers was measured to take containment from 1.00 to 0.48. Fall
        # back to the abstracted bodies, which survive renaming, and score the
        # result lower because abstraction also discards real evidence.
        abstracted = False
        bands = spec.thresholds
        if containment < bands["strong"] and signature.abstract_hashes:
            own_abs = (signature.version_abstract_hashes(verdict.best_index)
                       if verdict.best_index >= 0 else set())
            if own_abs:
                abstract_present = candidate.abstract_functions
                abstract_containment = len(abstract_present & own_abs) / len(own_abs)
                if abstract_containment > containment:
                    containment = abstract_containment
                    matched = len(abstract_present & own_abs)
                    own = own_abs
                    abstracted = True

        if spec.subset and containment < bands["strong"]:
            # Not all of the release is here. For a partial copy, containment
            # per release prefers the smallest, oldest release (the same
            # functions are a larger share of it), so the version is taken from
            # the reverse measure instead: the releases that hold every function
            # that is here. A directory too small or too foreign for that falls
            # through to the bands below.
            partial = self._by_subset(signature, present, rel, evidence)
            if partial is not None:
                return partial

        if containment >= bands["strong"]:
            identity = 0.90 if abstracted else 0.95
            band = "strong"
        elif containment >= bands["partial"]:
            identity = 0.75 if abstracted else 0.80
            band = "partial"
        elif containment >= bands["floor"]:
            identity = 0.50
            band = "weak -- needs review"
        else:
            if spec.derivative:
                return self._by_derivative(signature, present, rule, rel, evidence)
            return None

        evidence.append(Evidence(
            technique=Technique.AST_FINGERPRINT,
            confidence=identity,
            summary=(f"{matched} of {len(own)} "
                     + ("identifier-abstracted " if abstracted else "")
                     + f"functions of {rule.upstream_name} "
                       f"{verdict.best or '?'} are present "
                       f"({containment:.3f} containment, {band}); "
                       f"{len(present)} functions in this directory"
                     + ("; the exact bodies did not match, so symbols here have "
                        "been renamed" if abstracted else "")),
            locator=rel))
        if verdict.best:
            evidence.append(Evidence(
                technique=Technique.SOURCE_CODE_ANALYSIS,
                confidence=VERSION_CONFIDENCE["functions"],
                summary=verdict.detail,
                locator=rel))
        return identity, (verdict.label if verdict.best else None), verdict

    def _by_subset(self, signature, present, rel: str, evidence: List[Evidence]):
        """A directory holding only part of a component, as SDK packages ship it.

        Containment (how much of the release is here) cannot reach the floor for
        such a copy. The reverse measure can: how much of what is here comes from
        the component. It is asserted only for rules that opt in, and only when
        enough functions are involved for a coincidence to be implausible and
        nearly all of the directory's own functions are the component's.
        """
        matched = present & signature.hash_set
        if len(matched) < SUBSET_MIN_FUNCTIONS:
            return None
        share = len(matched) / len(present)
        if share < SUBSET_MIN_SHARE:
            return None
        verdict = infer_version_subset(signature, present)
        if not verdict.best:
            return None
        evidence.append(Evidence(
            technique=Technique.AST_FINGERPRINT,
            confidence=SUBSET_IDENTITY,
            summary=(f"partial copy: {len(matched)} of this directory's "
                     f"{len(present)} functions ({share:.0%}) are the component's, "
                     f"identical to a recorded release"),
            locator=rel))
        evidence.append(Evidence(
            technique=Technique.SOURCE_CODE_ANALYSIS,
            confidence=VERSION_CONFIDENCE["functions"],
            summary=verdict.detail, locator=rel))
        return SUBSET_IDENTITY, verdict.label, verdict

    def _by_derivative(self, signature, present, rule: Rule, rel: str,
                       evidence: List[Evidence]):
        """A directory that is a trimmed, rewritten port of the component.

        Too little of any release is present for containment, and too much of the
        directory is the vendor's own for ``_by_subset``'s 90% share, but a few
        hundred functions byte-identical to recorded releases are not a
        coincidence. Reported as a modified derivative: weak identity, no version
        (the identical functions come from several releases and the rest are the
        vendor's), so the advisory matcher can only report this product's
        advisories as ``in_triage``, never as exploitable.
        """
        matched = present & signature.hash_set
        if len(matched) < DERIVATIVE_MIN_FUNCTIONS:
            return None
        share = len(matched) / len(present)
        if share < DERIVATIVE_MIN_SHARE:
            return None
        verdict = infer_version_subset(signature, present)
        evidence.append(Evidence(
            technique=Technique.AST_FINGERPRINT,
            confidence=DERIVATIVE_IDENTITY,
            summary=(f"modified derivative of {rule.upstream_name}: "
                     f"{len(matched)} of this directory's {len(present)} functions "
                     f"({share:.0%}) are identical to recorded releases and the rest "
                     f"are not; the version is not asserted"
                     + (f" (identical functions span {verdict.low} to {verdict.high})"
                        if verdict.low and verdict.high else "")),
            locator=rel))
        return DERIVATIVE_IDENTITY, None, verdict

    def _similarity(self, directory: Path, rule: Rule):
        """Returns (similarity, exact_copy) where exact_copy may be None."""
        spec = rule.signature
        assert spec is not None
        include = rule.include or DEFAULT_INCLUDE
        exclude = rule.exclude or DEFAULT_EXCLUDE
        candidate = self.cache.get(directory, include, exclude,
                                   spec.signature.k, spec.signature.window)
        exact = (candidate.fileset_sha256 == spec.fileset_sha256
                 if spec.fileset_sha256 else None)
        if exact:
            # Byte-identical to the release the rule records. Tokenising it to
            # rediscover that would be the single most wasteful thing this tool
            # could do, and in a real SDK most copies land here.
            return 1.0, True
        sig = candidate.signature(spec.signature.k, spec.signature.window,
                                  spec.signature.size)
        if not sig.values:
            return 0.0, exact
        return sig.similarity(spec.signature), exact

    def _probe_version(self, directory: Path, rule: Rule,
                       evidence: List[Evidence], rel: str) -> Optional[str]:
        for probe in rule.probes:
            path = directory / probe.file
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            value = probe.apply(text)
            if value:
                evidence.append(Evidence(
                    technique=Technique.SOURCE_CODE_ANALYSIS,
                    confidence=VERSION_CONFIDENCE["probe"],
                    summary=f"version {value} read from {probe.file}",
                    locator=f"{rel}/{probe.file}",
                ))
                return value
        return None


def _repeated(values) -> set:
    ordered = list(values)
    if len(ordered) > 1_000_000:
        # A rule base this large is where numpy's sort pays for its import.
        from ..fingerprint import numpy_module
        np = numpy_module()
        if np is not None:
            arr = np.array(ordered, dtype=np.uint64)
            arr.sort()
            return set(arr[1:][arr[1:] == arr[:-1]].tolist())
    ordered.sort()
    return {a for a, b in zip(ordered, ordered[1:]) if a == b}


def spec_k(rule: Rule) -> int:
    return rule.signature.signature.k if rule.signature else DEFAULT_K_FALLBACK


def spec_window(rule: Rule) -> int:
    return rule.signature.signature.window if rule.signature else DEFAULT_WINDOW_FALLBACK


def _is_patched(rule: Rule, exact_copy, version, version_range=None) -> bool:
    """Does this copy differ from the release it claims to be?

    A rule may simply declare it (``vendor_fork.patched``). Function-level
    evidence answers it directly: a tree carrying functions from more than one
    recorded release, or functions no release explains, has been modified --
    and unlike a similarity score this is a statement about identified code, not
    about a distance. Only recorded functions that are *missing or altered* count:
    functions the signature never saw (headers, ports, vendor additions in files
    of their own) do not make a copy differ from the release, and counting them
    flagged pristine upstream trees as forks and demoted their advisories.
    """
    if rule.patched:
        return True
    if version_range is not None and version_range.changed > 0:
        return True
    if exact_copy is False and rule.signature is not None:
        reference = rule.signature.reference_version
        if reference is not None and version == reference:
            return True
    return False


def _band(similarity: float, thresholds: Dict[str, float]) -> Tuple[float, str]:
    """Map a similarity onto an identity confidence and a human-readable band."""
    if similarity >= thresholds["exact"]:
        return 0.95, "exact"
    if similarity >= thresholds["strong"]:
        return 0.90, "strong"
    if similarity >= thresholds["weak"]:
        return 0.75, "partial"
    if similarity >= thresholds["floor"]:
        return 0.50, "weak -- needs review"
    return 0.0, "no match"
