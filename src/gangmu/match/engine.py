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

import operator
from collections import Counter
from dataclasses import dataclass, field, replace
from itertools import chain, compress, islice
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Sequence, Tuple

from ..analysis import AnalysisStore
from ..dirprint import (DEFAULT_EXCLUDE, DEFAULT_INCLUDE, DirectoryPrint,
                        SketchCache, print_directory, print_from_store, sha256_file)
from ..fingerprint import DEFAULT_K as DEFAULT_K_FALLBACK
from ..fingerprint import DEFAULT_WINDOW as DEFAULT_WINDOW_FALLBACK
from ..fnsig import infer_version, infer_version_subset, intersects
from ..core.globbing import matches_suffix
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
    "anchor-shared": 0.88,      # a file several releases share: a span, not a point
}

# A partial copy (``functions.subset``) is accepted when at least this many of its
# functions are the component's and at least this share of its functions are.
# How much more of a release the identifier-abstracted bodies must cover before the
# copy is taken as renamed. The two measures have different denominators (bodies
# that differ only in names collapse to one abstract hash), so on an untouched copy
# the abstract one can come out a hair higher; a real rename moves it by tenths.
RENAMED_MARGIN = 0.05

SUBSET_MIN_FUNCTIONS = 40
# Identity given to a weak resemblance that also defines the component's version.
PROBE_CORROBORATED = 0.75
# Said in the evidence and the table when the best match is at the edge of the record.
EDGE_MARK = "this tree may be {side} than any release the rule records"
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
        # directory -> the only files its prints cover (see MatchEngine.identify_files)
        self._only: Dict[str, Tuple[str, ...]] = {}

    def get(self, directory: Path, include: Sequence[str], exclude: Sequence[str],
            k: int, window: int) -> DirectoryPrint:
        key = (str(directory), tuple(include), tuple(exclude), k, window)
        if key not in self._cache:
            only = self._only.get(str(directory))
            if self.store is not None and only is not None:
                self._cache[key] = print_from_store(self.store, directory, include,
                                                    exclude, k, window, only=only)
            elif self.store is not None and (k, window) == (self.store.k,
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

    def restrict(self, directory: Path, rels: Optional[Sequence[str]]) -> None:
        """Make the directory's prints cover only *rels* (root-relative), or, with
        None, all of it again. Needs a store; prints already held are dropped."""
        self.release(directory)
        if rels is None:
            self._only.pop(str(directory), None)
        else:
            self._only[str(directory)] = tuple(rels)


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
    _where: str = field(default="this directory", repr=False)   # what the evidence describes
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
            if sets is not None and not dp.functions:
                dp = self._function_print(directory, rule)[0]
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
            k, window, size = (spec.signature.k, spec.signature.window,
                               spec.signature.size)
            if dp.sketch_cannot_share(values, k, window, size):
                return False
            if not values.isdisjoint(dp.signature(k, window, size).values):
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

        The default is the conservative symmetric form: **a function that appears
        in more than one rule is application code for none of them.** It cannot
        invent a dependency that is not there, and a false component in an SBOM
        is the costlier error. But applied alone it strips a library that many
        projects bundle of its own identity: zlib, CMSIS-Core, littlefs and expat
        kept a few per cent of their functions or none, so a modified copy of
        them could only be found by anchor files, never by its code.

        So the one direction the signatures do show is taken: when B is bundled
        in A -- nearly all of one B release is inside A (``BUNDLED_SHARE``) and
        that is a small part of A (``BUNDLE_HOST_SHARE``) -- the shared functions
        are borrowed by A and stay B's own. A function stays B's only when every
        other rule holding it bundles B; anything else (forks such as OpenSSL
        and Tongsuo, a library split out of another such as Mbed TLS and Mbed
        Crypto, generic code many rules happen to share) is still nobody's.
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
                counted.append((rule.functions.family, signature, key))
        # Rules of one family (sibling ports of a code base) count as one
        # contributor: what they share is the family's own code.
        families: dict = {}
        contributors = []     # (exact hashes, abstract hashes, signatures) per contributor
        sidecars = []         # the sidecar digests each contributor stands for
        for family, sig, key in counted:
            if not family:
                contributors.append((sig.hashes, set(sig.abstract_hashes), [sig]))
                sidecars.append([key])
                continue
            if family not in families:
                families[family] = len(contributors)
                contributors.append((set(), set(), []))
                sidecars.append([])
            exact, abstract, members = contributors[families[family]]
            exact.update(sig.hashes)
            abstract.update(sig.abstract_hashes)
            members.append(sig)
            sidecars[families[family]].append(key)
        # A signature's hashes are distinct within it, so "in more than one
        # rule" is "repeated in the concatenation". Sorting one flat list and
        # comparing neighbours needs a fraction of the memory a counting dict
        # does, which matters once the rule base runs to hundreds of rules.
        shared = _repeated(chain.from_iterable(exact for exact, _, _ in contributors))
        abstract_shared = _repeated(chain.from_iterable(
            abstract for _, abstract, _ in contributors))
        keep_exact, keep_abstract = _bundled_keep(contributors, shared, abstract_shared)
        owner = {key: i for i, keys in enumerate(sidecars) for key in keys}
        marked = 0
        for rule, signature in specs:
            i = owner.get(rule.functions.sha256)
            if shared:
                kept = keep_exact.get(i) if i is not None else None
                marked += signature.segment(shared - kept if kept else shared)
            if abstract_shared:
                kept = keep_abstract.get(i) if i is not None else None
                marked += signature.segment_abstract(
                    abstract_shared - kept if kept else abstract_shared)
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

    def identify_files(self, root: Path, directory: Path, rels: Sequence[str],
                       rule: Rule, subset_min: int = SUBSET_MIN_FUNCTIONS
                       ) -> Optional[Finding]:
        """One rule against some of a directory's files: a component copied in
        among the project's own files, which no directory holds on its own.

        The tiers are those of a directory, applied to the files alone. A partial
        copy is accepted from *subset_min* functions on, which the caller lowers
        only when the files' own names corroborate the component.
        """
        if self.cache.store is None:
            return None
        rel = directory.relative_to(root).as_posix() or "."
        self.cache.restrict(directory, rels)
        self._where = "these files"
        try:
            self.stats["rule_checks"] += 1
            finding = self._apply(root, directory, rel, rule, None, subset_min)
        finally:
            self.cache.restrict(directory, None)
            self._where = "this directory"
        if finding is None or finding.identity_confidence < self.min_confidence:
            return None
        return finding

    # ---------------------------------------------------------------- tiers

    def _apply(self, root: Path, directory: Path, rel: str, rule: Rule,
               manifest: Optional[ManifestFacts],
               subset_min: int = SUBSET_MIN_FUNCTIONS) -> Optional[Finding]:
        evidence: List[Evidence] = []
        identity = 0.0
        version: Optional[str] = None
        version_source: Optional[str] = None

        # --- tier 1: anchor hashes -------------------------------------
        anchor_versions = self._check_anchors(directory, rule, evidence)
        anchor_hit = bool(anchor_versions)
        shared: List[str] = []
        if anchor_versions:
            identity = max(identity, 0.98)
            if len(anchor_versions) == 1:
                version, version_source = anchor_versions[0], "anchor"
            else:
                # Releases that ship the file unchanged cannot be told apart by
                # it. Pinning the first would report 1.4.3 for a 1.4.4 tree, so
                # the version is settled below by a probe or the functions, or
                # else reported as the span.
                shared = anchor_versions

        # --- tier 2a: function containment (preferred) ------------------
        # CENTRIS: a component is identified by how much of its own application
        # code is present, not by how similar two trees look overall. TIVER: the
        # versions those functions come from give a range, not a point.
        version_range = None
        if rule.functions is not None:
            outcome = self._by_functions(directory, rule, rel, evidence, subset_min)
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
                    summary=("every file matches the reference release "
                             "byte for byte"),
                    locator=rel,
                ))

        # --- an anchor is evidence about a FILE, the sketch about the TREE --
        # Two forks of the same upstream often share a file byte for byte, so an
        # anchor can match a directory that is not this component at all. When
        # the two disagree the tree wins: a single shared header is much weaker
        # evidence than the shape of several hundred files.
        demoted = False
        if anchor_hit and similarity is not None:
            if similarity < rule.thresholds["floor"]:
                return None
            if similarity < rule.thresholds["weak"]:
                demoted = True
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
            narrowed = (_narrow_range(rule, version, probed)
                        if probed and version_source == "functions" and version
                        else None)
            if narrowed:
                evidence.append(Evidence(
                    technique=Technique.SOURCE_CODE_ANALYSIS,
                    confidence=VERSION_CONFIDENCE["probe"],
                    summary=(f"the functions span {version}; the tree's own version "
                             f"definition says {probed}, which narrows it to "
                             f"{narrowed}"),
                    locator=rel))
                version = narrowed
            elif (probed and version_source == "functions" and version
                  and all(part.startswith(probed + ".")
                          for part in version.split("~"))):
                pass        # the functions already name the release more exactly
            elif probed and version_source != "anchor":
                version, version_source = probed, "probe"
            elif (probed and probed != version and version is not None
                  and not version.startswith("git-")
                  and not version.startswith(probed + ".")
                  and probed not in _recorded_versions(rule)):
                # An anchor says the files are those of a release, not that the
                # tree is that release: the next one may ship them unchanged. A
                # version definition naming a release the rule does not record is
                # news the anchor cannot contradict. (A definition that only gives
                # major.minor, like littlefs's 0x00020009, is a prefix of the anchor's
                # release, not a different one.)
                evidence.append(Evidence(
                    technique=Technique.SOURCE_CODE_ANALYSIS,
                    confidence=VERSION_CONFIDENCE["probe"],
                    summary=(f"the anchored files are those of {version}, but the "
                             f"tree's own version definition says {probed}, a "
                             f"release rule {rule.id} does not record"),
                    locator=rel))
                version, version_source = probed, "probe"
            if probed and not demoted and 0.0 < identity < PROBE_CORROBORATED:
                # What resembles the component only weakly (a vendor fork with most
                # of its functions rewritten) and also defines the component's own
                # version macro, which no other code does, is the component.
                identity = PROBE_CORROBORATED
                evidence.append(Evidence(
                    technique=Technique.SOURCE_CODE_ANALYSIS,
                    confidence=PROBE_CORROBORATED,
                    summary=(f"a weak resemblance to {rule.upstream_name} is "
                             f"corroborated by its version definition ({probed})"),
                    locator=rel))

        if shared and version_source != "manifest":
            if version not in shared:
                version, version_source = f"{shared[0]}~{shared[-1]}", "anchor-shared"
                version_range = None

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
                       evidence: List[Evidence]) -> List[str]:
        """Every release whose recorded hash the first matching anchor file has."""
        prefix = flat_prefix(rule)
        for anchor in rule.anchors:
            path = _locate(directory, anchor.path)
            if path is None and prefix and anchor.path.startswith(prefix + "/"):
                path = _locate(directory, anchor.path[len(prefix) + 1:])   # a flattened copy
            if path is None:
                continue
            try:
                digest = sha256_file(path)
            except OSError:
                continue
            versions = [ver for ver, expected in anchor.sha256.items()
                        if digest == expected]
            if versions:
                which = (versions[0] if len(versions) == 1 else
                         f"{versions[0]} to {versions[-1]} alike "
                         f"({len(versions)} releases ship it unchanged)")
                evidence.append(Evidence(
                    technique=Technique.HASH_COMPARISON,
                    confidence=VERSION_CONFIDENCE["anchor"],
                    summary=(f"{_shown(directory, path, anchor.path)} matches, byte "
                             f"for byte, the hash "
                             f"rule {rule.id} records for "
                             f"{rule.upstream_name} {which}"),
                    locator=f"{directory.name}/{_shown(directory, path, anchor.path)}",
                ))
                return versions
        return []

    def _content_hash(self, directory: Path, rule: Rule) -> Optional[str]:
        include = rule.include or DEFAULT_INCLUDE
        exclude = rule.exclude or DEFAULT_EXCLUDE
        try:
            return self.cache.get(directory, include, exclude,
                                  spec_k(rule), spec_window(rule)).fileset_sha256
        except OSError:
            return None

    def _function_print(self, directory: Path, rule: Rule) -> Tuple[DirectoryPrint, bool]:
        """The print the function tier reads, and whether it is of a flattened copy:
        when the rule's own globs select no function here and they all sit under one
        directory (``flat_prefix``), the same globs without it."""
        include = rule.include or DEFAULT_INCLUDE
        exclude = rule.exclude or DEFAULT_EXCLUDE
        k, window = spec_k(rule), spec_window(rule)
        dp = self.cache.get(directory, include, exclude, k, window)
        if dp.functions:
            return dp, False
        flat = flat_include(rule)
        if flat is None or (directory / (flat_prefix(rule) or "")).is_dir():
            return dp, False
        alt = self.cache.get(directory, flat, exclude, k, window)
        return (alt, True) if alt.functions else (dp, False)

    def _by_functions(self, directory: Path, rule: Rule, rel: str,
                      evidence: List[Evidence], subset_min: int = SUBSET_MIN_FUNCTIONS):
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

        candidate, flat = self._function_print(directory, rule)
        present = candidate.functions
        if not present:
            return None
        if flat:
            evidence.append(Evidence(
                technique=Technique.OTHER, confidence=0.0,
                summary=(f"a flattened copy: the contents of {rule.upstream_name}'s "
                         f"{flat_prefix(rule)}/ are here without the directory itself"),
                locator=rel))

        verdict = infer_version(signature, present)
        own = (signature.version_application_hashes(verdict.best_index)
               if verdict.best_index >= 0 else signature.application_hashes)
        if not own:
            return None
        containment = len(present & own) / len(own)
        matched = len(present & own)

        # A vendor who renames symbols -- prefixing a whole library with their
        # own tag is routine -- defeats exact hashing: renaming a tenth of the
        # identifiers was measured to take containment from 1.00 to 0.44. Fall
        # back to the abstracted bodies, which survive renaming, and score the
        # result lower because abstraction also discards real evidence.
        abstracted = False
        bands = spec.thresholds
        if containment < bands["strong"] and signature.abstract_hashes:
            abstract_present = candidate.abstract_functions

            def abstract_share(index: int):
                hashes = signature.version_abstract_hashes(index) if index >= 0 else set()
                return (len(abstract_present & hashes) / len(hashes) if hashes else 0.0,
                        hashes)

            # A cheap test first, against the release the exact bodies point to (or
            # the newest, when they point to none): most directories that fall short
            # of a strong match were not renamed, and only a renamed one pays for
            # reading the version a second time.
            gate = (verdict.best_index if verdict.best_index >= 0
                    else len(signature.versions) - 1)
            if abstract_share(gate)[0] >= containment + RENAMED_MARGIN:
                # The version is read from the abstracted bodies too: with names
                # changed, few exact bodies are left to vote and the range widens.
                abstract_verdict = infer_version(signature.abstract_view(), abstract_present)
                at = abstract_verdict.best_index if abstract_verdict.best_index >= 0 else gate
                abstract_containment, own_abs = abstract_share(at)
                if abstract_containment >= containment + RENAMED_MARGIN:
                    containment = abstract_containment
                    matched = len(abstract_present & own_abs)
                    own = own_abs
                    abstracted = True
                    if abstract_verdict.best:
                        verdict = replace(
                            abstract_verdict,
                            detail="over identifier-abstracted bodies: "
                                   + abstract_verdict.detail)

        if spec.subset and containment < bands["strong"]:
            # Not all of the release is here. For a partial copy, containment
            # per release prefers the smallest, oldest release (the same
            # functions are a larger share of it), so the version is taken from
            # the reverse measure instead: the releases that hold every function
            # that is here. A directory too small or too foreign for that falls
            # through to the bands below.
            partial = self._by_subset(signature, present, rel, evidence, subset_min)
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
                       f"{len(present)} functions in {self._where}"
                     + ("; the exact bodies did not match, so symbols here have "
                        "been renamed" if abstracted else "")),
            locator=rel))
        if verdict.best:
            evidence.append(Evidence(
                technique=Technique.SOURCE_CODE_ANALYSIS,
                confidence=VERSION_CONFIDENCE["functions"],
                summary=verdict.detail,
                locator=rel))
        if verdict.edge:
            side = "older" if verdict.edge == "oldest" else "newer"
            evidence.append(Evidence(
                technique=Technique.OTHER,
                confidence=0.0,
                summary=(f"{verdict.best} is the {verdict.edge} release rule {rule.id} "
                         f"records and {verdict.changed} of its functions are missing or "
                         f"altered: {EDGE_MARK.format(side=side)}"),
                locator=rel))
        return identity, (verdict.label if verdict.best else None), verdict

    def _by_subset(self, signature, present, rel: str, evidence: List[Evidence],
                   subset_min: int = SUBSET_MIN_FUNCTIONS):
        """A directory holding only part of a component, as SDK packages ship it.

        Containment (how much of the release is here) cannot reach the floor for
        such a copy. The reverse measure can: how much of what is here comes from
        the component. It is asserted only for rules that opt in, and only when
        enough functions are involved for a coincidence to be implausible and
        nearly all of the directory's own functions are the component's.

        Only the component's own code counts, as for containment: functions the
        segmentation found it shares with another rule (OP-TEE's bundled Mbed TLS)
        say nothing about this component, or a copy of the other one's headers
        reads as a partial copy of this one.
        """
        matched = present & signature.application_hashes
        if len(matched) < subset_min:
            return None
        share = len(matched) / len(present)
        if share < SUBSET_MIN_SHARE:
            return None
        verdict = infer_version_subset(signature, _without_borrowed(signature, present))
        if not verdict.best:
            return None
        evidence.append(Evidence(
            technique=Technique.AST_FINGERPRINT,
            confidence=SUBSET_IDENTITY,
            summary=(f"partial copy: {len(matched)} of the {len(present)} functions "
                     f"in {self._where} ({share:.0%}) are the component's, "
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
        advisories as ``in_triage``, never as exploitable. Borrowed code does not
        count, as in ``_by_subset``.
        """
        matched = present & signature.application_hashes
        if len(matched) < DERIVATIVE_MIN_FUNCTIONS:
            return None
        share = len(matched) / len(present)
        if share < DERIVATIVE_MIN_SHARE:
            return None
        verdict = infer_version_subset(signature, _without_borrowed(signature, present))
        evidence.append(Evidence(
            technique=Technique.AST_FINGERPRINT,
            confidence=DERIVATIVE_IDENTITY,
            summary=(f"modified derivative of {rule.upstream_name}: "
                     f"{len(matched)} of the {len(present)} functions in {self._where} "
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
        bases = [(directory, rel)]
        if directory.name.lower() in SOURCE_DIRECTORY_NAMES:
            # The component was found at its ``src``, with the header that names
            # the version beside it (LVGL's ``lvgl.h``, FreeRTOS's ``include/``).
            bases.append((directory.parent, str(PurePosixPath(rel).parent)))
        for probe in rule.probes:
            for base, where in bases:
                path = _locate(base, probe.file, by_name=True)
                if path is None:
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
                        locator=f"{where}/{probe.file}",
                    ))
                    return value
        return None


NESTED_LOOKUP_DEPTH = 2
SOURCE_DIRECTORY_NAMES = frozenset({"src", "source", "lib", "library"})
NAMED_LOOKUP_DEPTH = 4


def _narrow_range(rule: Rule, version: str, probed: str) -> Optional[str]:
    """The part of a ``low~high`` span a version definition leaves standing.

    A header that carries only major.minor (littlefs's ``LFS_VERSION`` is 2.10 for
    2.10.0 to 2.10.2) cannot name a release, but it can say which of the releases
    the functions span the tree belongs to.
    """
    if "~" not in version or rule.functions is None:
        return None
    low, _, high = version.partition("~")
    recorded = list(rule.functions.versions)
    if low not in recorded or high not in recorded:
        return None
    span = recorded[recorded.index(low):recorded.index(high) + 1]
    kept = [v for v in span if v == probed or v.startswith(probed + ".")]
    if not kept or len(kept) == len(span):
        return None
    return kept[0] if len(kept) == 1 else f"{kept[0]}~{kept[-1]}"


def _recorded_versions(rule: Rule) -> set:
    """Every release the rule has a hash or function set for."""
    out = {v for anchor in rule.anchors for v in anchor.sha256}
    if rule.functions is not None:
        out.update(rule.functions.versions)
    return out


def _shown(directory: Path, path: Path, recorded: str) -> str:
    """Where the file was found, relative to *directory*, else the recorded path."""
    try:
        return path.relative_to(directory).as_posix()
    except ValueError:
        return recorded


def flat_prefix(rule: Rule) -> Optional[str]:
    """The directory every include glob of *rule* sits under (``src`` for
    ``src/**/*.c``, ``src/**/*.h``), or ``None``.

    Vendors routinely copy only that directory's contents (aws-c-common's
    ``source/external/libcbor`` is libcbor's ``src/``; most products carry lwIP's
    ``src/`` as ``lwip/``), and the rule's globs then select nothing there."""
    if not rule.include:
        return None
    heads = set()
    for pattern in rule.include:
        head, sep, _ = pattern.partition("/")
        if not sep or any(c in head for c in "*?[") or head in (".", ".."):
            return None
        heads.add(head)
    return heads.pop() if len(heads) == 1 else None


def flat_include(rule: Rule) -> Optional[Tuple[str, ...]]:
    """*rule*'s include globs with ``flat_prefix`` taken off, for such a copy."""
    prefix = flat_prefix(rule)
    if prefix is None:
        return None
    return tuple(pattern[len(prefix) + 1:] for pattern in rule.include)


def _locate(directory: Path, relpath: str, by_name: bool = False) -> Optional[Path]:
    """The file a rule names, at its path or else one nested level or two below.

    A vendor that wraps a library in an extra directory (lwIP's ``core/`` in
    BTstack's copy, so ``core/src/include/lwip/init.h``) moves every path a rule
    records. The file is accepted from below only when exactly one candidate
    exists; two are ambiguous, and nothing is guessed.
    """
    path = directory / relpath
    if path.is_file():
        return path
    found = _unique_glob(directory, relpath, NESTED_LOOKUP_DEPTH)
    if found is None and by_name:
        found = _unique_glob(directory, Path(relpath).name, NAMED_LOOKUP_DEPTH, deep=True)
    return found


def _unique_glob(directory: Path, tail: str, depth: int, deep: bool = False) -> Optional[Path]:
    """The one file ``<directory>/<up to depth levels>/<tail>``, else ``None``."""
    found = []
    for level in range(1, depth + 1):
        pattern = "/".join(["*"] * level) + "/" + tail
        try:
            found += [p for p in directory.glob(pattern) if p.is_file()]
        except (OSError, ValueError):
            return None
        if found and not deep:
            break
    return found[0] if len(found) == 1 else None


# B is bundled in A when nearly all of one B release is inside A ...
BUNDLED_SHARE = 0.80
# ... and that is a small part of A. Mbed Crypto is 18% of Mbed TLS and Tongsuo far more
# of OpenSSL: lineage, not a bundled copy; zlib is under 5% of any project carrying it.
BUNDLE_HOST_SHARE = 0.10
# A function more rules than this share is generic code, not one project's copy of another.
BUNDLE_MAX_OWNERS = 16
# A recorded release smaller than this proves no bundling: the 5 to 60 functions some rules
# record for an early release fit inside an unrelated project by way of a shared helper.
BUNDLED_MIN_FUNCTIONS = 40
# ... nor does one far smaller than the rule's largest: a signature that recorded little of a
# release (Tasmota 15.x: 53 functions, against 974 for 9.4.0) holds mostly some third library,
# and two projects that bundle that library would look as if one bundled the other.
BUNDLED_MIN_OF_LARGEST = 0.5


def _bundled_keep(contributors, shared: set, abstract_shared: set):
    """{contributor: hashes it keeps as its own} for the bundled side of each bundle.

    A contributor keeps a shared hash only when every other contributor holding it
    bundles that contributor; see ``MatchEngine.segment_rule_base``."""
    owners: Dict[int, List[int]] = {}
    for i, (exact, _, _) in enumerate(contributors):
        for h in shared.intersection(exact):
            owners.setdefault(h, []).append(i)
    pair: Dict[Tuple[int, int], List[int]] = {}       # (a, b) -> the hashes they share
    for h, held in owners.items():
        if len(held) > BUNDLE_MAX_OWNERS:
            continue
        for a in held:
            for b in held:
                if a != b:
                    pair.setdefault((a, b), []).append(h)

    bundles: set = set()      # (host, bundled)
    for (a, b), common in pair.items():
        # Fewer shared functions than the smallest release that can prove bundling would
        # need: no release of B can be inside A. Most pairs end here, cheaply.
        if len(common) < BUNDLED_SHARE * BUNDLED_MIN_FUNCTIONS:
            continue
        if len(common) > BUNDLE_HOST_SHARE * len(contributors[a][0]):
            continue
        for sig in contributors[b][2]:
            sizes = _release_sizes(sig)
            floor = max(BUNDLED_MIN_FUNCTIONS, BUNDLED_MIN_OF_LARGEST * max(sizes, default=0))
            if len(common) < BUNDLED_SHARE * floor:
                continue        # not even a release of the smallest size that counts fits
            inside = _release_counts(sig, common)
            if any(size >= floor and inside[v] >= BUNDLED_SHARE * size
                   for v, size in enumerate(sizes)):
                bundles.add((a, b))
                break
    if not bundles:
        return {}, {}

    # Projects carrying part of a library some project bundles whole (freetype's and
    # libgit2's inflate, ATF's subset of zlib): the shared part is a small part of them.
    # Alone that proves nothing, as two projects carrying a third library look the same;
    # it counts only for a function a whole copy holds too (``keepers``).
    whole = {b for _, b in bundles}
    partial = {(a, b) for (a, b), common in pair.items()
               if b in whole and (a, b) not in bundles and (b, a) not in bundles
               and len(common) <= BUNDLE_HOST_SHARE * len(contributors[a][0])}

    def keepers(held: Sequence[int]) -> Optional[int]:
        """The one holder every other holder bundles. A holder carrying only part of
        it counts when a whole copy holds the function too: that copy says the
        function is the library's, not some third project's both happen to carry."""
        if len(held) > BUNDLE_MAX_OWNERS:
            return None
        for x in held:
            others = [y for y in held if y != x]
            if all((y, x) in bundles for y in others):
                return x
            if (any((y, x) in bundles for y in others)
                    and all((y, x) in bundles or (y, x) in partial for y in others)):
                return x
        return None

    # Only a bundled contributor can keep anything, so only its hashes are looked at.
    bundled = {b for _, b in bundles}
    keep_exact: Dict[int, set] = {}
    for b in bundled:
        for h in shared.intersection(contributors[b][0]):
            if keepers(owners[h]) == b:
                keep_exact.setdefault(b, set()).add(h)
    candidates: set = set()
    for b in bundled:
        candidates |= abstract_shared.intersection(contributors[b][1])
    abstract_owners: Dict[int, List[int]] = {}
    if candidates:
        for i, (_, abstract, _) in enumerate(contributors):
            for h in candidates.intersection(abstract):
                abstract_owners.setdefault(h, []).append(i)
    keep_abstract: Dict[int, set] = {}
    for h, held in abstract_owners.items():
        x = keepers(held)
        if x is not None:
            keep_abstract.setdefault(x, set()).add(h)
    return keep_exact, keep_abstract


def _without_borrowed(signature, present):
    """*present* minus the functions segmentation marked as another rule's. What is left
    still counts the directory's own, unrecorded functions (a vendor's additions)."""
    borrowed = signature.hash_set - signature.application_hashes
    return present - borrowed if borrowed else present


def _release_counts(sig, hashes: Sequence[int]) -> List[int]:
    """How many of *hashes* each recorded release of *sig* holds, read off the bitmaps."""
    counts = [0] * len(sig.versions)
    index, bitmaps = sig.index, sig.bitmaps
    for h in hashes:
        i = index.get(h)
        if i is None:
            continue
        bits = bitmaps[i]
        while bits:
            low = bits & -bits
            counts[low.bit_length() - 1] += 1
            bits ^= low
    return counts


def _release_sizes(sig) -> List[int]:
    """Functions per recorded release, without building one set per release.

    A function unchanged over a run of releases shares its bitmap with every other such
    function, so a signature has far fewer distinct bitmaps than functions: those are
    counted first (in C), and only they are taken apart bit by bit."""
    def build() -> List[int]:
        sizes = [0] * len(sig.versions)
        for bits, n in Counter(sig.bitmaps).items():
            while bits:
                low = bits & -bits
                sizes[low.bit_length() - 1] += n
                bits ^= low
        return sizes
    return sig._memo("release-sizes", build)


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
    # Neighbours compared in C; a Python-level comprehension was most of the cost.
    later = islice(ordered, 1, None)
    return set(compress(islice(ordered, 1, None), map(operator.eq, ordered, later)))


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
