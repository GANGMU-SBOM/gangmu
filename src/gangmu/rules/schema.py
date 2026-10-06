"""The rule format.

One rule is one directory's identity claim, plus the evidence that lets a
machine re-check it.  Everything a rule asserts must be falsifiable by CI
against a named upstream release -- that is the whole point of the format, and
the reason ``upstream.source`` is mandatory rather than documentation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import hashlib
import json
from pathlib import Path

from ..fingerprint import ALGO, DEFAULT_K, DEFAULT_SKETCH, DEFAULT_WINDOW, Signature
from ..fnsig import FunctionSignature
from ..support import Support, SupportError, parse_support

# Containment bands for function-level matching. A component's own functions
# are either present in the tree or they are not, so the bands sit much higher
# and much further apart than the whole-tree similarity bands below.
DEFAULT_FUNCTION_THRESHOLDS = {"strong": 0.80, "partial": 0.50, "floor": 0.20}

# Similarity bands, calibrated against real trees (see docs/CALIBRATION.md):
#   upstream 2.2.0 vs 2.2.2            0.984
#   upstream 2.2.0 vs Espressif fork   0.945
#   upstream 2.2.0 vs 2.1.3            0.859
#   lwIP vs cJSON                      0.000
DEFAULT_THRESHOLDS = {"exact": 0.98, "strong": 0.85, "weak": 0.60, "floor": 0.35}


class RuleError(ValueError):
    """A rule file is malformed. Always carries the rule's path."""


@dataclass(frozen=True)
class Anchor:
    """A file whose pristine hash pins an exact upstream release."""

    path: str
    sha256: Mapping[str, str]       # version -> digest


@dataclass(frozen=True)
class SignatureSpec:
    signature: Signature
    reference_version: Optional[str] = None
    algo: str = ALGO
    fileset_sha256: Optional[str] = None
    """Hash over the reference release's (path, sha256) pairs.

    MinHash answers "how similar", which is the wrong question for "was this
    touched" -- on a small component a one-function patch can still score 1.00.
    The fileset hash answers that question exactly and costs nothing, since the
    per-file digests are computed anyway.
    """


@dataclass
class FunctionSpec:
    """Points at the binary multi-version function signature beside the rule.

    Kept out of the YAML because a few thousand 64-bit hashes is not something a
    human reads. Its sha256 is in the YAML and CI regenerates the file from the
    upstream releases the rule names, so it is verified rather than reviewed.
    """

    file: str
    sha256: str
    versions: Tuple[str, ...] = ()
    count: int = 0
    thresholds: Dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_FUNCTION_THRESHOLDS))
    base_dir: Optional[str] = None
    calibration: Optional[Dict[str, object]] = None
    """For ``fnprint``: the author's self-test (``calibrate.py``), which must agree with
    the sidecar it points at."""
    format: str = "fnsig"
    """``fnsig`` (source function hashes) or ``fnprint`` (``fprint.FunctionPrints``)."""
    subset: bool = False
    """The rule's component is routinely copied in part (an SDK package carries
    only the drivers its chip uses). When the directory holds too little of a
    release for containment to reach the floor, accept it if nearly all of its own
    functions come from one recorded release (see ``MatchEngine._by_subset``)."""
    derivative: bool = False
    """The component is routinely trimmed and rewritten by vendors (a Wi-Fi supplicant
    port keeps about a third of upstream's functions unchanged). When too little of
    any release is present for containment to reach the floor, report the directory
    as a modified derivative if enough of its own functions are identical to
    recorded ones (see ``MatchEngine._by_derivative``). No version is asserted."""
    family: str = ""
    """Rules for sibling releases or ports of one code base (the GD32 library for
    each chip family) name the same family. Code they share is the family's own,
    not one rule borrowing from another, so it keeps counting as application code
    for each of them (see ``MatchEngine.segment_rule_base``)."""
    _loaded: Optional[object] = None

    def load(self):
        """Read and verify the sidecar. A digest mismatch is fatal: a rule whose
        evidence does not match its own record is not evidence."""
        if self._loaded is None:
            path = Path(self.base_dir or ".") / self.file
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if digest != self.sha256:
                raise RuleError(
                    f"{self.file}: sha256 is {digest[:12]}..., the rule records "
                    f"{self.sha256[:12]}.... Regenerate with "
                    f"`gangmu rules fingerprint --functions`.")
            if self.format == "fnprint":
                from ..fprint import FunctionPrints
                self._loaded = FunctionPrints.from_bytes(raw)
                if self.calibration != self._loaded.meta:
                    self._loaded = None
                    raise RuleError(
                        f"{self.file}: the rule's calibration block does not match the "
                        f"self-test stored in the sidecar. Regenerate both with "
                        f"`gangmu rules binary-prints`.")
            else:
                self._loaded = FunctionSignature.from_bytes(raw)
        return self._loaded


@dataclass(frozen=True)
class VersionProbe:
    """A regex probe that reconstructs a version from source."""

    file: str
    patterns: Mapping[str, str]
    template: str

    def apply(self, text: str) -> Optional[str]:
        values: Dict[str, str] = {}
        for name, pattern in self.patterns.items():
            m = re.search(pattern, text)
            if not m:
                return None
            values[name] = m.group(1) if m.groups() else m.group(0)
        try:
            return self.template.format(**values)
        except KeyError:
            return None


@dataclass(frozen=True)
class UpstreamSource:
    kind: str                       # "git" | "tarball"
    url: str
    ref: Optional[str] = None
    subdir: Optional[str] = None


@dataclass
class Rule:
    id: str
    upstream_name: str
    source_path: str = ""           # the .yaml this came from

    vendor: Optional[str] = None
    sdk: Optional[str] = None
    sdk_versions: Optional[str] = None
    path_globs: Tuple[str, ...] = ()
    ships_as: Optional[str] = None
    marker_files: Tuple[str, ...] = ()
    """Files that, found together in one directory, mark a copy of this
    component wherever a vendor put it and whatever they named the directory
    (``tasks.c`` + ``queue.c`` + ``list.c`` is FreeRTOS). Paths are relative to
    the component root. Discovery only: matching still decides identity."""
    config_gates: Tuple["ConfigGate", ...] = ()
    """Kconfig options that switch this component on (``component.config_symbols``).
    Plain names apply wherever the rule fires; a ``{path:, symbols:}`` entry applies
    only to a copy found under that path, because which option builds mbedTLS
    depends on the SDK it was found in, not on mbedTLS. When a ``sdkconfig`` /
    ``.config`` says all of a gate's options are off the component is left out of
    the SBOM; an option the file does not mention never removes anything (see
    ``gangmu.build.kconfig``)."""

    purl: Optional[str] = None
    cpe: Optional[str] = None
    cpe_aliases: Tuple[str, ...] = ()
    """Deprecated or alternative CPE names for the same product.

    NVD renames vendors (mbed TLS lived at ``mbed:mbedtls`` before
    ``arm:mbed_tls``) and old CVE records keep the old name forever. Matching on
    one name alone silently misses those, so a rule may carry the others.
    """
    cpe_evidence: Tuple[str, ...] = ()
    """CVEs that show NVD files this upstream under the CPE(s) above: records
    whose references point at the upstream's own repository or site. Found
    with ``gangmu rules cpe-evidence``; lets a reviewer check the CPE in a
    minute instead of trusting it."""
    cpe_status: Optional[str] = None
    """Why there is no CPE, when there is none -- so the next contributor does
    not repeat the search. ``none-in-nvd`` is a finding, not an omission."""
    homepage: Optional[str] = None
    license: Optional[str] = None
    supplier: Optional[str] = None
    """Who produces the upstream component. NTIA's first minimum element and
    CISA 2026's "Component Producer": without it a reader has nobody to ask."""
    support: Optional[Support] = None
    """Maintenance status and end-of-support date of the upstream project, with
    where to check it. Optional: most rules say nothing, and the SBOM then says
    ``unknown`` rather than guessing. Written under ``upstream.support``."""
    source: Optional[UpstreamSource] = None
    mirrors: Tuple[UpstreamSource, ...] = ()
    """Further repositories CI re-derives the same evidence from. For a rule
    whose releases are not all in one place: the primary repository lacks the
    newest tags that a mirror carries. ``gangmu rules verify`` fetches each."""

    patched: bool = False
    fork_url: Optional[str] = None
    fork_note: Optional[str] = None

    include: Tuple[str, ...] = ()
    exclude: Tuple[str, ...] = ()
    anchors: Tuple[Anchor, ...] = ()
    signature: Optional[SignatureSpec] = None
    functions: Optional[FunctionSpec] = None
    binary_strings: Optional[FunctionSpec] = None
    binary_functions: Optional[FunctionSpec] = None
    """Per-function fingerprints (strings and constants a function uses) for finding the
    component's functions inside compiled images (``fprint.py``)."""
    """String-constant signature for identifying the component inside compiled images
    (``binsig.py``); same sidecar format as ``functions``."""
    thresholds: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    probes: Tuple[VersionProbe, ...] = ()

    confidence_ceiling: float = 0.95

    @property
    def specificity(self) -> int:
        """How narrowly this rule is scoped; used to break ties."""
        score = 0
        if self.vendor:
            score += 2
        if self.sdk:
            score += 2
        if self.sdk_versions:
            score += 1
        score += len(self.path_globs)
        return score

    def purl_with_version(self, version: Optional[str]) -> Optional[str]:
        if not self.purl:
            return None
        # A "low~high" span is not a version; a PURL or CPE carrying one matches
        # nothing in other tools. Leave the version out and keep the span in the
        # component's own version field.
        if not version or "~" in version:
            return self.purl
        return f"{self.purl}@{version}"

    def cpe_with_version(self, version: Optional[str]) -> Optional[str]:
        return _splice_version(self.cpe, version)

    def cpe_aliases_with_version(self, version: Optional[str]) -> List[str]:
        return [c for c in (_splice_version(a, version) for a in self.cpe_aliases) if c]


def _splice_version(cpe: Optional[str], version: Optional[str]) -> Optional[str]:
    if not cpe:
        return None
    if version and "~" not in version:
        parts = cpe.split(":")
        if len(parts) > 5:
            parts[5] = version
            return ":".join(parts)
    return cpe


def _req(data: Mapping[str, Any], key: str, path: str) -> Any:
    if key not in data or data[key] in (None, ""):
        raise RuleError(f"{path}: missing required key '{key}'")
    return data[key]


@dataclass(frozen=True)
class ConfigGate:
    symbols: Tuple[str, ...]
    path: Optional[str] = None          # glob the component's directory must match


def _config_gates(value: Any, source_path: str) -> Tuple[ConfigGate, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        value = [value]
    plain = [str(v) for v in value if not isinstance(v, Mapping)]
    gates = [ConfigGate(tuple(plain))] if plain else []
    for entry in value:
        if not isinstance(entry, Mapping):
            continue
        symbols = _tuple(entry.get("symbols"))
        if not entry.get("path") or not symbols:
            raise RuleError(f"{source_path}: a config_symbols entry needs both "
                            f"'path' and 'symbols'")
        gates.append(ConfigGate(symbols, str(entry["path"])))
    return tuple(gates)


def _parse_rule_support(raw: Any, source_path: Any) -> Optional[Support]:
    if raw in (None, {}):
        return None
    try:
        return parse_support(raw, f"{source_path}: upstream.support")
    except SupportError as exc:
        raise RuleError(str(exc)) from None


def _tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def _upstream_source(raw: Mapping[str, Any], source_path: str) -> UpstreamSource:
    return UpstreamSource(
        kind=str(_req(raw, "kind", source_path)),
        url=str(_req(raw, "url", source_path)),
        ref=(str(raw["ref"]) if raw.get("ref") else None),
        subdir=(str(raw["subdir"]) if raw.get("subdir") else None),
    )


def rule_from_dict(data: Mapping[str, Any], source_path: str = "") -> Rule:
    """Parse and validate one rule mapping. Raises :class:`RuleError`."""
    if not isinstance(data, Mapping):
        raise RuleError(f"{source_path}: rule must be a mapping")

    rid = str(_req(data, "id", source_path))
    upstream = data.get("upstream") or {}
    if not isinstance(upstream, Mapping):
        raise RuleError(f"{source_path}: 'upstream' must be a mapping")
    name = str(_req(upstream, "name", source_path))

    src_raw = upstream.get("source")
    if not isinstance(src_raw, Mapping):
        raise RuleError(
            f"{source_path}: 'upstream.source' is required -- CI must be able to "
            f"re-derive this rule's evidence from a named upstream release"
        )
    source = _upstream_source(src_raw, source_path)
    mirrors_raw = upstream.get("mirrors") or []
    if not isinstance(mirrors_raw, list) or not all(
            isinstance(m, Mapping) for m in mirrors_raw):
        raise RuleError(f"{source_path}: 'upstream.mirrors' must be a list of "
                        f"source mappings")
    mirrors = tuple(_upstream_source(m, source_path) for m in mirrors_raw)

    component = data.get("component") or {}
    identity = data.get("identity") or {}
    version = data.get("version") or {}
    fork = data.get("vendor_fork") or {}

    anchors: List[Anchor] = []
    for raw in identity.get("anchors") or []:
        digests = raw.get("sha256") or {}
        if not isinstance(digests, Mapping) or not digests:
            raise RuleError(f"{source_path}: anchor '{raw.get('path')}' needs a "
                            f"version -> sha256 mapping")
        for ver, digest in digests.items():
            if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
                raise RuleError(f"{source_path}: anchor '{raw.get('path')}' "
                                f"version {ver}: sha256 must be 64 hex chars")
        anchors.append(Anchor(path=str(_req(raw, "path", source_path)),
                              sha256={str(k): str(v) for k, v in digests.items()}))

    sig_spec: Optional[SignatureSpec] = None
    raw_sig = identity.get("signature")
    if raw_sig:
        algo = str(raw_sig.get("algo", ALGO))
        if algo != ALGO:
            raise RuleError(
                f"{source_path}: signature algo is '{algo}', this build produces "
                f"'{ALGO}'. Regenerate the rule with `gangmu rules fingerprint`; "
                f"a sketch from another algorithm cannot be compared."
            )
        k = int(raw_sig.get("k", DEFAULT_K))
        window = int(raw_sig.get("window", DEFAULT_WINDOW))
        size = int(raw_sig.get("size", raw_sig.get("num_perm", DEFAULT_SKETCH)))
        try:
            sig = Signature.from_hex(str(_req(raw_sig, "values", source_path)),
                                     k=k, window=window, size=size)
        except ValueError as exc:
            raise RuleError(f"{source_path}: bad signature: {exc}") from exc
        fileset = raw_sig.get("fileset_sha256")
        if fileset is not None and not re.fullmatch(r"[0-9a-f]{64}", str(fileset)):
            raise RuleError(f"{source_path}: fileset_sha256 must be 64 hex chars")
        sig_spec = SignatureSpec(
            signature=sig,
            reference_version=(str(raw_sig["reference_version"])
                               if raw_sig.get("reference_version") else None),
            algo=algo,
            fileset_sha256=(str(fileset) if fileset else None),
        )

    fn_spec: Optional[FunctionSpec] = None
    raw_fn = identity.get("functions")
    if raw_fn:
        digest = str(_req(raw_fn, "sha256", source_path))
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuleError(f"{source_path}: identity.functions.sha256 must be "
                            f"64 hex chars")
        fn_thresholds = dict(DEFAULT_FUNCTION_THRESHOLDS)
        fn_thresholds.update({str(k): float(v)
                              for k, v in (raw_fn.get("thresholds") or {}).items()})
        fn_spec = FunctionSpec(
            file=str(_req(raw_fn, "file", source_path)),
            sha256=digest,
            versions=_tuple(raw_fn.get("versions")),
            count=int(raw_fn.get("count", 0)),
            thresholds=fn_thresholds,
            subset=bool(raw_fn.get("subset", False)),
            derivative=bool(raw_fn.get("derivative", False)),
            family=str(raw_fn.get("family") or ""))

    bs_spec: Optional[FunctionSpec] = None
    raw_bs = identity.get("binary_strings")
    if raw_bs:
        digest = str(_req(raw_bs, "sha256", source_path))
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuleError(f"{source_path}: identity.binary_strings.sha256 must be "
                            f"64 hex chars")
        bs_spec = FunctionSpec(
            file=str(_req(raw_bs, "file", source_path)), sha256=digest,
            versions=_tuple(raw_bs.get("versions")), count=int(raw_bs.get("count", 0)))

    bf_spec: Optional[FunctionSpec] = None
    raw_bf = identity.get("binary_functions")
    if raw_bf:
        digest = str(_req(raw_bf, "sha256", source_path))
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuleError(f"{source_path}: identity.binary_functions.sha256 must be "
                            f"64 hex chars")
        calibration = raw_bf.get("calibration")
        if not isinstance(calibration, Mapping) or calibration.get("passed") is not True:
            raise RuleError(
                f"{source_path}: identity.binary_functions needs the `calibration` block "
                f"that `gangmu rules binary-prints` prints, and its self-test must have "
                f"passed. A fingerprint nobody tested across builds is not evidence.")
        bf_spec = FunctionSpec(
            file=str(_req(raw_bf, "file", source_path)), sha256=digest, format="fnprint",
            versions=_tuple(raw_bf.get("versions")), count=int(raw_bf.get("count", 0)),
            calibration=json.loads(json.dumps(calibration)))

    if not anchors and sig_spec is None and fn_spec is None and bs_spec is None \
            and bf_spec is None:
        raise RuleError(f"{source_path}: a rule needs at least one anchor, a "
                        f"signature or a function signature, otherwise nothing "
                        f"can be checked")

    probes: List[VersionProbe] = []
    for raw in version.get("probes") or []:
        patterns = raw.get("patterns") or {}
        if not isinstance(patterns, Mapping) or not patterns:
            raise RuleError(f"{source_path}: probe on '{raw.get('file')}' needs "
                            f"a non-empty 'patterns' mapping")
        for pat in patterns.values():
            try:
                re.compile(str(pat))
            except re.error as exc:
                raise RuleError(f"{source_path}: bad probe regex {pat!r}: {exc}") from exc
        probes.append(VersionProbe(
            file=str(_req(raw, "file", source_path)),
            patterns={str(k): str(v) for k, v in patterns.items()},
            template=str(raw.get("template", "{version}")),
        ))

    thresholds = dict(DEFAULT_THRESHOLDS)
    thresholds.update({str(k): float(v)
                       for k, v in (identity.get("thresholds") or {}).items()})

    # A CPE with the wrong vendor silently matches no CVE at all, which is the
    # most expensive way for a rule to be wrong: the SBOM looks clean.
    aliases = _tuple(upstream.get("cpe_aliases"))
    primary = [str(upstream["cpe"])] if upstream.get("cpe") else []
    for candidate in [*primary, *aliases]:
        parts = str(candidate).split(":")
        if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
            raise RuleError(
                f"{source_path}: every CPE must be a well-formed CPE 2.3 name "
                f"with 13 colon-separated parts, got {candidate!r}")
        if parts[2] not in ("a", "o", "h"):
            raise RuleError(
                f"{source_path}: CPE part must be a, o or h, got {parts[2]!r}")
    if aliases and not primary:
        raise RuleError(f"{source_path}: 'cpe_aliases' without a primary 'cpe'")
    evidence = _tuple(upstream.get("cpe_evidence"))
    for cve in evidence:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise RuleError(f"{source_path}: cpe_evidence entries are CVE ids, "
                            f"got {cve!r}")
    if evidence and not primary:
        raise RuleError(f"{source_path}: 'cpe_evidence' without a 'cpe'")

    purl = upstream.get("purl")
    if purl and not str(purl).startswith("pkg:"):
        raise RuleError(f"{source_path}: 'upstream.purl' must start with 'pkg:', "
                        f"got {purl!r}")

    ceiling = float(data.get("confidence_ceiling", 0.95))
    if not 0.0 < ceiling <= 1.0:
        raise RuleError(f"{source_path}: confidence_ceiling must be in (0, 1]")

    return Rule(
        id=rid,
        upstream_name=name,
        source_path=source_path,
        vendor=(str(data["vendor"]) if data.get("vendor") else None),
        sdk=(str(data["sdk"]) if data.get("sdk") else None),
        sdk_versions=(str(data["sdk_versions"]) if data.get("sdk_versions") else None),
        path_globs=_tuple(component.get("path_globs")),
        ships_as=(str(component["ships_as"]) if component.get("ships_as") else None),
        marker_files=_tuple(component.get("marker_files")),
        config_gates=_config_gates(component.get("config_symbols"), source_path),
        purl=(str(upstream["purl"]) if upstream.get("purl") else None),
        cpe=(str(upstream["cpe"]) if upstream.get("cpe") else None),
        cpe_aliases=aliases,
        cpe_evidence=evidence,
        cpe_status=(str(upstream["cpe_status"]) if upstream.get("cpe_status") else None),
        homepage=(str(upstream["homepage"]) if upstream.get("homepage") else None),
        supplier=(str(upstream["supplier"]) if upstream.get("supplier") else None),
        license=(str(upstream["license"]) if upstream.get("license") else None),
        support=_parse_rule_support(upstream.get("support"), source_path),
        source=source,
        mirrors=mirrors,
        patched=bool(fork.get("patched", False)),
        fork_url=(str(fork["upstream_of_fork"]) if fork.get("upstream_of_fork") else None),
        fork_note=(str(fork["note"]) if fork.get("note") else None),
        include=_tuple(identity.get("include")),
        exclude=_tuple(identity.get("exclude")),
        anchors=tuple(anchors),
        signature=sig_spec,
        functions=fn_spec,
        binary_strings=bs_spec,
        binary_functions=bf_spec,
        thresholds=thresholds,
        probes=tuple(probes),
        confidence_ceiling=ceiling,
    )
