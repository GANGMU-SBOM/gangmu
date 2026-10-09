"""Cryptographic bill of materials (CBOM): which algorithms does this firmware use?

A CBOM is the inventory a post-quantum migration starts from: every cryptographic
algorithm the product contains, and which of them a quantum computer breaks.
CycloneDX 1.6 has the vocabulary for it (``cryptographic-asset`` components with
``cryptoProperties``); this module fills it for firmware.

What makes it more than a grep is the same thing that makes the SBOM useful: the
build facts. A crypto library's source tree *defines* every algorithm it offers; the
product *uses* only the ones its build compiled and its link map kept. With a compile
database or a link map, a hit counts only when it sits in a source file that went into
the image, and the asset says so. Without build facts the result lists what the tree
contains, and every asset is marked ``unverified``: an honest answer, not a confident
wrong one.

Detection is by name -- API symbols, configuration macros, algorithm strings -- in
sources, build configuration and the symbol and string tables of binaries. That finds
what a developer or a library names; it does not find an algorithm hand-written under
another name, and it says nothing about key sizes, key storage or protocol use.
"""

from __future__ import annotations

import bisect
import datetime as _dt
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__
from .binaries import FIXTURE_DIRS, IMAGE_SUFFIXES, MAX_BANNER_BYTES, SKIP_DIRS
from .build.facts import BuildFacts
from .core.packs import RuleRoot, check_manifest, default_roots, read_manifest
from .core.unpack import expand

SPEC_VERSION = "1.6"

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".s", ".asm"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".inc", ".ipp"}
CONFIG_NAMES = ("kconfig", "sdkconfig", "defconfig")
CONFIG_SUFFIXES = {".conf", ".config", ".defconfig", ".cmake", ".mk"}
BLOB_SUFFIXES = {".a", ".lib", ".so"} | IMAGE_SUFFIXES
MAX_TEXT_BYTES = 4 * 1024 * 1024
DOC_DIRS = {"doc", "docs", "doxygen"}   # prose about algorithms, not code that uses them
MAX_OCCURRENCES = 20          # stored per asset; the total is kept as a count

# Quantum status, the value of the ``gangmu:quantumStatus`` property.
VULNERABLE = "vulnerable"     # broken by Shor's algorithm: replace
SYMMETRIC = "symmetric"       # Grover halves the strength: prefer 256-bit keys, SHA-384 and up
PQC = "pqc"                   # a post-quantum scheme
BROKEN = "broken"             # weak against classical attackers already
NEUTRAL = "neutral"           # not a quantum question (a KDF, a DRBG)

_B = r"(?<![A-Za-z0-9_])"     # an identifier does not start in the middle of another one


@dataclass(frozen=True)
class Algo:
    key: str
    name: str
    primitive: str            # CycloneDX algorithmProperties.primitive
    quantum: str
    patterns: Tuple[str, ...]
    note: str = ""


ALGOS: Tuple[Algo, ...] = (
    Algo("aes", "AES", "block-cipher", SYMMETRIC, (
        _B + r"(?:mbedtls_aes_|esp_aes_|wc_Aes|tc_aes_|HAL_CRYP|AES_(?:set_)?(?:en|de)crypt_key|"
        r"AES_(?:encrypt|decrypt|ecb_encrypt|cbc_encrypt|ctr128_encrypt)\b|MBEDTLS_AES_C\b|"
        r"CONFIG_MBEDTLS_AES\w*|CONFIG_CRYPTO_AES\w*|PSA_KEY_TYPE_AES\b)",),
        "A 128-bit key leaves about 64 bits of quantum security; 256-bit keys are the usual advice."),
    Algo("des", "DES/3DES", "block-cipher", BROKEN, (
        _B + r"(?:mbedtls_des3?_|DES_(?:ecb|cbc|ede3|set_key)\w*|wc_Des3?_\w+|MBEDTLS_DES_C\b|"
        r"CONFIG_MBEDTLS_DES_C\b)",),
        "DES and 3DES are legacy; avoid them in new designs."),
    Algo("rc4", "RC4", "stream-cipher", BROKEN, (
        _B + r"(?:mbedtls_arc4_|RC4_set_key|RC4\(|wc_Arc4\w*|MBEDTLS_ARC4_C\b)",),
        "RC4 has practical attacks; remove it."),
    Algo("chacha20-poly1305", "ChaCha20-Poly1305", "ae", SYMMETRIC, (
        _B + r"(?:mbedtls_chacha20\w*|mbedtls_poly1305\w*|wc_Chacha\w*|wc_Poly1305\w*|"
        r"EVP_chacha20\w*|MBEDTLS_CHACHA20_C\b|MBEDTLS_CHACHAPOLY_C\b|crypto_aead_chacha20poly1305\w*)",),
        "A 256-bit key."),
    Algo("sm4", "SM4", "block-cipher", SYMMETRIC, (
        _B + r"(?:sm4_(?:setkey|crypt|encrypt|decrypt|set_key)\w*|SM4_(?:set_key|encrypt|decrypt|CTX)\w*|"
        r"mbedtls_sm4_\w+|EVP_sm4_\w+)",),
        "Chinese national block cipher (128-bit key)."),
    Algo("sm3", "SM3", "hash", NEUTRAL, (
        _B + r"(?:sm3_(?:init|update|finish|starts|hash)\w*|SM3_(?:Init|Update|Final)\w*|"
        r"mbedtls_sm3_\w+|EVP_sm3\b)",),
        "Chinese national hash (256-bit output)."),
    Algo("sm2", "SM2", "signature", VULNERABLE, (
        _B + r"(?:sm2_(?:sign|verify|encrypt|decrypt|do_sign|do_verify)\w*|SM2_(?:sign|verify|encrypt|"
        r"decrypt|compute_z_digest)\w*|mbedtls_sm2_\w+|ossl_sm2_\w+|MBEDTLS_ECP_DP_SM2\w*|\bsm2p256v1\b)",),
        "Elliptic-curve scheme: a quantum computer breaks it like ECDSA."),
    Algo("md5", "MD5", "hash", BROKEN, (
        _B + r"(?:mbedtls_md5\w*|MD5_(?:Init|Update|Final)\b|MD5Init\b|MD5Update\b|wc_Md5\w+|"
        r"MBEDTLS_MD5_C\b|CONFIG_MBEDTLS_MD5_C\b|\bMD5\(|\bMD5 digest\b)",),
        "Collisions are practical; not for signatures or integrity."),
    Algo("sha1", "SHA-1", "hash", BROKEN, (
        _B + r"(?:mbedtls_sha1\w*|SHA1_(?:Init|Update|Final)\b|SHA1\(|wc_Sha\b|wc_ShaUpdate\b|"
        r"MBEDTLS_SHA1_C\b|CONFIG_MBEDTLS_SHA1_C\b|PSA_ALG_SHA_1\b|\bSHA-?1 digest\b)",),
        "Collisions are practical; avoid in signatures."),
    Algo("sha-256", "SHA-256", "hash", SYMMETRIC, (
        _B + r"(?:mbedtls_sha256\w*|SHA256_(?:Init|Update|Final)\b|SHA256\(|wc_Sha256\w*|"
        r"MBEDTLS_SHA256_C\b|CONFIG_MBEDTLS_SHA256_C\b|PSA_ALG_SHA_256\b|esp_sha\b|"
        r"HAL_HASH\w*|CRYP_SHA256\w*)",),
        "Fine today; 128-bit collision strength is the figure to weigh long-lived signatures against."),
    Algo("sha-512", "SHA-384/SHA-512", "hash", SYMMETRIC, (
        _B + r"(?:mbedtls_sha512\w*|SHA384_(?:Init|Update|Final)\b|SHA512_(?:Init|Update|Final)\b|"
        r"SHA512\(|wc_Sha(?:384|512)\w*|MBEDTLS_SHA512_C\b|CONFIG_MBEDTLS_SHA512_C\b|"
        r"PSA_ALG_SHA_(?:384|512)\b)",),
        "SHA-384 and up are the sizes the post-quantum guidance names."),
    Algo("sha-3", "SHA-3", "hash", SYMMETRIC, (
        _B + r"(?:mbedtls_sha3_\w+|SHA3_\w+|wc_Sha3_\w+|MBEDTLS_SHA3_C\b|keccak_\w+|PSA_ALG_SHA3_\w+)",),
        ""),
    Algo("hmac", "HMAC", "mac", SYMMETRIC, (
        _B + r"(?:mbedtls_md_hmac\w*|HMAC_(?:Init|Update|Final|CTX)\w*|wc_Hmac\w+|PSA_ALG_HMAC\b|"
        r"hmac_sha\w*|CONFIG_MBEDTLS_HMAC\w*)",),
        ""),
    Algo("kdf", "HKDF/PBKDF2", "kdf", NEUTRAL, (
        _B + r"(?:mbedtls_hkdf\w*|HKDF\w*|mbedtls_pkcs5_pbkdf2\w*|PKCS5_PBKDF2\w*|wc_PBKDF2\w*|"
        r"wc_HKDF\w*|PSA_ALG_HKDF\b|PSA_ALG_PBKDF2\w*|MBEDTLS_HKDF_C\b|MBEDTLS_PKCS5_C\b)",),
        ""),
    Algo("drbg", "CTR_DRBG/HMAC_DRBG", "drbg", NEUTRAL, (
        _B + r"(?:mbedtls_ctr_drbg_\w+|mbedtls_hmac_drbg_\w+|MBEDTLS_CTR_DRBG_C\b|"
        r"MBEDTLS_HMAC_DRBG_C\b|wc_InitRng\w*|RAND_DRBG\w*)",),
        ""),
    Algo("rsa", "RSA", "pke", VULNERABLE, (
        _B + r"(?:mbedtls_rsa_\w+|RSA_(?:new|generate_key\w*|public_encrypt|private_decrypt|sign|verify)\b|"
        r"wc_(?:Init)?Rsa\w+|MBEDTLS_RSA_C\b|CONFIG_MBEDTLS_RSA_C\b|PSA_ALG_RSA_\w+|PSA_KEY_TYPE_RSA\w*|"
        r"\brsaEncryption\b|\bsha\d+WithRSAEncryption\b)",),
        "Broken by Shor's algorithm at every key size."),
    Algo("ecdsa", "ECDSA", "signature", VULNERABLE, (
        _B + r"(?:mbedtls_ecdsa_\w+|ECDSA_(?:do_)?(?:sign|verify|SIG_\w+)\b|wc_ecc_(?:sign|verify)_hash\w*|"
        r"uECC_(?:sign|verify)\w*|MBEDTLS_ECDSA_C\b|CONFIG_MBEDTLS_ECDSA_C\b|PSA_ALG_ECDSA\b|"
        r"PSA_ALG_DETERMINISTIC_ECDSA\b|\becdsa-with-SHA\d+\b)",),
        "Broken by Shor's algorithm at every curve."),
    Algo("ecdh", "ECDH", "key-agree", VULNERABLE, (
        _B + r"(?:mbedtls_ecdh_\w+|ECDH_compute_key\b|wc_ecc_shared_secret\w*|uECC_shared_secret\b|"
        r"MBEDTLS_ECDH_C\b|CONFIG_MBEDTLS_ECDH_C\b|PSA_ALG_ECDH\b)",),
        "Broken by Shor's algorithm at every curve."),
    Algo("ed25519", "Ed25519", "signature", VULNERABLE, (
        _B + r"(?:ed25519_(?:sign|verify|create_keypair|publickey)\w*|wc_ed25519_\w+|"
        r"crypto_sign_ed25519\w*|\bEd25519\b)",),
        "Elliptic-curve scheme: broken by Shor's algorithm."),
    Algo("x25519", "X25519", "key-agree", VULNERABLE, (
        _B + r"(?:curve25519_\w+|x25519_\w+|wc_curve25519\w*|crypto_scalarmult_curve25519\w*|"
        r"MBEDTLS_ECP_DP_CURVE25519\w*|X25519\b)",),
        "Elliptic-curve key agreement: broken by Shor's algorithm."),
    Algo("dh", "Diffie-Hellman", "key-agree", VULNERABLE, (
        _B + r"(?:mbedtls_dhm_\w+|DH_(?:generate_key|compute_key)\b|wc_Dh\w+|MBEDTLS_DHM_C\b)",),
        "Finite-field key agreement: broken by Shor's algorithm."),
    Algo("ml-kem", "ML-KEM (Kyber)", "kem", PQC, (
        _B + r"(?:ML[-_]KEM\w*|mlkem\w*|PQCLEAN_MLKEM\w*|OQS_KEM_alg_(?:ml_kem|kyber)\w*|"
        r"pqcrystals_kyber\w*|crypto_kem_(?:keypair|enc|dec)\b|wc_MlKem\w*)",),
        "NIST FIPS 203."),
    Algo("ml-dsa", "ML-DSA (Dilithium)", "signature", PQC, (
        _B + r"(?:ML[-_]DSA\w*|mldsa\w*|PQCLEAN_MLDSA\w*|OQS_SIG_alg_(?:ml_dsa|dilithium)\w*|"
        r"pqcrystals_dilithium\w*|wc_MlDsa\w*|wc_dilithium\w*)",),
        "NIST FIPS 204."),
    Algo("slh-dsa", "SLH-DSA (SPHINCS+)", "signature", PQC, (
        _B + r"(?:SLH[-_]DSA\w*|slhdsa\w*|SPHINCS\w*|sphincs\w*|PQCLEAN_SPHINCS\w*)",),
        "NIST FIPS 205."),
    Algo("hash-based-sig", "LMS/XMSS", "signature", PQC, (
        _B + r"(?:mbedtls_lms_\w+|wc_Lms\w+|wc_Xmss\w+|\bXMSS\w*|HSS_(?:generate|sign|verify)\w*|"
        r"MBEDTLS_LMS_C\b)",),
        "Stateful hash-based signatures (NIST SP 800-208), the scheme CNSA 2.0 names for firmware signing."),
)

# Variants found next to the family hit. AES carries a key size and a mode in its name.
_AES_VARIANT = re.compile(
    rb"(?<![A-Za-z])AES[-_ ]?(128|192|256)[-_ ]?(GCM|CBC|CTR|CCM|ECB|CFB|OFB|XTS)", re.IGNORECASE)
_AES_MODES = {"CBC": "cbc", "ECB": "ecb", "CCM": "ccm", "GCM": "gcm", "CFB": "cfb",
              "OFB": "ofb", "CTR": "ctr", "XTS": "other"}
_AES_QUANTUM_LEVEL = {"128": 1, "192": 3, "256": 5}

PRIMITIVES = frozenset({"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
                        "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap",
                        "other"})                # CycloneDX algorithmProperties.primitive
QUANTUM_STATUSES = frozenset({VULNERABLE, SYMMETRIC, PQC, BROKEN, NEUTRAL})
ALGO_DIR = "algorithms"       # inside a rule pack of kind ``cbom``


class CbomRuleError(ValueError):
    """An algorithm rule that cannot be loaded."""


class AlgoSet:
    """The algorithms a scan looks for: the built-in table, overlaid by rule packs.

    A pack entry with the key of a built-in replaces it; a new key adds an algorithm.
    """

    def __init__(self, algos: Iterable[Algo], sources: Sequence[str] = (),
                 libraries: Optional[Dict[str, "Library"]] = None) -> None:
        by_key: Dict[str, Algo] = {}
        for a in algos:
            by_key[a.key] = a                    # dicts keep first-seen order on replacement
        self.algos: List[Algo] = list(by_key.values())
        self.by_key = by_key
        self.sources: List[str] = list(sources)
        self.libraries: Dict[str, "Library"] = dict(libraries or {})
        self.regexes: List[Tuple[Algo, "re.Pattern[bytes]"]] = [
            (a, re.compile("|".join(a.patterns).encode("ascii"))) for a in self.algos]


@dataclass(frozen=True)
class Release:
    """One span of a library's versions and the algorithms its source provides there."""
    algorithms: Tuple[str, ...]
    introduced: Optional[str] = None
    fixed: Optional[str] = None           # exclusive upper bound
    source: str = ""                      # where a reviewer can check the claim

    def holds(self, version: str) -> Optional[bool]:
        from .vuln.version import in_range
        if self.introduced is None and self.fixed is None:
            return True
        return in_range(version, introduced=self.introduced, fixed=self.fixed)


@dataclass(frozen=True)
class Library:
    rule: str                             # id of the SBOM rule that identifies the library
    name: str
    releases: Tuple[Release, ...]

    def algorithms_for(self, version: str) -> Optional[Tuple[str, ...]]:
        """The algorithms of the release span holding *version*; None when no span
        does or the version cannot be ordered."""
        for release in self.releases:
            verdict = release.holds(version)
            if verdict:
                return release.algorithms
        return None


LIBRARY_DIR = "libraries"     # inside a rule pack of kind ``cbom``


def _library_from_rule(entry: object, where: str) -> Library:
    if not isinstance(entry, dict):
        raise CbomRuleError(f"{where}: a library rule must be a mapping")
    for field_name in ("rule", "name", "releases"):
        if not entry.get(field_name):
            raise CbomRuleError(f"{where}: missing '{field_name}'")
    if not isinstance(entry["releases"], list):
        raise CbomRuleError(f"{where}: 'releases' must be a list")
    releases = []
    for i, rel in enumerate(entry["releases"]):
        here = f"{where}.releases[{i}]"
        if not isinstance(rel, dict) or not rel.get("algorithms"):
            raise CbomRuleError(f"{here}: needs a non-empty 'algorithms' list")
        algos = rel["algorithms"]
        if not isinstance(algos, list) or not all(isinstance(a, str) for a in algos):
            raise CbomRuleError(f"{here}: 'algorithms' must be a list of algorithm keys")
        releases.append(Release(tuple(algos),
                                str(rel["introduced"]) if rel.get("introduced") else None,
                                str(rel["fixed"]) if rel.get("fixed") else None,
                                str(rel.get("source") or "")))
    return Library(str(entry["rule"]), str(entry["name"]), tuple(releases))


DEFAULT_ALGOS = AlgoSet(ALGOS)


def _algo_from_rule(entry: object, where: str) -> Algo:
    if not isinstance(entry, dict):
        raise CbomRuleError(f"{where}: an algorithm rule must be a mapping")
    for field_name in ("key", "name", "primitive", "quantum", "patterns"):
        if not entry.get(field_name):
            raise CbomRuleError(f"{where}: missing '{field_name}'")
    key = str(entry["key"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", key):
        raise CbomRuleError(f"{where}: key '{key}' must be lower-case letters, digits, . _ -")
    if entry["primitive"] not in PRIMITIVES:
        raise CbomRuleError(f"{where}: primitive '{entry['primitive']}' is not one of "
                            + ", ".join(sorted(PRIMITIVES)))
    if entry["quantum"] not in QUANTUM_STATUSES:
        raise CbomRuleError(f"{where}: quantum '{entry['quantum']}' is not one of "
                            + ", ".join(sorted(QUANTUM_STATUSES)))
    patterns = entry["patterns"]
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, list) or not all(isinstance(p, str) and p for p in patterns):
        raise CbomRuleError(f"{where}: 'patterns' must be a list of regular expressions")
    wrapped = []
    for pat in patterns:
        try:
            re.compile(pat.encode("ascii"))
        except (re.error, UnicodeEncodeError) as exc:
            raise CbomRuleError(f"{where}: pattern {pat!r} is not a usable ASCII regex: {exc}")
        wrapped.append(pat)
    return Algo(key, str(entry["name"]), str(entry["primitive"]), str(entry["quantum"]),
                (_B + "(?:" + "|".join(wrapped) + ")",), str(entry.get("note") or ""))


def load_algo_roots(roots: Sequence["RuleRoot"]) -> AlgoSet:
    """The built-in algorithms overlaid by the ``algorithms/*.yaml`` of each rule root.

    Roots load in order, so a later root replaces an earlier one's rule of the same key.
    Each pattern is a regular expression for an identifier; the scan puts an identifier
    boundary in front of it, so write ``mbedtls_aes_`` and not ``\\bmbedtls_aes_``.
    """
    import yaml

    algos: List[Algo] = list(ALGOS)
    libraries: Dict[str, Library] = {}
    sources: List[str] = []
    for root in roots:
        lib_folder = root.path / LIBRARY_DIR
        if lib_folder.is_dir():
            count = 0
            for path in sorted(lib_folder.glob("*.y*ml")):
                try:
                    data = yaml.safe_load(path.read_text(encoding="utf-8"))
                except (OSError, yaml.YAMLError) as exc:
                    raise CbomRuleError(f"{path}: unreadable: {exc}") from exc
                entries = data.get("libraries") if isinstance(data, dict) else data
                if not isinstance(entries, list):
                    raise CbomRuleError(f"{path}: expected a list under 'libraries:'")
                for i, entry in enumerate(entries):
                    lib = _library_from_rule(entry, f"{path}[{i}]")
                    libraries[lib.rule] = lib        # a later root replaces an earlier one
                    count += 1
            if count:
                sources.append(f"{root.label}: {count} library rule(s)")
        folder = root.path / ALGO_DIR
        if not folder.is_dir():
            continue
        added = 0
        for path in sorted(folder.glob("*.y*ml")):
            where = f"{path}"
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise CbomRuleError(f"{where}: unreadable: {exc}") from exc
            entries = data.get("algorithms") if isinstance(data, dict) else data
            if not isinstance(entries, list):
                raise CbomRuleError(f"{where}: expected a list under 'algorithms:'")
            for i, entry in enumerate(entries):
                algos.append(_algo_from_rule(entry, f"{where}[{i}]"))
                added += 1
        if added:
            sources.append(f"{root.label}: {added} algorithm rule(s)")
    result = AlgoSet(algos, sources, libraries)
    for lib in libraries.values():
        for release in lib.releases:
            unknown = [a for a in release.algorithms if a not in result.by_key]
            if unknown:
                raise CbomRuleError(f"library {lib.rule}: unknown algorithm key(s) "
                                    + ", ".join(unknown))
    return result


def cbom_roots(given: Sequence[str] = ()) -> List["RuleRoot"]:
    """Rule roots for a CBOM scan: the ones named, else the installed packs of kind ``cbom``."""
    if given:
        roots = [RuleRoot(Path(p), "--rules") for p in given]
        for r in roots:
            r.manifest = read_manifest(r.path)
    else:
        roots = default_roots(kind="cbom")
    for r in roots:
        check_manifest(r.path, r.manifest)
    return roots


@dataclass
class Occurrence:
    path: str
    line: Optional[int]
    symbol: str
    kind: str                 # code | config | header | binary | library
    state: str                # linked | not-linked | unknown
    image: bool = False       # a binary hit inside a firmware image, not a library


_STATE_RANK = {"linked": 0, "unknown": 1, "not-linked": 2}
_KIND_RANK = {"code": 0, "binary": 1, "library": 2, "config": 3, "header": 4}


def _rank(occ: "Occurrence") -> Tuple[int, int]:
    return (_STATE_RANK[occ.state], _KIND_RANK[occ.kind])


@dataclass
class Asset:
    algo: Algo
    variant: str = ""         # "AES-128-GCM"; empty for the family itself
    key_bits: str = ""
    mode: str = ""
    occurrences: List[Occurrence] = field(default_factory=list)
    count: int = 0
    in_image: bool = False    # kept apart from the capped occurrence list, which may drop it

    @property
    def name(self) -> str:
        return self.variant or self.algo.name

    @property
    def ref(self) -> str:
        return "crypto/" + (self.variant or self.algo.key).lower().replace(" ", "-")

    def add(self, occ: Occurrence) -> None:
        """Count the hit; keep the best-evidenced ones (linked code first), not the first ones."""
        self.count += 1
        self.in_image = self.in_image or occ.image
        if len(self.occurrences) < MAX_OCCURRENCES:
            self.occurrences.append(occ)
            self.occurrences.sort(key=_rank)
        elif _rank(occ) < _rank(self.occurrences[-1]):
            self.occurrences[-1] = occ
            self.occurrences.sort(key=_rank)

    def verdict(self) -> str:
        """linked, not-linked or unverified: the build facts' reading of this asset."""
        states = {o.state for o in self.occurrences}
        if "linked" in states:
            return "linked"
        if states == {"not-linked"}:
            return "not-linked"
        return "unverified"

    def image_check(self, images: int) -> str:
        """Does a firmware image back up what the sources say?

        ``present``: the algorithm's names are in a built image. ``absent``: an image was
        read and has none of them, though the sources do -- either the algorithm is compiled
        out or it is named by a macro, which leaves no symbol, so this is a reason to look,
        not proof. ``not-checked``: no image was read."""
        if not images:
            return "not-checked"
        if self.in_image:
            return "present"
        return "absent" if any(o.kind in ("code", "config") for o in self.occurrences) \
            else "not-checked"

    def confidence(self) -> float:
        best = 0.0
        for o in self.occurrences:
            if o.state == "not-linked":
                score = 0.2
            elif o.kind == "binary":
                score = 0.85 if o.state == "linked" else 0.6
            elif o.kind == "code":
                score = 0.9 if o.state == "linked" else 0.5
            elif o.kind == "library":
                score = 0.6 if o.state == "linked" else 0.4
            elif o.kind == "config":
                score = 0.5
            else:
                score = 0.3
            best = max(best, score)
        return best


@dataclass
class CbomResult:
    root: str
    assets: List[Asset]
    build_facts_used: bool
    files_scanned: int = 0
    notes: List[str] = field(default_factory=list)
    images: int = 0           # firmware images read that the build facts do not rule out

    def counted(self) -> List[Asset]:
        """Assets that the build facts do not rule out."""
        return [a for a in self.assets if a.verdict() != "not-linked"]


def _is_config(name: str) -> bool:
    low = name.lower()
    return low.startswith(CONFIG_NAMES) or Path(low).suffix in CONFIG_SUFFIXES


def _line_of(offsets: Sequence[int], pos: int) -> int:
    return bisect.bisect_right(offsets, pos) + 1


def _scan_bytes(data: bytes, path: str, kind: str, state: str,
                assets: Dict[Tuple[str, str], Asset], with_lines: bool,
                image: bool = False, algos: AlgoSet = DEFAULT_ALGOS) -> None:
    offsets: List[int] = []
    if with_lines:
        offsets = [m.start() for m in re.finditer(b"\n", data)]
    for algo, regex in algos.regexes:
        for m in regex.finditer(data):
            asset = assets.setdefault((algo.key, ""), Asset(algo))
            asset.add(Occurrence(path, _line_of(offsets, m.start()) if with_lines else None,
                                 m.group(0).decode("ascii", "replace")[:80], kind, state, image))
    if b"AES" not in data and b"aes" not in data:
        return
    for m in _AES_VARIANT.finditer(data):
        bits = m.group(1).decode()
        mode = m.group(2).decode().upper()
        label = f"AES-{bits}-{mode}"
        asset = assets.setdefault(("aes", label), Asset(algos.by_key["aes"], label, bits, mode))
        asset.add(Occurrence(path, _line_of(offsets, m.start()) if with_lines else None,
                             m.group(0).decode("ascii", "replace")[:80], kind, state, image))


def _source_state(path: Path, kind: str, facts: Optional[BuildFacts]) -> Optional[str]:
    """The linkage of one text file, or None when the file should not count at all.

    With build facts a header is only a declaration (a crypto library's header names every
    algorithm it has), so it is skipped; a source file counts when it was compiled and, if
    a link map is in hand, linked."""
    if facts is None:
        return "unknown"
    if kind == "header":
        return None
    resolved = path.resolve()
    if resolved in facts.linked:
        return "linked"
    return "not-linked"


def _blob_state(path: Path, facts: Optional[BuildFacts]) -> str:
    if facts is None or not facts.have_link_map:
        return "unknown"
    if path.suffix.lower() in IMAGE_SUFFIXES:
        return "linked" if path.stem.lower() == facts.link_map_stem else "not-linked"
    parent = path.parent.name
    for archive in facts.linked_archives:
        parts = Path(archive.replace("\\", "/"))
        if parts.name == path.name and parent in parts.parts:
            return "linked"
    return "not-linked"


def scan_cbom(root: Path, facts: Optional[BuildFacts] = None,
              include_tests: bool = False, binaries: bool = True,
              algos: AlgoSet = DEFAULT_ALGOS,
              components: Optional[Sequence[Any]] = None) -> CbomResult:
    root = Path(root).resolve()
    assets: Dict[Tuple[str, str], Asset] = {}
    scanned = 0
    images = 0
    notes: List[str] = []
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and d.lower() not in DOC_DIRS)
        rel_parts = Path(here).relative_to(root).parts
        in_fixtures = any(p.lower() in FIXTURE_DIRS for p in rel_parts)
        if in_fixtures and not include_tests:
            continue
        for name in sorted(files):
            path = Path(here) / name
            if path.is_symlink():
                continue
            suffix = path.suffix.lower()
            rel = path.relative_to(root).as_posix()
            try:
                size = path.stat().st_size
                if suffix in SOURCE_SUFFIXES or suffix in HEADER_SUFFIXES or _is_config(name):
                    if size > MAX_TEXT_BYTES:
                        continue
                    if suffix in SOURCE_SUFFIXES:
                        kind = "code"
                    elif suffix in HEADER_SUFFIXES:
                        kind = "header"
                    else:
                        kind = "config"
                    state = "unknown" if kind == "config" else _source_state(path, kind, facts)
                    if state is None:
                        continue
                    _scan_bytes(path.read_bytes(), rel, kind, state, assets, True, algos=algos)
                    scanned += 1
                elif binaries and suffix in BLOB_SUFFIXES and size <= MAX_BANNER_BYTES:
                    state = _blob_state(path, facts)
                    data = path.read_bytes()
                    layers = (expand(data, suffix) if suffix in IMAGE_SUFFIXES
                              else None)
                    is_image = suffix in IMAGE_SUFFIXES
                    for blob in ([l.data for l in layers] if layers else [data]):
                        _scan_bytes(blob, rel, "binary", state, assets, False, is_image, algos)
                    scanned += 1
                    if is_image and state != "not-linked":
                        images += 1
            except OSError:
                continue
    if facts is None:
        notes.append("No compile database or link map was given, so this lists what the tree "
                     "contains, not what ships: every algorithm in a crypto library's source "
                     "appears. Pass --compile-db / --link-map to count only what was built.")
    if components is not None:
        if not algos.libraries:
            notes.append("--libraries needs a rule pack with libraries/*.yaml (gangmu-cbom-rules); "
                         "none is installed, so no algorithm was derived from the libraries.")
        else:
            covered = add_library_assets(assets, components, algos, notes)
            notes.append(f"Algorithms derived from {covered} identified librar"
                         f"{'y' if covered == 1 else 'ies'} are what their source provides, "
                         "not proof the firmware calls them (kind: library).")
    notes.extend(f"Algorithm rules from {src}" for src in algos.sources)
    ordered = sorted(assets.values(), key=lambda a: (a.algo.key, a.variant))
    return CbomResult(str(root), ordered, facts is not None, scanned, notes, images)


def add_library_assets(assets: Dict[Tuple[str, str], Asset], components: Iterable[Any],
                       algos: AlgoSet, notes: List[str]) -> int:
    """Add what the capability tables say the identified libraries provide.

    A library *provides* an algorithm when its source contains it; the firmware may still
    never call it, so these hits rank below a call site and count 0.6 at most. Returns the
    number of components the tables covered."""
    covered = 0
    unversioned: List[str] = []
    for comp in components:
        lib = algos.libraries.get(comp.rule_id)
        if lib is None:
            continue
        version = getattr(comp, "version", None)
        keys = lib.algorithms_for(version) if version else None
        if keys is None:
            unversioned.append(f"{lib.name} {version or '(no version)'}".strip())
            continue
        covered += 1
        state = {True: "linked", False: "not-linked", None: "unknown"}[getattr(comp, "linked", None)]
        for key in keys:
            algo = algos.by_key[key]
            asset = assets.setdefault((key, ""), Asset(algo))
            asset.add(Occurrence(comp.directory, None, f"{lib.name} {version}", "library", state))
    if unversioned:
        notes.append("No capability table covers: " + ", ".join(sorted(set(unversioned)))
                     + " (version unknown, unorderable, or outside every release span).")
    return covered


# ------------------------------------------------------------------ output

def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _component(asset: Asset, images: int = 0) -> Dict[str, Any]:
    algo = asset.algo
    props: Dict[str, Any] = {"primitive": algo.primitive,
                             "executionEnvironment": "unknown",
                             "implementationPlatform": "unknown"}
    if asset.variant:
        props["parameterSetIdentifier"] = asset.key_bits
        props["mode"] = _AES_MODES.get(asset.mode, "unknown")
        if asset.mode in ("GCM", "CCM"):
            props["primitive"] = "ae"
        props["nistQuantumSecurityLevel"] = _AES_QUANTUM_LEVEL[asset.key_bits]
    elif algo.quantum == VULNERABLE:
        props["nistQuantumSecurityLevel"] = 0
    occurrences = [{
        "location": o.path,
        **({"line": o.line} if o.line else {}),
        "symbol": o.symbol,
        "additionalContext": f"{o.kind}; build: {o.state}",
    } for o in asset.occurrences]
    properties = [
        {"name": "gangmu:quantumStatus", "value": algo.quantum},
        {"name": "gangmu:linkage", "value": asset.verdict()},
        {"name": "gangmu:hits", "value": str(asset.count)},
        {"name": "gangmu:imageCheck", "value": asset.image_check(images)},
    ]
    if algo.note:
        properties.append({"name": "gangmu:note", "value": algo.note})
    comp: Dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": asset.ref,
        "name": asset.name,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
        "evidence": {
            "identity": [{
                "field": "name", "confidence": round(asset.confidence(), 2),
                "concludedValue": asset.name,
                "methods": [{"technique": "source-code-analysis",
                             "confidence": round(asset.confidence(), 2),
                             "value": "matched by name, not by behaviour"}],
            }],
            "occurrences": occurrences,
        },
        "properties": properties,
    }
    return comp


def to_cbom(result: CbomResult, app_name: str = "firmware",
            app_version: str = "") -> Dict[str, Any]:
    app: Dict[str, Any] = {"type": "firmware", "name": app_name, "bom-ref": "firmware"}
    if app_version:
        app["version"] = app_version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {"components": [{"type": "application", "name": "gangmu",
                                      "version": __version__}]},
            "component": app,
            "properties": [
                {"name": "gangmu:cbom:buildFacts",
                 "value": "used" if result.build_facts_used else "none"},
                *({"name": "gangmu:cbom:note", "value": n} for n in result.notes),
            ],
        },
        "components": [_component(a, result.images) for a in result.assets],
        "dependencies": [{"ref": "firmware", "dependsOn": [a.ref for a in result.counted()]}],
    }


QUANTUM_LABEL = {VULNERABLE: "quantum-vulnerable", SYMMETRIC: "symmetric", PQC: "post-quantum",
                 BROKEN: "legacy/weak", NEUTRAL: "-"}


def cbom_table(result: CbomResult) -> str:
    rows = [("ALGORITHM", "QUANTUM", "BUILD", "IMAGE", "CONF", "HITS", "FIRST SEEN")]
    for a in result.assets:
        first = a.occurrences[0]
        where = first.path + (f":{first.line}" if first.line else "")
        check = a.image_check(result.images)
        rows.append((a.name, QUANTUM_LABEL[a.algo.quantum], a.verdict(),
                     {"present": "yes", "absent": "no"}.get(check, "-"),
                     f"{a.confidence():.2f}", str(a.count), where))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]
    counted = result.counted()
    vulnerable = [a for a in counted if a.algo.quantum == VULNERABLE]
    legacy = [a for a in counted if a.algo.quantum == BROKEN]
    lines.append("")
    lines.append(f"{len(counted)} algorithm(s) counted over {result.files_scanned} file(s); "
                 f"{len(vulnerable)} quantum-vulnerable, {len(legacy)} legacy/weak.")
    absent = [a for a in counted if a.image_check(result.images) == "absent"]
    if absent:
        lines.append(f"{len(absent)} algorithm(s) are named in the sources but not in the firmware "
                     "image (IMAGE = no): compiled out, or named by a macro that leaves no symbol. "
                     "Look at them before dropping them.")
    lines.extend(f"note: {n}" for n in result.notes)
    return "\n".join(lines)


def failing(result: CbomResult, what: Iterable[str]) -> List[Asset]:
    """The counted assets that fall under the ``--fail-on`` classes."""
    want = set(what)
    out = []
    for a in result.counted():
        if "quantum-vulnerable" in want and a.algo.quantum == VULNERABLE:
            out.append(a)
        elif "legacy" in want and a.algo.quantum == BROKEN:
            out.append(a)
    return out
