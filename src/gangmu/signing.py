"""Signing SBOMs and evidence bundles.

The evidence bundle's ``manifest.json`` records a sha256 for every file, which
shows the files agree with each other but not who produced them or that nobody
rewrote the manifest too. A detached signature closes that: sign the SBOM, or
the manifest, and anyone holding your public key can check it.

This is deliberately small. It signs with Ed25519 (the optional ``cryptography``
package: ``pip install gangmu-sbom[sign]``), reads and writes ordinary PEM keys
that OpenSSL and ``cosign`` understand, and writes a JSON signature next to the
file. It does **not** do timestamping, key custody or transparency logs: a
signature proves the key signed it, and says nothing about when. For keyless
signing or a timestamp authority use ``cosign sign-blob`` on the same file; the
commercial edition hosts the retention side.

Trust is out of band. The signature file carries the public key for
convenience, but ``verify`` only reports a match when you pass the public key
you trust, and says so when you do not.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

FORMAT = "gangmu-signature/1"
ALGORITHM = "ed25519"
SUFFIX = ".gangmu-sig"


class SigningError(RuntimeError):
    pass


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:                  # pragma: no cover - depends on env
        raise SigningError("signing needs the 'cryptography' package: "
                           "pip install gangmu-sbom[sign]") from exc
    return InvalidSignature, serialization, ed25519


def _raw_public(public_key, serialization) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)


def key_id(raw_public: bytes) -> str:
    return hashlib.sha256(raw_public).hexdigest()[:16]


def generate_keypair(directory: Path, name: str = "gangmu-signing") -> tuple:
    """Write ``<name>.key`` (private, mode 0600) and ``<name>.pub``; refuse to overwrite."""
    _, serialization, ed25519 = _crypto()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = directory / f"{name}.key", directory / f"{name}.pub"
    for path in (priv_path, pub_path):
        if path.exists():
            raise SigningError(f"{path} already exists; not overwriting a key")
    private = ed25519.Ed25519PrivateKey.generate()
    priv_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    priv_path.chmod(0o600)
    pub_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv_path, pub_path


def sign_file(path: Path, key_path: Path, out: Optional[Path] = None,
              signed_at: Optional[str] = None) -> Path:
    _, serialization, ed25519 = _crypto()
    path = Path(path)
    data = path.read_bytes()
    try:
        private = serialization.load_pem_private_key(Path(key_path).read_bytes(), None)
    except (ValueError, TypeError) as exc:
        raise SigningError(f"{key_path}: not a usable unencrypted PEM private key: {exc}")
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SigningError(f"{key_path}: not an Ed25519 key")
    raw = _raw_public(private.public_key(), serialization)
    doc = {
        "format": FORMAT, "algorithm": ALGORITHM, "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "keyId": key_id(raw),
        "publicKey": base64.b64encode(raw).decode(),
        "signedAt": signed_at or _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "signature": base64.b64encode(private.sign(data)).decode(),
    }
    out = Path(out) if out else path.with_name(path.name + SUFFIX)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return out


@dataclass
class Verification:
    valid: bool                   # the signature matches the file under the key it carries
    trusted: Optional[bool]       # None: no trusted key was supplied to compare against
    key_id: str
    signed_at: str
    problem: str = ""


def verify_file(path: Path, sig_path: Optional[Path] = None,
                trusted_key: Optional[Path] = None) -> Verification:
    InvalidSignature, serialization, ed25519 = _crypto()
    path = Path(path)
    sig_path = Path(sig_path) if sig_path else path.with_name(path.name + SUFFIX)
    try:
        doc = json.loads(sig_path.read_text(encoding="utf-8"))
        if doc.get("format") != FORMAT or doc.get("algorithm") != ALGORITHM:
            raise ValueError("unsupported signature format")
        raw = base64.b64decode(doc["publicKey"])
        signature = base64.b64decode(doc["signature"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return Verification(False, None, "", "", f"unreadable signature file: {exc}")
    kid, when = key_id(raw), str(doc.get("signedAt", ""))
    try:
        data = path.read_bytes()
    except OSError as exc:
        return Verification(False, None, kid, when, f"cannot read {path}: {exc}")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(signature, data)
    except (InvalidSignature, ValueError):
        return Verification(False, None, kid, when,
                            "the file does not match the signature (changed after signing, "
                            "or signed by a different key)")
    trusted = None
    if trusted_key is not None:
        try:
            pub = serialization.load_pem_public_key(Path(trusted_key).read_bytes())
            trusted = _raw_public(pub, serialization) == raw
        except (OSError, ValueError) as exc:
            return Verification(False, None, kid, when, f"{trusted_key}: {exc}")
        if not trusted:
            return Verification(True, False, kid, when,
                                "valid, but signed by a different key than the one you trust")
    return Verification(True, trusted, kid, when)
