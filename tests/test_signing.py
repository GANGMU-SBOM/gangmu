import json

import pytest

pytest.importorskip("cryptography")

from gangmu.cli import main
from gangmu.signing import generate_keypair, sign_file, verify_file


def _setup(tmp_path):
    priv, pub = generate_keypair(tmp_path / "keys")
    doc = tmp_path / "sbom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    return priv, pub, doc


def test_round_trip_with_trusted_key(tmp_path):
    priv, pub, doc = _setup(tmp_path)
    sig = sign_file(doc, priv)
    assert sig.name == "sbom.json.gangmu-sig"
    result = verify_file(doc, trusted_key=pub)
    assert result.valid and result.trusted is True
    assert json.loads(sig.read_text())["sha256"]


def test_without_a_trusted_key_the_result_is_not_trusted(tmp_path):
    priv, _, doc = _setup(tmp_path)
    sign_file(doc, priv)
    result = verify_file(doc)
    assert result.valid and result.trusted is None


def test_a_changed_file_fails(tmp_path):
    priv, pub, doc = _setup(tmp_path)
    sign_file(doc, priv)
    doc.write_text('{"bomFormat": "CycloneDX", "x": 1}')
    result = verify_file(doc, trusted_key=pub)
    assert not result.valid and "does not match" in result.problem


def test_a_different_key_is_valid_but_untrusted(tmp_path):
    priv, _, doc = _setup(tmp_path)
    _, other_pub = generate_keypair(tmp_path / "other")
    sign_file(doc, priv)
    result = verify_file(doc, trusted_key=other_pub)
    assert result.valid and result.trusted is False


def test_a_swapped_embedded_key_cannot_forge(tmp_path):
    priv, pub, doc = _setup(tmp_path)
    sig = sign_file(doc, priv)
    attacker, _ = generate_keypair(tmp_path / "attacker")
    forged = sign_file(doc, attacker, out=tmp_path / "forged.sig")
    assert not verify_file(doc, forged, trusted_key=pub).trusted     # attacker's key


def test_garbage_signature_file_is_reported_not_raised(tmp_path):
    _, _, doc = _setup(tmp_path)
    (tmp_path / "bad.sig").write_text("nope")
    result = verify_file(doc, tmp_path / "bad.sig")
    assert not result.valid and "unreadable" in result.problem


def test_keygen_refuses_to_overwrite(tmp_path):
    generate_keypair(tmp_path)
    with pytest.raises(Exception):
        generate_keypair(tmp_path)


def test_cli_flow_and_exit_codes(tmp_path, capsys):
    out = tmp_path / "keys"
    assert main(["keygen", "--out", str(out)]) == 0
    doc = tmp_path / "bom.json"
    doc.write_text("{}")
    key, pub = out / "gangmu-signing.key", out / "gangmu-signing.pub"
    assert main(["sign", str(doc), "--key", str(key)]) == 0
    assert main(["sign-verify", str(doc), "--pubkey", str(pub)]) == 0
    doc.write_text("{ }")
    assert main(["sign-verify", str(doc), "--pubkey", str(pub)]) == 1
