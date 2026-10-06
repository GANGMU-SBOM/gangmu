"""CBOM: which cryptographic algorithms the firmware contains, per the build.

The document is validated against the published CycloneDX 1.6 schema (vendored under
tests/fixtures/schemas), like the other output formats.
"""

import json
from pathlib import Path

import pytest

from gangmu.cbom import cbom_table, failing, scan_cbom, to_cbom
from gangmu.cli import main

SCHEMAS = Path(__file__).resolve().parent / "fixtures" / "schemas"

MAIN_C = """\
#include "mbedtls/aes.h"
int main(void) {
    mbedtls_aes_setkey_enc(&c, key, 128);
    const char *n = "AES-256-GCM";
    mbedtls_ecdsa_sign(0);
    mbedtls_md5(in, n, out);
    return 0;
}
"""
UNUSED_C = "int f(void) { return mbedtls_rsa_pkcs1_sign(0); }\n"
HEADER_H = "int mbedtls_dhm_make_public(void);\n"


def _tree(tmp_path: Path, with_db: bool = False) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text(MAIN_C)
    (tmp_path / "src" / "unused.c").write_text(UNUSED_C)
    (tmp_path / "src" / "api.h").write_text(HEADER_H)
    if with_db:
        (tmp_path / "compile_commands.json").write_text(json.dumps([{
            "directory": str(tmp_path), "command": "cc -c src/main.c -o main.o",
            "file": "src/main.c"}]))
    return tmp_path


def _names(result):
    return {a.name: a for a in result.assets}


def test_without_build_facts_everything_is_unverified(tmp_path):
    result = scan_cbom(_tree(tmp_path))
    assets = _names(result)
    assert {"AES", "AES-256-GCM", "ECDSA", "MD5", "RSA", "Diffie-Hellman"} <= set(assets)
    assert {a.verdict() for a in result.assets} == {"unverified"}
    assert result.notes and "not what ships" in result.notes[0]
    assert assets["RSA"].occurrences[0].line == 1
    assert assets["AES"].occurrences[0].path == "src/main.c"


def test_build_facts_keep_only_compiled_sources(tmp_path):
    from gangmu.build.facts import collect_build_facts
    root = _tree(tmp_path, with_db=True)
    facts = collect_build_facts(root, root / "compile_commands.json")
    result = scan_cbom(root, facts)
    assets = _names(result)
    # unused.c was never compiled; a header is only a declaration.
    assert "RSA" not in {a.name for a in result.counted()}
    assert assets["RSA"].verdict() == "not-linked"
    assert "Diffie-Hellman" not in assets
    assert assets["ECDSA"].verdict() == "linked"
    assert assets["ECDSA"].confidence() == 0.9


def test_aes_variant_carries_key_size_and_mode(tmp_path):
    bom = to_cbom(scan_cbom(_tree(tmp_path)))
    comp = next(c for c in bom["components"] if c["name"] == "AES-256-GCM")
    props = comp["cryptoProperties"]["algorithmProperties"]
    assert props["mode"] == "gcm" and props["primitive"] == "ae"
    assert props["nistQuantumSecurityLevel"] == 5
    assert props["parameterSetIdentifier"] == "256"


def test_quantum_status_marks_public_key_algorithms(tmp_path):
    bom = to_cbom(scan_cbom(_tree(tmp_path)))
    by = {c["name"]: c for c in bom["components"]}
    status = lambda n: {p["name"]: p["value"] for p in by[n]["properties"]}["gangmu:quantumStatus"]
    assert status("RSA") == "vulnerable" and status("ECDSA") == "vulnerable"
    assert status("MD5") == "broken"
    assert by["RSA"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0


def test_binary_symbol_names_are_read(tmp_path):
    (tmp_path / "libcrypto.a").write_bytes(b"\x00mbedtls_rsa_gen_key\x00mbedtls_sha512_finish\x00")
    result = scan_cbom(tmp_path)
    assets = _names(result)
    assert assets["RSA"].occurrences[0].kind == "binary"
    assert "SHA-384/SHA-512" in assets
    assert assets["RSA"].occurrences[0].line is None


def test_test_directories_are_skipped_unless_asked(tmp_path):
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "t.c").write_text("mbedtls_rsa_gen_key();\n")
    assert scan_cbom(tmp_path).assets == []
    assert scan_cbom(tmp_path, include_tests=True).assets


def test_pqc_names_are_recognised(tmp_path):
    (tmp_path / "pq.c").write_text("OQS_KEM_alg_ml_kem_768; PQCLEAN_MLDSA65_CLEAN_crypto_sign;\n")
    names = _names(scan_cbom(tmp_path))
    assert names["ML-KEM (Kyber)"].algo.quantum == "pqc"
    assert "ML-DSA (Dilithium)" in names


def test_cyclonedx_cbom_validates_against_the_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    registry = Registry()
    for name, uri in (("spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"),
                      ("jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json")):
        registry = registry.with_resource(
            uri, Resource.from_contents(json.loads((SCHEMAS / name).read_text(encoding="utf-8"))))
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    bom = to_cbom(scan_cbom(_tree(tmp_path)), "gateway", "1.2.0")
    errors = list(jsonschema.Draft7Validator(schema, registry=registry).iter_errors(bom))
    assert not errors, errors[0].message
    assert all(c["type"] == "cryptographic-asset" for c in bom["components"])
    refs = {c["bom-ref"] for c in bom["components"]}
    assert set(bom["dependencies"][0]["dependsOn"]) <= refs


def test_fail_on_selects_the_requested_classes(tmp_path):
    result = scan_cbom(_tree(tmp_path))
    assert {a.name for a in failing(result, ["quantum-vulnerable"])} == {
        "ECDSA", "RSA", "Diffie-Hellman"}
    assert {a.name for a in failing(result, ["legacy"])} == {"MD5"}


def test_cli_table_json_and_fail_on(tmp_path, capsys):
    root = _tree(tmp_path)
    assert main(["cbom", str(root)]) == 0
    assert "quantum-vulnerable" in capsys.readouterr().out
    assert main(["cbom", str(root), "--fail-on", "quantum-vulnerable"]) == 1
    out = tmp_path / "cbom.json"
    assert main(["cbom", str(root), "--format", "cyclonedx", "-o", str(out)]) == 0
    assert json.loads(out.read_text())["bomFormat"] == "CycloneDX"
    assert main(["cbom", str(tmp_path / "nope")]) == 2


def test_table_summary_counts_only_what_the_build_kept(tmp_path):
    from gangmu.build.facts import collect_build_facts
    root = _tree(tmp_path, with_db=True)
    table = cbom_table(scan_cbom(root, collect_build_facts(root, root / "compile_commands.json")))
    assert "not-linked" in table and "1 quantum-vulnerable" in table
