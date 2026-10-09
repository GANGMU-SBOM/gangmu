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


def test_the_best_evidence_is_kept_not_the_first(tmp_path):
    from gangmu.build.facts import collect_build_facts
    root = _tree(tmp_path, with_db=True)
    (root / "src" / "a_first.c").write_text("int x = mbedtls_ecdsa_sign(0);\n")   # not compiled
    asset = _names(scan_cbom(root, collect_build_facts(root, root / "compile_commands.json")))["ECDSA"]
    assert asset.occurrences[0].path == "src/main.c" and asset.occurrences[0].state == "linked"


def test_image_check_compares_sources_with_the_built_image(tmp_path):
    root = _tree(tmp_path)
    # the image carries AES and MD5 symbols, but not the ECDSA call the sources make
    (root / "fw.elf").write_bytes(b"\x00mbedtls_aes_crypt_ecb\x00mbedtls_md5_finish\x00")
    result = scan_cbom(root)
    assert result.images == 1
    assets = _names(result)
    assert assets["MD5"].image_check(result.images) == "present"
    assert assets["ECDSA"].image_check(result.images) == "absent"
    assert "IMAGE" in cbom_table(result) and "not in the firmware" in cbom_table(result)
    comp = next(c for c in to_cbom(result)["components"] if c["name"] == "ECDSA")
    assert {p["name"]: p["value"] for p in comp["properties"]}["gangmu:imageCheck"] == "absent"


def test_without_an_image_nothing_is_claimed_about_it(tmp_path):
    result = scan_cbom(_tree(tmp_path))
    assert result.images == 0
    assert _names(result)["RSA"].image_check(result.images) == "not-checked"


def test_image_presence_survives_many_source_hits(tmp_path):
    root = _tree(tmp_path)
    (root / "many.c").write_text("mbedtls_aes_crypt_ecb();\n" * 50)
    (root / "fw.elf").write_bytes(b"\x00mbedtls_aes_crypt_ecb\x00")
    result = scan_cbom(root)
    assert _names(result)["AES"].image_check(result.images) == "present"


# algorithm rules from rule packs --------------------------------------------------

def _pack(base: Path, rules: str, kind: str = "cbom") -> Path:
    (base / "algorithms").mkdir(parents=True)
    (base / "rulebase.json").write_text(json.dumps({"name": "extra", "version": "1", "kind": kind}))
    (base / "algorithms" / "extra.yaml").write_text(rules)
    return base


FRODO = """\
algorithms:
  - key: frodokem
    name: FrodoKEM
    primitive: kem
    quantum: pqc
    patterns: ['FrodoKEM\\w*', 'PQCLEAN_FRODOKEM\\w*']
    note: Not standardised by NIST.
"""


def test_a_pack_adds_an_algorithm_and_can_replace_a_built_in(tmp_path):
    from gangmu.cbom import cbom_roots, load_algo_roots
    (tmp_path / "fw").mkdir()
    root = _tree(tmp_path / "fw")
    (root / "src" / "kem.c").write_text("int k = FrodoKEM_keypair(0); int h = mbedtls_md5(0);\n")
    pack = _pack(tmp_path / "pack", FRODO + """\
  - key: md5
    name: MD5
    primitive: hash
    quantum: neutral
    patterns: ['mbedtls_md5\\w*']
""")
    result = scan_cbom(root, algos=load_algo_roots(cbom_roots([str(pack)])))
    assets = _names(result)
    assert assets["FrodoKEM"].algo.quantum == "pqc"
    assert assets["MD5"].algo.quantum == "neutral"                  # the pack's reading wins
    assert any("2 algorithm rule(s)" in n for n in result.notes)
    assert "FrodoKEM" not in _names(scan_cbom(root))                # built-ins alone do not know it


def test_cli_rules_option_and_bad_rules(tmp_path, capsys):
    (tmp_path / "fw").mkdir()
    root = _tree(tmp_path / "fw")
    (root / "k.c").write_text("FrodoKEM_enc();\n")
    pack = _pack(tmp_path / "pack", FRODO)
    out = tmp_path / "o.json"
    assert main(["cbom", str(root), "--rules", str(pack), "--format", "cyclonedx",
                 "-o", str(out)]) == 0
    assert "FrodoKEM" in out.read_text()

    bad = _pack(tmp_path / "bad", "algorithms:\n  - {key: x, name: X, primitive: nope, "
                                  "quantum: pqc, patterns: [x]}\n")
    assert main(["cbom", str(root), "--rules", str(bad)]) == 2
    assert "primitive 'nope'" in capsys.readouterr().err


@pytest.mark.parametrize("entry, message", [
    ("{key: a, name: A, primitive: kem, quantum: maybe, patterns: [a]}", "quantum 'maybe'"),
    ("{key: a, name: A, primitive: kem, quantum: pqc, patterns: ['(']}", "usable ASCII regex"),
    ("{key: A!, name: A, primitive: kem, quantum: pqc, patterns: [a]}", "key 'A!'"),
    ("{key: a, name: A, primitive: kem, quantum: pqc}", "missing 'patterns'"),
])
def test_an_invalid_algorithm_rule_is_refused_with_the_reason(tmp_path, entry, message):
    from gangmu.cbom import CbomRuleError, cbom_roots, load_algo_roots
    pack = _pack(tmp_path / "p", f"algorithms:\n  - {entry}\n")
    with pytest.raises(CbomRuleError, match=message):
        load_algo_roots(cbom_roots([str(pack)]))


def test_installed_packs_of_another_kind_are_not_read_for_algorithms(tmp_path):
    from gangmu import cbom
    from gangmu.core import packs
    sbom_pack = _pack(tmp_path / "s", FRODO, kind="sbom")
    cbom_pack = _pack(tmp_path / "c", FRODO.replace("frodokem", "frodo2"), kind="cbom")
    roots = packs.default_roots(packs=[("s", sbom_pack), ("c", cbom_pack)], kind="cbom")
    assert [r.pack_name for r in roots] == ["extra"] and roots[0].path == cbom_pack
    assert "frodo2" in cbom.load_algo_roots(roots).by_key


# what an identified library provides ----------------------------------------------

LIBS = """\
libraries:
  - rule: generic/mbedtls
    name: Mbed TLS
    releases:
      - {introduced: "2.0", fixed: "3.0", algorithms: [aes, rsa, md5, des], source: "tags v2.28.9"}
      - {introduced: "3.0", algorithms: [aes, rsa, ecdsa], source: "tags v3.6.2"}
"""


def _lib_pack(base: Path, text: str = LIBS) -> Path:
    pack = _pack(base, FRODO)
    (pack / "libraries").mkdir()
    (pack / "libraries" / "mbedtls.yaml").write_text(text)
    return pack


def _finding(version, linked=None, rule="generic/mbedtls"):
    from gangmu.model import Finding
    return Finding(directory="third_party/mbedtls", rule_id=rule, upstream_name="Mbed TLS",
                   version=version, linked=linked)


def test_the_release_span_holding_the_version_decides_the_algorithms(tmp_path):
    from gangmu.cbom import cbom_roots, load_algo_roots
    algos = load_algo_roots(cbom_roots([str(_lib_pack(tmp_path / "p"))]))
    lib = algos.libraries["generic/mbedtls"]
    assert lib.algorithms_for("2.28.9") == ("aes", "rsa", "md5", "des")
    assert lib.algorithms_for("3.6.2") == ("aes", "rsa", "ecdsa")
    assert lib.algorithms_for("1.3.0") is None                      # before every span


def test_library_hits_are_marked_as_provided_not_called(tmp_path):
    from gangmu.cbom import cbom_roots, load_algo_roots
    (tmp_path / "fw").mkdir()
    root = tmp_path / "fw"
    (root / "a.c").write_text("int x;\n")
    algos = load_algo_roots(cbom_roots([str(_lib_pack(tmp_path / "p"))]))
    result = scan_cbom(root, algos=algos, components=[_finding("2.28.9", linked=True)])
    assets = _names(result)
    assert set(assets) == {"AES", "RSA", "MD5", "DES/3DES"}
    rsa = assets["RSA"]
    assert rsa.occurrences[0].kind == "library" and rsa.verdict() == "linked"
    assert rsa.confidence() == 0.6                                  # below a linked call site
    assert any("derived from 1 identified library" in n for n in result.notes)
    comp = next(c for c in to_cbom(result)["components"] if c["name"] == "RSA")
    assert comp["evidence"]["occurrences"][0]["additionalContext"] == "library; build: linked"


def test_a_library_the_build_left_out_does_not_count(tmp_path):
    from gangmu.cbom import cbom_roots, load_algo_roots
    (tmp_path / "fw").mkdir()
    algos = load_algo_roots(cbom_roots([str(_lib_pack(tmp_path / "p"))]))
    result = scan_cbom(tmp_path / "fw", algos=algos,
                       components=[_finding("3.6.2", linked=False)])
    assert result.assets and result.counted() == []


def test_unknown_versions_and_libraries_are_said_not_guessed(tmp_path):
    from gangmu.cbom import cbom_roots, load_algo_roots
    (tmp_path / "fw").mkdir()
    algos = load_algo_roots(cbom_roots([str(_lib_pack(tmp_path / "p"))]))
    result = scan_cbom(tmp_path / "fw", algos=algos, components=[
        _finding(None), _finding("0.9"), _finding("1.0", rule="generic/unknown")])
    assert result.assets == []
    assert any("No capability table covers: Mbed TLS (no version), Mbed TLS 0.9" in n
               for n in result.notes)


def test_libraries_without_a_table_pack_say_so(tmp_path):
    (tmp_path / "fw").mkdir()
    result = scan_cbom(tmp_path / "fw", components=[_finding("3.6.2")])
    assert any("needs a rule pack with libraries/*.yaml" in n for n in result.notes)


def test_a_library_rule_naming_an_unknown_algorithm_is_refused(tmp_path):
    from gangmu.cbom import CbomRuleError, cbom_roots, load_algo_roots
    bad = _lib_pack(tmp_path / "p", "libraries:\n  - {rule: r, name: R, releases: "
                                   "[{algorithms: [aes, nope]}]}\n")
    with pytest.raises(CbomRuleError, match="unknown algorithm key.*nope"):
        load_algo_roots(cbom_roots([str(bad)]))


def test_cli_libraries_flag_uses_the_identified_components(tmp_path, monkeypatch, capsys):
    import gangmu.cli as cli
    (tmp_path / "fw").mkdir()
    (tmp_path / "fw" / "a.c").write_text("int x;\n")
    pack = _lib_pack(tmp_path / "p")
    monkeypatch.setattr(cli, "_identified_components",
                        lambda root, facts: [_finding("3.6.2", linked=True)])
    out = tmp_path / "o.json"
    assert main(["cbom", str(tmp_path / "fw"), "--libraries", "--rules", str(pack),
                 "--format", "cyclonedx", "-o", str(out)]) == 0
    assert {c["name"] for c in json.loads(out.read_text())["components"]} == {"AES", "RSA", "ECDSA"}
    # without the flag nothing is derived
    assert main(["cbom", str(tmp_path / "fw"), "--rules", str(pack)]) == 0
    assert "RSA" not in capsys.readouterr().out
