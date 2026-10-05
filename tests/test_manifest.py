"""Vendor manifests: ESP-IDF's sbom.yml and Zephyr's module.yml."""

from gangmu.manifest import read_manifest


def _module(tmp_path, body):
    (tmp_path / "zephyr").mkdir()
    (tmp_path / "zephyr" / "module.yml").write_text(body)
    return tmp_path


def test_zephyr_security_references_give_cpe_purl_and_version(tmp_path):
    _module(tmp_path, """
name: mbedtls
build:
  cmake-ext: True
security:
  external-references:
    - cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*
    - pkg:github/Mbed-TLS/mbedtls@v4.1.0
""")
    facts = read_manifest(tmp_path)
    assert facts.source == "zephyr/module.yml"
    assert facts.version == "4.1.0"
    # The CPE becomes a template: a rule never carries a release in it.
    assert facts.cpe == "cpe:2.3:a:arm:mbed_tls:*:*:*:*:*:*:*:*"
    assert facts.purl == "pkg:github/Mbed-TLS/mbedtls"


def test_purl_qualifiers_are_dropped(tmp_path):
    _module(tmp_path, """
security:
  external-references:
    - pkg:generic/hostap@hostap_2_11?vcs_url=git://w1.fi/hostap.git
""")
    facts = read_manifest(tmp_path)
    assert facts.purl == "pkg:generic/hostap"
    assert facts.version == "hostap_2_11"


def test_a_module_without_security_references_declares_nothing(tmp_path):
    _module(tmp_path, "name: hal_wch\nbuild:\n  cmake: .\n")
    assert read_manifest(tmp_path) is None


def test_esp_idf_manifest_still_wins(tmp_path):
    _module(tmp_path, "security:\n  external-references:\n"
                      "    - pkg:github/x/y@1.0\n")
    (tmp_path / "sbom.yml").write_text("name: thing\nversion: 2.0\n")
    assert read_manifest(tmp_path).version == "2.0"
