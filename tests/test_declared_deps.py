"""CMake, vcpkg, Meson and Cargo declarations."""

import json
from pathlib import Path

from gangmu.declared_deps import (_tag_version, read_cargo, read_cmake, read_meson,
                                  read_vcpkg)
from gangmu.rules.loader import load_rules
from gangmu.scan import scan


def _w(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_tags_that_are_releases_are_versions_and_nothing_else_is():
    assert _tag_version("v1.7.17") == "1.7.17"
    assert _tag_version("release-2.2.0") == "2.2.0"
    assert _tag_version("mbedtls-3.6.0") == "3.6.0"
    assert _tag_version("3.0") == "3.0"
    assert _tag_version("main") is None
    assert _tag_version("a" * 40) is None
    assert _tag_version("${FOO_TAG}") is None


def test_fetchcontent_and_externalproject_are_read(tmp_path):
    _w(tmp_path / "CMakeLists.txt", """
include(FetchContent)
FetchContent_Declare(
  cjson   # a comment
  GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
  GIT_TAG v1.7.17)
FetchContent_Declare(lwip GIT_REPOSITORY https://git.savannah.nongnu.org/git/lwip.git GIT_TAG master)
FetchContent_Declare(zlib URL https://zlib.net/zlib-1.3.1.tar.gz)
FetchContent_Declare(var GIT_REPOSITORY https://example.com/x.git GIT_TAG ${VAR_TAG})
ExternalProject_Add(mbedtls_ep GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls GIT_TAG "mbedtls-3.6.0")
""")
    found = {d.name: d for d in read_cmake(tmp_path)}
    assert found["cjson"].version == "1.7.17"
    assert found["cjson"].upstream_url == "https://github.com/DaveGamble/cJSON.git"
    assert found["lwip"].version is None and found["lwip"].description
    assert found["zlib"].version == "1.3.1"
    assert found["var"].version is None
    assert found["mbedtls_ep"].version == "3.6.0"
    assert all(d.manifest_only for d in found.values())


def test_cpm_forms(tmp_path):
    _w(tmp_path / "cmake" / "deps.cmake", """
CPMAddPackage("gh:fmtlib/fmt@10.2.1")
CPMAddPackage(NAME zstd VERSION 1.5.5 GITHUB_REPOSITORY facebook/zstd)
CPMAddPackage(NAME json GITHUB_REPOSITORY nlohmann/json GIT_TAG v3.11.3)
""")
    found = {d.name: d.version for d in read_cmake(tmp_path)}
    assert found == {"fmt": "10.2.1", "zstd": "1.5.5", "json": "3.11.3"}


def test_a_comment_is_not_a_declaration(tmp_path):
    _w(tmp_path / "CMakeLists.txt", "# FetchContent_Declare(x GIT_TAG v1.0)\n")
    assert read_cmake(tmp_path) == []


def test_vcpkg_pins_come_from_overrides_and_host_deps_are_left_out(tmp_path):
    _w(tmp_path / "vcpkg.json", json.dumps({
        "dependencies": ["zlib", {"name": "curl", "version>=": "8.0.0"},
                         {"name": "vcpkg-tool-meson", "host": True}, "openssl"],
        "overrides": [{"name": "openssl", "version": "3.2.1"}]}))
    found = {d.name: d.version for d in read_vcpkg(tmp_path)}
    assert found == {"zlib": None, "curl": None, "openssl": "3.2.1"}


def test_meson_wraps(tmp_path):
    _w(tmp_path / "subprojects" / "zlib.wrap",
       "[wrap-file]\ndirectory = zlib-1.3.1\nsource_url = https://zlib.net/zlib-1.3.1.tar.gz\n")
    _w(tmp_path / "subprojects" / "cjson.wrap",
       "[wrap-git]\nurl = https://github.com/DaveGamble/cJSON.git\nrevision = v1.7.17\n")
    _w(tmp_path / "subprojects" / "tip.wrap",
       "[wrap-git]\nurl = https://example.com/t.git\nrevision = head\n")
    found = {d.name: d.version for d in read_meson(tmp_path)}
    assert found == {"zlib": "1.3.1", "cjson": "1.7.17", "tip": None}


def test_cargo_lock_keeps_only_sys_crates_from_a_registry(tmp_path):
    _w(tmp_path / "Cargo.lock", '''version = 3

[[package]]
name = "myfw"
version = "0.1.0"

[[package]]
name = "libz-sys"
version = "1.1.15"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-sys"
version = "0.1.0"
''')
    found = read_cargo(tmp_path)
    assert [(d.name, d.version) for d in found] == [("libz-sys", "1.1.15")]
    assert found[0].purl == "pkg:cargo/libz-sys@1.1.15"
    assert not found[0].version_is_upstream and found[0].cpe is None


def test_a_scan_reports_cmake_declarations(tmp_path):
    _w(tmp_path / "CMakeLists.txt",
       "FetchContent_Declare(zlib URL https://zlib.net/zlib-1.3.1.tar.gz)\n")
    result = scan(tmp_path, load_rules(Path(__file__).parent / "fixtures" / "rules"))
    names = {(f.rule_id, f.version) for f in result.findings}
    assert ("declared/cmake/zlib", "1.3.1") in names


def test_arduino_libraries_are_read_but_platformio_ones_are_left_alone(tmp_path):
    from gangmu.declared_deps import read_arduino
    _w(tmp_path / "libraries" / "ArduinoJson" / "library.properties",
       "name=ArduinoJson\nversion=6.21.3\nauthor=Benoit Blanchon\n"
       "sentence=JSON library\nurl=https://arduinojson.org\n")
    _w(tmp_path / "libraries" / "NoName" / "library.properties", "version=1.0\n")
    _w(tmp_path / "pio" / "platformio.ini", "[env:a]\n")
    _w(tmp_path / "pio" / "lib" / "Inner" / "library.properties", "name=Inner\nversion=1.0\n")
    found = {d.name: d for d in read_arduino(tmp_path)}
    assert set(found) == {"ArduinoJson"}
    d = found["ArduinoJson"]
    assert d.version == "6.21.3" and d.version_is_upstream
    assert d.supplier == "Benoit Blanchon" and d.upstream_url == "https://arduinojson.org"
    assert d.source == "libraries/ArduinoJson/library.properties"


def test_idf_dependencies_lock(tmp_path):
    from gangmu.declared_deps import read_idf_lock
    _w(tmp_path / "dependencies.lock", """
dependencies:
  espressif/mdns:
    component_hash: abc
    source: {registry_url: https://components.espressif.com/, type: service}
    version: 1.2.0
  espressif/cjson:
    source: {type: service}
    version: 1.7.16
  idf:
    source: {type: idf}
    version: 5.2.1
  broken: {source: {type: local}}
direct_dependencies: [espressif/mdns]
manifest_hash: x
target: esp32
version: 2.0.0
""")
    (tmp_path / "managed_components" / "espressif__mdns").mkdir(parents=True)
    found = {d.name: d for d in read_idf_lock(tmp_path)}
    assert set(found) == {"esp-idf", "espressif/mdns", "espressif/cjson"}
    assert found["esp-idf"].version == "5.2.1" and found["esp-idf"].version_is_upstream
    assert found["espressif/mdns"].present and not found["espressif/mdns"].manifest_only
    assert found["espressif/cjson"].directory is None and found["espressif/cjson"].manifest_only
    assert not found["espressif/mdns"].version_is_upstream
    assert found["espressif/mdns"].version == "1.2.0"
