"""Yocto and PlatformIO declarations."""

import json
from pathlib import Path

from gangmu.declared_build import _pio_dep, _yocto_version, read_platformio, read_yocto
from gangmu.rules.loader import load_rules
from gangmu.scan import scan


def _w(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _yocto_build(tmp: Path) -> Path:
    _w(tmp / "build" / "conf" / "bblayers.conf")
    _w(tmp / "build" / "tmp" / "deploy" / "licenses" / "core-image" / "license.manifest",
       "PACKAGE NAME: busybox\nPACKAGE VERSION: 1.36.1\nRECIPE NAME: busybox\n"
       "LICENSE: GPL-2.0-only & bzip2-1.0.6\n\n"
       "PACKAGE NAME: busybox-udhcpc\nPACKAGE VERSION: 1.36.1\nRECIPE NAME: busybox\n"
       "LICENSE: GPL-2.0-only\n\n"
       "PACKAGE NAME: libcurl4\nPACKAGE VERSION: 8.5.0\nRECIPE NAME: curl\nLICENSE: curl\n\n"
       "PACKAGE NAME: mytool\nPACKAGE VERSION: 1.0+gitAUTOINC+abc123\nRECIPE NAME: mytool\n"
       "LICENSE: MIT\n")
    return tmp


def test_version_strips_revision_and_refuses_git_snapshots():
    assert _yocto_version("1.36.1-r0") == "1.36.1"
    assert _yocto_version("2.0+git0+abc-r3") is None
    assert _yocto_version("git0+abc") is None


def test_license_manifest_gives_one_entry_per_recipe_version(tmp_path):
    found = {(d.name, d.version) for d in read_yocto(_yocto_build(tmp_path))}
    assert found == {("busybox", "1.36.1"), ("curl", "8.5.0"), ("mytool", None)}


def test_image_manifest_is_used_when_there_is_no_license_manifest(tmp_path):
    _w(tmp_path / "build" / "conf" / "bblayers.conf")
    _w(tmp_path / "build" / "tmp" / "deploy" / "images" / "qemu" / "core.rootfs.manifest",
       "zlib core2-64 1.3.1-r0\nbad line\n")
    assert {(d.name, d.version) for d in read_yocto(tmp_path)} == {("zlib", "1.3.1")}


def test_recipes_are_read_only_when_selected_and_only_without_build_output(tmp_path):
    _w(tmp_path / "build" / "conf" / "bblayers.conf")
    _w(tmp_path / "build" / "conf" / "local.conf",
       'IMAGE_INSTALL:append = " zlib curl \\\n  ${EXTRA}"\n')
    _w(tmp_path / "meta-x" / "recipes-core" / "zlib" / "zlib_1.3.1.bb")
    _w(tmp_path / "meta-x" / "recipes-support" / "curl" / "curl_git.bb")
    _w(tmp_path / "meta-x" / "recipes-support" / "unused" / "unused_9.9.bb")
    found = {d.name: d.version for d in read_yocto(tmp_path)}
    assert found == {"zlib": "1.3.1", "curl": None}


def test_pio_dep_forms():
    assert _pio_dep("bblanchon/ArduinoJson@6.21.3")[:2] == ("ArduinoJson", "6.21.3")
    assert _pio_dep("ArduinoJson@^6.21") == ("ArduinoJson", None, None, "^6.21")
    assert _pio_dep("ArduinoJson")[:2] == ("ArduinoJson", None)
    name, version, url, _ = _pio_dep("https://github.com/o/lib.git#v1.2.3")
    assert (name, version, url) == ("lib", "1.2.3", "https://github.com/o/lib.git")
    assert _pio_dep("${env.lib_deps}") is None and _pio_dep("symlink://../x") is None


def test_platformio_installed_library_beats_the_ini(tmp_path):
    _w(tmp_path / "platformio.ini",
       "[env:esp32]\nplatform = espressif32\nlib_deps =\n"
       "  bblanchon/ArduinoJson@^6.21 ; json\n  knolleary/PubSubClient@2.8\n")
    lib = tmp_path / ".pio" / "libdeps" / "esp32" / "ArduinoJson"
    _w(lib / "library.json", json.dumps({
        "name": "ArduinoJson", "version": "6.21.5", "license": "MIT",
        "repository": {"url": "https://github.com/bblanchon/ArduinoJson.git"}}))
    found = {d.name: d for d in read_platformio(tmp_path)}
    assert found["ArduinoJson"].version == "6.21.5" and found["ArduinoJson"].present \
        and not found["ArduinoJson"].manifest_only
    assert found["PubSubClient"].version == "2.8" and found["PubSubClient"].manifest_only


def test_range_only_library_has_no_version(tmp_path):
    _w(tmp_path / "platformio.ini", "[env:a]\nlib_deps = Foo@^1.0\n")
    (decl,) = read_platformio(tmp_path)
    assert decl.version is None and "range" in decl.description


def test_scan_reports_yocto_and_platformio_without_source(tmp_path, rules_dir):
    _yocto_build(tmp_path)
    _w(tmp_path / "platformio.ini", "[env:a]\nlib_deps = knolleary/PubSubClient@2.8\n")
    result = scan(tmp_path, load_rules(rules_dir, strict=True))
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["declared/yocto/busybox"].version == "1.36.1"
    assert by_rule["declared/yocto/curl"].cpe.startswith("cpe:2.3:a:haxx:curl:8.5.0")
    assert by_rule["declared/yocto/mytool"].version is None
    assert by_rule["declared/platformio/PubSubClient"].version == "2.8"


# ----------------------------------------------------------------------- Conan

from gangmu.declared_build import _conan_ref, read_bazel, read_conan


def test_conan_ref_forms():
    assert _conan_ref("zlib/1.3.1") == ("zlib", "1.3.1")
    assert _conan_ref("zlib/1.3.1@user/stable") == ("zlib", "1.3.1")
    assert _conan_ref("zlib/1.3.1#abc123%1700000000") == ("zlib", "1.3.1")
    assert _conan_ref("openssl/[>=3.0 <4]") == ("openssl", None)
    assert _conan_ref("nonsense") is None


def test_conan_lock_beats_the_conanfile(tmp_path):
    _w(tmp_path / "conanfile.txt", "[requires]\nzlib/[>=1.2]\n")
    _w(tmp_path / "conan.lock", json.dumps({
        "version": "0.5", "requires": ["zlib/1.3.1#rev%123", "openssl/3.2.0#r"],
        "build_requires": ["cmake/3.28.0#r"]}))
    found = {d.name: d.version for d in read_conan(tmp_path)}
    assert found == {"zlib": "1.3.1", "openssl": "3.2.0"}


def test_conanfile_txt_and_py_without_tool_requires(tmp_path):
    _w(tmp_path / "a" / "conanfile.txt",
       "[requires]\nzlib/1.3.1\nfmt/[~10]  # range\n[tool_requires]\ncmake/3.28.0\n")
    _w(tmp_path / "b" / "conanfile.py",
       'class P:\n    requires = "sqlite3/3.45.0", "libcurl/8.5.0"\n'
       '    tool_requires = "cmake/3.28.0"\n'
       '    def requirements(self):\n        self.requires("expat/2.5.0")\n'
       '        self.tool_requires("ninja/1.11")\n')
    found = {d.name: d.version for d in read_conan(tmp_path)}
    assert found == {"zlib": "1.3.1", "fmt": None, "sqlite3": "3.45.0",
                     "libcurl": "8.5.0", "expat": "2.5.0"}


def test_conan_purl_and_cpe(tmp_path):
    _w(tmp_path / "conanfile.txt", "[requires]\nlibcurl/8.5.0\n")
    (decl,) = read_conan(tmp_path)
    assert decl.purl == "pkg:conan/libcurl@8.5.0"
    assert decl.cpe.startswith("cpe:2.3:a:haxx:curl")


# ------------------------------------------------------------------------ Bazel

def test_module_bazel_reads_runtime_deps_only(tmp_path):
    _w(tmp_path / "MODULE.bazel", '''
module(name = "app", version = "1.0")
bazel_dep(name = "zlib", version = "1.3.1.bcr.1")
bazel_dep(name = "rules_cc", version = "0.0.9")
bazel_dep(name = "googletest", version = "1.14.0", dev_dependency = True)
bazel_dep(name = "mbedtls", version = "3.5.0")
single_version_override(module_name = "mbedtls", version = "3.5.1")
bazel_dep(name = "libfoo", version = "1.0")
git_override(module_name = "libfoo", remote = "https://github.com/x/libfoo", commit = "abc")
''')
    found = {d.name: d.version for d in read_bazel(tmp_path)}
    assert found == {"zlib": "1.3.1", "mbedtls": "3.5.1", "libfoo": None}


def test_workspace_http_archive_and_git_repository(tmp_path):
    _w(tmp_path / "WORKSPACE", '''
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
http_archive(
    name = "zlib",
    urls = ["https://zlib.net/zlib-1.2.11.tar.gz"],
    sha256 = "abc",
)
http_archive(name = "curl", strip_prefix = "curl-8.5.0", url = "https://x/y.tar.gz")
http_archive(name = "mystery", url = "https://x/latest.zip")
git_repository(name = "cjson", remote = "https://github.com/DaveGamble/cJSON", tag = "v1.7.17")
http_archive(name = "rules_foreign_cc", url = "https://x/rules_foreign_cc-0.9.0.tar.gz")
''')
    found = {d.name: d.version for d in read_bazel(tmp_path)}
    assert found == {"zlib": "1.2.11", "curl": "8.5.0", "mystery": None, "cjson": "1.7.17"}


def test_unparseable_starlark_is_skipped(tmp_path):
    _w(tmp_path / "MODULE.bazel", "bazel_dep(name = ")
    assert read_bazel(tmp_path) == []


def test_scan_reports_conan_and_bazel(tmp_path, rules_dir):
    _w(tmp_path / "conanfile.txt", "[requires]\nzlib/1.3.1\n")
    _w(tmp_path / "MODULE.bazel", 'bazel_dep(name = "mbedtls", version = "3.5.0")\n')
    result = scan(tmp_path, load_rules(rules_dir, strict=True))
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["declared/conan/zlib"].version == "1.3.1"
    assert by_rule["declared/bazel/mbedtls"].version == "3.5.0"
