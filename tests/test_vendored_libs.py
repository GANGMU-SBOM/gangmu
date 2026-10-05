"""Generic rules for the libraries Chinese chip-vendor SDKs vendor most.

Mbed TLS, FatFs and littlefs already had rules, but only for Zephyr's and
ESP-IDF's directory layouts. These tests pin the properties that make the
generic rules usable elsewhere, without the network: discovery wherever the
vendor put the copy, the tag spellings the upstreams use, and who wins when a
generic rule and a vendor rule both recognise the same directory.
"""

import subprocess
from pathlib import Path

import pytest

from gangmu.discover import discover_roots
from gangmu.model import Evidence, Finding, Technique
from gangmu.rules.loader import RuleBase, load_rules
from gangmu.rules.resolve import resolve
from gangmu.vuln.version import compare, in_range, in_tag_set, normalize_tag
from gangmu.verify import verify_rule

from community import REPO_RULES, needs_rules

pytestmark = needs_rules


@pytest.fixture(scope="module")
def shipped():
    return {r.id: r for r in load_rules(REPO_RULES)}


# ------------------------------------------------------------------ the rules

def test_the_generic_rules_cover_the_releases_the_sdks_ship(shipped):
    mbedtls = set(shipped["generic/mbedtls"].functions.load().versions)
    # Bouffalo bouffalo_sdk / bl_iot_sdk, WinnerMicro wm_iot_sdk, ESP8266_RTOS_SDK
    assert {"2.16.5", "2.28.0", "2.28.1", "2.28.2", "3.4.0", "3.6.5", "4.1.1"} <= mbedtls
    fatfs = set(shipped["generic/fatfs"].functions.load().versions)
    assert {"0.13c", "0.14b", "0.15"} <= fatfs         # ESP8266, WCH, Bouffalo/WinnerMicro
    littlefs = set(shipped["generic/littlefs"].functions.load().versions)
    assert {"2.10.2", "2.11.3"} <= littlefs


def test_the_generic_rules_name_marker_files_and_pin_a_release(shipped):
    for rule_id in ("generic/mbedtls", "generic/fatfs", "generic/littlefs"):
        rule = shipped[rule_id]
        assert len(rule.marker_files) >= 3, rule_id
        assert rule.source.ref and rule.source.ref not in ("master", "main", "HEAD")


def test_the_generic_rules_do_not_claim_a_vendor_rule_s_own_path(shipped):
    """A path glob matching modules/fs/fatfs would give the generic rule the same
    path_match as Zephyr's, and the vendor rule would no longer win in its own
    tree. Discovery relies on markers and the directory name instead."""
    for rule_id in ("generic/mbedtls", "generic/fatfs", "generic/littlefs"):
        assert shipped[rule_id].path_globs == (), rule_id


# ------------------------------------------------------------------- discovery

def _touch(root: Path, *paths: str) -> None:
    for rel in paths:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n")


def _roots(tree: Path, shipped, *ids):
    base = RuleBase(rules=[shipped[i] for i in ids])
    return sorted(p.relative_to(tree.resolve()).as_posix()
                  for p in discover_roots(tree, base))


def test_mbedtls_is_found_under_any_directory_name(tmp_path, shipped):
    # Bouffalo: mbedtls_v3; bl_iot_sdk: security/mbedtls_lts/mbedtls; WinnerMicro: src
    for name in ("components/crypto/mbedtls/mbedtls_v3", "components/mbedtls/src",
                 "components/stage/tls_lib"):
        _touch(tmp_path, f"{name}/library/ssl_tls.c", f"{name}/library/x509_crt.c",
               f"{name}/include/mbedtls/ssl.h")
    # (directories named "mbedtls" are candidates by name as well; what matters
    # is that the renamed ones are found too)
    assert {"components/crypto/mbedtls/mbedtls_v3", "components/mbedtls/src",
            "components/stage/tls_lib"} <= set(_roots(tmp_path, shipped,
                                                      "generic/mbedtls"))


def test_fatfs_is_found_flat_or_in_a_subdirectory(tmp_path, shipped):
    _touch(tmp_path, "components/fs/fatfs/ff.c", "components/fs/fatfs/ff.h",
           "components/fs/fatfs/diskio.h",
           "EVT/EXAM/SDIO/FATFS/ff.c", "EVT/EXAM/SDIO/FATFS/ff.h",
           "EVT/EXAM/SDIO/FATFS/diskio.h")
    assert _roots(tmp_path, shipped, "generic/fatfs") == [
        "EVT/EXAM/SDIO/FATFS", "components/fs/fatfs"]


def test_a_lone_marker_file_is_not_a_component(tmp_path, shipped):
    _touch(tmp_path, "app/ff.c", "app/lfs.c", "app/library/ssl_tls.c")
    base = RuleBase(rules=[shipped[i] for i in
                           ("generic/mbedtls", "generic/fatfs", "generic/littlefs")])
    roots = [p.relative_to(tmp_path.resolve()).as_posix()
             for p in discover_roots(tmp_path, base)]
    assert roots == []


# ----------------------------------------------------------------- tag styles

@pytest.mark.parametrize("tag,expected", [
    ("mbedtls-2.28.10", "2.28.10"),
    ("v3.6.3.1", "3.6.3.1"),
    ("mbedtls-4.0.0-beta", "4.0.0-beta"),
    ("v2.11.3", "2.11.3"),
    # FatFs: the letter is a later release, not a beta
    ("R0.14b", "0.14b"),
    ("R0.15a", "0.15a"),
    ("R0.12c", "0.12c"),
    ("R0.16", "0.16"),
    # but these are still pre-releases
    ("1.0b2", "1.0-b2"),
    ("v1.0-a1", "1.0-a1"),
    ("v2.0-alpha", "2.0-alpha"),
])
def test_upstream_tag_styles_normalise_to_comparable_versions(tag, expected):
    assert normalize_tag(tag) == expected


def test_a_letter_after_the_digits_is_a_later_release():
    assert compare("0.14b", "0.14a") == 1
    assert compare("0.14a", "0.14") == 1
    assert compare("0.15", "0.14b") == 1
    assert compare("1.1.1k", "1.1.1n") == -1         # OpenSSL, same convention
    assert compare("1.1.1w", "1.1.2") == -1
    assert compare("1.0-b2", "1.0") == -1            # a real pre-release stays below


def test_a_letter_release_is_matched_against_cve_ranges():
    # OpenSSL 1.1.1k lies before a fix in 1.1.1n; before the comparator ignored
    # the letter this answered "not affected" for every 1.1.1 release.
    assert in_range("1.1.1k", fixed="1.1.1n") is True
    assert in_range("1.1.1w", fixed="1.1.1n") is False
    assert in_range("0.14a", introduced="0.13", fixed="0.14b") is True
    assert in_range("0.14b", introduced="0.13", fixed="0.14b") is False


def test_fatfs_release_tags_are_found_in_an_osv_tag_list():
    tags = ["R0.13c", "R0.14", "R0.14a", "R0.14b"]
    assert in_tag_set("0.14a", tags) is True
    assert in_tag_set("0.14b", tags) is True
    assert in_tag_set("0.13c", ["R0.14", "R0.14a"]) is False
    assert in_tag_set("0.15", tags) is False


def test_mbedtls_release_tags_are_found_in_an_osv_tag_list():
    tags = ["mbedtls-2.28.0", "mbedtls-2.28.1", "mbedtls-2.28.2"]
    assert in_tag_set("2.28.1", tags) is True
    assert in_tag_set("2.28.10", tags, open_ended=False) is False
    assert in_tag_set("3.6.5", ["v3.6.0", "v3.6.5"]) is True


# ---------------------------------------------------------- generic vs vendor

def _finding(rule_id, techniques, path_match=0, version="4.1.1", conf=0.95,
             source="anchor"):
    return Finding(
        directory="third_party/tls", rule_id=rule_id, upstream_name="Mbed TLS",
        version=version, version_source=source, identity_confidence=conf,
        version_confidence=0.95 if version else 0.0, path_match=path_match,
        evidence=[Evidence(t, 0.9, "x") for t in techniques])


GENERIC = [Technique.HASH_COMPARISON, Technique.AST_FINGERPRINT,
           Technique.SOURCE_CODE_ANALYSIS]
VENDOR = [Technique.HASH_COMPARISON, Technique.AST_FINGERPRINT]
# the vendor rule is the narrower one, so on a tie it would win
SPECIFICITY = {"vendor/sdk/mbedtls": 5, "generic/mbedtls": 0}


def test_better_corroborated_generic_finding_beats_a_vendor_rule_off_its_path():
    vendor = _finding("vendor/sdk/mbedtls", VENDOR, version="4.1.0")
    generic = _finding("generic/mbedtls", GENERIC)
    won = resolve([vendor, generic], SPECIFICITY)
    assert [f.rule_id for f in won] == ["generic/mbedtls"]


def test_a_vendor_rule_still_wins_at_its_own_path():
    vendor = _finding("vendor/sdk/mbedtls", VENDOR, path_match=2, version="4.1.0")
    generic = _finding("generic/mbedtls", GENERIC, path_match=1)
    assert resolve([generic, vendor], SPECIFICITY)[0].rule_id == "vendor/sdk/mbedtls"


def test_a_filename_hint_is_not_a_witness():
    padded = VENDOR + [Technique.FILENAME, Technique.FILENAME]
    vendor = _finding("vendor/sdk/mbedtls", padded)
    generic = _finding("generic/mbedtls", VENDOR + [Technique.SOURCE_CODE_ANALYSIS])
    assert resolve([vendor, generic], SPECIFICITY)[0].rule_id == "generic/mbedtls"


def test_of_two_equal_claims_the_one_with_a_matchable_version_is_reported():
    vendor = _finding("vendor/sdk/mbedtls", VENDOR, version="git-e9a8638fc228")
    generic = _finding("generic/mbedtls", VENDOR, version="2.11.3")
    assert resolve([vendor, generic], SPECIFICITY)[0].rule_id == "generic/mbedtls"


def test_identity_confidence_still_outranks_everything():
    weak = _finding("generic/mbedtls", GENERIC, conf=0.50)
    strong = _finding("vendor/sdk/mbedtls", VENDOR, conf=0.95, version="4.1.0")
    assert resolve([weak, strong], SPECIFICITY)[0].rule_id == "vendor/sdk/mbedtls"


# --------------------------------------------------------------------- verify

def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                        "PATH": "/usr/bin:/bin"})


def _anchored_rule(anchors):
    from gangmu.rules.schema import rule_from_dict
    return rule_from_dict({
        "id": "test/hdr",
        "upstream": {"name": "hdr", "purl": "pkg:generic/hdr", "cpe_status": "none: test",
                     "source": {"kind": "git", "url": "https://example.invalid/h",
                                "ref": "v2"}},
        "identity": {"anchors": anchors},
    }, source_path="test.yaml")


def test_an_anchor_file_that_outlives_a_layout_change_is_not_a_failure(tmp_path):
    """Mbed TLS keeps include/mbedtls/version.h in 3.x without a version in it.
    With another anchor matching the pinned release, the stale one is a note."""
    import hashlib
    (tmp_path / "version.h").write_text("/* declarations only */\n")
    (tmp_path / "build_info.h").write_text("#define VERSION 3\n")
    digest = hashlib.sha256((tmp_path / "build_info.h").read_bytes()).hexdigest()
    rule = _anchored_rule([
        {"path": "version.h", "sha256": {"2.28.0": "0" * 64}},
        {"path": "build_info.h", "sha256": {"3.0.0": digest}}])
    report = verify_rule(rule, tmp_path)
    assert report.ok, report.problems
    assert any("alternative anchor version.h" in line for line in report.checked)


def test_a_stale_anchor_with_nothing_else_matching_still_fails(tmp_path):
    (tmp_path / "version.h").write_text("changed\n")
    rule = _anchored_rule([{"path": "version.h", "sha256": {"2.28.0": "0" * 64}}])
    assert not verify_rule(rule, tmp_path).ok


# ---------------------------------------------- LVGL, libcoap, TinyCrypt (0.7+)

def test_lvgl_libcoap_and_tinycrypt_cover_the_releases_the_sdks_ship(shipped):
    lvgl = set(shipped["generic/lvgl"].functions.load().versions)
    assert {"7.11.0", "8.3.11", "8.4.0", "9.5.0"} <= lvgl      # Bouffalo, WinnerMicro
    coap = set(shipped["generic/libcoap"].functions.load().versions)
    assert {"4.3.4", "4.3.4a", "4.3.5b"} <= coap               # letter releases kept apart
    assert "0.2.7" in set(shipped["generic/tinycrypt"].functions.load().versions)
    for rule_id in ("generic/lvgl", "generic/libcoap", "generic/tinycrypt"):
        rule = shipped[rule_id]
        assert rule.path_globs == () and len(rule.marker_files) >= 3
        # a CPE is written only with NVD evidence; otherwise the search is on record
        assert (rule.cpe and rule.cpe_evidence) or (
            rule.cpe is None and rule.cpe_status.startswith(("none-found", "none-in-nvd")))


def test_lvgl_is_found_whether_or_not_the_vendor_kept_src(tmp_path, shipped):
    for root in ("components/graphics/lvgl_v9", "components/lvgl/lvgl/src"):
        _touch(tmp_path, f"{root}/core/lv_obj.c", f"{root}/core/lv_group.c",
               f"{root}/draw/lv_draw.c")
    assert set(_roots(tmp_path, shipped, "generic/lvgl")) >= {
        "components/graphics/lvgl_v9", "components/lvgl/lvgl/src"}


def test_tinycrypt_is_found_by_its_headers_whatever_the_source_dir_is_called(tmp_path, shipped):
    for root, src in (("bt/tinycrypt", "source"), ("bluetooth/tinycrypt", "src")):
        _touch(tmp_path, f"{root}/{src}/ecc.c", f"{root}/include/tinycrypt/ecc.h",
               f"{root}/include/tinycrypt/aes.h", f"{root}/include/tinycrypt/sha256.h")
    # (the include/tinycrypt directory is a candidate by name too; nested ones
    # are dropped later by the scan)
    assert {"bluetooth/tinycrypt", "bt/tinycrypt"} <= set(
        _roots(tmp_path, shipped, "generic/tinycrypt"))


def test_lvgl_and_libcoap_tags_normalise():
    assert normalize_tag("v8.3.11") == "8.3.11"
    assert normalize_tag("v9.0.0") == "9.0.0"
    assert normalize_tag("v4.3.4a") == "4.3.4a"
    assert compare("4.3.4a", "4.3.4") == 1 and compare("4.3.5", "4.3.4a") == 1
    assert in_tag_set("4.3.4", ["v4.3.3", "v4.3.4", "v4.3.4a"]) is True


# ------------------------- nghttp2, libwebsockets, Paho MQTT C, OpenThread, AWS IoT SDK

NEW_RULES = ("generic/nghttp2", "generic/libwebsockets", "generic/paho-mqtt-c",
             "generic/openthread", "generic/aws-iot-device-sdk-c")


def test_the_sdk_libraries_cover_the_releases_the_sdks_ship(shipped):
    assert {"1.59.0"} <= set(shipped["generic/nghttp2"].functions.load().versions)
    assert {"4.3.3"} <= set(shipped["generic/libwebsockets"].functions.load().versions)
    assert {"1.3.11"} <= set(shipped["generic/paho-mqtt-c"].functions.load().versions)
    # bouffalo_sdk carries 20250612; bl_iot_sdk's copy has exactly 20221027's functions
    assert {"20221027", "20250612"} <= set(
        shipped["generic/openthread"].functions.load().versions)
    assert {"3.0.1"} <= set(shipped["generic/aws-iot-device-sdk-c"].functions.load().versions)
    for rule_id in NEW_RULES:
        rule = shipped[rule_id]
        assert rule.path_globs == () and len(rule.marker_files) >= 3
        # a CPE is written only with NVD evidence; otherwise the search is on record
        assert (rule.cpe and rule.cpe_evidence) or (
            rule.cpe is None and rule.cpe_status.startswith(("none-found", "none-in-nvd")))


def test_the_sdk_library_rules_are_found_wherever_the_vendor_put_them(tmp_path, shipped):
    layouts = {
        "generic/nghttp2": ["lib/nghttp2_session.c", "lib/nghttp2_frame.c",
                            "lib/includes/nghttp2/nghttp2.h"],
        "generic/libwebsockets": ["lib/core/libwebsockets.c", "lib/core/context.c",
                                  "include/libwebsockets.h"],
        "generic/paho-mqtt-c": ["src/MQTTClient.c", "src/MQTTProtocolClient.c",
                                "src/MQTTPacket.c"],
        "generic/openthread": ["src/core/thread/mle.cpp", "include/openthread/instance.h",
                               "src/core/openthread-core-config.h"],
        "generic/aws-iot-device-sdk-c": ["src/aws_iot_mqtt_client.c",
                                         "include/aws_iot_mqtt_client.h",
                                         "include/aws_iot_version.h"],
    }
    for rule_id, files in layouts.items():
        assert files == list(shipped[rule_id].marker_files)
        _touch(tmp_path, *[f"components/{rule_id.split('/')[1]}/{f}" for f in files])
        assert f"components/{rule_id.split('/')[1]}" in _roots(tmp_path, shipped, rule_id)


def test_probes_read_the_versions_the_sdks_carry(shipped):
    def version(rule_id, name, text):
        for probe in shipped[rule_id].probes:
            if probe.file == name and (v := probe.apply(text)):
                return v
        return None
    assert version("generic/nghttp2", "configure.ac",
                   "AC_INIT([nghttp2], [1.59.0], [t-tujikawa@users.sourceforge.net])") == "1.59.0"
    assert version("generic/libwebsockets", "CMakeLists.txt",
                   'set(CPACK_PACKAGE_VERSION_MAJOR "4")\nset(CPACK_PACKAGE_VERSION_MINOR "3")\n'
                   'set(CPACK_PACKAGE_VERSION_PATCH_NUMBER "3")') == "4.3.3"
    assert version("generic/paho-mqtt-c", "src/MQTTClient.c",
                   '#define CLIENT_VERSION  "1.3.11"') == "1.3.11"
    # the CMake probe must not read cmake_minimum_required's VERSION
    assert version("generic/paho-mqtt-c", "CMakeLists.txt",
                   'CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)\nPROJECT("Eclipse Paho C" C)') is None
    # upstream left aws_iot_version.h at 3.0.1 for the 3.1.x releases, so the
    # AWS rule reads its version from the functions instead of a probe
    assert shipped["generic/aws-iot-device-sdk-c"].probes == ()


# ---------------------------------------------- wolfSSL, miniz, nanopb, NimBLE

TLS_AND_CODEC_RULES = ("generic/wolfssl", "generic/miniz", "generic/nanopb", "generic/nimble")


def test_wolfssl_miniz_nanopb_and_nimble_cover_the_releases_the_sdks_ship(shipped):
    # ESP8266 RTOS SDK ships wolfSSL 3.15.7; LuatOS ships miniz 3.1.x and nanopb 0.4.9.1
    assert {"3.15.7", "5.7.0"} <= set(shipped["generic/wolfssl"].functions.load().versions)
    assert {"2.2.0", "3.1.0"} <= set(shipped["generic/miniz"].functions.load().versions)
    assert {"0.3.9.10", "0.4.9.1"} <= set(shipped["generic/nanopb"].functions.load().versions)
    assert {"1.4.0", "1.10.0"} <= set(shipped["generic/nimble"].functions.load().versions)
    for rule_id in TLS_AND_CODEC_RULES:
        rule = shipped[rule_id]
        assert rule.cpe and rule.cpe_evidence, rule_id


def test_wolfssl_miniz_nanopb_and_nimble_are_found_by_their_markers(tmp_path, shipped):
    layouts = {
        "generic/wolfssl": ["wolfssl/ssl.h"],
        "generic/miniz": ["miniz.c", "miniz.h"],
        "generic/nanopb": ["pb_encode.c", "pb_decode.c", "pb.h"],
        "generic/nimble": ["nimble/host/src/ble_hs.c", "nimble/host/src/ble_gap.c"],
    }
    for rule_id, files in layouts.items():
        assert files == list(shipped[rule_id].marker_files)
        _touch(tmp_path, *[f"components/{rule_id.split('/')[1]}/{f}" for f in files])
        assert f"components/{rule_id.split('/')[1]}" in _roots(tmp_path, shipped, rule_id)


def test_wolfssl_and_nanopb_probes_read_the_versions_the_sdks_carry(shipped):
    def version(rule_id, name, text):
        for probe in shipped[rule_id].probes:
            if probe.file == name and (v := probe.apply(text)):
                return v
        return None
    assert version("generic/wolfssl", "wolfssl/version.h",
                   '#define LIBWOLFSSL_VERSION_STRING "3.15.7"') == "3.15.7"
    # LuatOS keeps pb.h under include/, upstream keeps it at the root
    assert version("generic/nanopb", "include/pb.h",
                   '#define NANOPB_VERSION "nanopb-0.4.9.1"') == "0.4.9.1"
    assert version("generic/nanopb", "pb.h",
                   '#define NANOPB_VERSION "nanopb-0.4.9.2"') == "0.4.9.2"
    # MZ_VERSION is miniz's zlib-compatibility number, not a release: no probe
    assert shipped["generic/miniz"].probes == ()


# ------------------- CherryUSB, libsrtp, libyaml, MQTT-C, libmetal, FastLZ, XZ Embedded

SMALL_LIBS = {
    "generic/cherryusb": ["core/usbd_core.c", "core/usbh_core.c", "common/usb_version.h"],
    "generic/libsrtp": ["srtp/srtp.c", "srtp/ekt.c"],
    "generic/libyaml": ["src/scanner.c", "src/parser.c", "include/yaml.h"],
    "generic/mqtt-c": ["src/mqtt.c", "src/mqtt_pal.c", "include/mqtt.h"],
    "generic/libmetal": ["lib/alloc.h", "lib/device.c", "lib/shmem.c"],
    "generic/fastlz": ["fastlz.c", "fastlz.h"],
    "generic/xz-embedded": ["xz_dec_stream.c", "xz_dec_lzma2.c"],
}


def test_the_small_sdk_libraries_cover_the_releases_the_sdks_ship(shipped):
    # bouffalo_sdk: CherryUSB 1.6.1, libsrtp 2.3.0, MQTT-C 1.1.2; wm_iot_sdk: libyaml 0.2.5;
    # LuatOS: FastLZ 0.5.0
    assert "1.6.1" in set(shipped["generic/cherryusb"].functions.load().versions)
    assert "2.3.0" in set(shipped["generic/libsrtp"].functions.load().versions)
    assert "0.2.5" in set(shipped["generic/libyaml"].functions.load().versions)
    assert {"1.1.2", "1.1.6"} <= set(shipped["generic/mqtt-c"].functions.load().versions)
    assert "0.5.0" in set(shipped["generic/fastlz"].functions.load().versions)
    for rule_id in SMALL_LIBS:
        rule = shipped[rule_id]
        assert (rule.cpe and rule.cpe_evidence) or (
            rule.cpe is None and rule.cpe_status.startswith(("none-found", "none-in-nvd"))), rule_id
    # NVD registers these two, with CVEs that point at the upstream
    assert shipped["generic/libsrtp"].cpe.startswith("cpe:2.3:a:cisco:libsrtp:")
    assert shipped["generic/libyaml"].cpe.startswith("cpe:2.3:a:pyyaml:libyaml:")


def test_the_small_sdk_libraries_are_found_wherever_the_vendor_put_them(tmp_path, shipped):
    for rule_id, files in SMALL_LIBS.items():
        assert files == list(shipped[rule_id].marker_files)
        name = rule_id.split("/")[1]
        _touch(tmp_path, *[f"components/{name}/{f}" for f in files])
        assert f"components/{name}" in _roots(tmp_path, shipped, rule_id)


def test_small_library_probes_read_the_versions_the_sdks_carry(shipped):
    def version(rule_id, name, text):
        for probe in shipped[rule_id].probes:
            if probe.file == name and (v := probe.apply(text)):
                return v
        return None
    assert version("generic/cherryusb", "common/usb_version.h",
                   '#define CHERRYUSB_VERSION_STR "v1.6.1"') == "1.6.1"
    assert version("generic/libsrtp", "configure.ac",
                   "AC_INIT([libsrtp2], [2.3.0], [https://github.com/cisco/libsrtp/issues])") == "2.3.0"
    assert version("generic/libyaml", "CMakeLists.txt",
                   "set (YAML_VERSION_MAJOR 0)\nset (YAML_VERSION_MINOR 2)\n"
                   "set (YAML_VERSION_PATCH 5)") == "0.2.5"
    assert version("generic/mqtt-c", "CMakeLists.txt",
                   "project(MQTT-C VERSION 1.1.2 LANGUAGES C)") == "1.1.2"
    assert version("generic/fastlz", "fastlz.h",
                   "#define FASTLZ_VERSION_MAJOR 0\n#define FASTLZ_VERSION_MINOR 5\n"
                   "#define FASTLZ_VERSION_REVISION 0") == "0.5.0"
    # libmetal's VERSION file is the library number, not the year-month release tag
    assert shipped["generic/libmetal"].probes == ()
    assert shipped["generic/xz-embedded"].probes == ()


# ------------------- FlashDB, SFUD, LodePNG (LuatOS)

def test_flashdb_sfud_lodepng_cover_what_luatos_ships(shipped):
    # LuatOS: FlashDB 1.1.0, SFUD 1.1.0, LodePNG 20210627 (its own lv_png: 2020-10-17)
    assert "1.1.0" in set(shipped["generic/flashdb"].functions.load().versions)
    assert "1.1.0" in set(shipped["generic/sfud"].functions.load().versions)
    lode = set(shipped["generic/lodepng"].functions.load().versions)
    assert {"2020-10-17", "2021-06-27", "2022-07-17"} <= lode
    # NVD writes LodePNG versions as dates with dashes; the labels must compare with them
    assert shipped["generic/lodepng"].cpe == "cpe:2.3:a:lodev:lodepng:*:*:*:*:*:*:*:*"
    assert shipped["generic/lodepng"].cpe_evidence == ("CVE-2022-44081",)
    for rule_id in ("generic/flashdb", "generic/sfud"):
        assert shipped[rule_id].cpe is None
        assert shipped[rule_id].cpe_status.startswith("none-found")


def test_flashdb_sfud_lodepng_probes_read_the_versions_the_sdk_carries(shipped):
    def version(rule_id, name, text):
        for probe in shipped[rule_id].probes:
            if probe.file == name and (v := probe.apply(text)):
                return v
        return None
    assert version("generic/flashdb", "inc/fdb_def.h",
                   '#define FDB_SW_VERSION                 "1.1.0"') == "1.1.0"
    # upstream keeps the header in inc/, vendors flatten it
    for name in ("sfud_def.h", "inc/sfud_def.h"):
        assert version("generic/sfud", name,
                       '#define SFUD_SW_VERSION                             "1.1.0"') == "1.1.0"
    assert version("generic/lodepng", "lodepng.h",
                   "LodePNG version 20210627\n\nCopyright (c) 2005-2021") == "2021-06-27"
