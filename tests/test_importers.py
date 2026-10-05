from gangmu.importers import parse_gitmodules
from gangmu.importers.common import pick_anchors
from gangmu.importers.gitmodules import _absolute_url

GITMODULES = """
# comment that must be ignored
[submodule "components/mbedtls/mbedtls"]
\tpath = components/mbedtls/mbedtls
\turl = ../../espressif/mbedtls.git

[submodule "components/spiffs/spiffs"]
\tpath = components/spiffs/spiffs
\turl = ../../pellepl/spiffs.git
\tsbom-version = 0.2-265-gad902ca
\tsbom-cpe = cpe:2.3:a:spiffs_project:spiffs:{}:*:*:*:*:*:*:*
\tsbom-url = https://github.com/pellepl/spiffs

[submodule "components/esp_wifi/lib"]
\tpath = components/esp_wifi/lib
\turl = ../../espressif/esp32-wifi-lib.git
\tshallow = true
"""


def test_every_submodule_is_found():
    mods = parse_gitmodules(GITMODULES)
    assert [m.path for m in mods] == [
        "components/mbedtls/mbedtls", "components/spiffs/spiffs",
        "components/esp_wifi/lib"]


def test_relative_urls_resolve_against_the_sdk_origin():
    mods = parse_gitmodules(GITMODULES, origin="https://github.com/espressif/esp-idf")
    assert mods[0].url == "https://github.com/espressif/mbedtls"
    assert mods[1].url == "https://github.com/pellepl/spiffs"


def test_vendor_sbom_metadata_is_read():
    spiffs = parse_gitmodules(GITMODULES)[1]
    assert spiffs.sbom_version == "0.2-265-gad902ca"
    assert spiffs.sbom_url == "https://github.com/pellepl/spiffs"


def test_the_cpe_version_placeholder_becomes_a_wildcard():
    """Espressif writes the version field as the literal {}."""
    spiffs = parse_gitmodules(GITMODULES)[1]
    assert spiffs.sbom_cpe == "cpe:2.3:a:spiffs_project:spiffs:*:*:*:*:*:*:*:*"
    assert "{}" not in spiffs.sbom_cpe


def test_absolute_urls_are_left_alone():
    assert _absolute_url("https://github.com/a/b.git", "x") == "https://github.com/a/b"
    assert _absolute_url("git@github.com:a/b.git", "x") == "git@github.com:a/b"


def test_a_version_header_is_preferred_as_an_anchor(tmp_path):
    (tmp_path / "include").mkdir()
    big = tmp_path / "huge.h"
    big.write_text("x" * 5000)
    version = tmp_path / "include" / "version.h"
    version.write_text("#define V 1")
    picked = pick_anchors(tmp_path, [big, version], limit=1)
    assert picked == [version]


def test_without_a_version_header_the_largest_header_wins(tmp_path):
    small = tmp_path / "small.h"; small.write_text("a")
    large = tmp_path / "large.h"; large.write_text("a" * 500)
    source = tmp_path / "x.c"; source.write_text("a" * 9000)
    assert pick_anchors(tmp_path, [small, large, source], limit=1) == [large]


def _git(cwd, *args):
    import subprocess
    return subprocess.run(
        ["git", "-c", "protocol.file.allow=always", "-c", "user.name=t",
         "-c", "user.email=t@t", *args],
        cwd=cwd, check=True, capture_output=True, text=True).stdout


def _repo(path, files):
    path.mkdir(parents=True)
    _git(path, "init", "-q")
    for name, text in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text)
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "init")
    return path


def _nested_sdk(tmp_path):
    body = "int f%d(int x) {\n  int y = x * %d;\n  return y + %d;\n}\n"
    grand = _repo(tmp_path / "grand", {"g.c": body * 1 % (1, 3, 5), "g.h": "int f1(int);\n"})
    child = _repo(tmp_path / "child", {"c.c": body % (2, 7, 9), "c.h": "int f2(int);\n"})
    _git(child, "submodule", "add", "-q", grand.as_posix(), "deps/grand")
    _git(child, "commit", "-qm", "add grand")
    sdk = _repo(tmp_path / "sdk", {"readme": "sdk"})
    _git(sdk, "submodule", "add", "-q", child.as_posix(), "third/child")
    _git(sdk, "commit", "-qm", "add child")
    _git(sdk, "remote", "add", "origin", sdk.as_posix())
    return sdk


def test_recursive_import_finds_submodules_inside_submodules(tmp_path):
    from gangmu.importers import import_gitmodules
    sdk = _nested_sdk(tmp_path)
    flat = import_gitmodules(sdk.as_posix(), "v", "s", workdir=tmp_path / "w1")
    assert [r.project.path for r in flat] == ["third/child"]

    deep = import_gitmodules(sdk.as_posix(), "v", "s", recursive=True,
                             workdir=tmp_path / "w2")
    by_path = {r.project.path: r for r in deep}
    assert set(by_path) == {"third/child", "third/child/deps/grand"}
    assert all(r.status == "ok" for r in deep)
    grand = by_path["third/child/deps/grand"].rule
    assert "third/child/deps/grand" in grand["component"]["path_globs"]
    # The parent's fingerprint must not swallow the nested project's files.
    assert by_path["third/child"].file_count == 2


# --- west recursive import ---------------------------------------------------

_BODY = "int f%d(int x) {\n  int y = x * %d;\n  return y + %d;\n}\n"


def _head(repo):
    return _git(repo, "rev-parse", "HEAD").strip()


def _west_fixture(tmp_path, *, cycle=False):
    """app -> (zephyr: import true) -> {hal, skipme}; a path-prefix import of tools."""
    hal = _repo(tmp_path / "hal", {"h.c": _BODY % (1, 3, 5), "h.h": "int f1(int);\n"})
    skip = _repo(tmp_path / "skipme", {"s.c": _BODY % (2, 4, 6), "s.h": "int f2(int);\n"})
    lib = _repo(tmp_path / "lib", {"l.c": _BODY % (3, 5, 7), "l.h": "int f3(int);\n"})
    zephyr_manifest = f"""
manifest:
  remotes:
    - name: local
      url-base: {tmp_path.as_posix()}
  projects:
    - name: hal
      remote: local
      revision: {_head(hal)}
      path: modules/hal
    - name: skipme
      remote: local
      revision: {_head(skip)}
      path: modules/skipme
"""
    if cycle:
        zephyr_manifest += "    - name: zephyr\n      remote: local\n      revision: 0123456789abcdef\n      import: true\n"
    zephyr = _repo(tmp_path / "zephyr", {"west.yml": zephyr_manifest, "z.c": _BODY % (4, 6, 8)})
    sdk = _repo(tmp_path / "sdk", {"west.yml": f"""
manifest:
  remotes:
    - name: local
      url-base: {tmp_path.as_posix()}
  projects:
    - name: zephyr
      remote: local
      revision: {_head(zephyr)}
      import:
        name-blocklist: [skipme]
        path-prefix: deps
    - name: lib
      remote: local
      revision: {_head(lib)}
"""})
    _git(sdk, "remote", "add", "origin", sdk.as_posix())
    return sdk


def test_west_import_is_flat_without_recursive(tmp_path):
    from gangmu.importers import import_west
    sdk = _west_fixture(tmp_path)
    flat = import_west(sdk.as_posix(), "v", "s", workdir=tmp_path / "w1")
    assert {r.project.name for r in flat} == {"zephyr", "lib"}


def test_west_recursive_follows_import_with_filters_and_prefix(tmp_path):
    from gangmu.importers import import_west
    sdk = _west_fixture(tmp_path)
    deep = import_west(sdk.as_posix(), "v", "s", recursive=True,
                       workdir=tmp_path / "w2")
    by_name = {r.project.name: r for r in deep}
    assert set(by_name) == {"zephyr", "lib", "hal"}      # skipme is blocklisted
    assert by_name["hal"].project.path == "deps/modules/hal"
    assert all(r.status == "ok" for r in deep)


def test_west_recursive_cuts_cycles_and_respects_depth(tmp_path):
    from gangmu.importers import import_west
    sdk = _west_fixture(tmp_path, cycle=True)
    deep = import_west(sdk.as_posix(), "v", "s", recursive=True,
                       workdir=tmp_path / "w3")
    # zephyr's manifest re-declares (and re-imports) zephyr: the name is already
    # taken by the importing manifest, so it is dropped rather than looped on.
    assert sorted(r.project.name for r in deep) == ["hal", "lib", "zephyr"]
    assert all(r.status == "ok" for r in deep)
    shallow = import_west(sdk.as_posix(), "v", "s", recursive=True, max_depth=0,
                          workdir=tmp_path / "w4")
    assert {r.project.name for r in shallow} == {"zephyr", "lib"}


def test_west_import_forms_are_normalized():
    from gangmu.importers.west import normalize_imports
    assert [i.file for i in normalize_imports(True)] == ["west.yml"]
    assert [i.file for i in normalize_imports("sub/dir")] == ["sub/dir"]
    specs = normalize_imports(["a.yml", {"file": "b.yml", "name-allowlist": "x",
                                         "path-prefix": "/p/"}])
    assert [i.file for i in specs] == ["a.yml", "b.yml"]
    assert specs[1].name_allow == ["x"] and specs[1].prefix == "p"
    assert normalize_imports(False) == []


def test_west_imports_cannot_escape_their_project(tmp_path):
    from gangmu.importers.west import _manifest_texts
    (tmp_path / "x").mkdir()
    (tmp_path / "secret.yml").write_text("manifest: {}")
    assert _manifest_texts(tmp_path / "x", "../secret.yml") == []
