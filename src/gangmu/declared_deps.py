"""Declared components for CMake, vcpkg, Meson and Cargo projects.

These are the places an MCU or gateway project writes down what it pulls in when
it is not a submodule or a Conan/PlatformIO project. Like the other readers they
name the component and its version outright, so they are exact where
fingerprinting would only estimate, and none of them fetches anything.

CMake
    ``FetchContent_Declare`` / ``ExternalProject_Add`` (``GIT_REPOSITORY`` with a
    ``GIT_TAG``, or a ``URL`` to a release archive) and CPM.cmake's
    ``CPMAddPackage``. A tag that is a release (``v1.2.3``, ``release-1.2.3``,
    ``name-1.2.3``) is a version; a branch name or a commit hash is not, and the
    component is reported without one. Arguments built from variables
    (``${FOO_VERSION}``) are not guessed at. Only the build files of the tree
    are read, not those of fetched sources.

vcpkg
    ``vcpkg.json`` ``dependencies`` (``host`` dependencies run on the build
    machine and are left out). ``overrides`` pin an exact version; a
    ``version>=`` is a minimum, not a version, so it is reported without one.

Meson
    ``subprojects/*.wrap``: the release in ``directory`` / ``source_url`` of a
    ``wrap-file``, or the ``revision`` of a ``wrap-git`` when it is a release tag.

Cargo
    ``Cargo.lock``, but only ``*-sys`` crates from a registry or git source:
    those are the ones that bind or bundle a C library, which is what a C/C++
    SBOM is for. The rest of a Rust dependency graph is a different inventory,
    and ``Cargo.lock`` does not say which crates run on the build machine only.

Arduino
    ``library.properties`` of every library in the tree (name, version, url,
    author as supplier). Libraries inside a PlatformIO project are the
    PlatformIO reader's and are skipped here.

ESP-IDF component manager
    ``dependencies.lock``: each locked registry component with its exact
    version, and the ESP-IDF release itself (``idf``). A component whose
    sources are under ``managed_components/`` points there; one that is locked
    but not downloaded is reported without a directory.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from .declared import Declaration
from .declared_build import _NAME_VERSION, _read, _walk
from .declared_linux import _known

ECOSYSTEM_CMAKE = "cmake"
ECOSYSTEM_VCPKG = "vcpkg"
ECOSYSTEM_MESON = "meson"
ECOSYSTEM_CARGO = "cargo"
ECOSYSTEM_ARDUINO = "arduino"
ECOSYSTEM_IDF = "idf-component"

# Names in these build files that the NVD files under another product name.
_ALIASES = {"libz": "zlib", "libpng16": "libpng", "libxml-2.0": "libxml2"}

_RELEASE_TAG = re.compile(r"^(?:[A-Za-z][A-Za-z0-9_.+]*?[-_/])?v?(\d+(?:\.\d+)+(?:[-+.\w]*)?)$")
_HASH = re.compile(r"^[0-9a-f]{7,40}$")


def read_dependency_files(root: Path) -> List[Declaration]:
    root = Path(root).resolve()
    return (read_cmake(root) + read_vcpkg(root) + read_meson(root) + read_cargo(root)
            + read_arduino(root) + read_idf_lock(root))


def _decl(ecosystem: str, name: str, version: Optional[str], source: str, where: Path,
          url: Optional[str] = None, note: Optional[str] = None) -> Declaration:
    display, cpe = _known(_ALIASES.get(name.lower(), name.lower()))
    return Declaration(
        ecosystem=ecosystem, name=name, directory=where, source=source,
        version=version, version_is_upstream=version is not None, cpe=cpe,
        display_name=display, description=note, upstream_url=url, manifest_only=True)


def _tag_version(tag: Optional[str]) -> Optional[str]:
    """The release a git tag names, or None for a branch, a hash or a variable."""
    if not tag or "$" in tag or "@" in tag or _HASH.match(tag):
        return None
    m = _RELEASE_TAG.match(tag.strip())
    return m.group(1) if m else None


# ------------------------------------------------------------------------ CMake

_CMAKE_CALL = re.compile(
    r"\b(FetchContent_Declare|ExternalProject_Add|CPMAddPackage|CPMFindPackage)\s*\(",
    re.IGNORECASE)
_CPM_SHORT = re.compile(r"^(?:gh|gl|bb):([\w.-]+)/([\w.-]+)@([^\s\"]+)$")


def _cmake_text(path: Path) -> str:
    return "\n".join(line.split("#", 1)[0] for line in _read(path).splitlines())


def _balanced(text: str, start: int) -> str:
    """The text between the parenthesis at *start* and its match."""
    depth, i = 0, start
    while i < len(text):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return text[start + 1:]


def _cmake_args(body: str) -> List[str]:
    return [a.strip().strip('"') for a in re.findall(r'"[^"]*"|[^\s"]+', body)]


def _cmake_decls(text: str, source: str, where: Path) -> List[Declaration]:
    out: List[Declaration] = []
    for m in _CMAKE_CALL.finditer(text):
        func = m.group(1).lower()
        args = _cmake_args(_balanced(text, m.end() - 1))
        if not args:
            continue
        keywords: Dict[str, str] = {}
        for i, word in enumerate(args[:-1]):
            if word.isupper() and word.replace("_", "").isalpha():
                keywords.setdefault(word, args[i + 1])
        name = keywords.get("NAME") if func.startswith("cpm") else args[0]
        version = keywords.get("VERSION") if func.startswith("cpm") else None
        url = keywords.get("GIT_REPOSITORY")
        if func.startswith("cpm") and len(args) == 1:
            short = _CPM_SHORT.match(args[0])
            if not short:
                continue
            name, version = short.group(2), _tag_version(short.group(3))
            url = f"https://github.com/{short.group(1)}/{short.group(2)}" \
                if args[0].startswith("gh:") else None
        elif func.startswith("cpm"):
            url = url or (f"https://github.com/{keywords['GITHUB_REPOSITORY']}"
                          if "GITHUB_REPOSITORY" in keywords else None)
            version = version or _tag_version(keywords.get("GIT_TAG"))
        if not name or "$" in name:
            continue
        if version is None:
            version = _tag_version(keywords.get("GIT_TAG"))
        if version is None and "URL" in keywords:
            archive = keywords["URL"].rsplit("/", 1)[-1]
            archive = re.sub(r"(\.tar\.(?:gz|xz|bz2|zst)|\.tgz|\.zip|\.tar)$", "", archive)
            found = None if "$" in archive else _NAME_VERSION.search(archive)
            version = found.group(1) if found else None
        if version and "$" in version:
            version = None
        if url is not None and "$" in url:
            url = None
        out.append(_decl(ECOSYSTEM_CMAKE, name, version, source, where, url=url,
                         note=None if version else
                         f"{source} gives no release version (branch, commit or variable)"))
    return out


def read_cmake(root: Path) -> List[Declaration]:
    out: Dict[str, Declaration] = {}
    for here, files in _walk(root, 4):
        for fname in sorted(files):
            if fname != "CMakeLists.txt" and not fname.endswith(".cmake"):
                continue
            path = here / fname
            source = path.relative_to(root).as_posix()
            try:
                found = _cmake_decls(_cmake_text(path), source, here)
            except OSError:
                continue
            for decl in found:
                out.setdefault(decl.name.lower(), decl)
    return list(out.values())


# ------------------------------------------------------------------------ vcpkg

def read_vcpkg(root: Path) -> List[Declaration]:
    out: Dict[str, Declaration] = {}
    for here, files in _walk(root, 4):
        if "vcpkg.json" not in files:
            continue
        try:
            data = json.loads(_read(here / "vcpkg.json"))
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        source = (here / "vcpkg.json").relative_to(root).as_posix()
        pins = {o["name"]: o["version"] for o in data.get("overrides", [])
                if isinstance(o, dict) and isinstance(o.get("name"), str)
                and isinstance(o.get("version"), str)}
        for dep in data.get("dependencies", []):
            if isinstance(dep, str):
                name, minimum = dep, None
            elif isinstance(dep, dict) and isinstance(dep.get("name"), str):
                if dep.get("host") is True:
                    continue
                name, minimum = dep["name"], dep.get("version>=")
            else:
                continue
            version = pins.get(name)
            note = None
            if version is None:
                note = (f"{source} requires at least {minimum}, which is a minimum and "
                        "not the version in the build" if minimum
                        else f"{source} does not pin a version")
            out.setdefault(name.lower(), _decl(ECOSYSTEM_VCPKG, name, version, source,
                                               here, note=note))
    return list(out.values())


# ------------------------------------------------------------------------ Meson

_WRAP_KEY = re.compile(r"^\s*([\w-]+)\s*=\s*(.+?)\s*$")


def _wrap_sections(text: str) -> Dict[str, Dict[str, str]]:
    sections: Dict[str, Dict[str, str]] = {}
    current: Optional[Dict[str, str]] = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), {})
        elif current is not None:
            m = _WRAP_KEY.match(line)
            if m:
                current[m.group(1)] = m.group(2)
    return sections


def read_meson(root: Path) -> List[Declaration]:
    out: Dict[str, Declaration] = {}
    for here, files in _walk(root, 4):
        if here.name != "subprojects":
            continue
        for fname in sorted(f for f in files if f.endswith(".wrap")):
            sections = _wrap_sections(_read(here / fname))
            source = (here / fname).relative_to(root).as_posix()
            name = fname[:-5]
            version, url = None, None
            if "wrap-file" in sections:
                body = sections["wrap-file"]
                for key in ("directory", "source_filename", "source_url"):
                    text = body.get(key, "").rsplit("/", 1)[-1]
                    text = re.sub(r"(\.tar\.(?:gz|xz|bz2|zst)|\.tgz|\.zip|\.tar)$", "", text)
                    found = _NAME_VERSION.search(text) if text else None
                    if found:
                        version = found.group(1)
                        break
            elif "wrap-git" in sections:
                body = sections["wrap-git"]
                version = _tag_version(body.get("revision"))
                remote = body.get("url", "")
                url = remote if "github.com" in remote else None
            else:
                continue
            out.setdefault(name.lower(), _decl(
                ECOSYSTEM_MESON, name, version, source, here, url=url,
                note=None if version else f"{source} gives no release version"))
    return list(out.values())


# ------------------------------------------------------------------------ Cargo

_CARGO_BLOCK = re.compile(r"\[\[package\]\]\s*\n(.*?)(?=\n\[\[package\]\]|\Z)", re.DOTALL)


def read_cargo(root: Path) -> List[Declaration]:
    out: Dict[tuple, Declaration] = {}
    for here, files in _walk(root, 4):
        if "Cargo.lock" not in files:
            continue
        source = (here / "Cargo.lock").relative_to(root).as_posix()
        for block in _CARGO_BLOCK.findall(_read(here / "Cargo.lock")):
            fields = dict(re.findall(r'^(\w+)\s*=\s*"([^"]*)"', block, re.MULTILINE))
            name, version = fields.get("name"), fields.get("version")
            if not name or not name.endswith("-sys") or not fields.get("source"):
                continue
            # The version is the crate's, not the C library's, so no upstream
            # version or CPE is claimed.
            out.setdefault((name, version), Declaration(
                ecosystem=ECOSYSTEM_CARGO, name=name, directory=here, source=source,
                version=version, version_is_upstream=False,
                description="Rust crate that binds or bundles a C library; the C "
                            "library's own version is not the crate's",
                manifest_only=True))
    return list(out.values())


# ---------------------------------------------------------------------- Arduino

def _properties(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def _inside_platformio(path: Path, root: Path) -> bool:
    for parent in path.parents:
        if (parent / "platformio.ini").is_file():
            return True
        if parent == root:
            break
    return False


def read_arduino(root: Path) -> List[Declaration]:
    out: Dict[tuple, Declaration] = {}
    for here, files in _walk(root, 6):
        if "library.properties" not in files or _inside_platformio(here, root):
            continue
        props = _properties(_read(here / "library.properties"))
        name = props.get("name")
        if not name:
            continue
        version = props.get("version") or None
        display, cpe = _known(_ALIASES.get(name.lower(), name.lower()))
        source = (here / "library.properties").relative_to(root).as_posix()
        out.setdefault((name.lower(), version), Declaration(
            ecosystem=ECOSYSTEM_ARDUINO, name=name, directory=here, source=source,
            version=version, version_is_upstream=version is not None,
            upstream_url=props.get("url") or None, cpe=cpe, display_name=display,
            supplier=props.get("author") or None,
            description=props.get("sentence") or None))
    return list(out.values())


# ------------------------------------------------- ESP-IDF component manager lock

def read_idf_lock(root: Path) -> List[Declaration]:
    import yaml
    out: List[Declaration] = []
    for here, files in _walk(root, 4):
        if "dependencies.lock" not in files:
            continue
        path = here / "dependencies.lock"
        try:
            data = yaml.safe_load(_read(path)) or {}
        except yaml.YAMLError:
            continue
        deps = data.get("dependencies") if isinstance(data, dict) else None
        if not isinstance(deps, dict):
            continue
        source = path.relative_to(root).as_posix()
        for name, entry in deps.items():
            if not isinstance(entry, dict) or not entry.get("version"):
                continue
            version = str(entry["version"])
            kind = (entry.get("source") or {}).get("type") if isinstance(
                entry.get("source"), dict) else None
            short = str(name).split("/")[-1]
            managed = here / "managed_components" / str(name).replace("/", "__")
            if name == "idf" or kind == "idf":
                out.append(Declaration(
                    ecosystem=ECOSYSTEM_IDF, name="esp-idf", directory=here,
                    source=source, version=version, version_is_upstream=True,
                    upstream_url="https://github.com/espressif/esp-idf",
                    display_name="ESP-IDF", manifest_only=True))
                continue
            display, cpe = _known(_ALIASES.get(short.lower(), short.lower()))
            present = managed.is_dir()
            out.append(Declaration(
                ecosystem=ECOSYSTEM_IDF, name=str(name),
                directory=managed if present else None, source=source,
                version=version, version_is_upstream=False, cpe=cpe,
                display_name=display, manifest_only=not present,
                description="ESP-IDF component-registry package; its version is "
                            "the registry package's, which wraps the upstream "
                            "library and is not the upstream release"))
    return out
