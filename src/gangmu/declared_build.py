"""Declared components for Yocto/OpenEmbedded, PlatformIO, Conan and Bazel projects.

Both systems already write down what goes into the product, and both spell the
version out, so reading them is exact where fingerprinting would only estimate.

Yocto
    A finished build leaves the answer in ``tmp*/deploy``:
    ``licenses/<image>/license.manifest`` lists every package with its recipe,
    version and licence, and ``images/<machine>/<image>.manifest`` lists every
    installed package with its version. Those are what shipped, so they win.
    With no build output, the recipes the image selects are read instead:
    ``IMAGE_INSTALL`` in ``conf/local.conf`` and image recipes, matched against
    ``<name>_<version>.bb`` files in the layers. A recipe tree holds hundreds of
    recipes and an image installs a few dozen, so unselected recipes are never
    reported. Recipes that track a branch (``_git.bb``, ``%``) have no release
    version and are reported without one rather than with a guess.

PlatformIO
    ``.pio/libdeps/<env>/<lib>/library.json`` (or ``library.properties``) is the
    library that was actually downloaded, with its exact version, and its
    directory is real source the rule base can fingerprint as well. Libraries
    only named in ``platformio.ini`` ``lib_deps`` are reported from the file: with
    their version when it is pinned, without one when it is a range (``^1.2``),
    since a range is a promise about what may be installed and not a fact.

Conan
    ``conan.lock`` (exact, with its revisions stripped) is read first, then
    ``conanfile.txt`` ``[requires]`` and ``conanfile.py`` ``requires`` /
    ``self.requires(...)``. ``tool_requires`` and ``build_requires`` are left out:
    they run on the build machine and are not in the firmware. A version range
    (``[>=3.0 <4]``) is not a version and is reported without one.

Bazel
    ``MODULE.bazel`` ``bazel_dep`` (the Bazel Central Registry's ``.bcr.N``
    packaging suffix is dropped to get the upstream release), and the
    ``http_archive`` / ``git_repository`` rules of a ``WORKSPACE``, whose version
    is read from ``strip_prefix``, the URL or the tag. Dev dependencies and the
    ``rules_*`` / ``bazel_*`` toolchain modules are skipped. These files are
    Starlark, which is close enough to Python to be read with ``ast``; a file that
    does not parse is skipped, not guessed at.

None of the readers fetches anything.
"""

from __future__ import annotations

import ast
import configparser
import json
import os
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .declared import Declaration
from .declared_linux import _known, _literal

ECOSYSTEM_YOCTO = "yocto"
ECOSYSTEM_PLATFORMIO = "platformio"
ECOSYSTEM_CONAN = "conan"
ECOSYSTEM_BAZEL = "bazel"

_SKIP = {".git", "node_modules", "__pycache__", "sstate-cache", "downloads", "work",
         "work-shared", "cache", "buildhistory"}
_MAX_DEPTH = 5


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _walk(root: Path, max_depth: int = _MAX_DEPTH,
          keep_hidden: bool = False) -> Iterator[Tuple[Path, List[str]]]:
    base = len(root.parts)
    for here, dirs, files in os.walk(root):
        depth = len(Path(here).parts) - base
        dirs[:] = [d for d in dirs if d not in _SKIP and depth < max_depth
                   and (keep_hidden or not d.startswith("."))]
        yield Path(here), files


def read_build_ecosystems(root: Path) -> List[Declaration]:
    root = Path(root).resolve()
    return (read_yocto(root) + read_platformio(root) + read_conan(root)
            + read_bazel(root))


# ------------------------------------------------------------------------ Yocto

_PV_REVISION = re.compile(r"-r\d+$")


def _yocto_version(raw: str) -> Optional[str]:
    """The upstream release from a Yocto ``PV-PR``, or None for a git snapshot."""
    version = _PV_REVISION.sub("", raw.strip())
    if not version or version.startswith("git") or "+git" in version \
            or "AUTOINC" in version or "+svn" in version:
        return None
    return version


def _yocto_decl(name: str, version: Optional[str], source: str, directory: Path,
                license: Optional[str] = None, note: Optional[str] = None
                ) -> Declaration:
    display, cpe = _known(name)
    return Declaration(
        ecosystem=ECOSYSTEM_YOCTO, name=name, directory=directory, source=source,
        version=version, version_is_upstream=version is not None,
        license=license, cpe=cpe, display_name=display, description=note,
        manifest_only=True)


def read_yocto(root: Path) -> List[Declaration]:
    builds = [here for here, files in _walk(root, 4)
              if (here / "conf" / "bblayers.conf").is_file()]
    out: List[Declaration] = []
    for build in builds:
        found = _yocto_build_output(root, build)
        out.extend(found if found else _yocto_recipes(root, build))
    return out


def _yocto_build_output(root: Path, build: Path) -> List[Declaration]:
    out: Dict[Tuple[str, Optional[str]], Declaration] = {}
    for tmp in sorted(build.glob("tmp*")):
        for path in sorted((tmp / "deploy" / "licenses").glob("*/license.manifest")):
            for block in _read(path).split("\n\n"):
                fields = dict(line.split(": ", 1) for line in block.splitlines()
                              if ": " in line)
                recipe = fields.get("RECIPE NAME") or fields.get("PACKAGE NAME")
                if not recipe:
                    continue
                version = _yocto_version(fields.get("PACKAGE VERSION", ""))
                out.setdefault((recipe, version), _yocto_decl(
                    recipe, version, path.relative_to(root).as_posix(), path.parent,
                    license=fields.get("LICENSE"),
                    note=None if version else "tracks a branch; no release version"))
    if out:
        return list(out.values())
    for tmp in sorted(build.glob("tmp*")):
        for path in sorted((tmp / "deploy" / "images").glob("*/*.manifest")):
            for line in _read(path).splitlines():
                parts = line.split()
                if len(parts) != 3:
                    continue
                name, _arch, raw = parts
                version = _yocto_version(raw)
                out.setdefault((name, version), _yocto_decl(
                    name, version, path.relative_to(root).as_posix(), path.parent,
                    note=None if version else "tracks a branch; no release version"))
    return list(out.values())


_IMAGE_INSTALL = re.compile(
    r'^(?:IMAGE_INSTALL|CORE_IMAGE_EXTRA_INSTALL)(?:[:_][\w-]+)*\s*'
    r'(?:\+=|\?=|:=|=|\.=)\s*"([^"]*)"', re.M)


def _selected_recipes(root: Path, build: Path) -> Set[str]:
    texts = []
    local = build / "conf" / "local.conf"
    if local.is_file():
        texts.append(_read(local))
    for here, files in _walk(root, _MAX_DEPTH):
        if "images" in here.parts and here.parent.name.startswith("recipes-"):
            texts.extend(_read(here / f) for f in files
                         if f.endswith((".bb", ".bbappend", ".inc")))
    selected: Set[str] = set()
    for text in texts:
        for value in _IMAGE_INSTALL.findall(text.replace("\\\n", " ")):
            selected.update(t for t in value.split() if "$" not in t)
    return selected


def _yocto_recipes(root: Path, build: Path) -> List[Declaration]:
    selected = _selected_recipes(root, build)
    if not selected:
        return []
    source = (build / "conf" / "local.conf").relative_to(root).as_posix()
    out: Dict[str, Declaration] = {}
    for here, files in _walk(root, _MAX_DEPTH + 2):
        if not any(p.startswith("recipes-") for p in here.parts):
            continue
        for fname in sorted(files):
            if not fname.endswith(".bb"):
                continue
            stem = fname[:-3]
            name, _, version = stem.partition("_")
            if name not in selected or name in out:
                continue
            clean = None if not version or version in ("git", "svn") or "%" in version \
                else version
            out[name] = _yocto_decl(
                name, clean, (here / fname).relative_to(root).as_posix(), here,
                note=f"selected by IMAGE_INSTALL in {source}")
    return list(out.values())


# -------------------------------------------------------------------- PlatformIO

_EXACT = re.compile(r"^=?v?(\d+(?:\.\d+)*[\w.+-]*)$")
_RANGE_CHARS = re.compile(r"[\^~<>*|,\s]")


def _pio_dep(entry: str) -> Optional[Tuple[str, Optional[str], Optional[str], Optional[str]]]:
    """(name, exact version, upstream url, constraint) from one ``lib_deps`` line."""
    entry = re.split(r"\s[;#]", entry.strip() + " ")[0].strip()
    if not entry or entry.startswith(("${", "-<", "symlink://", "file://")):
        return None
    url = None
    if "://" in entry:
        label, _, rest = entry.partition("=")
        if "://" in rest and "://" not in label:
            entry, url = label.strip(), rest.strip()
        else:
            url, entry = entry, ""
    if url:
        ref = url.partition("#")[2] or None
        bare = url.partition("#")[0]
        name = entry or bare.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        version = ref[1:] if ref and re.match(r"^v\d", ref) else (
            ref if ref and re.match(r"^\d", ref) else None)
        return name, version, bare if "github.com" in bare else None, ref
    name, _, spec = entry.partition("@")
    name, spec = name.strip(), spec.strip()
    if not name:
        return None
    if not spec:
        return name.rsplit("/", 1)[-1], None, None, None
    m = _EXACT.match(spec) if not _RANGE_CHARS.search(spec) else None
    return name.rsplit("/", 1)[-1], (m.group(1) if m else None), None, spec


def _pio_installed(root: Path) -> Dict[str, Declaration]:
    out: Dict[str, Declaration] = {}
    for ini in _pio_projects(root):
        proj = ini.parent
        homes = [proj / ".pio" / "libdeps", proj / "lib"]
        for home in homes:
            if not home.is_dir():
                continue
            for here, files in _walk(home, 3, keep_hidden=True):
                meta = None
                if "library.json" in files:
                    try:
                        meta = json.loads(_read(here / "library.json"))
                    except ValueError:
                        meta = None
                    if isinstance(meta, dict):
                        name, version = meta.get("name"), meta.get("version")
                        repo = (meta.get("repository") or {})
                        url = repo.get("url") if isinstance(repo, dict) else None
                        lic = meta.get("license")
                    else:
                        meta = None
                if meta is None and "library.properties" in files:
                    props = dict(
                        line.split("=", 1) for line in
                        _read(here / "library.properties").splitlines() if "=" in line)
                    name, version = props.get("name"), props.get("version")
                    url, lic = props.get("url"), None
                    meta = props
                if not meta or not name:
                    continue
                key = str(name).strip().lower()
                if key in out:
                    continue
                display, cpe = _known(key)
                out[key] = Declaration(
                    ecosystem=ECOSYSTEM_PLATFORMIO, name=str(name).strip(),
                    directory=here.resolve(),
                    source=(here / ("library.json" if "library.json" in files
                                    else "library.properties")).relative_to(root).as_posix(),
                    version=str(version).strip() if version else None,
                    version_is_upstream=bool(version),
                    license=lic if isinstance(lic, str) else None,
                    upstream_url=url if isinstance(url, str) else None,
                    cpe=cpe, display_name=display)
    return out


def _pio_projects(root: Path) -> List[Path]:
    return [here / "platformio.ini" for here, files in _walk(root, 4)
            if "platformio.ini" in files]


def read_platformio(root: Path) -> List[Declaration]:
    inis = _pio_projects(root)
    if not inis:
        return []
    out = dict(_pio_installed(root))
    for ini in inis:
        parser = configparser.ConfigParser(interpolation=None, strict=False,
                                           allow_no_value=True, inline_comment_prefixes=(";",))
        try:
            parser.read_string(_read(ini))
        except configparser.Error:
            continue
        source = ini.relative_to(root).as_posix()
        for section in parser.sections():
            if not (section.startswith("env") or section == "platformio"):
                continue
            for line in (parser.get(section, "lib_deps", fallback="") or "").splitlines():
                parsed = _pio_dep(line)
                if not parsed:
                    continue
                name, version, url, constraint = parsed
                key = name.lower()
                if key in out:
                    continue
                display, cpe = _known(key)
                note = (f"{source} requires {name}"
                        + (f" {constraint}, which is a range, not an installed version"
                           if constraint and not version else ""))
                out[key] = Declaration(
                    ecosystem=ECOSYSTEM_PLATFORMIO, name=name, directory=ini.parent.resolve(),
                    source=source, version=version, version_is_upstream=version is not None,
                    upstream_url=url, cpe=cpe, display_name=display, description=note,
                    manifest_only=True)
    return list(out.values())


# ------------------------------------------------------------------------ Conan

# Conan Center and NVD disagree on a few names.
_ALIASES = {"sqlite3": "sqlite", "libcurl": "curl", "libpng": "libpng", "zlib-ng": "zlib-ng",
            "libexpat": "expat", "libjpeg-turbo": "libjpeg-turbo"}


def _conan_ref(ref: str) -> Optional[Tuple[str, Optional[str]]]:
    """``name/version`` from a Conan reference; the version is None for a range."""
    ref = ref.strip().split("@", 1)[0].split("#", 1)[0].split("%", 1)[0]
    if "/" not in ref:
        return None
    name, version = (part.strip() for part in ref.split("/", 1))
    if not name or not re.match(r"^[A-Za-z0-9_.+-]+$", name):
        return None
    if not version or any(c in version for c in "[]<>=~^*|, "):
        return None if not version else (name, None)
    return name, version


def _conan_decl(name: str, version: Optional[str], source: str, where: Path,
                note: Optional[str] = None) -> Declaration:
    display, cpe = _known(_ALIASES.get(name.lower(), name.lower()))
    return Declaration(
        ecosystem=ECOSYSTEM_CONAN, name=name, directory=where, source=source,
        version=version, version_is_upstream=version is not None, cpe=cpe,
        display_name=display, description=note, manifest_only=True)


def _py_strings(node: ast.AST) -> List[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [v for el in node.elts for v in _py_strings(el)]
    return []


def read_conan(root: Path) -> List[Declaration]:
    out: Dict[Tuple[str, str], Declaration] = {}
    projects = [(here, files) for here, files in _walk(root, 4)
                if {"conanfile.txt", "conanfile.py", "conan.lock"} & set(files)]
    for here, files in projects:
        refs: List[Tuple[str, str]] = []          # (reference, source file)
        if "conan.lock" in files:
            refs += [(r, "conan.lock") for r in _conan_lock_refs(here / "conan.lock")]
        if not refs and "conanfile.txt" in files:
            refs += [(r, "conanfile.txt") for r in _conanfile_txt(here / "conanfile.txt")]
        if not refs and "conanfile.py" in files:
            refs += [(r, "conanfile.py") for r in _conanfile_py(here / "conanfile.py")]
        for ref, fname in refs:
            parsed = _conan_ref(ref)
            if not parsed:
                continue
            name, version = parsed
            source = (here / fname).relative_to(root).as_posix()
            out.setdefault((name, version or ""), _conan_decl(
                name, version, source, here,
                note=None if version else f"{source} gives a version range, not a version"))
    return list(out.values())


def _conan_lock_refs(path: Path) -> List[str]:
    try:
        data = json.loads(_read(path))
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    refs = [r for r in data.get("requires", []) if isinstance(r, str)]
    nodes = ((data.get("graph_lock") or {}).get("nodes") or {})        # Conan 1 lock
    for node_id, node in nodes.items() if isinstance(nodes, dict) else []:
        if node_id != "0" and isinstance(node, dict) and isinstance(node.get("ref"), str) \
                and not node.get("context") == "build":
            refs.append(node["ref"])
    return refs


def _conanfile_txt(path: Path) -> List[str]:
    refs, section = [], None
    for line in _read(path).splitlines():
        line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("[") else line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
        elif section == "requires" and line:
            refs.append(line)
    return refs


def _conanfile_py(path: Path) -> List[str]:
    try:
        tree = ast.parse(_read(path))
    except (SyntaxError, ValueError):
        return []
    refs: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "requires" for t in node.targets):
            refs += _py_strings(node.value)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr == "requires" and node.args):
            refs += _py_strings(node.args[0])
    return refs


# ------------------------------------------------------------------------- Bazel

_BAZEL_SKIP = re.compile(r"^(rules_|bazel_|platforms$|stardoc$|apple_support$|aspect_|"
                         r"buildifier|buildozer|toolchains_)")
_BCR_SUFFIX = re.compile(r"\.bcr\.\d+$")
_NAME_VERSION = re.compile(r"[-_]v?(\d+(?:\.\d+)+(?:[-+.\w]*)?)$")
_ARCHIVE_EXT = re.compile(r"(\.tar\.(?:gz|xz|bz2|zst)|\.tgz|\.zip|\.tar)$")


def _starlark_calls(path: Path):
    try:
        tree = ast.parse(_read(path))
    except (SyntaxError, ValueError):
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            kwargs = {}
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                strings = _py_strings(kw.value)
                if strings:
                    kwargs[kw.arg] = strings if isinstance(
                        kw.value, (ast.List, ast.Tuple)) else strings[0]
                elif isinstance(kw.value, ast.Constant):
                    kwargs[kw.arg] = kw.value.value
            yield node.func.id, kwargs


def _bazel_decl(name: str, version: Optional[str], source: str, where: Path,
                url: Optional[str] = None, note: Optional[str] = None) -> Declaration:
    display, cpe = _known(_ALIASES.get(name.lower(), name.lower()))
    return Declaration(
        ecosystem=ECOSYSTEM_BAZEL, name=name, directory=where, source=source,
        version=version, version_is_upstream=version is not None, cpe=cpe,
        display_name=display, description=note, upstream_url=url, manifest_only=True)


def _version_from_archive(name: str, kwargs: dict) -> Optional[str]:
    """A release number from ``strip_prefix``, else from the first URL's file name."""
    candidates = [kwargs.get("strip_prefix", "")]
    urls = kwargs.get("urls") or kwargs.get("url") or []
    for url in ([urls] if isinstance(urls, str) else urls)[:1]:
        candidates.append(_ARCHIVE_EXT.sub("", str(url).rsplit("/", 1)[-1]))
    for text in candidates:
        m = _NAME_VERSION.search(str(text))
        if m:
            return m.group(1)
    return None


def read_bazel(root: Path) -> List[Declaration]:
    out: Dict[str, Declaration] = {}
    for here, files in _walk(root, 4):
        for fname in ("MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"):
            if fname not in files:
                continue
            source = (here / fname).relative_to(root).as_posix()
            overrides: Dict[str, dict] = {}
            calls = list(_starlark_calls(here / fname) or [])
            for func, kw in calls:
                if func in ("single_version_override", "git_override") and kw.get("module_name"):
                    overrides[kw["module_name"]] = (func, kw)
            for func, kw in calls:
                name = kw.get("name")
                if not isinstance(name, str) or not name:
                    continue
                if func == "bazel_dep":
                    if kw.get("dev_dependency") is True or _BAZEL_SKIP.match(name):
                        continue
                    version, note = kw.get("version"), None
                    over = overrides.get(name)
                    if over and over[0] == "single_version_override" and over[1].get("version"):
                        version = over[1]["version"]
                    elif over and over[0] == "git_override":
                        version, note = None, "built from a git commit, not a release"
                    version = _BCR_SUFFIX.sub("", version) if isinstance(version, str) and version \
                        else None
                    key = name.lower()
                    out.setdefault(key, _bazel_decl(name, version, source, here, note=note))
                elif func in ("http_archive", "git_repository", "new_git_repository"):
                    if _BAZEL_SKIP.match(name):
                        continue
                    if func == "http_archive":
                        version = _version_from_archive(name, kw)
                        url = None
                    else:
                        tag = kw.get("tag")
                        version = tag[1:] if isinstance(tag, str) and re.match(r"^v\d", tag) \
                            else (tag if isinstance(tag, str) and re.match(r"^\d", tag) else None)
                        remote = kw.get("remote")
                        url = remote if isinstance(remote, str) and "github.com" in remote else None
                    out.setdefault(name.lower(), _bazel_decl(
                        name, version, source, here, url=url,
                        note=None if version else "no release version in strip_prefix, URL or tag"))
    return list(out.values())
