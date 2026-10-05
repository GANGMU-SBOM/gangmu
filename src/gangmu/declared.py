"""Declared components: read what a package manager already wrote down.

Where an ecosystem has a package manager, fingerprinting is the wrong tool. A
declaration names the component and its version outright; similarity can only
estimate both. Two Chinese ecosystems are the useful cases, and both are
*easier* than their international counterparts because the declaration sits in
the source tree:

RT-Thread
    The Env tool writes the selected packages into ``.config`` as Kconfig
    symbols (``CONFIG_PKG_USING_CJSON=y``, ``CONFIG_PKG_CJSON_PATH``,
    ``CONFIG_PKG_CJSON_VER``) and downloads each one to
    ``packages/<name>-<ver>``. ``packages/pkgs.json`` records what was actually
    installed.

OpenHarmony
    Every third-party directory carries ``README.OpenSource``, a JSON list
    naming the upstream project, its version, licence and upstream URL. It is
    maintained by the OpenHarmony community and reviewed on every import.

    Every component -- OpenHarmony's own and the third-party ones -- also has
    a ``bundle.json``: its component name, subsystem, licence, bundle version,
    and the components and third-party code it depends on. That is the only
    place a source tree records *who uses what*, which is the question a CVE
    in ``bounds_checking_function`` or ``mbedtls`` actually raises.

The two declare different things, and the difference matters for CVE matching:

* OpenHarmony declares the **upstream** version ("cJSON v1.7.17"), so the
  upstream CPE applies.
* RT-Thread declares the **package** version (the RT-Thread wrapper's own tag).
  It is not the upstream release number, so no upstream CPE is spliced with it;
  a fingerprint rule, when one fires on the same directory, supplies the
  upstream identity and the declaration is attached as evidence.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ECOSYSTEM_RTTHREAD = "rt-thread"
ECOSYSTEM_OPENHARMONY = "openharmony"

OPENSOURCE_README = "README.OpenSource"
OPENHARMONY_BUNDLE = "bundle.json"
OPENHARMONY_SUPPLIER = "OpenAtom Foundation (OpenHarmony project)"
THIRD_PARTY_SUBSYSTEM = "thirdparty"
_SKIP_DIRS = {".git", "out", "build", "node_modules", "__pycache__"}

_PKG_USING = re.compile(r"^CONFIG_PKG_USING_([A-Z0-9_]+)=y\s*$", re.M)
_PKG_STRING = re.compile(r'^CONFIG_PKG_([A-Z0-9_]+?)_(PATH|VER)="([^"]*)"\s*$', re.M)


@dataclass(frozen=True)
class Declaration:
    ecosystem: str
    name: str
    directory: Optional[Path]          # absolute; None when declared but absent
    source: str                        # the file that declared it, relative to root
    version: Optional[str] = None
    version_is_upstream: bool = False  # True when the version is the upstream release
    license: Optional[str] = None
    upstream_url: Optional[str] = None
    description: Optional[str] = None
    component: Optional[str] = None    # OpenHarmony component.name from bundle.json
    depends_on: Tuple[str, ...] = ()   # component names this one declares it uses
    supplier: Optional[str] = None
    cpe: Optional[str] = None          # upstream CPE, when the reader knows one
    display_name: Optional[str] = None
    forked: bool = False               # a vendor tree of this project (Linux SDK kernels)
    fork_note: Optional[str] = None
    manifest_only: bool = False        # no source on disk: the declaration is all there is

    @property
    def present(self) -> bool:
        return self.directory is not None

    @property
    def purl(self) -> Optional[str]:
        if self.ecosystem == ECOSYSTEM_RTTHREAD:
            # The package index is RT-Thread's own namespace; the version is the
            # package's, so it belongs with that namespace and nowhere else.
            base = f"pkg:generic/rt-thread/{_purl_name(self.name)}"
        elif self.ecosystem in ("conan", "bazel"):
            base = f"pkg:{self.ecosystem}/{_purl_name(self.name)}"
        elif self.supplier == OPENHARMONY_SUPPLIER:
            base = f"pkg:generic/openharmony/{_purl_name(self.name)}"
        elif self.cpe or self.ecosystem in ("buildroot", "openwrt", "kbuild", "yocto"):
            base = f"pkg:generic/{_purl_name(self.name)}"
        else:
            github = _github_purl(self.upstream_url)
            base = github or f"pkg:generic/{_purl_name(self.name)}"
        return f"{base}@{self.version}" if self.version else base


def collect_declarations(root: Path) -> List[Declaration]:
    root = Path(root).resolve()
    found = read_rtthread(root)
    found.extend(read_openharmony(root))
    from .declared_linux import read_linux_ecosystems
    found.extend(read_linux_ecosystems(root))
    from .declared_sdk import read_vendor_sdks
    found.extend(read_vendor_sdks(root))
    from .declared_build import read_build_ecosystems
    found.extend(read_build_ecosystems(root))
    return found


# ------------------------------------------------------------------ RT-Thread

def read_rtthread(root: Path) -> List[Declaration]:
    """Packages an RT-Thread BSP selected, located on disk where Env put them.

    ``.config`` is what the developer selected; ``packages/pkgs.json`` is what
    Env installed. Either is enough. A package selected but never downloaded is
    still reported, with no directory, because "the build will pull this in" is
    exactly what an SBOM reviewer needs to hear.
    """
    root = Path(root)
    by_key: Dict[str, Dict[str, str]] = {}

    config = root / ".config"
    if config.is_file():
        text = _read(config)
        for key in _PKG_USING.findall(text):
            by_key.setdefault(key, {})
        for key, field, value in _PKG_STRING.findall(text):
            if key in by_key and value:
                by_key[key][field.lower()] = value

    installed = root / "packages" / "pkgs.json"
    if installed.is_file():
        try:
            entries = json.loads(_read(installed)) or []
        except ValueError:
            entries = []
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            key = str(entry["name"]).upper()
            slot = by_key.setdefault(key, {})
            if entry.get("path"):
                slot.setdefault("path", str(entry["path"]))
            if entry.get("ver"):
                slot["ver"] = str(entry["ver"])     # installed beats selected

    source = ".config" if config.is_file() else "packages/pkgs.json"
    out: List[Declaration] = []
    for key in sorted(by_key):
        slot = by_key[key]
        path = slot.get("path")
        if not path:
            # A PKG_USING symbol with no PATH is a sub-option of a package
            # (CONFIG_PKG_USING_CJSON_V1717 and the like), not a package.
            continue
        name = path.rstrip("/").rsplit("/", 1)[-1]
        version = slot.get("ver")
        directory = _rtthread_dir(root, name, version)
        out.append(Declaration(
            ecosystem=ECOSYSTEM_RTTHREAD, name=name, directory=directory,
            source=source, version=version, version_is_upstream=False,
        ))
    return out


def _rtthread_dir(root: Path, name: str, version: Optional[str]) -> Optional[Path]:
    packages = root / "packages"
    if not packages.is_dir():
        return None
    if version:
        exact = packages / f"{name}-{version}"
        if exact.is_dir():
            return exact.resolve()
    lowered = name.lower()
    candidates = sorted(p for p in packages.iterdir() if p.is_dir() and
                        (p.name.lower() == lowered or
                         p.name.lower().startswith(lowered + "-")))
    return candidates[0].resolve() if len(candidates) == 1 else None


# ---------------------------------------------------------------- OpenHarmony

def read_openharmony(root: Path, max_depth: int = 8) -> List[Declaration]:
    """``README.OpenSource`` and ``bundle.json`` declarations in an OpenHarmony tree.

    A directory with both yields its README.OpenSource entries (the upstream
    identity) carrying the bundle's component name and dependencies. A
    directory with only a bundle is an OpenHarmony component in its own right:
    OpenHarmony is its upstream and the bundle version is its release.
    """
    root = Path(root)
    out: List[Declaration] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        if depth >= max_depth:
            dirnames[:] = []
        has_readme = OPENSOURCE_README in filenames
        if not has_readme and OPENHARMONY_BUNDLE not in filenames:
            continue
        here = Path(dirpath)
        bundle = _read_bundle(here / OPENHARMONY_BUNDLE) \
            if OPENHARMONY_BUNDLE in filenames else None
        component = bundle["name"] if bundle else None
        depends_on = bundle["depends_on"] if bundle else ()
        if has_readme:
            readme = here / OPENSOURCE_README
            for entry in _readme_entries(readme):
                name = _field(entry, "Name")
                if not name:
                    continue
                out.append(Declaration(
                    ecosystem=ECOSYSTEM_OPENHARMONY, name=name,
                    directory=here.resolve(),
                    source=readme.relative_to(root).as_posix(),
                    version=normalise_version(_field(entry, "Version Number", "Version")),
                    version_is_upstream=True,
                    license=_field(entry, "License"),
                    upstream_url=_field(entry, "Upstream URL"),
                    description=_field(entry, "Description"),
                    component=component, depends_on=depends_on,
                ))
            continue
        if bundle is None:
            continue
        # Third-party code without a README.OpenSource: the bundle names it,
        # but its version is OpenHarmony's packaging, not the upstream release,
        # so it is left for the rule base to version.
        own = bundle["subsystem"] != THIRD_PARTY_SUBSYSTEM
        out.append(Declaration(
            ecosystem=ECOSYSTEM_OPENHARMONY, name=bundle["name"],
            directory=here.resolve(),
            source=(here / OPENHARMONY_BUNDLE).relative_to(root).as_posix(),
            version=bundle["version"] if own else None,
            version_is_upstream=own,
            license=bundle["license"],
            description=bundle["description"],
            component=bundle["name"], depends_on=depends_on,
            supplier=OPENHARMONY_SUPPLIER if own else None,
        ))
    return out


def _readme_entries(path: Path) -> List[dict]:
    try:
        entries = json.loads(_read(path))
    except ValueError:
        return []
    if isinstance(entries, dict):
        entries = [entries]
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


def _read_bundle(path: Path) -> Optional[dict]:
    """The parts of an OpenHarmony ``bundle.json`` an SBOM needs, or None.

    ``bundle.json`` is also a common name elsewhere, so a file only counts when
    it has OpenHarmony's shape: a ``component`` with a name and a subsystem.
    """
    try:
        data = json.loads(_read(path))
    except ValueError:
        return None
    component = data.get("component") if isinstance(data, dict) else None
    if not isinstance(component, dict):
        return None
    name = _field(component, "name")
    subsystem = _field(component, "subsystem")
    if not name or not subsystem:
        return None
    deps = component.get("deps") if isinstance(component.get("deps"), dict) else {}
    depends_on: List[str] = []
    for key in ("components", "third_party"):
        for dep in deps.get(key) or []:
            if isinstance(dep, str) and dep.strip() and dep.strip() != name \
                    and dep.strip() not in depends_on:
                depends_on.append(dep.strip())
    return {"name": name, "subsystem": subsystem,
            "version": normalise_version(_field(data, "version")),
            "license": _field(data, "license"),
            "description": _field(data, "description"),
            "depends_on": tuple(depends_on)}


# -------------------------------------------------------------------- helpers

def normalise_version(version: Optional[str]) -> Optional[str]:
    """``v1.7.17`` -> ``1.7.17``; anything that is not a release is left alone.

    NVD and OSV record releases without the tag prefix. Leaving it on would
    make every range comparison fail, and a failed comparison looks clean.
    """
    if not version:
        return None
    version = version.strip()
    if re.match(r"^[vV]\d", version):
        return version[1:]
    return version or None


def _field(entry: dict, *keys: str) -> Optional[str]:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return None


def _purl_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-").lower() or "unknown"


def _github_purl(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    m = re.match(r"^https?://github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", url.strip())
    if not m:
        return None
    return f"pkg:github/{m.group(1).lower()}/{m.group(2).lower()}"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")
