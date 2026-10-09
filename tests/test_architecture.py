"""The shape of the package: what ``gangmu.core`` may depend on.

``gangmu.core`` is what every bill of materials (SBOM today, CBOM and AIBOM next)
stands on. It is meant to become its own distribution, so it must not reach back
into an engine. These tests read the source, not the running interpreter, so a
lazy import inside a function is caught as well.
"""
import ast
from pathlib import Path

import gangmu

SRC = Path(gangmu.__file__).parent
CORE = SRC / "core"


def _gangmu_imports(path: Path):
    """Absolute dotted names of every gangmu module ``path`` imports."""
    rel = path.relative_to(SRC.parent).with_suffix("")
    parts = list(rel.parts)
    package = parts[:-1] if path.name != "__init__.py" else parts[:-1]
    if path.name == "__init__.py":
        parts = parts[:-1]
        package = parts
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.split(".")[0] == "gangmu"]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - (node.level - 1)]
                target = ".".join(base + ([node.module] if node.module else []))
            else:
                target = node.module or ""
            if target.split(".")[0] != "gangmu":
                continue
            found.append(target)
            found += [f"{target}.{a.name}" for a in node.names]
    return found


def test_core_does_not_import_an_engine():
    bad = []
    for path in sorted(CORE.glob("*.py")):
        for name in _gangmu_imports(path):
            if name in ("gangmu", "gangmu.core") or name.startswith("gangmu.core."):
                continue
            if name == "gangmu.__version__":
                continue
            bad.append(f"{path.name}: {name}")
    assert not bad, "gangmu.core must stand alone:\n  " + "\n  ".join(bad)


def test_engines_do_not_import_each_other():
    """The SBOM engine knows nothing of the CBOM module; the reverse runs through core."""
    sbom_side = [SRC / "scan.py", SRC / "match" / "engine.py", SRC / "sbom" / "cyclonedx.py"]
    for path in sbom_side:
        assert not [n for n in _gangmu_imports(path) if n.startswith("gangmu.cbom")], path.name


def test_old_import_paths_are_the_same_modules():
    import importlib
    for old, new in [("gangmu.plugins", "gangmu.core.plugins"),
                     ("gangmu.signing", "gangmu.core.signing"),
                     ("gangmu.globbing", "gangmu.core.globbing"),
                     ("gangmu.unpack", "gangmu.core.unpack"),
                     ("gangmu.rules.packs", "gangmu.core.packs")]:
        assert importlib.import_module(old) is importlib.import_module(new), old
    from gangmu.model import Evidence, Technique
    from gangmu.core.evidence import Evidence as E2, Technique as T2
    assert Evidence is E2 and Technique is T2
