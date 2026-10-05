import sys
from pathlib import Path

import pytest
import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def upstream_dir() -> Path:
    return FIXTURES / "upstream" / "tinynet"


@pytest.fixture(scope="session")
def project_dir() -> Path:
    return FIXTURES / "project"


@pytest.fixture(scope="session")
def rules_dir(tmp_path_factory, upstream_dir) -> Path:
    """A rule generated from the pristine fixture, exactly as a contributor would.

    Generating it rather than committing it means the test suite also proves the
    authoring path works, and keeps a kilobyte of hex out of the repository.
    """
    from gangmu.dirprint import print_directory, sha256_file
    from gangmu.fingerprint import ALGO

    out = tmp_path_factory.mktemp("rules")
    dp = print_directory(upstream_dir, ["src/**/*.c", "include/**/*.h"])
    sig = dp.signature()
    rule = {
        "id": "test/tinynet",
        "component": {"path_globs": ["**/tinynet"], "ships_as": "tinynet"},
        "upstream": {
            "name": "tinynet",
            "purl": "pkg:generic/tinynet",
            "cpe": "cpe:2.3:a:tinynet_project:tinynet:*:*:*:*:*:*:*:*",
            "license": "MIT",
            "source": {"kind": "git", "url": "https://example.invalid/tinynet",
                       "ref": "v1.4.2"},
        },
        "identity": {
            "include": ["src/**/*.c", "include/**/*.h"],
            "anchors": [{
                "path": "src/core.c",
                "sha256": {"1.4.2": sha256_file(upstream_dir / "src" / "core.c")},
            }],
            "signature": {
                "algo": ALGO,
                "k": sig.k,
                "window": sig.window,
                "size": sig.size,
                "reference_version": "1.4.2",
                "fileset_sha256": dp.fileset_sha256,
                "values": sig.to_hex(),
            },
        },
        "version": {
            "probes": [{
                "file": "include/tinynet/version.h",
                "patterns": {
                    "major": r"TINYNET_VERSION_MAJOR\s+(\d+)",
                    "minor": r"TINYNET_VERSION_MINOR\s+(\d+)",
                    "revision": r"TINYNET_VERSION_REVISION\s+(\d+)",
                },
                "template": "{major}.{minor}.{revision}",
            }]
        },
    }
    (out / "tinynet.yaml").write_text(yaml.safe_dump(rule, sort_keys=False))
    return out
