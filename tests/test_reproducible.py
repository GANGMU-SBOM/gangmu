"""SOURCE_DATE_EPOCH: the same input gives byte-identical documents.

Without it every document carries the current time and a random id (CycloneDX
asks for a fresh serial per BOM). With it, as reproducible builds set it, the time
is that moment and the id comes from the content, so a signed SBOM or an evidence
bundle can be regenerated and compared byte for byte.
"""

import json
from pathlib import Path

import pytest

from gangmu.cli import main
from gangmu.core.repro import ID_PLACEHOLDER

ADVISORIES = Path(__file__).resolve().parent / "fixtures" / "advisories"
EPOCH = "1767225600"                     # 2026-01-01T00:00:00Z


def _scan(project_dir, rules_dir, out, fmt):
    assert main(["scan", str(project_dir), "--rules", str(rules_dir),
                 "--format", fmt, "-o", str(out)]) == 0
    return out.read_text(encoding="utf-8")


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx", "spdx3"])
def test_scan_output_is_byte_identical_under_source_date_epoch(
        project_dir, rules_dir, tmp_path, monkeypatch, fmt):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    first = _scan(project_dir, rules_dir, tmp_path / "a.json", fmt)
    second = _scan(project_dir, rules_dir, tmp_path / "b.json", fmt)
    assert first == second
    assert "2026-01-01T00:00:00Z" in first
    assert ID_PLACEHOLDER not in first


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx", "spdx3"])
def test_without_it_each_document_gets_its_own_id(project_dir, rules_dir, tmp_path,
                                                  monkeypatch, fmt):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    first = _scan(project_dir, rules_dir, tmp_path / "a.json", fmt)
    second = _scan(project_dir, rules_dir, tmp_path / "b.json", fmt)
    assert ID_PLACEHOLDER not in first
    if fmt == "cyclonedx":
        assert json.loads(first)["serialNumber"] != json.loads(second)["serialNumber"]
    elif fmt == "spdx":
        assert (json.loads(first)["documentNamespace"]
                != json.loads(second)["documentNamespace"])
    else:
        assert first != second


def test_different_content_gets_a_different_id(project_dir, rules_dir, tmp_path,
                                               monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    a = json.loads(_scan(project_dir, rules_dir, tmp_path / "a.json", "cyclonedx"))
    assert main(["scan", str(project_dir), "--rules", str(rules_dir), "--format",
                 "cyclonedx", "--app-name", "other", "-o", str(tmp_path / "b.json")]) == 0
    b = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert a["serialNumber"] != b["serialNumber"]


@pytest.mark.parametrize("fmt", ["cyclonedx", "openvex", "csaf"])
def test_vex_output_is_byte_identical_under_source_date_epoch(
        project_dir, rules_dir, tmp_path, monkeypatch, fmt):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    _scan(project_dir, rules_dir, tmp_path / "sbom.json", "cyclonedx")
    outs = []
    for name in ("a", "b"):
        out = tmp_path / f"{name}.json"
        assert main(["vuln", str(tmp_path / "sbom.json"), "--db", str(ADVISORIES),
                     "--format", fmt, "--publisher", "x", "--publisher-url",
                     "https://example.invalid", "--no-threat", "-o", str(out)]) == 0
        outs.append(out.read_text(encoding="utf-8"))
    assert outs[0] == outs[1]
    assert ID_PLACEHOLDER not in outs[0]


@pytest.mark.parametrize("command", ["cbom", "aibom"])
def test_cbom_and_aibom_are_byte_identical_under_source_date_epoch(
        project_dir, tmp_path, monkeypatch, command):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    outs = []
    for name in ("a", "b"):
        out = tmp_path / f"{name}.json"
        assert main([command, str(project_dir), "--format", "cyclonedx", "-o", str(out)]) == 0
        outs.append(out.read_text(encoding="utf-8"))
    assert outs[0] == outs[1]
    assert json.loads(outs[0])["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"


def test_an_unusable_source_date_epoch_falls_back_to_now(monkeypatch):
    from gangmu.core import repro
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "yesterday")
    assert repro.source_date_epoch() is None
    assert repro.timestamp() > "2026-01-01"
