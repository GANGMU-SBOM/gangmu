"""Patch records built in bulk for the advisories an SBOM matches."""

import json
import subprocess
from pathlib import Path

import pytest

from gangmu.cli import main
from gangmu.patchfetch import build_missing, fix_sources
from gangmu.patchtest import PatchError, PatchRecord, load_patches, load_skipped
from gangmu.vuln.model import Advisory, Match, VexState

REPO = "https://github.com/lwip-tcpip/lwip"
VULN = ("int parse_hdr(char *p, int n) {\n  char b[8];\n  int i;\n"
        "  for (i = 0; i < n; i++) b[i] = p[i];\n  return b[0];\n}\n")
FIXED = VULN.replace("  int i;\n", "  int i;\n  if (n > 8) return -1;\n")


def _adv(id_, aliases=(), commits=("a" * 40,), repo=REPO, kind="GIT"):
    return Advisory(id=id_, source="osv", aliases=list(aliases), osv_ranges=[
        {"purl": "pkg:github/lwip-tcpip/lwip", "type": kind, "repo": repo,
         "fixed_commits": list(commits)}])


def _match(adv):
    return Match(advisory=adv, component="lwip", directory="lwip", version="2.1.0",
                 channel="purl", matched_on="x", state=VexState.IN_TRIAGE)


def test_a_record_is_filed_under_the_cve_and_read_from_the_osv_record():
    ghsa = _adv("GHSA-xxxx-yyyy-zzzz", aliases=["CVE-2021-0001"])
    nvd = Advisory(id="CVE-2021-0001", source="nvd")           # the match's record: no OSV ranges
    got = fix_sources([_match(nvd)], [nvd, ghsa])
    assert got == {"CVE-2021-0001": (REPO, ["a" * 40])}


def test_only_matched_vulnerabilities_with_a_stated_fix_are_built():
    matched = _adv("CVE-2021-0002")
    other = _adv("CVE-2021-0003")                              # in the database, not matched
    no_commit = _adv("CVE-2021-0004", commits=())
    ecosystem = _adv("CVE-2021-0005", kind="ECOSYSTEM")
    got = fix_sources([_match(a) for a in (matched, no_commit, ecosystem)],
                      [matched, other, no_commit, ecosystem])
    assert list(got) == ["CVE-2021-0002"]


def _stub(calls, failing=()):
    def build(advisory, repo, commits):
        calls.append(advisory)
        if advisory in failing:
            raise PatchError("changes no C/C++ function body")
        return PatchRecord(advisory=advisory, repo=repo, commits=list(commits))
    return build


def test_building_goes_on_where_it_stopped(tmp_path):
    path = tmp_path / "patches.json"
    sources = {f"CVE-2021-000{i}": (REPO, ["b" * 40]) for i in range(1, 5)}
    records, skipped, calls = {}, {}, []
    first = build_missing(sources, path, records, skipped, limit=2, build=_stub(calls))
    assert first.built == ["CVE-2021-0001", "CVE-2021-0002"] and first.deferred == 2
    assert set(load_patches(path)) == {"CVE-2021-0001", "CVE-2021-0002"}

    records, skipped = load_patches(path), load_skipped(path)    # a new run reads the file
    second = build_missing(sources, path, records, skipped, limit=10, build=_stub(calls))
    assert second.already == 2 and second.built == ["CVE-2021-0003", "CVE-2021-0004"]
    assert calls == sorted(set(calls))                           # nothing was built twice


def test_what_cannot_be_recorded_is_remembered_not_retried(tmp_path):
    path = tmp_path / "patches.json"
    sources = {"CVE-2021-0001": (REPO, ["b" * 40]), "CVE-2021-0002": (REPO, ["c" * 40])}
    calls: list = []
    out = build_missing(sources, path, {}, {}, 10, build=_stub(calls, failing={"CVE-2021-0001"}))
    assert out.built == ["CVE-2021-0002"] and "CVE-2021-0001" in out.skipped
    assert "CVE-2021-0001" in load_skipped(path)

    calls.clear()
    again = build_missing(sources, path, load_patches(path), load_skipped(path), 10,
                          build=_stub(calls))
    assert calls == [] and again.already == 2
    refreshed = build_missing(sources, path, load_patches(path), load_skipped(path), 10,
                              refresh=True, build=_stub(calls))
    assert sorted(calls) == ["CVE-2021-0001", "CVE-2021-0002"] and len(refreshed.built) == 2
    assert load_skipped(path) == {}


def test_a_failed_refresh_keeps_the_record_it_had(tmp_path):
    path = tmp_path / "patches.json"
    sources = {"CVE-2021-0001": (REPO, ["b" * 40])}
    records = {}
    build_missing(sources, path, records, {}, 10, build=_stub([]))
    build_missing(sources, path, records, {}, 10, refresh=True,
                  build=_stub([], failing={"CVE-2021-0001"}))
    assert "CVE-2021-0001" in load_patches(path) and load_skipped(path) == {}


def _git(repo, *args):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
                          cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def test_a_record_built_from_a_real_fix_commit_names_the_function(tmp_path):
    repo = tmp_path / "up"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "core.c").write_text(VULN)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    (repo / "core.c").write_text(FIXED)
    _git(repo, "commit", "-qam", "fix")
    fix = _git(repo, "rev-parse", "HEAD")
    path = tmp_path / "patches.json"
    out = build_missing({"CVE-2021-0001": (str(repo), [fix])}, path, {}, {}, 5)
    assert out.built == ["CVE-2021-0001"]
    assert load_patches(path)["CVE-2021-0001"].vulnerable_functions() == ["parse_hdr"]


# -------------------------------------------------------------------- the command

def _osv(path: Path, commit: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "osv-1.json").write_text(json.dumps({
        "id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2021-0001"],
        "summary": "overflow in the header parser",
        "affected": [{"package": {"purl": "pkg:github/lwip-tcpip/lwip"},
                      "ranges": [{"type": "GIT", "repo": REPO, "events": [
                          {"introduced": "0"}, {"fixed": commit}]}],
                      "versions": ["STABLE-2_1_0"]}]}))


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr("gangmu.vuln.fetch.fetch_nvd", lambda *a, **k: 0)
    monkeypatch.setattr("gangmu.vuln.fetch.fetch_osv", lambda *a, **k: 0)


def _sbom(tmp_path):
    p = tmp_path / "sbom.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{
        "type": "library", "name": "lwip", "version": "STABLE-2_1_0", "bom-ref": "lwip",
        "purl": "pkg:github/lwip-tcpip/lwip@STABLE-2_1_0",
        "cpe": "cpe:2.3:a:lwip_project:lwip:2.1.0:*:*:*:*:*:*:*",
        "properties": [{"name": "gangmu:directory", "value": "lwip"}]}]}))
    return p


def test_build_patches_needs_an_sbom(tmp_path, capsys):
    assert main(["vuln-fetch", "--db", str(tmp_path), "--all",
                 "--build-patches", str(tmp_path / "p.json")]) == 2
    assert "--sbom" in capsys.readouterr().err


def test_vuln_fetch_builds_the_records_for_what_the_sbom_matches(
        tmp_path, capsys, offline, monkeypatch):
    commit = "d" * 40
    _osv(tmp_path / "db", commit)
    calls: list = []
    monkeypatch.setattr("gangmu.patchfetch.build_record",
                        lambda adv, repo, commits: calls.append((adv, repo, commits))
                        or PatchRecord(advisory=adv, repo=repo, commits=list(commits)))
    out = tmp_path / "patches.json"
    assert main(["vuln-fetch", "--db", str(tmp_path / "db"), "--sbom", str(_sbom(tmp_path)),
                 "--build-patches", str(out)]) == 0
    assert calls == [("CVE-2021-0001", REPO, [commit])]
    assert "1 built" in capsys.readouterr().out
    assert "CVE-2021-0001" in load_patches(out)

    assert main(["vuln-fetch", "--db", str(tmp_path / "db"), "--sbom", str(_sbom(tmp_path)),
                 "--build-patches", str(out)]) == 0
    assert len(calls) == 1 and "1 already" in capsys.readouterr().out
