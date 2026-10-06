"""Patch presence: test the code, not the version.

A vendor fork reports the release it started from, so every advisory fixed in a
later release matches it. These tests build real git history, record what a fix
changed, and check the verdict on the copies a vendor actually ships: untouched,
fixed, backported, edited, pruned, reformatted and renamed.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from gangmu.cli import main
from gangmu.patchtest import (PatchError, assess, build_record, functions_changed_by,
                              load_patches, save_patches)

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git is required")

VULN = ("int parse_len(const unsigned char *p, int n)\n"
        "{ int len = p[0]; int i; for (i = 0; i < len; i++) { n += p[i + 1]; } "
        "return n; }\n")
FIXED = ("int parse_len(const unsigned char *p, int n)\n"
         "{ int len = p[0]; int i; if (len > n) { return -1; } "
         "for (i = 0; i < len; i++) { n += p[i + 1]; } return n; }\n")
OTHER = "int other(int a) { return a * 2 + 1 + a - 3 + a * a; }\n"
SECOND_VULN = ("int read_tag(const char *s, int n)\n"
               "{ int i; int sum = 0; for (i = 0; i <= n; i++) { sum += s[i]; } "
               "return sum; }\n")
SECOND_FIXED = SECOND_VULN.replace("i <= n", "i < n")


def _git(repo, *args):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                           *args], cwd=repo, check=True, capture_output=True,
                          text=True).stdout.strip()


def _history(tmp_path, before, after, name="lib.c"):
    """A repo whose last commit turns *before* into *after*; returns (repo, fix)."""
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / name).write_text(before)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    (repo / name).write_text(after)
    _git(repo, "commit", "-qam", "fix")
    return repo, _git(repo, "rev-parse", "HEAD")


def _tree(tmp_path, name, source, directory="lwip"):
    root = tmp_path / name
    (root / directory).mkdir(parents=True)
    (root / directory / "core.c").write_text(source)
    return root


@pytest.fixture
def fix(tmp_path):
    repo, sha = _history(tmp_path, VULN + OTHER, FIXED + OTHER)
    return build_record("CVE-2021-0001", str(repo), [sha])


# ---------------------------------------------------------------- building

def test_a_record_holds_only_the_functions_the_fix_changed(fix):
    assert [f.function for f in fix.functions] == ["parse_len"]
    patch = fix.functions[0]
    assert len(patch.vulnerable) == 1 and len(patch.fixed) == 1
    assert not patch.vulnerable & patch.fixed


def test_reformatting_alone_is_not_a_change(tmp_path):
    repo, sha = _history(tmp_path, VULN, "/* tidy */\n" + VULN.replace(" ", "  "))
    with pytest.raises(PatchError, match="no C/C\\+\\+ function body"):
        build_record("CVE-X", str(repo), [sha])


def test_a_non_source_commit_has_nothing_to_test_for(tmp_path):
    repo, sha = _history(tmp_path, "one\n", "two\n", name="README.md")
    with pytest.raises(PatchError, match="no C/C\\+\\+ function body"):
        build_record("CVE-X", str(repo), [sha])


def test_a_refactor_is_refused_unless_the_functions_are_named(tmp_path):
    many = "".join(f"int f{i}(int a) {{ return a * {i} + a - {i} + a * a; }}\n"
                   for i in range(45))
    repo, sha = _history(tmp_path, many, many.replace("+ a *", "+ a + a *"))
    with pytest.raises(PatchError, match="refactor"):
        build_record("CVE-X", str(repo), [sha])
    rec = build_record("CVE-X", str(repo), [sha], only=["f3", "f9"])
    assert sorted(f.function for f in rec.functions) == ["f3", "f9"]


def test_a_merge_commit_is_not_a_fix(tmp_path):
    repo, _ = _history(tmp_path, VULN, FIXED)
    base = _git(repo, "rev-parse", "HEAD~1")
    _git(repo, "checkout", "-q", "-b", "side", base)
    (repo / "x.c").write_text(OTHER)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "side")
    _git(repo, "checkout", "-q", "-")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    with pytest.raises(PatchError, match="parents"):
        functions_changed_by(repo, "HEAD")


def test_a_branch_name_is_not_a_commit_id(tmp_path):
    repo, _ = _history(tmp_path, VULN, FIXED)
    with pytest.raises(PatchError, match="not a commit id"):
        build_record("CVE-X", str(repo), ["main"])


def test_records_round_trip_through_the_file(tmp_path, fix):
    path = tmp_path / "p.json"
    save_patches(path, {fix.advisory: fix})
    again = load_patches(path)["CVE-2021-0001"]
    assert again.functions == fix.functions and again.commits == fix.commits


def test_a_file_that_is_not_a_record_file_says_so(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"CVE-1": ["a"]}))
    with pytest.raises(PatchError, match="not a patch record file"):
        load_patches(path)


# ---------------------------------------------------------------- verdicts

def test_the_vulnerable_copy_is_vulnerable(tmp_path, fix):
    assert assess(fix, _tree(tmp_path, "t", VULN + OTHER), "lwip").status == "vulnerable"


def test_the_fixed_copy_is_fixed(tmp_path, fix):
    v = assess(fix, _tree(tmp_path, "t", FIXED + OTHER), "lwip")
    assert v.status == "fixed" and "parse_len" in v.detail


def test_reformatting_and_comments_do_not_change_the_verdict(tmp_path, fix):
    noisy = "/* vendor */\n" + VULN.replace("{ int", "{\n\tint").replace(";", ";\n")
    assert assess(fix, _tree(tmp_path, "t", noisy + OTHER), "lwip").status == "vulnerable"


def test_a_vendor_edit_is_modified_not_guessed(tmp_path, fix):
    edited = ("int parse_len(const unsigned char *p, int n)\n"
              "{ int len = p[0]; if (len > 99) { return -2; } return n + len; }\n")
    v = assess(fix, _tree(tmp_path, "t", edited + OTHER), "lwip")
    assert v.status == "modified" and "needs a person" in v.detail


def test_a_pruned_copy_is_absent(tmp_path, fix):
    assert assess(fix, _tree(tmp_path, "t", OTHER), "lwip").status == "absent"


def test_renamed_identifiers_are_still_recognised_but_flagged_as_such(tmp_path, fix):
    import re
    renamed = VULN
    for old, new in (("parse_len", "vnd_parse_len"), ("len", "length"),
                     ("n", "count"), ("p", "buf"), ("i", "idx")):
        renamed = re.sub(rf"\b{old}\b", new, renamed)
    v = assess(fix, _tree(tmp_path, "t", renamed + OTHER), "lwip")
    assert v.status == "vulnerable" and v.basis == "identifier-abstracted"
    assert "renamed identifiers" in v.detail


def test_an_incomplete_fix_is_partial(tmp_path):
    repo, sha = _history(tmp_path, VULN + SECOND_VULN, FIXED + SECOND_FIXED)
    rec = build_record("CVE-X", str(repo), [sha])
    assert sorted(f.function for f in rec.functions) == ["parse_len", "read_tag"]
    v = assess(rec, _tree(tmp_path, "t", FIXED + SECOND_VULN), "lwip")
    assert v.status == "partial" and "incomplete" in v.detail
    assert assess(rec, _tree(tmp_path, "u", FIXED + SECOND_FIXED), "lwip").status == "fixed"


def test_only_the_component_directory_is_read(tmp_path, fix):
    root = _tree(tmp_path, "t", OTHER)
    (root / "app").mkdir()
    (root / "app" / "x.c").write_text(FIXED)          # elsewhere in the firmware
    assert assess(fix, root, "lwip").status == "absent"


def test_tests_and_examples_of_the_component_are_not_shipped(tmp_path, fix):
    root = _tree(tmp_path, "t", VULN + OTHER)
    (root / "lwip" / "test").mkdir()
    (root / "lwip" / "test" / "t.c").write_text(FIXED)
    assert assess(fix, root, "lwip").status == "vulnerable"


# -------------------------------------------------------------------- CLI

def _db(tmp_path):
    feed = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-0001",
        "descriptions": [{"lang": "en", "value": "overflow in parse_len"}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.2.0"}]}]}]}}]}
    db = tmp_path / "db"
    db.mkdir()
    (db / "nvd-2021.json").write_text(json.dumps(feed))
    return db


def _sbom(tmp_path, fork=True):
    component = {"type": "library", "name": "lwip", "version": "2.1.0",
                 "bom-ref": "lwip",
                 "cpe": "cpe:2.3:a:lwip_project:lwip:2.1.0:*:*:*:*:*:*:*",
                 "properties": [{"name": "gangmu:directory", "value": "lwip"}]}
    if fork:
        component["pedigree"] = {"patches": [{"type": "backport"}],
                                 "notes": "vendor-modified"}
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                "components": [component]}))
    return path


def _vuln(tmp_path, capsys, source, patches, *extra, fork=True):
    rc = main(["vuln", str(_sbom(tmp_path, fork)), "--db", str(_db(tmp_path)),
               "--format", "json", "--source", str(source),
               *(["--patches", str(patches)] if patches else []), *extra])
    out = capsys.readouterr().out
    return rc, (json.loads(out)["matches"][0] if rc == 0 else None)


@pytest.fixture
def patches(tmp_path, fix):
    path = tmp_path / "patches.json"
    save_patches(path, {fix.advisory: fix})
    return path


def test_a_fork_with_no_patch_record_stays_in_triage(tmp_path, capsys):
    _, m = _vuln(tmp_path, capsys, _tree(tmp_path, "t", FIXED + OTHER), None)
    assert m["state"] == "in_triage" and "patchPresence" not in m


def test_a_fork_that_took_the_fix_is_resolved(tmp_path, capsys, patches):
    _, m = _vuln(tmp_path, capsys, _tree(tmp_path, "t", FIXED + OTHER), patches)
    assert m["state"] == "resolved"
    assert m["patchPresence"]["status"] == "fixed"
    assert m["detail"].startswith("patch test:")


def test_a_fork_that_did_not_is_confirmed_exploitable(tmp_path, capsys, patches):
    _, m = _vuln(tmp_path, capsys, _tree(tmp_path, "t", VULN + OTHER), patches)
    assert m["state"] == "exploitable"
    assert m["patchPresence"]["status"] == "vulnerable"


def test_an_edited_function_is_left_for_a_person(tmp_path, capsys, patches):
    edited = "int parse_len(const unsigned char *p, int n) { return n + p[0] + 1 + n; }\n"
    _, m = _vuln(tmp_path, capsys, _tree(tmp_path, "t", edited + OTHER), patches)
    assert m["state"] == "in_triage"
    assert m["patchPresence"]["status"] == "modified"
    assert "[patch test:" in m["detail"]


def test_a_pruned_copy_is_reported_but_not_ruled_out(tmp_path, capsys, patches):
    _, m = _vuln(tmp_path, capsys, _tree(tmp_path, "t", OTHER), patches)
    assert m["state"] == "in_triage" and m["patchPresence"]["status"] == "absent"


def test_the_verdict_reaches_the_vex_document(tmp_path, capsys, patches):
    assert main(["vuln", str(_sbom(tmp_path)), "--db", str(_db(tmp_path)),
                 "--format", "cyclonedx", "--source",
                 str(_tree(tmp_path, "t", FIXED + OTHER)),
                 "--patches", str(patches)]) == 0
    vuln = json.loads(capsys.readouterr().out)["vulnerabilities"][0]
    assert vuln["analysis"]["state"] == "resolved"
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["gangmu:patchPresence"] == "fixed"
    assert props["gangmu:patchPresenceBasis"] == "exact"


def test_patches_without_source_is_an_error(tmp_path, capsys, patches):
    rc = main(["vuln", str(_sbom(tmp_path)), "--db", str(_db(tmp_path)),
               "--patches", str(patches)])
    assert rc == 2 and "--source" in capsys.readouterr().err


def test_a_malformed_record_file_is_an_error_not_a_crash(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    rc = main(["vuln", str(_sbom(tmp_path)), "--db", str(_db(tmp_path)),
               "--source", str(tmp_path), "--patches", str(bad)])
    assert rc == 2 and "cannot read" in capsys.readouterr().err


def test_patch_build_writes_a_file_vuln_can_use(tmp_path, capsys):
    repo, sha = _history(tmp_path, VULN + OTHER, FIXED + OTHER)
    out = tmp_path / "out.json"
    assert main(["patch-build", "cve-2021-0001", "--repo", str(repo), "--fix", sha,
                 "-o", str(out)]) == 0
    assert "CVE-2021-0001" in load_patches(out)
    # A second record is added to the file, not written over it.
    assert main(["patch-build", "CVE-2021-0002", "--repo", str(repo), "--fix", sha,
                 "-o", str(out)]) == 0
    assert set(load_patches(out)) == {"CVE-2021-0001", "CVE-2021-0002"}


def test_patch_build_needs_something_to_work_from(tmp_path, capsys):
    assert main(["patch-build", "CVE-1", "-o", str(tmp_path / "o.json")]) == 2
    assert "--repo and --fix" in capsys.readouterr().err


def test_patch_build_reads_the_fix_from_an_osv_advisory(tmp_path, capsys):
    repo, sha = _history(tmp_path, VULN + OTHER, FIXED + OTHER)
    db = tmp_path / "osv"
    db.mkdir()
    (db / "GHSA-x.json").write_text(json.dumps({
        "id": "GHSA-x", "aliases": ["CVE-2021-0001"], "summary": "s",
        "affected": [{"ranges": [{
            "type": "GIT", "repo": "https://github.com/example/lwip",
            "events": [{"introduced": "0"}, {"fixed": sha}]}]}]}))
    out = tmp_path / "out.json"
    # The repository comes from the advisory, the clone from --repo (offline).
    assert main(["patch-build", "CVE-2021-0001", "--db", str(db), "--repo", str(repo),
                 "-o", str(out)]) == 0
    rec = load_patches(out)["CVE-2021-0001"]
    assert rec.commits == [sha] and [f.function for f in rec.functions] == ["parse_len"]
    assert main(["patch-build", "CVE-9999-1", "--db", str(db), "-o", str(out)]) == 2
    assert "records no fix commit" in capsys.readouterr().err
