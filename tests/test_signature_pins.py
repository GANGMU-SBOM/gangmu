"""A function signature must record the release its rule pins, as that release is."""

from gangmu.cli import main
from gangmu.fnsig import MAX_VERSIONS, FunctionSignature
from gangmu.functions import extract_functions
from gangmu.rules.loader import load_rules
from gangmu.verify import verify_rule


def _fn(name, i):
    return (f"int {name}(int x) {{ int y = x * {i} + 3; while (y > {i}) {{ y -= 3; }} "
            f"if (y % 5 == {i % 5}) {{ y ^= {i}; }} return y + x; }}\n")


SOURCE = "".join(_fn(f"fn{i}", i) for i in range(40))


def _hashes(text):
    return {f.hash for f in extract_functions(text.encode())}


def _rule(tmp_path, versions, ref="v1.1"):
    rules = tmp_path / "rules"
    rules.mkdir()
    sig = FunctionSignature.build([(v, _hashes(SOURCE), set()) for v in versions])
    digest = sig.write(rules / "synth.fnsig")
    (rules / "synth.yaml").write_text(f"""id: test/synth
component:
  path_globs: ['**/synth']
upstream:
  name: synth
  purl: pkg:generic/synth
  cpe_status: 'none-in-nvd: test fixture'
  source: {{kind: git, url: 'https://example.invalid/synth', ref: {ref}}}
identity:
  include: ['*.c']
  functions:
    file: synth.fnsig
    sha256: {digest}
    count: 0
    versions: {list(versions)}
""")
    return rules


def test_beyond_the_limit_the_newest_releases_are_kept():
    versions = [f"1.{n}" for n in range(MAX_VERSIONS + 6)]
    sig = FunctionSignature.build([(v, {n + 1}, set()) for n, v in enumerate(versions)])
    assert sig.versions == versions[-MAX_VERSIONS:]


def test_lint_warns_about_a_pinned_release_the_signature_lacks(tmp_path, capsys):
    rules = _rule(tmp_path, ["1.0", "1.1"], ref="v1.2")
    assert main(["rules", "lint", "--rules", str(rules)]) == 0
    assert "warn test/synth: pins 1.2; the signature records 1.0 to 1.1" in capsys.readouterr().out


def test_lint_is_quiet_when_the_pinned_release_is_recorded(tmp_path, capsys):
    rules = _rule(tmp_path, ["1.0", "1.1"])
    assert main(["rules", "lint", "--rules", str(rules)]) == 0
    assert "warn" not in capsys.readouterr().out


def test_verify_reproduces_the_pinned_releases_functions(tmp_path):
    [rule] = load_rules(_rule(tmp_path, ["1.0", "1.1"])).rules
    checkout = tmp_path / "upstream"
    checkout.mkdir()
    (checkout / "synth.c").write_text(SOURCE)
    report = verify_rule(rule, checkout)
    assert report.ok and any("reproduces exactly for 1.1 (40 functions)" in c
                             for c in report.checked)

    (checkout / "more.c").write_text(_fn("later", 99))     # globs the signature missed
    report = verify_rule(rule, checkout)
    assert not report.ok
    assert "41 functions under the rule's globs, the signature records 40 " \
           "(1 upstream only, 0 recorded only)" in report.problems[0]


def test_verify_notes_a_pinned_release_it_cannot_compare(tmp_path):
    [rule] = load_rules(_rule(tmp_path, ["1.0", "1.1"], ref="v2.0")).rules
    checkout = tmp_path / "upstream"
    checkout.mkdir()
    (checkout / "synth.c").write_text(SOURCE)
    report = verify_rule(rule, checkout)
    assert report.ok
    assert any("does not record the pinned release 2.0" in c for c in report.checked)


def test_verify_uses_the_globs_the_signature_records(tmp_path):
    # FreeRTOS's signature holds the kernel's sources, not the ports beside them.
    rules = _rule(tmp_path, ["1.0", "1.1"])
    yml = rules / "synth.yaml"
    yml.write_text(yml.read_text().replace("    file: synth.fnsig",
                                           "    file: synth.fnsig\n    subdir: kernel"))
    [rule] = load_rules(rules).rules
    checkout = tmp_path / "upstream"
    (checkout / "kernel").mkdir(parents=True)
    (checkout / "kernel" / "synth.c").write_text(SOURCE)
    (checkout / "port.c").write_text(_fn("port_only", 7))
    report = verify_rule(rule, checkout)
    assert report.ok, report.problems


def test_tags_without_a_dotted_version_are_not_the_newest_release():
    from gangmu.importers.versions import pick_releases
    tags = ["clamav-1.4.0", "clamav-1.5.4", "r5076", "merge-llvm-97877", "clamav-20080204"]
    assert pick_releases(tags, 3) == ["clamav-1.4.0", "clamav-1.5.4"]
    assert pick_releases(["v20240124", "v20240322"], 12) == ["v20240124", "v20240322"]


def test_releases_look_like_the_pinned_one():
    from gangmu.importers.versions import pick_releases
    tags = ["Copter-4.6.0", "Copter-4.7.2", "ArduPlane-4.7.2", "2021.02.24", "240720"]
    assert pick_releases(tags, 12, like="Copter-4.7.2") == ["Copter-4.6.0", "Copter-4.7.2"]
    assert pick_releases(["6.1.4", "6.1.5", "17368.8"], 12, like="6.1.5") == ["6.1.4", "6.1.5"]


def test_letter_releases_keep_their_letter_and_prereleases_are_left_out():
    from gangmu.importers.candidates import release_tags
    from gangmu.importers.versions import tag_to_version
    assert [tag_to_version(t) for t in ("v1.3.9", "v1.3.9c", "OpenSSL_1_1_1w", "R0.14b")] == \
        ["1.3.9", "1.3.9c", "1.1.1w", "0.14b"]
    assert tag_to_version("v1.93.0-docking") == "1.93.0"
    assert release_tags(["v3.14.9", "v3.15.0a3", "v3.15.0b3", "v3.15.0rc1", "R0.14b"]) == \
        ["v3.14.9", "R0.14b"]


def test_a_second_tag_for_one_release_is_not_recorded_twice(tmp_path):
    import subprocess
    from gangmu.importers.versions import build_function_signature
    repo = tmp_path / "upstream"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                       env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                            "PATH": "/usr/bin:/bin"})
    git("init", "-q")
    (repo / "a.c").write_text(SOURCE)
    git("add", "-A"); git("commit", "-qm", "r"); git("tag", "v1.0"); git("tag", "spin-v1.0")
    report = build_function_signature(str(repo), ["v1.0", "spin-v1.0"], include=["*.c"],
                                      label=lambda t: t.rsplit("v", 1)[1])
    assert report.signature.versions == ["1.0"]
    assert report.skipped == [("spin-v1.0", "another tag already gave release 1.0")]


def test_a_prefix_matches_up_to_punctuation_and_a_bare_v():
    from gangmu.importers.versions import pick_releases
    tags = ["ptpd-2.2.2", "ptpd-2.3.0", "ptpd-2.3.1", "ptpd.2.3.1"]
    assert len(pick_releases(tags, 12, like="ptpd.2.3.1")) == 3
    assert pick_releases(["2.1.0", "v2.2.0", "v.2.2.3"], 12, like="v.2.2.3") == \
        ["2.1.0", "v2.2.0", "v.2.2.3"]
