"""Marker-file discovery and the generic RTOS rules it exists for.

Vendors move an RTOS kernel to wherever their build wants it and rename the
directory (``freertos_riscv``, ``bl702_freertos``, ``FreeRTOS_Core/FreeRTOS``),
and they rarely copy the LICENSE alongside. A rule naming the files that only
that component has together finds those copies; the function signature then
decides what they are.
"""

import subprocess
from pathlib import Path

from gangmu.discover import discover_roots
from gangmu.importers.versions import build_function_signature
from gangmu.rules.loader import RuleBase, load_rules
from gangmu.rules.schema import rule_from_dict

from community import REPO_RULES, needs_rules

pytestmark = needs_rules


def _rule(markers):
    return rule_from_dict({
        "id": "test/kernel",
        "component": {"marker_files": markers},
        "upstream": {"name": "kernel", "purl": "pkg:generic/kernel",
                     "source": {"kind": "git", "url": "https://example.invalid/k",
                                "ref": "v1.0"}},
        "identity": {"anchors": [{"path": "k.c", "sha256": {"1.0": "0" * 64}}]},
    }, source_path="test.yaml")


def _touch(root: Path, *paths: str) -> None:
    for rel in paths:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n")


def test_markers_find_a_renamed_directory(tmp_path):
    _touch(tmp_path, "platform/soc/x/bl702_os/tasks.c", "platform/soc/x/bl702_os/queue.c",
           "platform/soc/x/bl702_os/list.c", "other/tasks.c")
    rules = RuleBase(rules=[_rule(["tasks.c", "queue.c", "list.c"])])
    roots = [p.relative_to(tmp_path.resolve()).as_posix()
             for p in discover_roots(tmp_path, rules)]
    assert roots == ["platform/soc/x/bl702_os"]       # one marker alone is not enough


def test_markers_in_subdirectories_name_the_component_root(tmp_path):
    _touch(tmp_path, "vendor/rtos/src/thread.c", "vendor/rtos/src/ipc.c",
           "vendor/rtos/include/rtthread.h")
    rules = RuleBase(rules=[_rule(["src/thread.c", "src/ipc.c", "include/rtthread.h"])])
    roots = [p.relative_to(tmp_path.resolve()).as_posix()
             for p in discover_roots(tmp_path, rules)]
    assert roots == ["vendor/rtos"]


def test_the_shipped_rtos_rules_load_with_markers():
    rules = {r.id: r for r in load_rules(REPO_RULES)}
    assert rules["generic/freertos-kernel"].marker_files == ("tasks.c", "queue.c", "list.c")
    assert "src/thread.c" in rules["generic/rt-thread-kernel"].marker_files
    for rule_id in ("generic/freertos-kernel", "generic/rt-thread-kernel"):
        signature = rules[rule_id].functions.load()     # sha256 checked on load
        assert len(signature.versions) >= 27


def test_signature_builder_falls_back_across_layouts(tmp_path):
    """FreeRTOS kept the kernel under FreeRTOS/Source until 10.3."""
    repo = tmp_path / "upstream"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                       env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                            "PATH": "/usr/bin:/bin"})

    git("init", "-q")
    body = "int task_create(int a, int b) { int c = a + b; return c * 2 + a; }\n"
    (repo / "FreeRTOS" / "Source").mkdir(parents=True)
    (repo / "FreeRTOS" / "Source" / "tasks.c").write_text(body)
    git("add", "-A"); git("commit", "-qm", "old"); git("tag", "v1.0.0")
    git("rm", "-rq", "FreeRTOS")
    (repo / "tasks.c").write_text(body.replace("* 2", "* 3"))
    git("add", "-A"); git("commit", "-qm", "new"); git("tag", "v2.0.0")

    report = build_function_signature(str(repo), ["v1.0.0", "v2.0.0"],
                                      include=["*.c"], subdir=["FreeRTOS/Source", "."],
                                      label=lambda t: t.lstrip("v"))
    assert report.tags == ["1.0.0", "2.0.0"] and not report.skipped


def test_signature_builder_pins_untagged_releases_to_commits(tmp_path):
    """GmSSL 2.x was never tagged: LABEL=<commit> fetches the commit and keeps
    the label, instead of reading digits out of the commit id."""
    repo = tmp_path / "upstream"
    repo.mkdir()

    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                              text=True,
                              env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                                   "PATH": "/usr/bin:/bin"}).stdout.strip()

    git("init", "-q")
    git("config", "uploadpack.allowAnySHA1InWant", "true")
    shas = []
    for n in (1, 2):
        (repo / "sm3.c").write_text(
            f"int sm3_update(int a, int b) {{ int c = a + b; return c * {n} + a; }}\n")
        git("add", "-A"); git("commit", "-qm", f"2.5.{n}")
        shas.append(git("rev-parse", "HEAD"))
    report = build_function_signature(
        str(repo), [f"2.5.0={shas[0]}", f"2.5.1={shas[1]}"], include=["*.c"],
        label=lambda t: "wrong-" + t)
    assert report.tags == ["2.5.0", "2.5.1"] and not report.skipped


def test_functions_command_refuses_a_branch_as_a_pin(capsys):
    from gangmu.cli import main
    code = main(["rules", "functions", "https://example.invalid/x",
                 "--tag", "2.5.4=GmSSL-v2", "--out", "unused.fnsig"])
    assert code == 2
    assert "40-hex" in capsys.readouterr().err


def test_shipped_national_crypto_rules_cover_the_older_generations():
    from gangmu.rules.loader import load_rules
    rules = {r.id: r for r in load_rules(REPO_RULES)}
    gm2 = rules["generic/gmssl-2"]
    assert {"crypto/sm3/sm3.c", "crypto/sm2/sm2_sign.c"} <= set(gm2.marker_files)
    assert {"2.0.0", "2.5.0", "2.5.4"} <= set(gm2.functions.load().versions)
    tongsuo = set(rules["generic/tongsuo"].functions.load().versions)
    assert {"8.1.3", "8.3.3", "8.4.0", "8.5.0"} <= tongsuo
    # Both older generations are OpenSSL 1.1.x forks. Unless OpenSSL 1.1.x is in
    # the base, an unmodified OpenSSL 1.1.1 tree matches them (measured: 0.80).
    openssl = set(rules["generic/openssl"].functions.load().versions)
    assert {"1.1.0l", "1.1.1k", "1.1.1w", "3.0.22"} <= openssl
