"""Kernel rules for the Chinese RTOSes, without the network.

TencentOS-tiny first. The properties worth pinning are the ones that decide
whether a vendor copy is found and not confused with another kernel: markers
that survive renaming, markers that no other kernel's files satisfy, and the
tag spelling upstream uses.
"""

from pathlib import Path

import pytest

from gangmu.discover import discover_roots
from gangmu.rules.loader import RuleBase, load_rules
from gangmu.vuln.version import compare, normalize_tag

from community import REPO_RULES, needs_rules

pytestmark = needs_rules


@pytest.fixture(scope="module")
def shipped():
    return {r.id: r for r in load_rules(REPO_RULES)}


def _touch(root: Path, *paths: str) -> None:
    for rel in paths:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n")


def _roots(tree: Path, shipped, *ids):
    base = RuleBase(rules=[shipped[i] for i in ids])
    return sorted(p.relative_to(tree.resolve()).as_posix()
                  for p in discover_roots(tree, base))


# ------------------------------------------------------------- TencentOS-tiny

TOS = "generic/tencentos-tiny-kernel"
TOS_SOURCES = ("tos_task.c", "tos_sys.c", "tos_mutex.c", "tos_event.c")


def test_tencentos_rule_covers_the_releases_wch_ships(shipped):
    rule = shipped[TOS]
    versions = set(rule.functions.load().versions)
    # WCH ch32v307 / ch32v20x ship 2.4.5; upstream's own tags are 2.1.0, 2.4.5, 2.5.0
    assert {"2.1.0", "2.4.5", "2.5.0", "2.5.2"} <= versions
    assert rule.source.ref and rule.source.ref not in ("master", "main", "HEAD")
    assert rule.cpe and rule.cpe.startswith("cpe:2.3:o:tencent:tencentos-tiny:")


def test_tencentos_is_found_under_any_directory_name(tmp_path, shipped):
    # WCH: EVT/EXAM/TencentOS/TencentOS/TencentOS_Tiny/kernel/core; a vendor may flatten it
    for name in ("EVT/EXAM/TencentOS/TencentOS/TencentOS_Tiny/kernel/core",
                 "third_party/rtos_x"):
        _touch(tmp_path, *(f"{name}/{s}" for s in TOS_SOURCES))
    _touch(tmp_path, "partial/tos_task.c", "partial/tos_sys.c")      # two of four: not enough
    assert _roots(tmp_path, shipped, TOS) == [
        "EVT/EXAM/TencentOS/TencentOS/TencentOS_Tiny/kernel/core", "third_party/rtos_x"]


def test_tencentos_markers_do_not_claim_other_kernels(tmp_path, shipped):
    _touch(tmp_path, "freertos/tasks.c", "freertos/queue.c", "freertos/list.c",
           "freertos/include/FreeRTOS.h", "freertos/include/task.h")
    _touch(tmp_path, "rtt/src/thread.c", "rtt/src/ipc.c", "rtt/src/mutex.c",
           "rtt/include/rtthread.h")
    assert _roots(tmp_path, shipped, TOS) == []
    # and the other way round: TencentOS sources are not FreeRTOS or RT-Thread
    other = tmp_path / "tos"
    _touch(other, *(f"kernel/core/{s}" for s in TOS_SOURCES), "kernel/core/tos_list.c")
    assert _roots(other, shipped, "generic/freertos-kernel", "generic/rt-thread-kernel") == []


def test_tencentos_tags_normalise_to_the_versions_the_rule_covers(shipped):
    """OSV GIT ranges list upstream's tags; they must compare against our versions."""
    covered = set(shipped[TOS].functions.load().versions)
    for tag in ("v2.1.0", "v2.4.5", "v2.5.0"):
        assert normalize_tag(tag) in covered


# --------------------------------------------------------------- AliOS Things

ALIOS = "generic/alios-things-kernel"
RHINO_SOURCES = ("k_task.c", "k_sys.c", "k_mutex.c", "k_event.c")


def test_alios_rule_covers_every_release_line(shipped):
    rule = shipped[ALIOS]
    versions = set(rule.functions.load().versions)
    assert {"1.1.0", "1.3.4", "2.0.0", "2.1.0", "3.0.0", "3.1.0", "3.3.0"} <= versions
    assert len(versions) == 16
    assert rule.cpe is None and rule.cpe_status.startswith("none-in-nvd")
    assert rule.source.ref and rule.source.ref not in ("master", "main", "HEAD")


def test_alios_is_found_in_all_three_layouts(tmp_path, shipped):
    # kernel/rhino/core (<= 2.0.0), kernel/rhino (2.1.0, 3.0.0, 3.3.0), core/rhino (3.1.0)
    layouts = ("a/kernel/rhino/core", "b/kernel/rhino", "c/core/rhino", "d/vendor/rt_core")
    for name in layouts:
        _touch(tmp_path, *(f"{name}/{s}" for s in RHINO_SOURCES))
    _touch(tmp_path, "e/k_task.c", "e/k_sys.c")                         # two of four
    assert _roots(tmp_path, shipped, ALIOS) == sorted(layouts)


def test_alios_markers_do_not_claim_other_kernels(tmp_path, shipped):
    _touch(tmp_path, "freertos/tasks.c", "freertos/queue.c", "freertos/list.c")
    _touch(tmp_path, "tos/tos_task.c", "tos/tos_sys.c", "tos/tos_mutex.c", "tos/tos_event.c")
    _touch(tmp_path, "rtt/src/thread.c", "rtt/src/ipc.c", "rtt/include/rtthread.h")
    assert _roots(tmp_path, shipped, ALIOS) == []
    other = tmp_path / "rhino"
    _touch(other, *(f"kernel/rhino/{s}" for s in RHINO_SOURCES))
    assert _roots(other, shipped, "generic/freertos-kernel", "generic/rt-thread-kernel",
                  TOS) == []


def test_alios_tags_normalise_to_the_versions_the_rule_covers(shipped):
    covered = set(shipped[ALIOS].functions.load().versions)
    for tag in ("aos1.1.0", "aos1.1.1", "v1.1.2", "v1.2.2", "v1.3.4", "v2.0.0", "v2.1.0"):
        assert normalize_tag(tag) in covered, tag


# --------------------------------------------------------------------- LiteOS

LOS_M = "generic/liteos-m-kernel"
LOS_A = "generic/liteos-a-kernel"
LOS_5 = "generic/liteos-kernel"
OH_TAGS = ("OpenHarmony-1.0", "OpenHarmony-v3.0-LTS", "OpenHarmony-v3.1-Release",
           "OpenHarmony-v3.2-Release", "OpenHarmony-v3.2.4-Release",
           "OpenHarmony-v4.0-Release", "OpenHarmony-v5.0.0-Release",
           "OpenHarmony-v5.1.0-Release", "OpenHarmony-v6.0-Release",
           "OpenHarmony-v6.0.0.2-Release", "OpenHarmony-v7.0-Release")


def test_liteos_rules_cover_the_openharmony_releases(shipped):
    m = set(shipped[LOS_M].functions.load().versions)
    a = set(shipped[LOS_A].functions.load().versions)
    # LiteOS-M 1.1.x wraps every file in extern "C"; the extractor sees through it
    assert {"1.0", "1.1.0", "1.1.1", "1.1.5", "3.0", "3.2", "3.2.4", "5.1.0", "7.0"} <= m
    assert len(m) == len(a) == 48
    assert {"1.0", "1.1.0", "1.1.5", "3.0", "3.2", "5.1.0", "7.0"} <= a
    # ranges are printed from the stored order, so it has to be version order
    ordered = list(shipped[LOS_A].functions.load().versions)
    assert all(compare(x, y) <= 0 for x, y in zip(ordered, ordered[1:]))
    for rule_id in (LOS_M, LOS_A, LOS_5):
        rule = shipped[rule_id]
        assert rule.source.ref and rule.source.ref not in ("master", "main", "HEAD")
        assert rule.cpe is None and rule.cpe_status       # OS-wide CPEs only, see the rule


def test_liteos_oh_rules_use_gitcode_with_gitee_and_github_mirrors(shipped):
    """OpenHarmony moved to GitCode in September 2025; Gitee is a mirror that stops
    at OpenHarmony-v6.0-Release, so the 7.0 commit is pinned on GitCode and GitHub."""
    from gangmu.vuln.match import purl_from_repo, purl_key
    for rule_id, repo in ((LOS_M, "kernel_liteos_m"), (LOS_A, "kernel_liteos_a")):
        rule = shipped[rule_id]
        assert rule.source.url == f"https://gitcode.com/openharmony/{repo}"
        assert rule.source.ref == "OpenHarmony-v6.0-Release"
        mirrors = {m.url: m for m in rule.mirrors}
        assert set(mirrors) == {f"https://{host}/openharmony/{repo}"
                                for host in ("gitcode.com", "gitee.com", "github.com")}
        for host in ("gitcode.com", "github.com"):
            assert len(mirrors[f"https://{host}/openharmony/{repo}"].ref) == 40
        assert rule.homepage == rule.source.url
        # OSV GIT ranges name the repository by URL: every host reaches this rule
        for url in (rule.source.url, *mirrors):
            assert purl_from_repo(url) == purl_key(rule.purl)
        assert {"6.0.0.1", "6.0.0.2", "6.1", "7.0"} <= set(rule.functions.load().versions)


def test_liteos_versions_are_spelled_like_the_upstream_tags(shipped):
    """OSV GIT ranges list tags; ``in_tag_set`` compares normalised strings, so a
    label of 3.2.0 would never be found in the tag list ['OpenHarmony-v3.2-Release']."""
    from gangmu.vuln.version import in_tag_set
    covered = set(shipped[LOS_A].functions.load().versions)
    for tag in OH_TAGS:
        assert normalize_tag(tag) in covered, tag
        assert in_tag_set(normalize_tag(tag), [tag]) is True
    # the legacy build ids are not release versions: no normal form, never covered
    assert normalize_tag("LiteOSV200R001C50B039") is None
    assert set(shipped[LOS_5].functions.load().versions) == {"5.0.0", "5.1.0"}
    assert {"5.0.0", "5.1.0"} == {v for a in shipped[LOS_5].anchors for v in a.sha256}


def test_liteos_m_found_where_wch_put_it(tmp_path, shipped):
    # WCH ch32v307: LiteOS_m/LiteOS/kernel/src; ch583: kernel_liteos_m/kernel/src
    layouts = ("EVT/EXAM/HarmonyOS/LiteOS_m/LiteOS/kernel", "x/kernel_liteos_m/kernel",
               "y/os")
    for name in layouts:
        _touch(tmp_path, *(f"{name}/src/{s}" for s in
                           ("los_task.c", "los_mux.c", "los_sem.c", "los_queue.c")))
    _touch(tmp_path, "z/src/los_task.c", "z/src/los_mux.c")            # two of four
    assert _roots(tmp_path, shipped, LOS_M) == sorted(layouts)


def test_liteos_a_and_5x_layouts_are_told_apart(tmp_path, shipped):
    a = tmp_path / "a"
    _touch(a, "kernel/base/core/los_task.c", "kernel/base/ipc/los_mux.c",
           "kernel/base/ipc/los_sem.c", "kernel/base/core/los_swtmr.c")
    five = tmp_path / "five"
    _touch(five, *(f"kernel/base/{s}" for s in
                   ("los_task.c", "los_mux.c", "los_sem.c", "los_queue.c")))
    m = tmp_path / "m"
    _touch(m, *(f"kernel/src/{s}" for s in
                ("los_task.c", "los_mux.c", "los_sem.c", "los_queue.c")))
    assert _roots(a, shipped, LOS_A) == ["kernel"]
    assert _roots(a, shipped, LOS_M, LOS_5) == []
    assert _roots(five, shipped, LOS_5) == ["kernel"]
    assert _roots(five, shipped, LOS_A, LOS_M) == []
    assert _roots(m, shipped, LOS_M) == ["kernel"]
    assert _roots(m, shipped, LOS_A, LOS_5) == []


def test_liteos_markers_do_not_claim_other_kernels(tmp_path, shipped):
    _touch(tmp_path, "freertos/tasks.c", "freertos/queue.c", "freertos/list.c")
    _touch(tmp_path, "tos/tos_task.c", "tos/tos_sys.c", "tos/tos_mutex.c", "tos/tos_event.c")
    _touch(tmp_path, "rhino/k_task.c", "rhino/k_sys.c", "rhino/k_mutex.c", "rhino/k_event.c")
    _touch(tmp_path, "rtt/src/thread.c", "rtt/src/ipc.c", "rtt/include/rtthread.h")
    assert _roots(tmp_path, shipped, LOS_M, LOS_A, LOS_5) == []
