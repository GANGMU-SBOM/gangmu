"""Finding a rule's CPE from NVD records instead of guessing it.

Synthetic records only (``TEST-`` ids), for the reason test_vuln.py gives.
"""

import json

import pytest

from gangmu.rules.schema import RuleError, rule_from_dict
from gangmu.vuln.evidence import Terms, find_evidence, repo_key


def _record(cve_id, cpe, refs=(), text="Synthetic."):
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": text}],
        "references": [{"url": u} for u in refs],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": f"cpe:2.3:{cpe}:*:*:*:*:*:*:*:*"}]}]}],
    }}


@pytest.fixture()
def mirror(tmp_path):
    records = [
        _record("TEST-1", "o:acme:rtos",
                ["https://github.com/Acme/RTOS-Kernel/commit/abc"]),
        _record("TEST-2", "o:acme:rtos",
                ["https://github.com/acme/rtos-kernel/security/advisories/x"]),
        _record("TEST-3", "a:other:rtos_kernel_fork",          # a lookalike repo
                ["https://github.com/acme/rtos-kernel-extras/issues/1"]),
        _record("TEST-4", "h:vendor:gadget", text="A flaw in RTOS-Kernel on Gadget."),
        _record("TEST-5", "a:chan:fatfs", ["http://elm-chan.org/fsw/ff/"]),
    ]
    (tmp_path / "feed.json").write_text(json.dumps({"vulnerabilities": records}))
    return tmp_path


def test_repository_references_rank_above_name_mentions(mirror):
    terms = [Terms("x/rtos", "RTOS-Kernel", ("github.com/acme/rtos-kernel",))]
    found = find_evidence(mirror, terms)["x/rtos"]
    assert [c.cpe_key for c in found] == ["o:acme:rtos", "h:vendor:gadget"]
    assert found[0].by_reference == ["TEST-1", "TEST-2"]       # case-insensitive
    assert found[1].by_reference == [] and found[1].by_name == ["TEST-4"]
    assert found[0].cpe == "cpe:2.3:o:acme:rtos:*:*:*:*:*:*:*:*"


def test_a_site_outside_github_is_evidence_too(mirror):
    terms = [Terms("x/fatfs", "", (repo_key("http://elm-chan.org/fsw/ff/"),))]
    found = find_evidence(mirror, terms, jobs=2)["x/fatfs"]
    assert [(c.cpe_key, c.by_reference) for c in found] == [("a:chan:fatfs", ["TEST-5"])]


def test_repo_keys():
    assert repo_key("https://github.com/DaveGamble/cJSON.git") == "github.com/davegamble/cjson"
    assert repo_key("pkg:github/RT-Thread/rt-thread@v5.1.0") == "github.com/rt-thread/rt-thread"
    assert repo_key("https://www.freertos.org") == "freertos.org"
    assert repo_key("pkg:generic/fatfs") is None and repo_key(None) is None


def _rule(**upstream):
    source = {"kind": "git", "url": "https://example.invalid/r", "ref": "v1"}
    return {"id": "t/r", "upstream": {"name": "r", "source": source, **upstream},
            "identity": {"anchors": [{"path": "a.c", "sha256": {"1": "0" * 64}}]}}


def test_cpe_evidence_must_be_cve_ids_backing_a_cpe():
    ok = rule_from_dict(_rule(cpe="cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                              cpe_evidence=["CVE-2024-28115"]), source_path="r.yaml")
    assert ok.cpe_evidence == ("CVE-2024-28115",)
    with pytest.raises(RuleError):
        rule_from_dict(_rule(cpe="cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                             cpe_evidence=["see the NVD"]), source_path="r.yaml")
    with pytest.raises(RuleError):
        rule_from_dict(_rule(cpe_evidence=["CVE-2024-28115"]), source_path="r.yaml")
