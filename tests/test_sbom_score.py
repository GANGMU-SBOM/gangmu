"""Minimum-element scoring.

Comparable to Interlynk's sbomqs, and stricter in one place: a placeholder
counts as absent.
"""

from gangmu.eval import CISA_2026, NTIA_2021, score_sbom

FULL = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "metadata": {
        "timestamp": "2026-01-01T00:00:00Z",
        "tools": {"components": [{"name": "gangmu-sbom", "version": "0.3.0"}]},
        "properties": [{"name": "gangmu:generationContext", "value": "build"}],
    },
    "components": [{
        "bom-ref": "c1", "name": "lwIP", "version": "2.2.0",
        "supplier": {"name": "lwIP Project"},
        "purl": "pkg:generic/lwip@2.2.0",
        "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
        "licenses": [{"license": {"id": "BSD-3-Clause"}}],
    }],
    "dependencies": [{"ref": "root-application", "dependsOn": ["c1"]}],
}


def test_a_complete_document_scores_full_marks():
    assert score_sbom(FULL, NTIA_2021, "ntia").out_of_ten == 10.0
    assert score_sbom(FULL, CISA_2026, "cisa").out_of_ten == 10.0


def test_the_2026_additions_are_actually_checked():
    names = {e.name for e in CISA_2026}
    assert {"Component Hash", "Component License", "SBOM Generation Context",
            "SBOM Tool Name and Version", "SBOM Data Format"} <= names


def test_a_missing_hash_only_costs_the_2026_standard():
    import copy
    bom = copy.deepcopy(FULL)
    bom["components"][0].pop("hashes")
    assert score_sbom(bom, NTIA_2021, "ntia").out_of_ten == 10.0
    assert score_sbom(bom, CISA_2026, "cisa").out_of_ten < 10.0


def test_noassertion_counts_as_absent():
    import copy
    bom = copy.deepcopy(FULL)
    bom["components"][0]["version"] = "NOASSERTION"
    report = score_sbom(bom, NTIA_2021, "ntia")
    version = next(s for s in report.scores if s.element.id == "ntia-version")
    assert version.passed == 0


def test_failures_name_the_components():
    import copy
    bom = copy.deepcopy(FULL)
    bom["components"][0].pop("purl")
    report = score_sbom(bom, NTIA_2021, "ntia")
    ident = next(s for s in report.scores if s.element.id == "ntia-identifier")
    assert ident.failures == ["lwIP"]


def test_an_empty_document_scores_but_does_not_crash():
    report = score_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6"},
                        CISA_2026, "cisa")
    assert 0.0 <= report.out_of_ten <= 10.0
