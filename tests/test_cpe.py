"""CPE 2.3 names with escaped characters (NISTIR 7695 6.2).

``\\:`` inside a component is part of it; splitting on every colon shifted the
vendor, product and version, so the product key and the pinned version were wrong.
"""

from gangmu.core.cpe import escape_value, split_cpe
from gangmu.rules.schema import _splice_version
from gangmu.vuln.match import Candidate, cpe_product_key, match
from gangmu.vuln.sources import advisory_from_nvd

ESCAPED = r"cpe:2.3:a:acme\:labs:tiny\:net:1.4.2:*:*:*:*:*:*:*"


def test_an_escaped_colon_stays_inside_its_component():
    parts = split_cpe(ESCAPED)
    assert len(parts) == 13
    assert parts[3:6] == [r"acme\:labs", r"tiny\:net", "1.4.2"]


def test_an_escaped_backslash_does_not_escape_the_colon_after_it():
    parts = split_cpe("cpe:2.3:a:x\\\\:y:1:*:*:*:*:*:*:*")
    assert parts[3:6] == ["x\\\\", "y", "1"]


def test_the_product_key_keeps_the_escaped_vendor_and_product():
    assert cpe_product_key(ESCAPED) == r"a:acme\:labs:tiny\:net"


def test_splicing_a_version_quotes_it_and_keeps_the_name_intact():
    spliced = _splice_version(ESCAPED.replace("1.4.2", "*"), "2.0:beta")
    parts = split_cpe(spliced)
    assert len(parts) == 13 and parts[3:6] == [r"acme\:labs", r"tiny\:net", r"2.0\:beta"]
    assert escape_value("a\\b") == "a\\\\b"


def test_a_pinned_advisory_cpe_with_an_escaped_name_matches_its_version():
    adv = advisory_from_nvd({"cve": {"id": "CVE-2099-0100", "configurations": [{"nodes": [{
        "cpeMatch": [{"vulnerable": True, "criteria": ESCAPED}]}]}]}})
    hit = Candidate(name="tinynet", version="1.4.2", directory="net", cpes=[ESCAPED], purls=[])
    other = Candidate(name="tinynet", version="1.4.3", directory="net2",
                      cpes=[ESCAPED.replace("1.4.2", "1.4.3")], purls=[])
    found = match([hit, other], [adv], include_not_affected=True)
    assert {(m.directory, m.state.value) for m in found} == {
        ("net", "exploitable"), ("net2", "not_affected")}
