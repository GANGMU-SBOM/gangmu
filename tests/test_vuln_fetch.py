import json
import lzma
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from gangmu.cli import main
from gangmu.vuln import load_database
from gangmu.vuln.fetch import (FetchError, fetch_nvd, fetch_osv, http_json,
                               merge_nvd)


def _cve(cve_id, product="lwip", end="2.2.1"):
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": "synthetic"}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:lwip_project:{product}:*:*:*:*:*:*:*:*",
            "versionEndExcluding": end}]}]}]}}


class FakeNvd:
    """An NVD 2.0 endpoint over a fixed record list, honouring paging."""

    def __init__(self, records, page=2):
        self.records, self.page, self.urls = records, page, []

    def __call__(self, url, headers):
        self.urls.append(url)
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        start = int(q["startIndex"])
        return {"totalResults": len(self.records),
                "vulnerabilities": self.records[start:start + self.page]}


@pytest.fixture(autouse=True)
def small_pages(monkeypatch):
    monkeypatch.setattr("gangmu.vuln.fetch._NVD_PAGE", 2)


def test_paging_collects_every_record_into_year_shards(tmp_path):
    recs = [_cve("CVE-2023-0001"), _cve("CVE-2023-0002"), _cve("CVE-2024-0003")]
    fake = FakeNvd(recs)
    n = fetch_nvd(tmp_path, get=fake, sleep=lambda s: None)
    assert n == 3 and len(fake.urls) == 2
    assert (tmp_path / "nvd-2023.json.xz").exists()
    assert (tmp_path / "nvd-2024.json.xz").exists()
    ids = {a.id for a in load_database(tmp_path)}
    assert ids == {"CVE-2023-0001", "CVE-2023-0002", "CVE-2024-0003"}


def test_second_run_is_incremental_and_never_duplicates(tmp_path):
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    fetch_nvd(tmp_path, get=FakeNvd([_cve("CVE-2023-0001")]), now=now,
              sleep=lambda s: None)
    changed = _cve("CVE-2023-0001", end="9.9.9")
    fake = FakeNvd([changed, _cve("CVE-2023-0009")])
    n = fetch_nvd(tmp_path, get=fake, now=now + timedelta(days=200),
                  sleep=lambda s: None)
    assert n == 2
    assert all("lastModStartDate" in u for u in fake.urls)
    assert len(fake.urls) >= 2          # 200 days splits into <120-day windows
    adv = {a.id: a for a in load_database(tmp_path)}
    assert len(adv) == 2
    assert adv["CVE-2023-0001"].cpe_ranges[0]["end_excluding"] == "9.9.9"


def test_scoped_fetch_queries_by_product_and_merges_with_full(tmp_path):
    fake = FakeNvd([_cve("CVE-2024-0100")])
    fetch_nvd(tmp_path, get=fake, products=["a:lwip_project:lwip"],
              sleep=lambda s: None)
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Alwip_project%3Alwip" in fake.urls[0]
    assert not (tmp_path / ".gangmu-fetch.state").exists()   # scoped != complete
    merge_nvd(tmp_path, [_cve("CVE-2024-0100")])
    assert len(load_database(tmp_path)) == 1


def test_an_unreadable_shard_is_replaced_not_trusted(tmp_path):
    (tmp_path / "nvd-2023.json.xz").write_bytes(b"not xz")
    merge_nvd(tmp_path, [_cve("CVE-2023-0001")])
    with lzma.open(tmp_path / "nvd-2023.json.xz", "rt") as fh:
        assert len(json.load(fh)["vulnerabilities"]) == 1


def test_api_key_goes_in_a_header(tmp_path):
    seen = []

    def get(url, headers):
        seen.append(headers)
        return {"totalResults": 0, "vulnerabilities": []}
    fetch_nvd(tmp_path, get=get, api_key="K", sleep=lambda s: None)
    assert seen[0] == {"apiKey": "K"}


def test_osv_fetches_ids_then_records(tmp_path):
    def post(url, body):
        package = body["queries"][0]["package"]
        if package.get("ecosystem") == "GIT":     # see the GIT-repository test below
            return {"results": [{}]}
        assert package["purl"] == "pkg:github/o/r"
        return {"results": [{"vulns": [{"id": "OSV-1"}, {"id": "GHSA/2"}]}]}

    def get(url, headers):
        return {"id": url.rsplit("/", 1)[1], "affected": []}
    assert fetch_osv(tmp_path, ["pkg:github/o/r"], get=get, post=post) == 2
    assert fetch_osv(tmp_path, ["pkg:github/o/r"], get=get, post=post) == 0
    assert (tmp_path / "osv" / "GHSA_2.json").exists() or \
        (tmp_path / "osv" / "GHSA%2F2.json").exists()


def test_osv_github_purls_are_also_queried_as_git_repositories(tmp_path):
    # OSV answers {"package": {"purl": "pkg:github/o/r"}} with nothing, ever: its
    # records for C projects name the repository in a GIT range instead, and
    # only the GIT-ecosystem query finds them (checked against api.osv.dev for
    # nghttp2/nghttp2: purl query 0 records, GIT query 7).
    queries = []

    def post(url, body):
        queries.append(body["queries"][0]["package"])
        git = body["queries"][0]["package"].get("ecosystem") == "GIT"
        return {"results": [{"vulns": [{"id": "CVE-1"}] if git else []}]}

    def get(url, headers):
        return {"id": url.rsplit("/", 1)[1], "affected": []}
    assert fetch_osv(tmp_path, ["pkg:github/NGHTTP2/nghttp2@v1.5.0"],
                     get=get, post=post) == 1
    assert {"name": "https://github.com/nghttp2/nghttp2", "ecosystem": "GIT"} in queries
    assert {"purl": "pkg:github/NGHTTP2/nghttp2@v1.5.0"} in queries


def test_osv_purls_of_other_types_get_no_git_query(tmp_path):
    seen = []

    def post(url, body):
        seen.append(body["queries"][0]["package"])
        return {"results": [{}]}
    fetch_osv(tmp_path, ["pkg:generic/libcoap", "pkg:npm/left-pad"],
              get=lambda u, h: {}, post=post)
    assert all("ecosystem" not in q for q in seen)


class _Flaky(BaseHTTPRequestHandler):
    calls = 0

    def do_GET(self):
        type(self).calls += 1
        if type(self).calls < 3:
            self.send_response(429)
            self.send_header("Retry-After", "0")
            self.end_headers()
            return
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_http_retries_on_throttling_then_succeeds():
    srv = HTTPServer(("127.0.0.1", 0), _Flaky)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = http_json(f"http://127.0.0.1:{srv.server_port}/x", sleep=lambda s: None)
    finally:
        srv.shutdown()
    assert out == {"ok": True} and _Flaky.calls == 3


def test_http_gives_up_with_a_clear_error():
    with pytest.raises(FetchError):
        http_json("http://127.0.0.1:1/x", retries=1, sleep=lambda s: None,
                  timeout=1)


def test_cli_requires_a_scope(tmp_path, capsys):
    assert main(["vuln-fetch", "--db", str(tmp_path)]) == 2
    assert "--all" in capsys.readouterr().err
