"""Filling the local advisory directory, when the network is there.

``gangmu vuln`` reads only a local directory, on purpose. That left the
directory's origin to the user, and "download the NVD yourself" is the step that
gets skipped at 2am. This module is that step, kept strictly separate from the
lookup: run it on a connected machine (or in CI), carry the directory into the
factory network, and ``gangmu vuln`` works there unchanged.

Two modes, because the two needs differ:

* **Scoped** (``products`` / ``purls``): only what an SBOM can match. Seconds,
  not minutes -- the mode to run in the hour after a disclosure.
* **Full** (no scope): the whole NVD, sharded by CVE year, and thereafter
  incremental -- a stored watermark means the next run asks NVD only for
  records modified since.

NVD records are merged by CVE id into ``nvd-<year>.json.xz`` shards, so a scoped
run and a full run never leave the same CVE twice. Shards are written to a
temporary file and renamed, so an interrupted run cannot leave a truncated feed
that reads like a clean bill of health.
"""

from __future__ import annotations

import http.client
import json
import lzma
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence

from .match import purl_key

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1"
STATE_FILE = ".gangmu-fetch.state"
_NVD_PAGE = 2000
_NVD_MIN_PAGE = 100       # the smallest page a failing transfer is cut down to
_MAX_WINDOW = timedelta(days=119)       # the API rejects ranges over 120 days
_RETRY_STATUS = {403, 429, 500, 502, 503, 504}

JsonGetter = Callable[[str, Optional[dict]], dict]


class FetchError(RuntimeError):
    pass


class TransferError(FetchError):
    """The connection was made but the body did not arrive whole (cut off, timed out,
    not JSON). A smaller request can succeed where this one keeps failing."""


def http_json(url: str, body: Optional[dict] = None,
              headers: Optional[Dict[str, str]] = None,
              retries: int = 5, sleep: Callable[[float], None] = time.sleep,
              timeout: float = 60.0) -> dict:
    """GET (or POST, with *body*) a JSON document, backing off on throttling.

    The system proxy settings are honoured by urllib, which is what an
    intranet-adjacent build host needs.
    """
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": "gangmu-vuln-fetch", "Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    delay = 2.0
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code not in _RETRY_STATUS or attempt == retries:
                raise FetchError(f"{exc.code} from {url}: {exc.reason}") from exc
            wait = exc.headers.get("Retry-After") if exc.headers else None
            sleep(float(wait) if wait and wait.isdigit() else delay)
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError,
                http.client.HTTPException, ValueError) as exc:
            # IncompleteRead (a body cut off part-way) is an HTTPException, not an
            # OSError, and a truncated body fails to parse as JSON.
            if attempt == retries:
                if isinstance(exc, (http.client.IncompleteRead, TimeoutError,
                                    socket.timeout, ConnectionResetError, ValueError)):
                    raise TransferError(f"transfer from {url} failed: "
                                        f"{type(exc).__name__}: {exc}") from exc
                raise FetchError(f"cannot reach {url}: {exc}") from exc
            sleep(delay)
        delay = min(delay * 2, 60.0)
    raise FetchError(f"gave up on {url}")      # pragma: no cover


# ---------------------------------------------------------------- shards


def _year(cve_id: str) -> str:
    m = re.match(r"^[A-Za-z]+-(\d{4})-", cve_id or "")
    return m.group(1) if m else "misc"


def _shard_path(dest: Path, year: str) -> Path:
    return dest / f"nvd-{year}.json.xz"


class _UnreadableShard(Exception):
    pass


def _read_shard(path: Path) -> Dict[str, dict]:
    if not path.exists():
        return {}
    try:
        with lzma.open(path, "rt", encoding="utf-8") as fh:
            items = json.load(fh).get("vulnerabilities", [])
    except (OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        raise _UnreadableShard(str(exc)) from exc
    return {i["cve"]["id"]: i for i in items
            if (i.get("cve") or {}).get("id")}


def _write_shard(path: Path, records: Dict[str, dict]) -> None:
    doc = {"format": "NVD_CVE", "version": "2.0",
           "vulnerabilities": [records[k] for k in sorted(records)]}
    tmp = path.with_suffix(path.suffix + ".tmp")
    with lzma.open(tmp, "wt", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"))
    os.replace(tmp, path)


def merge_nvd(dest: Path, items: Iterable[dict],
              damaged: Optional[List[Path]] = None) -> int:
    """Merge records into the per-year shards; returns how many were new or
    changed.

    An unreadable shard is not trusted and not silently emptied either: it is moved
    aside to ``*.unreadable``, rebuilt from what is fetched now, and listed in
    *damaged*. Its other records are gone from the mirror until a full download.
    """
    by_year: Dict[str, List[dict]] = {}
    for item in items:
        cve_id = (item.get("cve") or {}).get("id")
        if cve_id:
            by_year.setdefault(_year(cve_id), []).append(item)
    changed = 0
    for year, batch in by_year.items():
        path = _shard_path(dest, year)
        try:
            records = _read_shard(path)
        except _UnreadableShard as exc:
            aside = path.with_name(path.name + ".unreadable")
            os.replace(path, aside)
            warnings.warn(f"{path}: unreadable ({exc}); moved to {aside.name}. Its "
                          f"records are missing until a full download (vuln-fetch --all "
                          f"with no --since).", stacklevel=2)
            if damaged is not None:
                damaged.append(path)
            records = {}
        for item in batch:
            cve_id = item["cve"]["id"]
            if records.get(cve_id) != item:
                records[cve_id] = item
                changed += 1
        _write_shard(path, records)
    return changed


# ------------------------------------------------------------------- NVD


def _nvd_headers(api_key: Optional[str]) -> Dict[str, str]:
    return {"apiKey": api_key} if api_key else {}


def iter_nvd(params: Dict[str, str], get: JsonGetter, api_key: Optional[str] = None,
             base_url: str = NVD_API, pause: Optional[float] = None,
             sleep: Callable[[float], None] = time.sleep,
             start: int = 0, page_size: Optional[int] = None,
             shrunk: Callable[[int], None] = lambda size: None) -> Iterator[List[dict]]:
    """Pages of one NVD query, from record *start*. NVD allows 5 requests / 30 s
    anonymously and 50 with a key; the pause keeps a long run inside that.

    A page is a few MB; on a poor link it may never arrive whole. When a transfer
    fails after its retries the page size is halved (down to ``_NVD_MIN_PAGE``) and
    the same records are asked for again; *shrunk* is told the new size."""
    if pause is None:
        pause = 0.7 if api_key else 6.5
    size = page_size or _NVD_PAGE
    while True:
        query = dict(params, resultsPerPage=str(size), startIndex=str(start))
        url = f"{base_url}?{urllib.parse.urlencode(query)}"
        try:
            page = get(url, _nvd_headers(api_key))
        except TransferError:
            if size <= _NVD_MIN_PAGE:
                raise
            size = max(size // 2, _NVD_MIN_PAGE)
            shrunk(size)
            continue
        items = page.get("vulnerabilities", []) or []
        yield items
        start += len(items)
        if not items or start >= int(page.get("totalResults", 0)):
            return
        sleep(pause)


def _nvd_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_nvd(dest: Path, get: Optional[JsonGetter] = None, products: Sequence[str] = (),
              api_key: Optional[str] = None, since: Optional[datetime] = None,
              now: Optional[datetime] = None, base_url: str = NVD_API,
              sleep: Callable[[float], None] = time.sleep,
              log: Callable[[str], None] = lambda m: None) -> int:
    """Fetch NVD records into *dest*; returns the count new or changed.

    *products* are ``part:vendor:product`` keys (what the matcher indexes). With
    none, this is a full / incremental sync of the whole NVD.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    get = get or (lambda url, headers: http_json(url, headers=headers, sleep=sleep))
    now = now or datetime.now(timezone.utc)
    state = _load_state(dest)
    total = 0
    damaged: List[Path] = []
    # the page size an earlier run had to shrink to on this link, so a rerun does not
    # fail its way down again
    remembered = state.get("nvd_page")
    page = (remembered if isinstance(remembered, int)
            and _NVD_MIN_PAGE <= remembered < _NVD_PAGE else _NVD_PAGE)

    def shrunk(size: int) -> None:
        nonlocal page
        page = size
        state["nvd_page"] = size
        _save_state(dest, state)
        log(f"  transfer failed; asking for {size} records per page")

    def run(params: Dict[str, str], first: int = 0, progress: bool = False) -> int:
        n = 0
        index = first
        for items in iter_nvd(params, get, api_key, base_url, sleep=sleep, start=first,
                              page_size=page, shrunk=shrunk):
            n += merge_nvd(dest, items, damaged)
            index += len(items)
            log(f"  {len(items)} record(s) fetched")
            if progress:
                # The shards already hold these records; remember where to go on from.
                state["nvd_full"]["next_index"] = index
                _save_state(dest, state)
        return n

    def run_windows(params: Dict[str, str], start: datetime) -> int:
        n = 0
        for window in _windows(start, now):
            log(f"  modified {window['lastModStartDate'][:10]} .. "
                f"{window['lastModEndDate'][:10]}")
            n += run(dict(params, **window))
        return n

    full = False
    if products:
        for key in products:
            parts = key.split(":")
            if len(parts) != 3:
                continue
            match = f"cpe:2.3:{parts[0]}:{parts[1]}:{parts[2]}"
            log(f"NVD: {key}")
            params = {"virtualMatchString": match}
            total += run_windows(params, since) if since is not None else run(params)
    else:
        mark = now
        start = since or _parse_time(state.get("nvd_watermark"))
        if start is None:
            # A full download is hours at the anonymous rate and can break anywhere. The
            # shards are merged page by page, so keep the position and the start time:
            # the next run goes on from there, and the watermark is the start time, so
            # whatever changed while the download ran is picked up by the incremental run.
            partial = state.get("nvd_full") or {}
            began = _parse_time(partial.get("started"))
            stamp = began or now
            first = int(partial.get("next_index", 0)) if began else 0
            if began:
                # a page back: records published meanwhile can shift the paging
                first = max(0, first - page)
                log(f"NVD: resuming the full download at record {first}")
            else:
                log("NVD: full download")
            state["nvd_full"] = {"started": stamp.astimezone(timezone.utc).isoformat(),
                                 "next_index": first}
            try:
                total = run({}, first, progress=True)
            except FetchError as exc:
                raise FetchError(f"{exc}\nProgress is saved; run the same command "
                                 f"again to continue the download.") from exc
            state.pop("nvd_full", None)
            mark = stamp
            full = True
        else:
            log("NVD: incremental")
            total = run_windows({}, start)
        state["nvd_watermark"] = mark.astimezone(timezone.utc).isoformat()

    if damaged and not full:
        # What the damaged shards held is not in this run; an incremental run from
        # the old watermark would never bring it back.
        state.pop("nvd_watermark", None)
        log(f"NVD: {len(damaged)} unreadable shard(s) set aside; the next run without "
            f"--since downloads everything again")
    if not products or damaged:
        _save_state(dest, state)
    return total


def _windows(since: datetime, now: datetime) -> Iterator[Dict[str, str]]:
    """``lastMod`` parameters covering *since* .. *now* in windows the API accepts."""
    start = since
    while start < now:
        end = min(start + _MAX_WINDOW, now)
        yield {"lastModStartDate": _nvd_time(start), "lastModEndDate": _nvd_time(end)}
        start = end


# ------------------------------------------------------------------- OSV


def _safe_name(osv_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", osv_id)


def _repo_url(purl: str) -> Optional[str]:
    """``pkg:github/o/r@v1`` -> ``https://github.com/o/r``, the form OSV's GIT
    ecosystem is queried by. Lower-cased: the purl has lost the repository's
    capitalisation, and OSV matches the URL exactly."""
    key = purl_key(purl)
    m = key and re.match(r"^pkg:(github|gitlab|bitbucket)/([^/]+)/([^/]+)$", key)
    if not m:
        return None
    host = {"github": "github.com", "gitlab": "gitlab.com",
            "bitbucket": "bitbucket.org"}[m.group(1)]
    return f"https://{host}/{m.group(2)}/{m.group(3)}"


def fetch_osv(dest: Path, purls: Sequence[str], get: Optional[JsonGetter] = None,
              post: Optional[Callable[[str, dict], dict]] = None,
              base_url: str = OSV_API,
              log: Callable[[str], None] = lambda m: None) -> int:
    """Fetch the OSV records affecting *purls* into ``dest/osv/``.

    Uses the batch query for ids, then one request per record the directory
    does not already hold. Versionless purls are queried as given, so every
    record for the package comes back and the matcher does the version test.
    """
    out = Path(dest) / "osv"
    out.mkdir(parents=True, exist_ok=True)
    get = get or (lambda url, headers: http_json(url, headers=headers))
    post = post or (lambda url, body: http_json(url, body))
    ids: List[str] = []
    packages: List[dict] = []
    for purl in dict.fromkeys(purls):
        packages.append({"purl": purl})
        repo = _repo_url(purl)
        if repo:
            packages.append({"name": repo, "ecosystem": "GIT"})
    for package in packages:
        token = None
        while True:
            query: dict = {"package": package}
            if token:
                query["page_token"] = token
            reply = post(f"{base_url}/querybatch", {"queries": [query]})
            result = (reply.get("results") or [{}])[0]
            ids.extend(v["id"] for v in result.get("vulns", []) if v.get("id"))
            token = result.get("next_page_token")
            if not token:
                break
    fetched = 0
    for osv_id in dict.fromkeys(ids):
        record = get(f"{base_url}/vulns/{urllib.parse.quote(osv_id)}", None)
        path = out / f"{_safe_name(osv_id)}.json"
        text = json.dumps(record, indent=1, sort_keys=True)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, path)
            fetched += 1
        log(f"  {osv_id}")
    return fetched


# ----------------------------------------------------------------- state


def _load_state(dest: Path) -> dict:
    try:
        return json.loads((dest / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(dest: Path, state: dict) -> None:
    (dest / STATE_FILE).write_text(json.dumps(state, indent=1), encoding="utf-8")


def _parse_time(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
