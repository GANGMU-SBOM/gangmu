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
_SAVE_BATCH = 2000        # records gathered before the year shards are rewritten
_XZ_PRESET = 3            # xz level of a shard: about 10x quicker to write than the default 6,
#                           for a file about a third larger
_NETWORK_MAX_DELAY = 16.0  # longest wait after a network error; throttling may wait longer
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
              retries: Optional[int] = 5, sleep: Callable[[float], None] = time.sleep,
              timeout: float = 60.0,
              log: Callable[[str], None] = lambda m: None) -> dict:
    """GET (or POST, with *body*) a JSON document, backing off on throttling.

    *retries* is how many times to try again (None: until it works; the caller stops it with
    Ctrl+C). Each retry is reported to *log* with its cause. A network error waits at most
    ``_NETWORK_MAX_DELAY`` seconds, which is still inside NVD's rate limit; a throttling
    answer waits as long as the server says, or backs off up to a minute.

    The system proxy settings are honoured by urllib, which is what an
    intranet-adjacent build host needs.
    """
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": "gangmu-vuln-fetch", "Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    delay = 2.0
    attempt = 0
    while True:
        last = retries is not None and attempt >= retries
        attempt += 1
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code not in _RETRY_STATUS or last:
                raise FetchError(f"{exc.code} from {url}: {exc.reason}") from exc
            wait = exc.headers.get("Retry-After") if exc.headers else None
            pause = float(wait) if wait and wait.isdigit() else delay
            log(f"  retry {attempt}: HTTP {exc.code}, again in {pause:g}s")
            sleep(pause)
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError,
                http.client.HTTPException, ValueError) as exc:
            # IncompleteRead (a body cut off part-way) is an HTTPException, not an
            # OSError, and a truncated body fails to parse as JSON.
            if last:
                if isinstance(exc, (http.client.IncompleteRead, TimeoutError,
                                    socket.timeout, ConnectionResetError, ValueError)):
                    raise TransferError(f"transfer from {url} failed: "
                                        f"{type(exc).__name__}: {exc}") from exc
                raise FetchError(f"cannot reach {url}: {exc}") from exc
            pause = min(delay, _NETWORK_MAX_DELAY)
            log(f"  retry {attempt}: {type(exc).__name__}: {exc}, again in {pause:g}s")
            sleep(pause)
        delay = min(delay * 2, 60.0)


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
    with lzma.open(tmp, "wt", encoding="utf-8", preset=_XZ_PRESET) as fh:
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
             shrunk: Callable[[int], None] = lambda size: None,
             progress: Callable[[int, int], None] = lambda nxt, total: None
             ) -> Iterator[List[dict]]:
    """Pages of one NVD query, from record *start*. NVD allows 5 requests / 30 s
    anonymously and 50 with a key; the pause keeps a long run inside that.

    A page is a few MB; on a poor link it may never arrive whole. When a transfer
    fails after its retries the page size is halved (down to ``_NVD_MIN_PAGE``) and
    the same records are asked for again; *shrunk* is told the new size. *progress* is told,
    after each page, the index of the next record and how many records the query has."""
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
        total = int(page.get("totalResults", 0))
        progress(start + len(items), total)
        yield items
        start += len(items)
        if not items or start >= total:
            return
        sleep(pause)


def _nvd_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_nvd(dest: Path, get: Optional[JsonGetter] = None, products: Sequence[str] = (),
              api_key: Optional[str] = None, since: Optional[datetime] = None,
              now: Optional[datetime] = None, base_url: str = NVD_API,
              sleep: Callable[[float], None] = time.sleep,
              log: Callable[[str], None] = lambda m: None,
              page_size: Optional[int] = None, retries: Optional[int] = 5,
              save_batch: Optional[int] = None,
              notice: Callable[[str], None] = lambda m: None) -> int:
    """Fetch NVD records into *dest*; returns the count new or changed.

    *products* are ``part:vendor:product`` keys (what the matcher indexes). With
    none, this is a full / incremental sync of the whole NVD. *page_size* is the
    records asked for per request (default: 2000, or the size an earlier run had to shrink
    to); *retries* how often a failed request is tried again (None: until it works).
    *save_batch* is how many records are gathered before the year shards are rewritten
    (default 2000; each held record takes about 15 KB of memory). *notice* is told what the
    user must not miss even without -v: that a stop is being saved first.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    get = get or (lambda url, headers: http_json(url, headers=headers, sleep=sleep,
                                                 retries=retries, log=log))
    now = now or datetime.now(timezone.utc)
    state = _load_state(dest)
    total = 0
    damaged: List[Path] = []
    # the page size an earlier run had to shrink to on this link, so a rerun does not
    # fail its way down again
    remembered = state.get("nvd_page")
    page = page_size or (remembered if isinstance(remembered, int)
                         and _NVD_MIN_PAGE <= remembered < _NVD_PAGE else _NVD_PAGE)

    def shrunk(size: int) -> None:
        nonlocal page
        page = size
        state["nvd_page"] = size
        _save_state(dest, state)
        log(f"  transfer failed; asking for {size} records per page")

    def run(params: Dict[str, str], first: int = 0, progress: bool = False) -> int:
        # A page is a few hundred to 2000 records and every year shard it touches is
        # rewritten whole (xz-compressing a big shard takes seconds), so pages are gathered
        # and merged _SAVE_BATCH records at a time. What was fetched is saved before an error
        # or Ctrl+C leaves; the position kept for a resume only ever covers saved records.
        n = 0
        index = first
        pending: List[dict] = []
        total = 0
        batch = save_batch or _SAVE_BATCH

        def fetched(next_index: int, count: int) -> None:
            nonlocal total
            total = count
            log(f"  {next_index - index} record(s) fetched, next index {next_index}, "
                f"total {count}")

        def save() -> None:
            nonlocal n
            if not pending:
                return
            began = time.monotonic()
            n += merge_nvd(dest, pending, damaged)
            log(f"  {len(pending)} record(s) saved, next index {index}, "
                f"took {time.monotonic() - began:.0f}s")
            pending.clear()
            if progress:
                # The shards now hold these records; remember where to go on from.
                state["nvd_full"]["next_index"] = index
                _save_state(dest, state)

        try:
            for items in iter_nvd(params, get, api_key, base_url, sleep=sleep, start=first,
                                  page_size=page, shrunk=shrunk, progress=fetched):
                pending.extend(items)
                index += len(items)
                if len(pending) >= batch:
                    save()
        except BaseException:
            if pending:
                notice(f"saving the {len(pending)} record(s) already fetched before stopping; "
                       f"this can take several minutes on a large database, so please wait "
                       f"and do not kill the process (Ctrl+C again gives them up; the next "
                       f"run fetches them again)")
            save()
            raise
        save()
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
