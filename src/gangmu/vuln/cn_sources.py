"""中国漏洞库适配：CNNVD、CNVD、工信部 NVDB。

为什么需要第三条通道
--------------------
NVD 和 OSV 都不收国内厂商自报的漏洞，而国产芯片 SDK、国产 RTOS 和国产密码库
的漏洞，往往只在 CNNVD（国家信息安全漏洞库）或 CNVD（国家信息安全漏洞共享
平台）里有条目。只接 NVD/OSV 的工具会把这些组件报成干净的。

与 NVD/OSV 的结构差异必须正视
------------------------------
CNNVD 与 CNVD 的条目通常**没有 CPE，也没有 PURL**，受影响范围是中文的产品
名称字符串。这意味着它们无法像 NVD 那样做版本区间匹配。本模块因此分两档处理：

* 条目带 CVE 编号的（多数国际组件的条目都带），按 CVE 编号与已有匹配**合并**，
  只补充中文描述与国内定级——定级与 CVSS 可能不一致，这本身就是要给人看的信息。
* 条目不带 CVE 编号的（国产组件的条目常常如此），只能按产品名称关键字给出
  **待人工确认的候选**，并明确标注为候选而不是匹配。把关键字命中当成确认匹配
  会制造大量误报，而在合规场景里误报和漏报都要有人付出代价。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .model import Advisory

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

_SEVERITY_FROM_CN = {
    "超危": "critical", "严重": "critical",
    "高危": "high", "高": "high",
    "中危": "medium", "中": "medium",
    "低危": "low", "低": "low",
}


def _first(data: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return None


def _severity(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    return _SEVERITY_FROM_CN.get(raw.strip(), raw.strip().lower())


@dataclass
class CnAdvisory:
    """一条国内库条目。保留原始中文字段，因为报送时要用中文。"""

    id: str
    source: str                       # "cnnvd" | "cnvd" | "nvdb"
    title: str = ""
    summary: str = ""
    severity_cn: Optional[str] = None
    severity: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    affected_text: str = ""
    published: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_advisory(self) -> Advisory:
        return Advisory(id=self.id, source=self.source, summary=self.summary,
                        severity=self.severity, references=self.references,
                        aliases=list(self.cve_ids))


def _norm(key: Any) -> str:
    """Field names differ in case, separators and language between exports
    (``cnnvdId``, ``vuln-id``, ``CNNVD编号``); compare them in one form."""
    return re.sub(r"[\s_\-:：]", "", str(key)).lower()


_ID_KEYS = ("cnnvdid", "cnvdid", "id", "number", "vulnid", "编号", "漏洞编号",
            "cnnvd编号", "cnvd编号", "cnnvdcode", "cnvdnumber", "xnvdid")
_TITLE_KEYS = ("vulnname", "title", "name", "漏洞名称", "名称")
_DESC_KEYS = ("vulndesc", "vulndescript", "description", "desc", "漏洞描述",
              "漏洞简介", "描述", "简介")
_SEVERITY_KEYS = ("severity", "serverity", "hazardlevel", "危害级别", "危害等级",
                  "severitycn", "level")
_AFFECTED_KEYS = ("affectedproduct", "affectedproducts", "products", "product",
                  "vulnsoftwarelist", "影响产品", "影响范围", "受影响产品")
_CVE_KEYS = ("cveid", "cve", "cvenumber", "cve编号", "cves", "otherid")
_REF_KEYS = ("references", "reflink", "refurl", "referencelink", "refs", "ref",
             "参考链接", "参考网址")
_PUBLISHED_KEYS = ("publishtime", "opentime", "published", "发布时间", "公开日期",
                   "公开时间")
# Keys the parser reads. Anything else in a dropped record is shown by the
# check command, because an unfamiliar export is how this fails.
_KNOWN = frozenset(_ID_KEYS + _TITLE_KEYS + _DESC_KEYS + _SEVERITY_KEYS
                   + _AFFECTED_KEYS + _CVE_KEYS + _REF_KEYS + _PUBLISHED_KEYS)


def _texts(value: Any) -> List[str]:
    """Every string inside a value, however nested (XML containers, lists)."""
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return [text] if text else []
    if isinstance(value, dict):
        return [t for v in value.values() for t in _texts(v)]
    if isinstance(value, (list, tuple)):
        return [t for v in value for t in _texts(v)]
    return []


def _source_for(ident: str, hint: str) -> str:
    """The record's own id prefix beats the file name: an export named
    ``vulns.json`` can still hold CNVD ids."""
    upper = ident.upper()
    if upper.startswith("CNNVD"):
        return "cnnvd"
    if upper.startswith("CNVD"):
        return "cnvd"
    if upper.startswith(("NVDB", "XNVD")):
        return "nvdb"
    return hint


def _parse_entry(raw: Dict[str, Any], source: str) -> Optional[CnAdvisory]:
    fields: Dict[str, Any] = {}
    for key, value in raw.items():
        fields.setdefault(_norm(key), value)

    def first(keys: Sequence[str]) -> Optional[str]:
        for key in keys:
            texts = _texts(fields.get(key))
            if texts:
                return texts[0]
        return None

    def every(keys: Sequence[str]) -> List[str]:
        return [t for key in keys for t in _texts(fields.get(key))]

    ident = first(_ID_KEYS)
    if not ident:
        return None
    title = first(_TITLE_KEYS) or ""
    summary = first(_DESC_KEYS) or title
    severity_cn = first(_SEVERITY_KEYS)
    affected = "；".join(every(_AFFECTED_KEYS))
    cves: List[str] = []
    for text in every(_CVE_KEYS) + [summary]:
        cves.extend(m.group(0).upper() for m in _CVE.finditer(text))
    refs = [t for t in every(_REF_KEYS) if t.startswith(("http://", "https://"))]
    return CnAdvisory(
        id=ident, source=_source_for(ident, source), title=title, summary=summary,
        severity_cn=severity_cn, severity=_severity(severity_cn),
        cve_ids=sorted(set(cves)), affected_text=affected,
        published=first(_PUBLISHED_KEYS), references=refs)


# --------------------------------------------------------------- file formats

_MAX_XML = 256 << 20
_RECORD_TAGS = {"entry", "vulnerability", "vuln", "item", "record", "row"}


def _decode(raw: bytes) -> str:
    """UTF-8 (with or without BOM), else GB18030: spreadsheets saved by Chinese
    Windows are very often GBK and would otherwise be unreadable."""
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("gb18030", raw[:0], 0, 0, "undecodable")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _flatten(element) -> Any:
    """An XML element as plain data: leaves become text, repeated tags lists."""
    children = list(element)
    if not children:
        return (element.text or "").strip()
    out: Dict[str, Any] = {}
    for child in children:
        value = _flatten(child)
        key = _local(child.tag)
        if key in out:
            if not isinstance(out[key], list):
                out[key] = [out[key]]
            out[key].append(value)
        else:
            out[key] = value
    return out


def _xml_records(text: str) -> List[Dict[str, Any]]:
    import xml.etree.ElementTree as ET
    head = text[:4096].upper()
    if "<!ENTITY" in head or "<!DOCTYPE" in head and "[" in head:
        raise ValueError("XML with entity declarations is refused")
    root = ET.fromstring(text)
    found = [e for e in root.iter() if _local(e.tag).lower() in _RECORD_TAGS
             and len(list(e)) > 0]
    # A record is the outermost match: <entry> inside <entry> is a sub-field.
    inner = {id(d) for e in found for d in e.iter() if d is not e}
    return [_flatten(e) for e in found if id(e) not in inner]


def _xml_stream(path: Path):
    """Records of a (possibly huge) XML export, one at a time.

    A year of CNNVD is 200 MB and the whole archive is a gigabyte, so the tree
    is never built: each record is flattened and released as soon as it ends.
    Parsing from bytes honours the encoding the file declares; a file that
    declares none and is not UTF-8 (GBK without a prolog) raises, and the
    caller falls back to the whole-file reader that tries GB18030.
    """
    import xml.etree.ElementTree as ET
    with open(path, "rb") as handle:
        head = handle.read(4096).upper()
        if b"<!ENTITY" in head or (b"<!DOCTYPE" in head and b"[" in head):
            raise ValueError("XML with entity declarations is refused")
        handle.seek(0)
        depth = 0
        for event, element in ET.iterparse(handle, events=("start", "end")):
            record = _local(element.tag).lower() in _RECORD_TAGS
            if event == "start":
                if record and depth >= 0:
                    depth += 1
                continue
            if not record:
                continue
            depth -= 1
            if depth == 0 and len(element) > 0:
                yield _flatten(element)
                element.clear()


def _chain(first, rest):
    yield first
    yield from rest


def _csv_records(text: str) -> List[Dict[str, Any]]:
    import csv
    import io
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def _json_records(text: str) -> List[Any]:
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "records", "vulnerabilities", "result", "list", "rows"):
            if isinstance(data.get(key), list):
                return data[key]
        inner = data.get("data")
        if isinstance(inner, dict):
            for key in ("list", "records", "rows"):
                if isinstance(inner.get(key), list):
                    return inner[key]
        return [data]
    return []


_READERS = {".json": ("json", _json_records), ".xml": ("xml", _xml_records),
            ".csv": ("csv", _csv_records)}
_UNSUPPORTED = {".xlsx": "xlsx", ".xls": "xls"}


@dataclass
class CnFileReport:
    path: Path
    format: str
    records: int = 0
    parsed: int = 0
    with_cve: int = 0
    with_severity: int = 0
    with_affected: int = 0
    error: Optional[str] = None
    unrecognised_keys: List[str] = field(default_factory=list)

    @property
    def dropped(self) -> int:
        return self.records - self.parsed


@dataclass
class CnLoadReport:
    files: List[CnFileReport] = field(default_factory=list)
    entries: List["CnAdvisory"] = field(default_factory=list)
    parsed: int = 0
    """Every record that was understood, whether or not ``keep`` retained it."""
    no_cve: int = 0
    sources: Dict[str, int] = field(default_factory=dict)

    @property
    def problems(self) -> List[str]:
        out: List[str] = []
        for f in self.files:
            if f.error:
                out.append(f"{f.path}: {f.error}")
            elif f.dropped:
                out.append(f"{f.path}: {f.dropped} of {f.records} record(s) have no "
                           f"recognisable id and were dropped"
                           + (f"; keys seen: {', '.join(f.unrecognised_keys)}"
                              if f.unrecognised_keys else ""))
        return out


def load_cn_report(directory: Path, keep=None) -> CnLoadReport:
    """Read every CNNVD / CNVD / NVDB export under *directory* and say what
    happened to each file.

    Exports differ by site, by year and by whoever saved them, so fields are
    matched by name (case, separators and language ignored) and the format by
    extension: ``.json``, ``.xml`` (CNNVD's NVD-style entries, CNVD's
    bulletins), ``.csv`` (UTF-8 or GBK). Nothing is dropped silently: a file
    that cannot be read, and records without an id, are reported, because a
    database that quietly loads as empty reads as a clean bill of health.

    *keep*, when given, is called on each entry and only entries it accepts are
    retained in ``entries``; the counts still cover every record. The full
    CNNVD archive is 139,000 entries and several GB as objects, while one SBOM
    needs the few that name its components.
    """
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"国内漏洞库目录不存在: {directory}")
    report = CnLoadReport()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        suffix = path.suffix.lower()
        if suffix in _UNSUPPORTED:
            report.files.append(CnFileReport(
                path, _UNSUPPORTED[suffix],
                error="spreadsheets are not read; save it as CSV (UTF-8 or GBK)"))
            continue
        if suffix not in _READERS:
            continue
        fmt, reader = _READERS[suffix]
        file_report = CnFileReport(path, fmt)
        report.files.append(file_report)
        records = None
        try:
            if fmt == "xml":
                try:
                    records = _xml_stream(path)
                    first = next(records, None)
                    records = ([] if first is None else _chain(first, records))
                except (UnicodeDecodeError, SyntaxError):
                    records = None              # undeclared GBK: whole-file path
                except ValueError:
                    raise
            if records is None:
                raw = path.read_bytes()
                if len(raw) > _MAX_XML:
                    raise ValueError("file is larger than 256 MB")
                records = reader(_decode(raw))
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            file_report.error = f"unreadable {fmt}: {exc}"
            continue
        except Exception as exc:                      # ElementTree.ParseError
            file_report.error = f"unreadable {fmt}: {exc}"
            continue
        name = path.name.lower()
        hint = ("cnvd" if "cnvd" in name else
                "nvdb" if "nvdb" in name or "cstis" in name else "cnnvd")
        seen = set()
        try:
            for raw_record in records:
                if not isinstance(raw_record, dict):
                    continue
                file_report.records += 1
                entry = _parse_entry(raw_record, hint)
                if entry is None:
                    seen.update(k for k in map(str, raw_record)
                                if _norm(k) not in _KNOWN)
                    continue
                file_report.parsed += 1
                file_report.with_cve += bool(entry.cve_ids)
                file_report.with_severity += bool(entry.severity_cn)
                file_report.with_affected += bool(entry.affected_text)
                report.parsed += 1
                report.no_cve += not entry.cve_ids
                report.sources[entry.source] = report.sources.get(entry.source, 0) + 1
                if keep is None or keep(entry):
                    report.entries.append(entry)
        except Exception as exc:                      # a parse error part-way through
            file_report.error = f"unreadable {fmt}: {exc}"
            continue
        file_report.unrecognised_keys = sorted(seen)[:12]
    return report


def load_cn_database(directory: Path, keep=None) -> List["CnAdvisory"]:
    """Entries of every export under *directory*; problems are warned about
    (see :func:`load_cn_report`, which returns them as data)."""
    import warnings
    report = load_cn_report(directory, keep)
    for problem in report.problems:
        warnings.warn(f"国内漏洞库: {problem}", stacklevel=2)
    return report.entries


@dataclass
class CnEnrichment:
    merged: Dict[str, List[CnAdvisory]] = field(default_factory=dict)
    """CVE 编号 -> 对应的国内条目。用于给已有匹配补中文描述与国内定级。"""
    candidates: List[tuple] = field(default_factory=list)
    """(组件名, 国内条目)。只按产品名关键字命中，必须人工确认。"""
    disagreements: List[tuple] = field(default_factory=list)
    """(CVE, 国际定级, 国内定级)。两边不一致本身是要上报的信息。"""


def enrich(components: Sequence, cn_advisories: Sequence[CnAdvisory],
           matches: Sequence) -> CnEnrichment:
    """把国内条目接到已有匹配上，并给无 CVE 的条目找候选组件。"""
    out = CnEnrichment()
    by_cve: Dict[str, List[CnAdvisory]] = {}
    without_cve: List[CnAdvisory] = []
    for entry in cn_advisories:
        if entry.cve_ids:
            for cve in entry.cve_ids:
                by_cve.setdefault(cve.upper(), []).append(entry)
        else:
            without_cve.append(entry)

    for match in matches:
        key = match.advisory.id.upper()
        hits = by_cve.get(key) or []
        for alias in match.advisory.aliases:
            hits.extend(by_cve.get(str(alias).upper(), []))
        if hits:
            out.merged[match.advisory.id] = hits
            for entry in hits:
                if (entry.severity and match.advisory.severity
                        and entry.severity != match.advisory.severity):
                    out.disagreements.append(
                        (match.advisory.id, match.advisory.severity, entry.severity))

    for component in components:
        name = (component.name or "").lower()
        if len(name) < 3:
            continue
        for entry in without_cve:
            haystack = f"{entry.title} {entry.affected_text}".lower()
            if name in haystack:
                out.candidates.append((component.name, entry))
    return out
