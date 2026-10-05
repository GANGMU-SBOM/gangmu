"""Loose version ordering.

Embedded component versions are not semver. Real values seen in the rule base
built so far: ``2.2.0``, ``1.7.19``, ``0.2-265-gad902ca``, ``v2.6.0-RC1``,
``4.1.1``, and ``git-2867f6883a12`` for components that have no release at all.

A comparator that refused anything non-semver would silently drop half the
components; one that guessed would produce wrong CVE matches, which is worse.
So this one is explicit about failure: :func:`compare` returns ``None`` when the
two values cannot be ordered, and every caller must decide what to do with that
rather than defaulting to "not affected".
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

INTERVAL_SEP = "~"
_NUMERIC = re.compile(r"\d+")
_PRERELEASE = re.compile(r"(?:-|\.)(rc|alpha|beta|pre|pr|a|b)\.?(\d*)$", re.I)
# A single letter straight after the last digit is a *later* release, not an
# earlier one: OpenSSL 1.1.1w follows 1.1.1, FatFs R0.14b follows R0.14a.
_LETTER_RELEASE = re.compile(r"(?<=\d)([a-z])$", re.I)
_RANK = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "pre": 2, "rc": 3}


def is_orderable(version: Optional[str]) -> bool:
    """False for a commit identifier or anything with no numeric backbone."""
    if not version:
        return False
    text = version.strip()
    if text.lower().startswith(("git-", "sha-", "commit-")):
        return False
    if INTERVAL_SEP in text:
        return all(is_orderable(end) for end in text.split(INTERVAL_SEP, 1))
    # A bare hash has at least one hex letter; eight digits is a date tag
    # (OpenThread's 20250612), which orders perfectly well.
    if re.fullmatch(r"[0-9a-f]{7,40}", text.lower()) and re.search(r"[a-f]", text.lower()):
        return False
    return bool(_NUMERIC.search(text))


def split_interval(version: Optional[str]) -> Optional[Tuple[str, str]]:
    """``"10.4.0~10.4.2"`` -> ``("10.4.0", "10.4.2")``; ``None`` for a plain version.

    A function signature that cannot tell neighbouring releases apart reports
    the whole span it cannot split, written ``low~high``.
    """
    if version and INTERVAL_SEP in version:
        low, high = (part.strip() for part in version.split(INTERVAL_SEP, 1))
        if low and high:
            return low, high
    return None


def _parts(version: str) -> Tuple[List[int], int, int]:
    text = version.strip().lstrip("vV")
    pre = _PRERELEASE.search(text)
    rank, pre_num = 4, 0          # 4 = a final release, higher than any pre-release
    if pre:
        rank = _RANK.get(pre.group(1).lower(), 2)
        pre_num = int(pre.group(2)) if pre.group(2) else 0
        text = text[:pre.start()]
    # 0.2-265-gad902ca -> [0, 2, 265]; the trailing git hash carries no order
    numbers = [int(n) for n in _NUMERIC.findall(text)]
    letter = _LETTER_RELEASE.search(text)
    if letter and numbers:
        numbers.append(ord(letter.group(1).lower()) - ord("a") + 1)
    return numbers, rank, pre_num


def compare(left: str, right: str) -> Optional[int]:
    """-1, 0, 1, or None when the two cannot be meaningfully ordered."""
    if INTERVAL_SEP in left or INTERVAL_SEP in right:
        return None
    if not is_orderable(left) or not is_orderable(right):
        return None
    ln, lr, lp = _parts(left)
    rn, rr, rp = _parts(right)
    if not ln or not rn:
        return None
    for a, b in zip(ln + [0] * len(rn), rn + [0] * len(ln)):
        if a != b:
            return -1 if a < b else 1
    if lr != rr:
        return -1 if lr < rr else 1
    if lp != rp:
        return -1 if lp < rp else 1
    return 0


def in_range(version: str, introduced: Optional[str] = None,
             fixed: Optional[str] = None,
             last_affected: Optional[str] = None,
             start_including: Optional[str] = None,
             start_excluding: Optional[str] = None,
             end_including: Optional[str] = None,
             end_excluding: Optional[str] = None) -> Optional[bool]:
    """Is *version* inside the range? ``None`` means "cannot tell".

    Accepts both the OSV vocabulary (introduced / fixed / last_affected) and the
    NVD one (versionStartIncluding and friends), because a component is matched
    through whichever database happens to know about it.
    """
    checks = [
        (introduced or start_including, lambda c: c >= 0),
        (start_excluding, lambda c: c > 0),
        (fixed or end_excluding, lambda c: c < 0),
        (last_affected or end_including, lambda c: c <= 0),
    ]
    span = split_interval(version)
    if span is not None:
        return _interval_verdict(span, checks)
    saw_bound = False
    for bound, ok in checks:
        if not bound or bound == "0":
            if bound == "0":
                saw_bound = True
            continue
        saw_bound = True
        result = compare(version, bound)
        if result is None:
            return None
        if not ok(result):
            return False
    return True if saw_bound else None


def _interval_verdict(span, checks) -> Optional[bool]:
    """A version known only as *low~high* against one contiguous range.

    Inside at both ends means every release between is inside. Outside on the
    same side at both ends means the whole span is outside. Anything else --
    the span straddles a bound, or the range sits wholly inside the span --
    cannot be decided from the version, so the answer is ``None`` (triage),
    never a guess.
    """
    sides = []
    for end in span:
        side = "in"
        for index, (bound, ok) in enumerate(checks):
            if not bound or bound == "0":
                continue
            result = compare(end, bound)
            if result is None:
                return None
            if not ok(result):
                side = "below" if index < 2 else "above"   # lower or upper bound failed
                break
        sides.append(side)
    if sides[0] != sides[1]:
        return None
    return sides[0] == "in"


_TAG_CORE = re.compile(r"\d+(?:[._]\d+)+|\d+")
# `rc1`, `-beta`, `.pre2` are pre-releases. A bare `a` or `b` after the digits is
# not: FatFs tags R0.14a and R0.14b are releases, so those two letters count as
# a pre-release only behind a separator or in front of a number (`1.0b2`).
_TAG_PRE = re.compile(r"^(?:[-_.]?(rc|alpha|beta|pre|pr)|[-_.](a|b)|(a|b)(?=\d))\.?(\d*)", re.I)


# What real OSV `versions` lists carry besides releases: browser-compat branches
# (`v1.6.0-chrome48-firefox42`, `support-chrome-20-firefox-12`) and dated test
# tags (`master-test-2015-11-19-1`). Their digits are not a release number, and
# one such tag stretches the span of listed tags to "2015", so every release
# below it turns "unlisted, maybe affected" instead of "past the fix".
_TAG_JUNK_REST = re.compile(r"[A-Za-z]+[-_.]?\d")
_TAG_DATE_CORE = re.compile(r"\d{4}-\d{1,2}-\d{1,2}")
_TAG_DATE_SUFFIX = re.compile(r"^[._-]v?\d{8}$")        # jetty-9.4.42.v20210604


def normalize_tag(tag: Optional[str]) -> Optional[str]:
    """A release tag as a comparable version, or ``None`` if it has no number.

    Upstreams tag however they like -- ``v1.7.15``, ``V10.4.1``,
    ``STABLE-2_2_0_RELEASE``, ``openssl-3.0.1``, ``OpenSSL_1_1_1w`` -- and an
    OSV record lists them verbatim. Reducing both the record's tags and the
    component's own version to this form is what lets them be compared.
    """
    if not tag:
        return None
    found = _TAG_CORE.search(tag)
    if not found:
        return None
    core = found.group(0).replace("_", ".")
    rest = tag[found.end():]
    if _TAG_DATE_CORE.match(tag, found.start()):
        return None
    pre = _TAG_PRE.match(rest)
    tail = rest[pre.end():] if pre else rest
    if _TAG_JUNK_REST.search(tail) and not _TAG_DATE_SUFFIX.match(tail):
        return None
    if pre:
        word = (pre.group(1) or pre.group(2) or pre.group(3)).lower()
        return f"{core}-{word}{pre.group(4)}"
    if re.match(r"^[a-z](?![a-z])", rest):        # OpenSSL 1.1.1w style
        return core + rest[0]
    return core


def in_tag_set(version: Optional[str], tags: List[str],
               open_ended: bool = False) -> Optional[bool]:
    """Is *version* among the affected release *tags* of an OSV GIT range?

    OSV lists the tags a GIT range covers; the range's own events are commit
    hashes and cannot be ordered. Exact membership is a yes. Outside the span of
    the listed tags is a no (above it, only if the range has a fix). Inside the
    span but unlisted could be a gap or a fix followed by a regression, and the
    record does not say which, so that is ``None``: a person decides.
    """
    span = split_interval(version)
    if span is not None:
        # Only a unanimous yes is safe: "outside" at both ends can also mean
        # the listed tags sit between them.
        verdicts = {in_tag_set(end, tags, open_ended) for end in span}
        return True if verdicts == {True} else None
    if not is_orderable(version):       # a commit id has digits but no order
        return None
    wanted = normalize_tag(version)
    if wanted is None:
        return None
    known = [t for t in map(normalize_tag, tags) if t and is_orderable(t)]
    if not known:
        return None
    if wanted in known:
        return True
    # `support-protocol-v7` is a branch, not release 7: where the list is
    # dotted releases, a bare integer must not set the span's ends.
    if any("." in t for t in known):
        known = [t for t in known if "." in t]
    lowest = highest = known[0]
    for t in known[1:]:
        lo, hi = compare(t, lowest), compare(t, highest)
        if lo is None or hi is None:
            return None
        lowest = t if lo < 0 else lowest
        highest = t if hi > 0 else highest
    below, above = compare(wanted, lowest), compare(wanted, highest)
    if below is None or above is None:
        return None
    if below < 0:
        return False
    if above > 0:
        return True if open_ended else False
    return None


def in_event_ranges(version: Optional[str], events: List[dict]) -> Optional[bool]:
    """Is *version* inside the intervals of an OSV event list written in versions?

    Some GIT ranges list no tags but carry ``database_specific.extracted_events``,
    OSV's own reading of the CVE's CPE ranges or description into version
    bounds. Anything not orderable (``<4.3.4``, a branch name) makes the answer
    ``None``, never a guess.
    """
    if not events or not is_orderable(version):
        return None
    wanted = normalize_tag(version)
    if wanted is None:
        return None
    intervals, start = [], None
    for event in events:
        for kind, bound in event.items():
            if kind == "introduced":
                start = bound
            elif kind in ("fixed", "last_affected", "limit") and start is not None:
                intervals.append((start, kind, bound))
                start = None
            else:
                return None
    if start is not None:
        intervals.append((start, None, None))
    if not intervals:
        return None
    verdict = False
    for lo, kind, hi in intervals:
        for bound in (lo, hi):
            if bound in (None, "0"):
                continue
            if (re.search(r"[<>=~,\s]", bound) or normalize_tag(bound) is None
                    or not is_orderable(normalize_tag(bound))):
                return None
        result = in_range(wanted, introduced=normalize_tag(lo) if lo != "0" else "0",
                          fixed=normalize_tag(hi) if kind in ("fixed", "limit") else None,
                          last_affected=normalize_tag(hi) if kind == "last_affected" else None)
        if result is None:
            return None
        verdict = verdict or result
    return verdict
