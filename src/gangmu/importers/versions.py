"""Building a multi-version function signature from upstream releases.

The signature is only as good as the releases it covers, so this walks the
upstream repository's own tags. Release tags are the ground truth a vendor fork
is measured against; a signature built from one release can say "this looks like
2.2.0" but cannot say "this is 2.2.0 with three functions backported from
2.2.2", which is the statement that actually decides whether a CVE applies.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from ..dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_directory
from ..fnsig import MAX_VERSIONS, FunctionSignature
from .common import git

_NUM = re.compile(r"\d+")


def list_tags(url: str, pattern: Optional[str] = None) -> List[str]:
    out = git(["ls-remote", "--tags", "--refs", url])
    tags = [line.split("refs/tags/", 1)[1].strip()
            for line in out.splitlines() if "refs/tags/" in line]
    if pattern:
        matcher = re.compile(pattern)
        tags = [t for t in tags if matcher.search(t)]
    return tags


def version_key(tag: str) -> Tuple:
    """Sort tags by their numeric backbone, oldest first."""
    return tuple(int(n) for n in _NUM.findall(tag)) or (0,)


def pick_releases(tags: Sequence[str], limit: int = 12,
                  like: Optional[str] = None) -> List[str]:
    """The most recent *limit* releases, oldest first.

    Recent releases are what firmware actually ships; a signature spanning ten
    years of history costs size and buys nothing, because nobody is shipping
    lwIP 1.3 in a product placed on the EU market in 2027.
    """
    # Ranked by their numbers alone, ``r5076``, ``merge-llvm-97877`` and
    # ``clamav-20080204`` outrank ``clamav-1.5.4``. Where releases carry a dotted
    # version, a tag without one is not a release.
    dotted = [t for t in set(tags) if _DOTTED.search(t)]
    if like:
        # Releases look like the one the rule pins: same prefix and a version of
        # about as many parts (kamailio's 17368.8 and ArduPilot's dated tags are not
        # Copter-4.7.2's kind).
        shaped = [t for t in dotted if _same_shape(t, like)]
        dotted = shaped or dotted
    chosen: Dict[str, str] = {}
    for tag in sorted(dotted or set(tags), key=version_key):
        key = tag_to_version(tag)
        # Two tags for one release (imgui's v1.93.0 and v1.93.0-docking, SRT's
        # v1.5.7 and DEVELOPMENT_STABLE_1.5.7): keep the one shaped like the pin.
        if key not in chosen or tag == like or (
                like and chosen[key] != like and _same_shape(tag, like)
                and not _same_shape(chosen[key], like)):
            chosen[key] = tag
    ordered = sorted(chosen.values(), key=version_key)
    return ordered[-min(limit, MAX_VERSIONS):]


@dataclass
class BuildReport:
    signature: FunctionSignature
    tags: List[str]
    per_version_counts: List[int]
    skipped: List[Tuple[str, str]]


FETCH_ATTEMPTS = 3
_DOTTED = re.compile(r"\d+[._]\d+")
_LETTER_SUFFIX = re.compile(r"\d([a-zA-Z])(?:$|[^a-zA-Z0-9])(?!.*\d)")
_VERSION_BODY = re.compile(r"\d+(?:[._]\d+)+(?:[-._]?[a-z]*\d*)?", re.I)


def _norm_prefix(prefix: str) -> str:
    """``ptpd.`` and ``ptpd-``, ``v.``, ``v`` and nothing: one prefix each."""
    letters = re.sub(r"[^a-z]", "", prefix.lower())
    return "" if letters == "v" else letters


def _same_shape(tag: str, like: str) -> bool:
    """Same text before the first digit, a dotted version after it, the number of
    version parts within one of *like*'s and a major version of its magnitude."""
    def split(t: str):
        prefix = re.match(r"\D*", t).group(0)            # type: ignore[union-attr]
        return prefix, t[len(prefix):]
    prefix, body = split(tag)
    want_prefix, want_body = split(like)
    nums, want = _NUM.findall(body), _NUM.findall(want_body)
    return (_norm_prefix(prefix) == _norm_prefix(want_prefix)
            and bool(_VERSION_BODY.fullmatch(body))
            and abs(len(nums) - len(want)) <= 1
            and bool(want) and int(nums[0]) <= 10 * (int(want[0]) + 1))


def _fetch(checkout: Path, ref: str) -> None:
    """A shallow fetch of *ref*, retried: a dropped connection is not a missing tag."""
    for attempt in range(FETCH_ATTEMPTS):
        try:
            git(["fetch", "--quiet", "--depth", "1", "origin", ref], cwd=checkout)
            return
        except subprocess.CalledProcessError:
            if attempt == FETCH_ATTEMPTS - 1:
                raise
            time.sleep(2 * (attempt + 1))


def build_function_signature(
        url: str, tags: Sequence[str],
        include: Sequence[str] = DEFAULT_INCLUDE,
        exclude: Sequence[str] = DEFAULT_EXCLUDE,
        subdir: Optional[Union[str, Sequence[str]]] = None,
        label: Optional[Callable[[str], str]] = None,
        jobs: int = 1, workdir: Optional[Path] = None, strings: bool = False,
        log: Callable[[str], None] = lambda m: None) -> BuildReport:
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="gangmu-fnsig-"))
    owns = workdir is None
    per_version: List[Tuple[str, Set[int], Set[int]]] = []
    counts: List[int] = []
    skipped: List[Tuple[str, str]] = []
    try:
        checkout = tmp / "repo"
        checkout.mkdir(parents=True, exist_ok=True)
        git(["init", "--quiet"], cwd=checkout)
        git(["remote", "add", "origin", url], cwd=checkout)
        # One shallow fetch per release into one repository: git's auto-gc, which
        # runs detached after a fetch, rewrites .git/shallow under the next fetch
        # ("shallow file has changed since we read it") and that release was lost.
        git(["config", "gc.auto", "0"], cwd=checkout)
        git(["config", "maintenance.auto", "false"], cwd=checkout)
        for entry in tags:
            # "2.5.4=<40-hex sha>" pins a release that upstream never tagged
            # (GmSSL 2.x): the label is what the signature records, the revision
            # is what is fetched. A bare tag labels itself via *label*.
            tag, _, rev = entry.partition("=")
            fetch_ref = rev or tag
            try:
                log(f"fetching {fetch_ref}")
                _fetch(checkout, fetch_ref)
                git(["checkout", "--quiet", "--force", "FETCH_HEAD"], cwd=checkout)
            except subprocess.CalledProcessError as exc:
                skipped.append((tag, (exc.stderr or "").strip()[:120]))
                continue
            # Projects move their sources (FreeRTOS kept the kernel under
            # FreeRTOS/Source until 10.3); the first candidate present wins.
            candidates = ([subdir] if isinstance(subdir, str) else list(subdir or [])) or ["."]
            root = next((checkout / c for c in candidates if (checkout / c).is_dir()), None)
            if root is None:
                skipped.append((tag, f"none of {', '.join(candidates)} is present "
                                     f"at this tag"))
                continue
            if strings:
                from ..binsig import tree_strings
                hashes, abstract = tree_strings(root, include, exclude), set()
            else:
                dp = print_directory(root, include, exclude, jobs=jobs)
                hashes, abstract = dp.functions, dp.abstract_functions
            if not hashes:
                skipped.append((tag, "no string constants extracted" if strings
                                else "no functions extracted"))
                continue
            name = tag if rev else (label(tag) if label else tag)
            if any(row[0] == name for row in per_version):
                skipped.append((tag, f"another tag already gave release {name}"))
                continue
            per_version.append((name, hashes, abstract))
            counts.append(len(hashes))
        return BuildReport(signature=FunctionSignature.build(per_version),
                           tags=[row[0] for row in per_version],
                           per_version_counts=counts, skipped=skipped)
    finally:
        if owns:
            shutil.rmtree(tmp, ignore_errors=True)


def tag_to_version(tag: str) -> str:
    """STABLE-2_2_0_RELEASE -> 2.2.0, v1.7.19 -> 1.7.19, v1.3.9c -> 1.3.9c.

    A letter straight after the last number is part of the release (ProFTPD
    1.3.9a to 1.3.9e, OpenSSL 1.1.1w); without it six releases were one label."""
    numbers = _NUM.findall(tag)
    if not numbers:
        return tag
    letter = _LETTER_SUFFIX.search(tag)
    return ".".join(numbers) + (letter.group(1).lower() if letter else "")
