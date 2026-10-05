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
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Set, Tuple, Union

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


def pick_releases(tags: Sequence[str], limit: int = 12) -> List[str]:
    """The most recent *limit* releases, oldest first.

    Recent releases are what firmware actually ships; a signature spanning ten
    years of history costs size and buys nothing, because nobody is shipping
    lwIP 1.3 in a product placed on the EU market in 2027.
    """
    ordered = sorted(set(tags), key=version_key)
    return ordered[-min(limit, MAX_VERSIONS):]


@dataclass
class BuildReport:
    signature: FunctionSignature
    tags: List[str]
    per_version_counts: List[int]
    skipped: List[Tuple[str, str]]


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
        for entry in tags:
            # "2.5.4=<40-hex sha>" pins a release that upstream never tagged
            # (GmSSL 2.x): the label is what the signature records, the revision
            # is what is fetched. A bare tag labels itself via *label*.
            tag, _, rev = entry.partition("=")
            fetch_ref = rev or tag
            try:
                log(f"fetching {fetch_ref}")
                git(["fetch", "--quiet", "--depth", "1", "origin", fetch_ref], cwd=checkout)
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
            per_version.append((tag if rev else (label(tag) if label else tag), hashes,
                                abstract))
            counts.append(len(hashes))
        return BuildReport(signature=FunctionSignature.build(per_version),
                           tags=[row[0] for row in per_version],
                           per_version_counts=counts, skipped=skipped)
    finally:
        if owns:
            shutil.rmtree(tmp, ignore_errors=True)


def tag_to_version(tag: str) -> str:
    """STABLE-2_2_0_RELEASE -> 2.2.0, v1.7.19 -> 1.7.19."""
    numbers = _NUM.findall(tag)
    return ".".join(numbers) if numbers else tag
