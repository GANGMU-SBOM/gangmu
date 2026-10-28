"""Rule verification: re-derive a rule's evidence from the named upstream release.

This is the mechanism the whole community model rests on.  A pull request that
adds a rule asserts "this directory is lwIP 2.2.0"; CI fetches lwIP 2.2.0 from
the URL the rule itself names, recomputes the signature and the anchor hashes,
and fails the pull request if they differ.  Review cost per rule approaches
zero, which is the only way a rule base of thousands of entries gets maintained
by volunteers.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import List, Optional

from .dirprint import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, print_directory, sha256_file
from .importers.versions import tag_to_version
from .rules.schema import Rule


@dataclass
class VerifyReport:
    rule_id: str
    ok: bool = True
    checked: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        self.ok = False
        self.problems.append(message)


FETCH_ATTEMPTS = 4


def pinned_release(rule: Rule) -> Optional[str]:
    """The release a rule's evidence is taken from: the signature's reference version,
    else its pinned tag read as a version. ``None`` for a pinned commit."""
    if rule.signature is not None and rule.signature.reference_version:
        return rule.signature.reference_version
    ref = rule.source.ref if rule.source else None
    if not ref or re.fullmatch(r"[0-9a-f]{40}", ref):
        return None
    return tag_to_version(ref)


def fetch_upstream(rule: Rule, dest: Path) -> Path:
    """Materialise the upstream release a rule names. Returns the subdir to use."""
    if rule.source is None:
        raise ValueError(f"{rule.id}: no upstream.source to fetch")
    dest = Path(dest)
    if rule.source.kind != "git":
        raise NotImplementedError(
            f"{rule.id}: upstream.source.kind '{rule.source.kind}' is not supported yet"
        )
    if shutil.which("git") is None:
        raise RuntimeError("git is not available")
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet"], cwd=dest, check=True)
    subprocess.run(["git", "remote", "add", "origin", rule.source.url],
                   cwd=dest, check=True)
    ref = rule.source.ref or "HEAD"
    # Gitee in particular drops TLS connections now and then; a few retries
    # keep CI from failing on the network rather than on the rule.
    for attempt in range(FETCH_ATTEMPTS):
        try:
            subprocess.run(["git", "fetch", "--quiet", "--depth", "1", "origin", ref],
                           cwd=dest, check=True)
            break
        except subprocess.CalledProcessError:
            if attempt == FETCH_ATTEMPTS - 1:
                raise
            time.sleep(2 * (attempt + 1))
    subprocess.run(["git", "checkout", "--quiet", "FETCH_HEAD"], cwd=dest, check=True)
    return dest / rule.source.subdir if rule.source.subdir else dest


def verify_rule(rule: Rule, checkout: Path,
                tolerance: float = 0.0) -> VerifyReport:
    """Check a rule's recorded evidence against a pristine upstream checkout."""
    report = VerifyReport(rule_id=rule.id)
    checkout = Path(checkout)
    if not checkout.is_dir():
        report.fail(f"checkout not found: {checkout}")
        return report

    # Like probes, anchors on different files are alternatives: a project that
    # changed layout between releases (Tongsuo 8.3 kept its version in
    # include/openssl/opensslv.h, 8.4 in VERSION.dat) needs one anchor per
    # layout, and only the anchors for the pinned release's layout can exist in
    # its checkout. The rule fails only when none of them does.
    present = [a for a in rule.anchors if (checkout / a.path).is_file()]
    # A header can survive a layout change with different content (Mbed TLS keeps
    # include/mbedtls/version.h in 3.x, but only 2.x versions are recorded for
    # it). With no reference version to hold it to, such an anchor is judged by
    # whether *another* anchor of the rule matches this release.
    unrecorded: List[tuple] = []
    for anchor in rule.anchors:
        path = checkout / anchor.path
        if not path.is_file():
            if present:
                report.checked.append(f"alternative anchor {anchor.path} does not "
                                      f"apply to this release")
            else:
                report.fail(f"anchor file missing upstream: {anchor.path}")
            continue
        digest = sha256_file(path)
        ref_version = (rule.signature.reference_version
                       if rule.signature else None)
        expected = anchor.sha256.get(ref_version) if ref_version else None
        if expected is None:
            if digest not in anchor.sha256.values():
                unrecorded.append(
                    (anchor.path, f"upstream hash {digest[:12]}... is not among "
                                  f"the {len(anchor.sha256)} recorded versions"))
            else:
                report.checked.append(f"anchor {anchor.path} matches a recorded version")
        elif digest != expected:
            report.fail(
                f"anchor {anchor.path}: recorded {expected[:12]}... for "
                f"{ref_version}, upstream is {digest[:12]}..."
            )
        else:
            report.checked.append(f"anchor {anchor.path} matches {ref_version}")

    matched_any = any(line.startswith("anchor ") and "matches" in line
                      for line in report.checked)
    for path, why in unrecorded:
        if matched_any:
            report.checked.append(f"alternative anchor {path} does not apply to "
                                  f"this release: {why}")
        else:
            report.fail(f"anchor {path}: {why}")

    if rule.signature is not None:
        spec = rule.signature.signature
        fresh_print = print_directory(checkout,
                                      rule.include or DEFAULT_INCLUDE,
                                      rule.exclude or DEFAULT_EXCLUDE,
                                      spec.k, spec.window)
        recorded_fileset = rule.signature.fileset_sha256
        if recorded_fileset and fresh_print.fileset_sha256 != recorded_fileset:
            report.fail(
                f"fileset hash does not reproduce: recorded "
                f"{recorded_fileset[:12]}..., upstream is "
                f"{fresh_print.fileset_sha256[:12]}... "
                f"({fresh_print.file_count} files matched the include globs)"
            )
        elif recorded_fileset:
            report.checked.append(
                f"fileset hash reproduces exactly ({fresh_print.file_count} files)")

        sim = fresh_print.signature(spec.k, spec.window, spec.size).similarity(spec)
        if sim < 1.0 - tolerance:
            report.fail(
                f"signature does not reproduce: recomputing from "
                f"{rule.source.url if rule.source else '?'}@"
                f"{rule.source.ref if rule.source else '?'} gives similarity "
                f"{sim:.4f}, expected 1.0"
            )
        else:
            report.checked.append(f"signature reproduces exactly (similarity {sim:.4f})")

    if rule.functions is not None:
        _verify_functions(rule, checkout, report)

    # Probes are alternatives tried in order -- RT-Thread spelled its version
    # macros one way up to 4.x and another from 5.0 -- so the release must be
    # readable by one of them, and the first that reads it is what a scan uses.
    used = None
    for probe in rule.probes:
        path = checkout / probe.file
        value = (probe.apply(path.read_text(encoding="utf-8", errors="replace"))
                 if path.is_file() else None)
        if value is None:
            if len(rule.probes) == 1:
                report.fail(f"probe file missing upstream: {probe.file}"
                            if not path.is_file() else
                            f"probe on {probe.file} does not match upstream source")
            else:
                report.checked.append(f"alternative probe on {probe.file} does not "
                                      f"apply to this release")
            continue
        report.checked.append(f"probe on {probe.file} yields {value}")
        if used is None:
            used = value
            ref_version = (rule.signature.reference_version if rule.signature else None)
            if ref_version and value != ref_version:
                report.fail(
                    f"probe on {probe.file} yields {value} but the signature's "
                    f"reference_version is {ref_version}"
                )
    if len(rule.probes) > 1 and used is None:
        report.fail("no version probe matches the upstream source")
    return report


def _verify_functions(rule: Rule, checkout: Path, report: VerifyReport) -> None:
    """The function signature records exactly the functions of the pinned release.

    A signature built with other globs than the rule's (Mbed TLS's held 26 of the
    148 functions in its include/) reports an untouched copy as carrying vendor
    additions; one that lacks the pinned release cannot place that release at all."""
    assert rule.functions is not None
    pinned = pinned_release(rule)
    try:
        signature = rule.functions.load()
    except Exception as exc:                      # noqa: BLE001 -- reported, not raised
        report.fail(f"function signature unusable: {exc}")
        return
    if pinned is None:
        report.checked.append("function signature: the rule pins a commit, not a "
                              "release; not compared")
        return
    if pinned not in signature.versions:
        report.checked.append(
            f"function signature does not record the pinned release {pinned} "
            f"({signature.versions[0]} to {signature.versions[-1]}); not compared")
        return
    recorded = signature.version_hashes(signature.versions.index(pinned))
    spec = rule.functions
    root = checkout / spec.subdir if spec.subdir else checkout
    include = spec.include or rule.include or DEFAULT_INCLUDE
    exclude = spec.exclude or rule.exclude or DEFAULT_EXCLUDE
    fresh = set(print_directory(root, include, exclude).functions) if root.is_dir() else set()
    where = "the signature's globs" if spec.include or spec.exclude or spec.subdir \
        else "the rule's globs"
    missing, extra = recorded - fresh, fresh - recorded
    if missing or extra:
        report.fail(
            f"function signature does not reproduce for {pinned}: upstream has "
            f"{len(fresh)} functions under {where}, the signature records "
            f"{len(recorded)} ({len(extra)} upstream only, {len(missing)} recorded only); "
            f"rebuild it with those globs, or record the ones it was built with as "
            f"identity.functions.include/exclude/subdir")
    else:
        report.checked.append(f"function signature reproduces exactly for {pinned} "
                              f"({len(fresh)} functions)")


def verify_with_fetch(rule: Rule, workdir: Optional[Path] = None,
                      tolerance: float = 0.0) -> VerifyReport:
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="gangmu-verify-"))
    try:
        subdir = fetch_upstream(rule, tmp)
        report = verify_rule(rule, subdir, tolerance)
    except Exception as exc:                   # noqa: BLE001 -- reported, not raised
        report = VerifyReport(rule_id=rule.id)
        report.fail(f"could not fetch upstream: {exc}")
    finally:
        if workdir is None:
            shutil.rmtree(tmp, ignore_errors=True)
    # A mirror carries releases the primary lacks, so the recorded evidence
    # (taken at the primary's ref) cannot be compared with it; what CI can and
    # must check is that the pinned ref is still there and has the component.
    for mirror in rule.mirrors:
        mtmp = Path(tempfile.mkdtemp(prefix="gangmu-verify-mirror-"))
        try:
            subdir = fetch_upstream(replace(rule, source=mirror), mtmp)
            if subdir.is_dir():
                report.checked.append(
                    f"mirror {mirror.url}@{mirror.ref or 'HEAD'} fetches")
            else:
                report.fail(f"mirror {mirror.url}@{mirror.ref or 'HEAD'} has no "
                            f"{mirror.subdir}")
        except Exception as exc:               # noqa: BLE001
            report.fail(f"could not fetch mirror {mirror.url}: {exc}")
        finally:
            shutil.rmtree(mtmp, ignore_errors=True)
    return report
