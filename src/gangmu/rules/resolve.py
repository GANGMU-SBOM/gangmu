"""Conflict resolution.

Several rules can legitimately describe the same directory: a generic 'vendored
lwIP' rule and a specific 'ESP-IDF ships lwIP here' one will both fire.  They
are not mutually exclusive and the loser is not discarded -- it is carried as an
alternative, because a reviewer looking at a 0.6-confidence call wants to see
what else it could have been.
"""

from __future__ import annotations

from typing import List

from ..model import Finding, Technique
from ..vuln.version import is_orderable


def _corroboration(finding: Finding) -> int:
    """How many independent kinds of evidence back this finding.

    A file hash, function containment and a version read from source are three
    separate witnesses; a sketch similarity plus one shared header is two. Where
    a vendor-specific rule and a generic one both reach the identity ceiling in
    a directory neither of them expects to find the component in, the one with
    more witnesses is the better-supported claim -- otherwise the vendor rule's
    higher specificity labels every pristine upstream copy as that vendor's fork.
    A path or name hint is not a witness: that is what ``path_match`` ranks.
    """
    return len({e.technique for e in finding.evidence
                if e.technique is not Technique.FILENAME})


def _rank(finding: Finding, specificity: int) -> tuple:
    return (
        round(finding.identity_confidence, 3),
        finding.path_match,             # above specificity, deliberately: a narrow
                                        # rule firing in the wrong directory must
                                        # not beat a general rule firing in the
                                        # right one, or every plain upstream copy
                                        # gets labelled as some vendor's fork
        _corroboration(finding),        # above specificity for the same reason
        1 if finding.version else 0,
        1 if is_orderable(finding.version) else 0,   # a commit id cannot be set
                                        # against a CVE's version range; of two
                                        # equally supported claims, the one that
                                        # can be matched is the one to report
        round(finding.version_confidence, 3),
        # A narrow rule only knows more than a general one where it is at home.
        # Elsewhere (path_match 0) it has no extra information, and when the
        # evidence is otherwise identical the general rule is the honest label:
        # a pristine upstream copy must not be named after one vendor's fork.
        specificity if finding.path_match else -specificity,
        finding.rule_id,                # stable tie-break, so output is reproducible
    )


def resolve(candidates: List[Finding], specificity: dict) -> List[Finding]:
    """Pick one winner per directory; attach the rest as alternatives."""
    by_dir: dict = {}
    for finding in candidates:
        by_dir.setdefault(finding.directory, []).append(finding)

    winners: List[Finding] = []
    for directory in sorted(by_dir):
        group = sorted(by_dir[directory],
                       key=lambda f: _rank(f, specificity.get(f.rule_id, 0)),
                       reverse=True)
        best, rest = group[0], group[1:]
        # Only keep alternatives that are genuinely competitive; a long tail of
        # near-zero candidates is noise, not information.
        best.alternatives = [r for r in rest
                             if r.identity_confidence >= best.identity_confidence * 0.6
                             and r.upstream_name != best.upstream_name][:3]
        winners.append(best)
    return winners
