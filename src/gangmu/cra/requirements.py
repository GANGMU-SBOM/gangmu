"""The CRA obligations this tool touches, and exactly how far it reaches.

The value of this table is as much in the ``out_of_scope`` entries as in the
others. A compliance tool that implies it covers Annex I Part II in full is
selling a false sense of safety: most of Part II is about process and update
infrastructure, which no scanner can attest to. Each entry below says what the
tool can establish from evidence, what it can only record from a declaration,
and what remains the manufacturer's to do.

Sources: Regulation (EU) 2024/2847, Annex I Part II (vulnerability handling),
Article 13 (manufacturer obligations) and Article 14 (reporting). Dates are the
ones in force: manufacturers' reporting obligations since 11 September 2026,
the remaining obligations from 11 December 2027.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Verdict(str, Enum):
    MET = "met"
    NOT_MET = "not met"
    PARTIAL = "partial"
    DECLARED = "declared"           # taken from config, not verified by the tool
    OUT_OF_SCOPE = "out of scope"   # the manufacturer's to do; named, not checked


@dataclass
class Requirement:
    id: str
    clause: str
    title: str
    text: str
    tool_role: str
    """What this tool can honestly contribute. Read it as the limit, not the
    claim."""
    checkable: bool = True


REQUIREMENTS: List[Requirement] = [
    Requirement(
        id="AI-II-1", clause="Annex I Part II (1)",
        title="Identify and document components, including an SBOM",
        text=("Identify and document vulnerabilities and components contained in "
              "products with digital elements, including by drawing up a software "
              "bill of materials in a commonly used and machine-readable format "
              "covering at the very least the top-level dependencies of the "
              "products."),
        tool_role=("This is the obligation the tool exists for. It checks the SBOM "
                   "is machine-readable, that every component carries a name and "
                   "an identifier, and that no directory which looks like a "
                   "component was left unidentified.")),
    Requirement(
        id="AI-II-2", clause="Annex I Part II (2)",
        title="Address and remediate vulnerabilities without delay",
        text=("In relation to the risks posed to products with digital elements, "
              "address and remediate vulnerabilities without delay, including by "
              "providing security updates; where technically feasible, new security "
              "updates shall be provided separately from functionality updates."),
        tool_role=("The tool can show that every known vulnerability has a recorded "
                   "analysis, which is the evidence a remediation process leaves "
                   "behind. It cannot show that a fix shipped.")),
    Requirement(
        id="AI-II-3", clause="Annex I Part II (3)",
        title="Effective and regular tests and reviews of security",
        text=("Apply effective and regular tests and reviews of the security of the "
              "product with digital elements."),
        tool_role=("Out of scope. A scan is not a security test. Running this tool "
                   "in CI is evidence of regular *component* review only, and "
                   "should be described that way."),
        checkable=False),
    Requirement(
        id="AI-II-4", clause="Annex I Part II (4)",
        title="Publicly disclose information about fixed vulnerabilities",
        text=("Once a security update has been made available, share and publicly "
              "disclose information about fixed vulnerabilities, including a "
              "description of the vulnerabilities, information allowing users to "
              "identify the product with digital elements affected, the impacts of "
              "the vulnerabilities, their severity and clear and accessible "
              "information helping users to remediate the vulnerabilities."),
        tool_role=("The VEX document carries the description, the affected "
                   "component and the severity. Publishing it is the "
                   "manufacturer's act, not the tool's.")),
    Requirement(
        id="AI-II-5", clause="Annex I Part II (5)",
        title="Coordinated vulnerability disclosure policy",
        text=("Put in place and enforce a policy on coordinated vulnerability "
              "disclosure."),
        tool_role=("Recorded from configuration. The tool checks a policy URL is "
                   "declared; it cannot judge the policy."),
        checkable=False),
    Requirement(
        id="AI-II-6", clause="Annex I Part II (6)",
        title="Contact address for reporting vulnerabilities",
        text=("Take measures to facilitate the sharing of information about "
              "potential vulnerabilities in their product with digital elements as "
              "well as in third-party components contained in that product, "
              "including by providing a contact address for the reporting of the "
              "vulnerabilities discovered in the product."),
        tool_role=("Recorded from configuration. The SBOM's third-party components "
                   "are the list this obligation is about."),
        checkable=False),
    Requirement(
        id="AI-II-7", clause="Annex I Part II (7)",
        title="Mechanisms to securely distribute updates",
        text=("Provide for mechanisms to securely distribute updates for products "
              "with digital elements to ensure that vulnerabilities are fixed or "
              "mitigated in a timely manner and, where applicable for security "
              "updates, in an automatic manner."),
        tool_role="Out of scope. This is product engineering, not SBOM tooling.",
        checkable=False),
    Requirement(
        id="AI-II-8", clause="Annex I Part II (8)",
        title="Security updates disseminated without delay and free of charge",
        text=("Ensure that, where security updates are available to address "
              "identified security issues, they are disseminated without delay "
              "and, unless otherwise agreed [...] free of charge, accompanied by "
              "advisory messages."),
        tool_role="Out of scope.",
        checkable=False),
    Requirement(
        id="ART-13-8", clause="Article 13(8) and Annex VII",
        title="Technical documentation, kept for ten years",
        text=("Manufacturers shall draw up the technical documentation referred to "
              "in Article 31 before placing the product on the market and keep it "
              "at the disposal of the market surveillance authorities for ten "
              "years after the product has been placed on the market or for the "
              "support period, whichever is longer."),
        tool_role=("`gangmu evidence` produces the component part of that "
                   "documentation as a hashed bundle: the SBOM, the VEX, the rule "
                   "base and its verification, and the build facts the SBOM was "
                   "derived from.")),
    Requirement(
        id="ART-14", clause="Article 14",
        title="Reporting actively exploited vulnerabilities and severe incidents",
        text=("Manufacturers shall notify any actively exploited vulnerability "
              "contained in the product: an early warning within 24 hours of "
              "becoming aware, a vulnerability notification within 72 hours, and a "
              "final report within 14 days of a corrective measure being "
              "available. In force since 11 September 2026."),
        tool_role=("The 24-hour form needs the product name and version, the "
                   "member states, the time of awareness, and -- optionally but "
                   "decisively -- the affected component and CVE. `gangmu report` "
                   "pre-fills them from the SBOM and the configuration. The ENISA "
                   "platform has no API at its first release, so a human still "
                   "pastes the result in.")),
]


def by_id(requirement_id: str) -> Optional[Requirement]:
    for requirement in REQUIREMENTS:
        if requirement.id == requirement_id:
            return requirement
    return None
