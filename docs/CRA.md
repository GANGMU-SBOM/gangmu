# What this tool does and does not do for CRA

Regulation (EU) 2024/2847. Manufacturers' reporting obligations have applied
since **11 September 2026**; the rest apply from **11 December 2027**.

`gangmu cra-check` prints this table against your actual artefacts. What follows
is the honest version of the claim behind it, written for whoever signs the
declaration of conformity.

| Clause | Obligation | What this tool contributes |
| --- | --- | --- |
| **Annex I Part II(1)** | Identify and document components, including an SBOM in a commonly used, machine-readable format covering at least the top-level dependencies | **The whole point of the tool.** It produces the SBOM, and the check verifies it is machine-readable, that every component carries a name, a version and an identifier, and that no directory which looks like a component was left unidentified. |
| **Annex I Part II(2)** | Address and remediate vulnerabilities without delay | Partial. The VEX shows every known vulnerability has a recorded analysis — the paper trail a remediation process leaves. It cannot show a fix shipped. |
| **Annex I Part II(3)** | Effective and regular tests and reviews of security | **Out of scope.** A component scan is not a security test. Running this in CI is evidence of regular *component* review, and should be described that way and no other. |
| **Annex I Part II(4)** | Publicly disclose information about fixed vulnerabilities | Partial. The VEX carries descriptions, affected components and severities. Publishing it is your act. |
| **Annex I Part II(5)** | Coordinated vulnerability disclosure policy | **Declared, never verified.** The check confirms a policy URL is on file. It cannot judge the policy. |
| **Annex I Part II(6)** | A contact address for reporting vulnerabilities | Declared, never verified. The SBOM is the list of third-party components this obligation is about. |
| **Annex I Part II(7)** | Mechanisms to securely distribute updates | **Out of scope.** Product engineering. |
| **Annex I Part II(8)** | Security updates without delay, free of charge, with advisories | **Out of scope.** |
| **Article 13(8), Annex VII** | Technical documentation, kept ten years | `gangmu evidence` assembles the component part: SBOM, VEX, the rule base, its verification output, the build facts, and a sha256 manifest. |
| **Article 14** | 24 h early warning, 72 h notification, 14 d final report | `gangmu report` pre-fills the ENISA platform's fields from the SBOM and your configuration. The platform has no API at its first release, so a person still pastes it in. |

Five of ten are partial, declared or out of scope. A tool that claimed
otherwise would be selling a false sense of safety.

## The honest reading of "top-level dependencies"

Annex I Part II(1) asks for "at the very least the top-level dependencies". That
bar is lower than most people assume — and for C/C++ firmware it is still hard,
because the *first* level is already invisible: source copied into the tree,
renamed by a silicon vendor, statically linked. That is the gap this tool
closes, not the deeper transitive one.

`cra-check` therefore refuses to call the obligation met while any candidate
directory is unidentified. An SBOM that omits a component silently is worse
under audit than one that says "this directory is unexplained".

## Where the self-check is deliberately strict

* **A declaration is never evidence.** A CVD policy URL in `gangmu.yaml` makes
  the obligation `declared`, never `met`.
* **A source-only SBOM is `partial`, not `met`.** Without a compile database the
  SBOM over-reports: code present but never compiled, or dropped by the linker,
  is listed as shipped.
* **`in_triage` findings are counted and surfaced.** Those are what a human must
  close before signing anything. A vendor fork reporting an upstream version is
  the usual reason one is open.

## A working sequence

```bash
gangmu init                                    # fill the REQUIRED fields once

gangmu scan --format cyclonedx -o sbom.json    # root, product, version from the config
gangmu scan --format json      -o scan.json    # keeps the unidentified list

gangmu vuln sbom.json --db advisories/ --format cyclonedx -o vex.json
gangmu rules verify > rules-verification.txt

gangmu cra-check --sbom sbom.json --vex vex.json --scan scan.json
gangmu evidence --out cra-evidence/ --sbom sbom.json --vex vex.json \
                --scan scan.json --verification rules-verification.txt
```

And, on the day it matters:

```bash
gangmu report CVE-2027-12345 --stage early-warning --vex vex.json \
              --aware-at 2027-05-14T08:12Z -o 24h-draft.md
```

## In CI

`cra-check` exits non-zero when an obligation is blocking, so it gates a release
the same way a failing test does:

```yaml
- run: gangmu scan --format cyclonedx -o sbom.json
- run: gangmu vuln sbom.json --db advisories/ --fail-on exploitable
- run: gangmu cra-check --sbom sbom.json --vex vex.json
```

Pass `--no-fail` while a project is still filling its configuration in.
