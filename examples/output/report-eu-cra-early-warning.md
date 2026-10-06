# CRA Article 14 — early-warning

**Deadline:** 24 hours from becoming aware

Submit at the ENISA Single Reporting Platform. The platform has no API at its first release, so copy each value across by hand.

| Field | Value | Source |
| --- | --- | --- |
| Notification type | Actively exploited vulnerability | chosen when the report was drafted |
| Manufacturer | **— MISSING —** | set manufacturer.name — Article 14 names the manufacturer |
| Product name | **— MISSING —** | set product.name — the notification identifies the product |
| Product version(s) affected | **— MISSING —** | set product.version — the notification identifies the affected versions |
| Member states where the product is available | **— MISSING —** | set market.member_states — the platform asks which markets |
| Date and time of becoming aware | 2026-10-06T08:00:00Z | supplied on the command line |
| Vulnerability identifier | CVE-2024-0000-EXAMPLE | supplied on the command line |
| Title | **— MISSING —** | write one line |
| Summary | **— MISSING —** | from the advisory summary in the VEX |
| Affected component | _(optional, not set)_ | optional on the form, but it is what a CSIRT acts on |
| Component version | _(optional, not set)_ | from the SBOM |

## Before you submit

- **Manufacturer** — set manufacturer.name — Article 14 names the manufacturer
- **Product name** — set product.name — the notification identifies the product
- **Product version(s) affected** — set product.version — the notification identifies the affected versions
- **Member states where the product is available** — set market.member_states — the platform asks which markets
- **Title** — write one line
- **Summary** — from the advisory summary in the VEX

## Notes

- The early warning may say the assessment is preliminary. It may not be late: the 24 hours run from awareness, not from confirmation.
- No coordinating CSIRT recorded. The platform asks you to choose one at registration, not at report time — set reporting.csirt.