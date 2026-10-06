# Example output

What gangmu produces for the README's opening experiment: a real GmSSL 3.0.0
release turned into a vendor-style fork by `examples/disguise.sh` (renamed
directory, version header deleted, a third of the SM3/SM4 identifiers prefixed,
vendor functions added, eight source files removed).

| File | Produced by |
| --- | --- |
| `sbom.cdx.json` | `gangmu scan firmware/ --app-name demo-firmware --app-version 1.0.0 --format cyclonedx` |
| `sbom.spdx.json` | the same with `--format spdx` |
| `cra-check.txt` | `gangmu cra-check --sbom sbom.cdx.json --scan scan.json --no-fail` |
| `report-eu-cra-early-warning.md` | `gangmu report CVE-2024-0000-EXAMPLE --regime eu-cra --stage early-warning --aware-at 2026-10-06T08:00:00Z` |
| `report-cn-miit.md` | `gangmu report CVE-2024-0000-EXAMPLE --regime cn-miit --scope "demo-firmware 1.0.0" --aware-at 2026-10-06T08:00:00Z` |

Read these as examples of the format, not as a compliance result:

- The scan used the source tree alone (no `--compile-db`), so `cra-check` marks
  the SBOM `partial`, and several obligations fail because no `gangmu.yaml` was
  declared. That is the tool being strict, not a bug.
- `CVE-2024-0000-EXAMPLE` is a placeholder id, not a real advisory. The report
  drafts show fields marked `MISSING` because no project configuration or VEX
  was supplied; gangmu never invents them.
- No VEX file is included: producing one needs a local NVD / OSV mirror
  (`gangmu vuln-fetch`), and a made-up one would be misleading.

Reproduce with:

```bash
./examples/disguise.sh /tmp/gangmu-disguise
gangmu scan /tmp/gangmu-disguise/firmware --app-name demo-firmware --app-version 1.0.0 \
    --format cyclonedx -o sbom.cdx.json
```

The serial number and timestamp differ between runs.
