# Gangmu (纲目): build-time SBOM and EU CRA compliance for embedded firmware

**Build-time SBOM for embedded C/C++, with a community-maintained rule base for
the components chip vendors rename and patch.**

Gangmu identifies open-source components that chip-vendor SDKs have renamed,
modified and statically linked (including Chinese silicon SDKs and Chinese
commercial cryptography libraries such as GmSSL and Tongsuo), writes CycloneDX
and SPDX SBOMs with VEX, checks them against the EU Cyber Resilience Act, and
drafts CRA Article 14 and China MIIT vulnerability reports.

[![ci](https://github.com/GANGMU-SBOM/gangmu/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GANGMU-SBOM/gangmu/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/gangmu-sbom.svg)](https://pypi.org/project/gangmu-sbom/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rules: CDLA-Permissive-2.0](https://img.shields.io/badge/rules-CDLA--Permissive--2.0-blue.svg)](https://github.com/GANGMU-SBOM/gangmu-rules/blob/main/rules/LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6-green.svg)](https://cyclonedx.org/)
[![SPDX 2.3](https://img.shields.io/badge/SPDX-2.3-green.svg)](https://spdx.dev/)

[中文](README.md) · [Rules: gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) · [Benchmark: gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench) · [FAQ](docs/FAQ.en.md) · [Glossary](docs/GLOSSARY.md) · [Rule format](docs/RULE-FORMAT.md) · [Benchmark](docs/BENCHMARK.md) · [CRA](docs/CRA.md) · [China](docs/CHINA.md) · [Example output](examples/output/) · [Comparison](docs/COMPARE.md)

The Chinese README is the primary document; this is a shorter English version.

> **The name.** *Gangmu* (纲目, "outline and detail") comes from the
> *Bencao Gangmu* (本草纲目), Li Shizhen's 16th-century compendium of materia
> medica, which classified nearly two thousand substances and recorded the
> source and properties of each so that later readers could identify and verify
> them. Firmware needs the same discipline for third-party code: a renamed,
> relocated component should still be traceable to its upstream project and
> release, with evidence anyone can re-check.

---

## The example

Take a real GmSSL 3.0.0 release and treat it the way vendor SDKs treat
third-party code: move it to `components/crypto_sm`, delete
`include/gmssl/version.h`, prefix a third of the files' `sm3_`/`sm4_`
identifiers with `vendor_`, add vendor functions, drop eight source files.

```
$ gangmu scan firmware/ --format table
CONF  COMPONENT  VERSION  SRC        DIRECTORY             NOTES
----  ---------  -------  ---------  --------------------  ---------------
0.88  GmSSL      3.0.0    functions  components/crypto_sm  vendor-modified

  - 1280 of 1508 functions of GmSSL 3.0.0 are present (0.849 containment, strong)
  - 758 version-discriminating function(s) matched; 758 are in 3.0.0 (agreement 0.85);
    35 function(s) match no recorded version at all (vendor additions, ...)
```

Right name, right version, and flagged as a modified copy rather than upstream.
Reproduce it with `./examples/disguise.sh`.

## Why this is hard

C/C++ has no lock file. Embedded C/C++ then erases what evidence is left:
source is copied wholesale into the tree, vendors fork and rename upstream
projects, everything is statically linked, and the build compiles far more than
it ships. Source-tree scanners over-report; binary scanners under-report.
gangmu reads the **build** (`compile_commands.json` for what was compiled, the
linker map for what survived) and resolves identity against an open rule base.

## Numbers

All reproducible with the tools in this repository; see
[docs/BENCHMARK.md](docs/BENCHMARK.md) and [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

| | |
| --- | --- |
| Separating "vendor fork" from "different release" | whole-tree similarity gap **0.06**; function level **0.25** |
| Version accuracy on real lwIP releases | **6/6 exact**, including Espressif's production fork |
| Synthetic vendor modifications | **9/9 identified, 9/9 correct version** |
| 10% of identifiers renamed | exact hashing 0.480 → abstract level **0.876** |
| NTIA 2021 / CISA 2026 minimum elements | **10.0 / 10** both |
| Whole ESP-IDF v5.4.2 (10,767 sources), single process | 72.5 s / 366 MB → **11.0 s / 123 MB**; warm rescan with 4 workers **2.1 s** |
| 16x more rules (27 → 432, including the commercial packs) | scan time grows only about 2x: 3.2 s → 6.8 s |
| FreeRTOS / RT-Thread copies in 7 Chinese vendor SDKs | **14/14** found, version exact or a range containing it |
| Matching an SBOM against a full NVD mirror | 200.8 s / 3.9 GB → **8.9 s / 25 MB**, identical results |

Identification is function level, following CENTRIS (ICSE 2021) and TIVER
(ICSE 2025): a component is identified by how much of its own code is present,
and its version by which releases those functions come from. A vendor fork
usually carries functions from several releases at once, which is why no
similarity threshold can version it. [docs/ALGORITHMS.md](docs/ALGORITHMS.md)
has the detail.

## Quick start

```bash
pip install gangmu-sbom                              # or: pipx install gangmu-sbom; add [fast] for numpy
                                                     # (pulls in the gangmu-rules rule base)          
gangmu init                                          # product, manufacturer, markets, support period
gangmu scan . --compile-db build/compile_commands.json \
              --link-map build/firmware.map --format cyclonedx -o sbom.json
gangmu scan . --project app.ewp --configuration Release   # IAR / Keil / CCS instead
gangmu wrap -o compile_commands.json -- make -j8          # or watch a real build
# Licences: the rule's upstream licence wins; SPDX-License-Identifier headers and top-level LICENSE files are read too,
# and a licence the rule does not mention is flagged (gangmu:observedLicenses / gangmu:licenseDiffersFromRule), never silently chosen.
# LICENSE text is recognised only for a few unmistakable permissive licences; copyleft is trusted from SPDX headers only. --no-licenses turns it off.
gangmu vuln-fetch --db advisories/ --sbom sbom.json       # online step: only what this SBOM can match
gangmu vuln-fetch --db advisories/ --threat                  # also CISA KEV + EPSS; `vuln` then ranks by exploited > EPSS > CVSS, `--fail-on kev` gates on KEV
gangmu vuln sbom.json --db advisories/ --source ROOT [--symbols syms.json] [--reachability-vex]   # per finding: is the vulnerable function absent, unreferenced, or reachable from your code? Over-approximate source call graph (names, macros, tables); VEX is only changed with --reachability-vex
gangmu patch-build CVE-2025-1866 --db advisories/ -o patches.json   # record the functions the fix changed (fix commit read from the OSV record; or --repo URL --fix SHA)
gangmu vuln sbom.json --db advisories/ --source ROOT --patches patches.json   # test the code, not the version: fixed body present -> resolved, vulnerable body present -> exploitable, edited -> left for a person (a near-identical variant is reported as likely_fixed / likely_vulnerable; --patch-near-vex lets it change the state)
gangmu patch-verify rules/patches/*.json   # rebuild every patch record from the upstream commits it names; fails on any difference
# Records in an installed rule pack's patches/ directory are used by `vuln --source` on their own (--no-pack-patches to skip).
gangmu rules index rules/                                   # precompile a rule directory (125 rules: 0.67 s -> 0.02 s to load); each entry is checked by file hash, so a stale index only costs speed
gangmu keygen && gangmu sign sbom.json --key gangmu-signing.key   # detached Ed25519 signature (pip install gangmu-sbom[sign])
gangmu sign-verify sbom.json --pubkey gangmu-signing.pub   # PEM keys, OpenSSL verifies them too; no timestamp: use cosign for that
gangmu vuln sbom.json --db advisories/ -o vex.json        # local NVD/OSV mirror -> CycloneDX VEX
gangmu cra-check --sbom sbom.json --vex vex.json
gangmu report CVE-2027-12345 --stage early-warning --vex vex.json   # CRA Art. 14 draft
gangmu report CVE-2027-12345 --regime cn-miit --vex vex.json        # China MIIT 2-day draft
```

Output is CycloneDX 1.6 with `pedigree` for vendor forks and
`evidence.identity` carrying every technique and its confidence (SPDX 2.3 is
also available). No finding claims certainty: confidence is capped at 0.95.

### In CI

The GitHub Action is listed on the [GitHub Marketplace](https://github.com/marketplace/actions/gangmu-sbom).

```yaml
# GitHub Actions
- uses: GANGMU-SBOM/gangmu@v0
  with:
    compile-db: build/compile_commands.json
    link-map: build/my-project.map
    app-name: my-firmware
    output: sbom.cdx.json
```

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/GANGMU-SBOM/gangmu
  rev: v0.6.2
  hooks:
    - id: gangmu-scan
```

## What it recognises

| Category | Examples | How |
| --- | --- | --- |
| General open-source components | lwIP, Mbed TLS, FreeRTOS, RT-Thread, LVGL, OpenSSL, littlefs, FatFs, libcoap, nghttp2 and more | Directory location plus function-level fingerprints; the version comes from which releases the matched functions belong to |
| National-crypto libraries | GmSSL 2.x / 3.x, Tongsuo | Per-release anchors, multi-release function signatures and version probes; code is split against OpenSSL so neither is mistaken for the other |
| Package-manager and ecosystem declarations | RT-Thread, OpenHarmony, Yocto, Buildroot / OpenWrt, PlatformIO, Conan, Bazel, Zephyr `module.yml` | Read directly; where a declaration and the code disagree, the code wins and the disagreement is recorded as evidence |
| Zephyr and its HALs | Mbed TLS, hostap, MCUboot, nanopb, and the Bouffalo, WCH, SiFli, Telink, Realtek and GigaDevice HALs | Rules generated from Zephyr's pinned commits |
| Kernels and libraries inside Chinese SDKs | FreeRTOS / RT-Thread / LiteOS / TencentOS-tiny / AliOS Things kernels, FreeType, Opus and others | Located by marker files, independent of directory names |

For what each Chinese ecosystem does and does not cover see [docs/CHINA.md](docs/CHINA.md); for what each release added see [docs/CHANGELOG.en.md](docs/CHANGELOG.en.md).


## The rule base is the point

A generator can be rewritten in a weekend; "which directory is which upstream
release" is data. Rules live in their own repository,
[gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules), licensed CDLA-Permissive-2.0 so
anyone can use them, and released by date on their own schedule. Pass
`--rules` more than once to overlay private rules on the community set.
The rules come in two parts: the free gangmu-rules holds the general open-source components vendor SDKs copy most, Zephyr
and its HAL modules, and community contributions; rules tied to one company (its own SDK, its firmware library, or an
open-source component it forked) belong to the commercial rule packs: contact us (see the end of this page). Rule ids are the same on both sides and the commercial packs overlay automatically once installed. CI re-derives every rule's evidence from the upstream
release it names (`gangmu rules verify`), so review cost is close to zero.
Rules never guess a CPE: 29 of the 60 free rules carry one, new ones citing the NVD records
that prove it, and the other 31 say why they have none. PURL is a first-class
matching channel. See [contributing a rule](https://github.com/GANGMU-SBOM/gangmu-rules/blob/main/CONTRIBUTING.md).

Chinese vendors and projects with at least one rule or SDK reader (depth differs per vendor):

<p><img src="docs/vendors/espressif.svg" alt="乐鑫 Espressif"> <img src="docs/vendors/bouffalo.svg" alt="博流 Bouffalo"> <img src="docs/vendors/winnermicro.svg" alt="联盛德 WinnerMicro"> <img src="docs/vendors/wch.svg" alt="沁恒 WCH"> <img src="docs/vendors/gigadevice.svg" alt="兆易 GigaDevice"> <img src="docs/vendors/hdsc.svg" alt="华大 HDSC"> <img src="docs/vendors/nationstech.svg" alt="国民技术 Nations"> <img src="docs/vendors/rockchip.svg" alt="瑞芯微 Rockchip"> <img src="docs/vendors/allwinner.svg" alt="全志 Allwinner"> <img src="docs/vendors/telink.svg" alt="泰凌微 Telink"> <img src="docs/vendors/realtek.svg" alt="瑞昱 Realtek"> <img src="docs/vendors/sifli.svg" alt="思澈 SiFli"> <img src="docs/vendors/openluat.svg" alt="合宙 openLuat"> <img src="docs/vendors/huawei.svg" alt="华为 LiteOS / OpenHarmony"> <img src="docs/vendors/tencent.svg" alt="腾讯 TencentOS-tiny"> <img src="docs/vendors/alibaba.svg" alt="阿里 AliOS Things"> <img src="docs/vendors/rt-thread.svg" alt="睿赛德 RT-Thread"> <img src="docs/vendors/gmssl.svg" alt="北大 GmSSL"> <img src="docs/vendors/tongsuo.svg" alt="蚂蚁 Tongsuo"></p>

These are text badges, not vendor logos. No vendor artwork is stored in this
repository because no vendor's brand terms were checked. See
[docs/CHINA.md](docs/CHINA.md) (Chinese) for what each one covers.

## Limits

Listed plainly, because the gaps are the roadmap. The main ones:

- **No deep binary analysis:** without source or a build, only an inventory, version banners and function boundaries, as lower-confidence supporting evidence.
- **Small evaluation and rule base:** the method is right, the scale is not yet; contributions welcome.
- **`gangmu vuln` never touches the network:** the online step is the separate `gangmu vuln-fetch`, so it works inside an air-gapped network.
- **The compiler wrapper only intercepts compilers found by name.**

Details, reasons and workarounds for each: [docs/LIMITS.en.md](docs/LIMITS.en.md).

## Repositories

Gangmu is three public repositories and two private ones, released independently:

| Repository | What is in it | Licence |
| --- | --- | --- |
| **[gangmu](https://github.com/GANGMU-SBOM/gangmu)** (this one) | Identification engine, CLI, build-time collection, SBOM and VEX output, vulnerability matching, CRA and MIIT report drafts | Apache-2.0 |
| **[gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)** | The free rule base: the general open-source components vendor SDKs copy most, plus Zephyr and its HALs, released by date (`pip install -U gangmu-rules`) | CDLA-Permissive-2.0 |
| **[gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench)** | The benchmark: pinned real upstream releases with their correct answers and a scoring script anyone can re-run | Apache-2.0 |

The commercial edition (rule packs, monitoring, reporting workbench) is not in these repositories; see [docs/EDITIONS.md](docs/EDITIONS.md).

`pip install gangmu-sbom` installs gangmu-rules for you. Where to file what: a wrong
identification or a missing SDK rule goes to gangmu-rules; a crash, a CLI or an output
format problem goes here; a new benchmark case goes to gangmu-bench.

## Contribute rules, get in touch

Rules are the most valuable part of this project and the part that needs the community most: a rule takes one clean upstream release and one run of `gangmu rules verify`.

- **General open-source components, Zephyr and its HALs, third-party libraries found in Chinese SDKs:** open an issue or pull request at [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules); see its [contributing guide](https://github.com/GANGMU-SBOM/gangmu-rules/blob/main/CONTRIBUTING.md).
- **Want to take on a chip SDK, unsure where a rule belongs, or have real firmware samples to help verify:** contact me first so we do not duplicate work, and I will tell you the cheapest way to do it.
- **Vendor-specific rules, private BSPs, commercial rule packs:** contact me as well.

Contact: email 64031875@qq.com, or join the WeChat "CRA compliance group" (the QR code expires; email if it does not scan).

<img src="docs/assets/cra-wechat-group.png" alt="WeChat group QR code" width="200">

Rules you contribute are licensed under gangmu-rules' licence (CDLA-Permissive-2.0). What is already in the open-source repositories will not be withdrawn or put behind a fee.

## Commercial edition and services

The open-source edition takes a team through the whole flow once. For running
it over the long term there is a commercial edition: continuous multi-source
vulnerability monitoring with reviewed VEX decisions, a reporting workbench
tracking the CRA and Chinese deadlines in parallel with ten-year retention, the
commercial rule packs for vendor-specific firmware libraries, an
enterprise rule service (offline mirror, update SLA, private rules for your own
BSPs), on-premises deployment, and support. The core (identification engine, build-time collection, SBOM and VEX
output, vulnerability matching, report drafts, the benchmark and the free rule base) stays open source, and the commercial edition
is a plug-in and rule packs layered on top of it that changes nothing in the open-source edition. See
[docs/EDITIONS.md](docs/EDITIONS.md#open-source-and-commercial-editions), or
for technical consulting and business enquiries see [Contact](#contribute-rules-get-in-touch), or open an issue whose title starts with "Commercial".

## Licence

Tool: Apache-2.0. Rules ([gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)): CDLA-Permissive-2.0. Commercial rule packs: proprietary. Benchmark ([gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench)): Apache-2.0.

```bash
git clone https://github.com/GANGMU-SBOM/gangmu-rules
pip install -e ./gangmu-rules -e ".[dev]" && pytest -q     # no network needed; the tests need only the free rule base
```
