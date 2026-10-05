# FAQ

[中文](FAQ.md) · [README](../README.en.md) · [Glossary](GLOSSARY.md)

The first sentence of each answer is the answer. Every number can be reproduced
with the tools in this repository; see [BENCHMARK.md](BENCHMARK.md).

## What is Gangmu?

Gangmu (纲目) is an open-source, build-time SBOM tool for embedded C/C++ firmware,
with a community-maintained rule base that identifies the open-source components
inside chip-vendor SDKs. It writes CycloneDX 1.6 or SPDX 2.3, matches
vulnerabilities into CycloneDX VEX, checks artefacts against the EU Cyber
Resilience Act (CRA), and drafts CRA Article 14 and China MIIT vulnerability
reports. The tool is Apache-2.0; the rules are CDLA-Permissive-2.0. The command
is `gangmu` and the Python package is `gangmu-sbom`.

## Where does the name come from?

From the *Bencao Gangmu* (本草纲目), Li Shizhen's 16th-century compendium of
materia medica, which classified nearly two thousand substances and recorded the
source and properties of each. Gangmu does the same for third-party code in
firmware: each component is filed under its upstream project, release and
vendor modifications, with evidence anyone can re-check.

## Why is SBOM generation hard for embedded C/C++?

Because C/C++ has no lock file and embedded development removes the remaining
evidence: source is copied into the tree, vendors fork and rename upstream
projects, everything is statically linked, and the build compiles far more than
it ships. Source-tree scanners over-report and binary scanners under-report.
Gangmu reads the build: `compile_commands.json` for what was compiled and the
linker map for what survived.

## How does it identify renamed or modified components?

By comparing code at function level rather than file names or whole-tree
similarity, following CENTRIS (ICSE 2021) and TIVER (ICSE 2025). Identity is how
much of the upstream component's code is present; version is which releases the
matched functions come from. A GmSSL 3.0.0 tree that was moved, stripped of its
version header, partly re-prefixed, extended and reduced by eight files is still
identified as GmSSL 3.0.0, vendor-modified, confidence 0.88
(`examples/disguise.sh`). On lwIP, whole-tree similarity separates a vendor fork
from a different release by 0.06; function level separates them by 0.25.

## Which SDKs and chips are covered?

The free rule base ([gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)) has 60 rules.

Covered: Zephyr (Mbed TLS 4.1, TF-PSA-Crypto, hostap, FatFs, littlefs, MCUboot, nanopb, zcbor, uOSCORE/uEDHOC) and its HALs for Chinese and APAC silicon from Zephyr 4.4 (GigaDevice GD32, Bouffalo Lab, WCH CH32, SiFli, Telink, Realtek); and the general components lwIP, cJSON, OpenSSL, GmSSL, Tongsuo, Mbed TLS, TF-PSA-Crypto, FatFs, littlefs, LVGL, libcoap, TinyCrypt, nghttp2, libwebsockets, Paho MQTT C, OpenThread, the AWS IoT Device SDK, FreeType, libjpeg-turbo, giflib, Opus and OpenAMP, plus the FreeRTOS, RT-Thread, TencentOS-tiny, AliOS Things and LiteOS (M, A, 5.x) kernels (found by marker files wherever a vendor put them).

Vendor-specific firmware-library rules (chip-vendor SDKs and forks) belong to the commercial rule packs; contact us, see [EDITIONS.md](EDITIONS.md).

RT-Thread and
OpenHarmony declarations and Zephyr `module.yml` security references are read
directly.

## Does it recognise Chinese commercial cryptography (SM2/SM3/SM4)?

Yes: GmSSL 3.0.0-3.2.0 and 2.0.0-2.5.4 (2.x is its own rule), Tongsuo
8.1.3-8.5.0 (8.1-8.3 are the BabaSSL-named releases), and OpenSSL 1.1.0-1.1.1w
(every release) plus 3.0 to 3.6. Tongsuo is an OpenSSL fork; with both rules loaded, the functions
they share count as identity evidence for neither, so a pristine OpenSSL tree is
not mistaken for Tongsuo.

## What does the CRA require, and what does Gangmu cover?

Annex I Part II(1) of Regulation (EU) 2024/2847 requires an SBOM in a commonly
used machine-readable format covering at least top-level dependencies, kept in
the technical documentation. Gangmu produces it, and `gangmu cra-check` reviews
ten clauses; five of them only ever return partial, declared or out of scope.
Manufacturers' reporting obligations apply from 11 September 2026 (24-hour
early warning, 72-hour notification, 14-day final report via the ENISA Single
Reporting Platform); everything else from 11 December 2027. The platform has no
API at first release, so `gangmu report` pre-fills the fields for a person to
paste in. See [CRA.md](CRA.md).

## Does it work offline?

Yes. `gangmu vuln` reads local NVD, OSV and CNNVD/CNVD directories and never
fetches over the network; the test suite needs no network either. Filling
those directories is the separate `gangmu vuln-fetch` command: run it on a
connected machine, then carry the directory in. It fetches NVD and OSV only;
CNNVD/CNVD data has to be exported from those platforms yourself.

## What does it not do?

No deep binary analysis (banners and exported symbols only), no security testing, no legal conclusions, no submission to
official platforms, and no guessed CPEs (35 of 92 rules carry one, new ones citing
the NVD records that prove it; the other 57 say why not; PURL and OSV are first-class channels).

## How do I add a rule?

Fingerprint a pristine upstream release with `gangmu rules fingerprint`, or
import from an SDK's `.gitmodules` or west manifest with `gangmu rules import`,
then open a pull request. CI re-derives the evidence from the upstream release
the rule names and rejects anything that does not reproduce. See
[CONTRIBUTING.md](../CONTRIBUTING.md) and [RULE-FORMAT.md](RULE-FORMAT.md).

## Is there a commercial edition?

Yes. The core stays open source; continuous monitoring, a reporting workbench,
an enterprise rule service and on-premises deployment are offered for teams that
run the process long term. See [EDITIONS.md](EDITIONS.md).
