# Changelog

What each release added and what was measured at the time, newest first. For the current capabilities see the [README](../README.en.md); for Chinese-ecosystem coverage see [CHINA.md](CHINA.md).

## 0.6.2

* **GitHub Action and pre-commit hook.** A root `action.yml`
  (`uses: GANGMU-SBOM/gangmu@v0`) generates an SBOM in CI; `.pre-commit-hooks.yaml`
  provides a `gangmu-scan` hook.
* **Documentation.** Task-oriented guides (ESP-IDF, Zephyr, RT-Thread / OpenHarmony,
  Chinese commercial cryptography, vendor-modified component identification, CRA and MIIT
  reporting), a comparison with similar tools, example output in `examples/output/`, and
  FAQPage structured data.
* The release workflow now runs only for `vX.Y.Z` tags; the moving `v0` tag no longer
  triggers a PyPI publish.


Accuracy and noise, found by scanning pristine upstream releases laid out the way
an SDK lays them out (lwIP, Mbed TLS, libcoap, littlefs, FreeRTOS-Kernel, nanopb,
miniz, TinyCrypt, cJSON, wolfSSL, LVGL, RT-Thread: 12 real releases in two
mock SDKs). Before: 7 of 9 pristine copies in the first SDK were labelled
`vendor-modified`, nanopb was reported three times (two phantoms from its own
`examples/`), and the second SDK lost the RT-Thread kernel and put FatFs at the
wrong directory.

* **`vendor-modified` now means recorded code is missing or altered.** It used to
  fire on any function the signature had never seen, which in a pristine tree
  means headers, ports and macros the signature does not cover (136 of lwIP's
  2,092, 1,487 of FreeRTOS's 1,743), and on `multi_version`, which pristine lwIP
  also triggers. `vendor_patched` feeds `is_fork` in vulnerability matching, so
  every false flag also demoted real advisories to triage. Now: 0 of 9 pristine
  copies flagged; three edited lwIP functions are flagged, with the count in the
  evidence. A copy that only *adds* code is not flagged: additions do not change
  whether vulnerable code is present.
* **Example and test manifests inside an identified component are not components.**
  nanopb's `examples/conan_dependency` (a second nanopb, at 0.4.6) and
  `examples/platformio` (a third, versionless). A project's own `examples/`
  directory is still read, and the scan says how many it ignored.
* **A component is attributed to the directory that holds it.** Function
  containment fires at every ancestor too, and one winner per directory let that
  displace the kernel that owns the parent (RT-Thread lost to its own FatFs).
  An ancestor's claim is now dropped when a descendant says the same thing; a
  weaker nested match, or an inner range against an exact root release, never
  displaces the root.

* **Patch presence testing.** `gangmu patch-build CVE` records the functions an
  advisory's fix changed (fix commit read from the OSV record, or `--repo` and
  `--fix`), and `gangmu vuln --source ROOT --patches FILE` tests the code instead
  of the version: the fixed body present resolves the finding, the vulnerable
  body confirms it, an edited one is left for a person. A vendor fork that
  reports the release it started from no longer sits in `in_triage` for every
  advisory fixed since. See [ALGORITHMS.md](ALGORITHMS.md#patch-presence).
* **Near matching for patch presence.** A function the vendor edited used to be
  a dead end (`modified`). Records now also keep the token windows the fix added
  and removed, so an edited copy can be reported `likely_fixed` or
  `likely_vulnerable`, with the shares it rests on. It changes the VEX state only
  with `--patch-near-vex`. On cJSON's history (112 security fixes against 49
  releases) it makes 853 correct claims beyond the 1,166 exact ones, none wrong.
  Not applied to identification: on a real fork 98.9% of functions already match
  exactly.
* **Patch records ship with rule packs.** `gangmu vuln --source ROOT` reads
  `patches/*.json` from the installed packs, so the community pack's records
  apply without being named (`--no-pack-patches`, `--rules DIR`). `gangmu
  patch-verify` rebuilds each record from the upstream commits it names, and
  `patch-build --first-parent` records a fix merged as a pull request. Fixes two
  faults found by verifying real records: several fix commits on one function,
  and a fix commit left on a shallow boundary by a neighbouring fetch.
* **The SBOM records which rule pack identified each component.** CycloneDX components gain the properties
  `gangmu:rulePack` and `gangmu:rulePackVersion` (the pack manifest's `name` and `version`; without a manifest the
  entry-point name or directory name, and no version). SPDX package comments say "from rule pack ...", and
  `gangmu scan --format json` carries `rule_pack` and `rule_pack_version` on each finding. When a later pack overlays
  a rule, the later pack is the one recorded. Components that come from build declarations or binary strings, not a
  rule, carry neither field. It lets a team see how many components of an SBOM each rule pack is responsible for,
  which is the data behind a commercial rule pack's value report.

## 0.6.1

Bug fixes found while verifying the 0.6.0 release from PyPI in a clean environment.

* **`gangmu init DIR` no longer crashes when `DIR` does not exist.** It creates
  the directory, and a target that cannot be written gives a one-line error
  instead of a traceback.
* **Test inputs are no longer reported as firmware.** `.bin`, `.elf` and `.axf`
  files below directories named `test`, `tests`, `testdata`, `test_data`,
  `fuzz` or `fixtures` (lwIP's `test/fuzz/inputs/*.bin` are fuzz packets) are not
  inventoried as prebuilt images, so they no longer appear in the SBOM or as
  components `gangmu vuln` cannot look up. Libraries (`.a`, `.lib`, `.so`) are
  still listed wherever they are.

## 0.6

* **Fast enough for every CI build.** Each file is analysed once per scan,
  keyed by content. Directory sketches are built exactly from per-file
  bottom-k sets. An incremental SQLite cache is keyed by content and by a
  digest of the analysing code. Rules that cannot fire are never evaluated.
  Findings are identical to 0.5. `gangmu perf --check` fails a pull request
  whose findings, work counters, time or memory regress against
  `benchmarks/perf-baseline.json`.
* **RTOS kernels wherever vendors put them.** FreeRTOS (28 releases) and
  RT-Thread (27 releases) rules locate a kernel by the files only it has
  together (`tasks.c` + `queue.c` + `list.c`), so renamed directories without
  a LICENSE are found. All 14 copies in seven Bouffalo Lab, WCH, WinnerMicro
  and Espressif SDKs are found; 0.5 found none.
* **Mbed TLS, FatFs and littlefs outside Zephyr and ESP-IDF.** Their rules
  only knew those two layouts, yet the libraries are in nearly every Chinese
  SDK and carry more CVEs than the vendors' own HALs. `generic/mbedtls` (63
  releases, 2.1.18 to 4.2.0), `generic/fatfs` (R0.10a to R0.16) and
  `generic/littlefs` (1.7.2, 2.0.0 to 2.11.3) find a copy by marker files under
  any name. All 12 copies in five Bouffalo Lab, WinnerMicro, WCH and Espressif
  SDKs are found with the right version or a range containing it; 34 pristine
  upstream trees (renamed, version headers deleted, or sources edited) are
  34/34 the right component, 28 exact and 6 ranges, none wrong. This exposed
  two bugs, both fixed: when a generic and a Zephyr/ESP rule recognised the same
  directory the more specific rule won, so a pristine Mbed TLS 4.1.1 was
  reported as "Zephyr's 4.1.0, patched" and a pristine littlefs 2.11.3 as
  `git-e9a8638fc228` (which no CVE range can be compared with); and version
  comparison ignored a trailing letter, so `1.1.1k` equalled `1.1.1n` and a CVE fixed in 1.1.1n was
  reported as not affecting 1.1.1k, while FatFs's `R0.14b` read as a beta. See [docs/BENCHMARK.md](BENCHMARK.md#1d-third-party-libraries-inside-chinese-vendor-sdks).
* **LVGL, libcoap and TinyCrypt.** `generic/lvgl` (54 releases, 6.0 to 9.6.0),
  `generic/libcoap` (13) and `generic/tinycrypt` (7), found by marker files. All
  7 copies in the Bouffalo Lab and WinnerMicro SDKs are found; 25 real upstream
  trees are 25/25 the right component (21 exact, 4 ranges, 0 wrong). Their CPE
  status is "unverified": NVD was unreachable when the rules were written, and
  none is guessed.
* **CPEs from evidence.** `gangmu rules cpe-evidence --nvd DIR` ranks the NVD
  vendor:product pairs whose CVEs cite a rule's upstream repository. It gave
  FreeRTOS, RT-Thread, OpenThread and FatFs their CPEs and found 13 cJSON CVEs
  filed under `davegamble:cjson` that the old CPE missed. Each new CPE cites
  its CVEs in `cpe_evidence`. `gangmu vuln` now streams a full NVD mirror
  (including `.json.xz`). Across eight SDKs, matched advisories rose from 133
  to 243.
* **OpenHarmony components and who uses what.** Each component's
  `bundle.json` is read for its name, version, licence and declared
  dependencies. OpenHarmony's own components are listed. Dependencies become
  CycloneDX `dependencies` and SPDX `DEPENDS_ON` edges. On the Hi3861 mini
  product (43 repositories from `default_mini.xml`, 181,000 files), 15 → 45
  components and 0 → 89 dependency edges at the same scan time. Mbed TLS is
  now visibly used by six components (device_auth, huks, dsoftbus, init, ...).

## 0.4–0.5

* **Declared components.** RT-Thread (`.config`, `packages/pkgs.json`) and
  OpenHarmony (`README.OpenSource`) are read directly. OpenHarmony declares the
  upstream version, so the rule's CPE applies; an RT-Thread package tag is the
  wrapper's own version and is never spliced into an upstream CPE: the
  directory is fingerprinted and the declaration is attached as evidence.
  Yocto is read from the build output (`license.manifest`, else the image
  manifest, else the recipes `IMAGE_INSTALL` selects), and PlatformIO from
  `.pio/libdeps/*/*/library.json` (exact version, and the directory is fingerprinted
  too), else `platformio.ini` `lib_deps`. Conan (`conan.lock`, `conanfile.txt`/`.py`; `tool_requires` excluded) and Bazel
  (`MODULE.bazel` `bazel_dep`, `WORKSPACE` `http_archive`/`git_repository`; dev
  dependencies and `rules_*` toolchain modules excluded) are read the same way. A
  branch-tracking recipe, a version range or an unversioned archive is reported
  without a version, never with a guess.
* **Chinese commercial cryptography.** GmSSL 3.0.0–3.2.0 (`generic/gmssl`)
  and 2.0.0–2.5.4 (its own rule, `generic/gmssl-2`: different layout, and
  upstream never tagged 2.x, so each version is pinned to a commit); Tongsuo
  8.1.3–8.5.0 (8.1–8.3 are the BabaSSL-named releases); and OpenSSL 1.1.0–1.1.1w
  (every release) plus 3.0–3.6. Tongsuo and GmSSL are OpenSSL forks; with the
  rules loaded, the functions they share count for neither. OpenSSL 1.1.x had
  to be added for that: GmSSL 2.x and Tongsuo 8.1–8.3 are 1.1.x forks, and an
  unmodified OpenSSL 1.1.1w otherwise matched Tongsuo 8.1.3 at 0.80. That segmentation
  now also covers the identifier-abstracted level: before 0.5, a pristine
  OpenSSL tree "also looked like" Tongsuo at 0.90 identity through the shared
  bodies.
* **Chinese and APAC silicon HALs** from Zephyr 4.4: Bouffalo Lab, WCH,
  SiFli, Telink, Realtek.
* **Zephyr `module.yml` security references** (CPE and PURL declared by the
  module) are read as a vendor manifest. Re-importing with them corrected the
  Zephyr Mbed TLS rule (it is Mbed TLS 4.1.0, not build glue) and added hostap.
