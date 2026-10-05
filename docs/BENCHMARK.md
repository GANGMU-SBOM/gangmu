# Benchmark

> Version-identification accuracy on real upstream releases (exact / range / wrong / missing) lives in [gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench). The rules these numbers depend on live in [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules).

## Why these numbers and not someone else's

The cross-tool SBOM benchmarks that exist — [sbomify's](https://github.com/sbomify/sbom-benchmarks),
and the quality scores behind [sbombenchmark.dev](https://github.com/interlynk-io/sbombenchmark.dev) —
cover Python, JavaScript, Java, Go, Rust and Docker. Every one of those
ecosystems has a lock file, and generating an SBOM for them is largely a matter
of reading it.

**None of them covers C/C++ or embedded.** The case where generation is actually
hard is the case nobody measures. So the numbers below are produced by a
harness in this repository, against real upstream releases, with a fixed seed,
and anyone can re-run them.

```bash
gangmu eval --signature gangmu-rules/rules/generic/lwip.fnsig \
    --include 'src/**/*.c' --include 'src/**/*.h' \
    --tree /path/lwip-2.2.0=2.2.0 --tree /path/esp-lwip=2.2.0 \
    --mutate /path/lwip-2.2.0=2.2.0
```

## 1. Version accuracy on real releases

Signature built from the eight most recent lwIP release tags (3,016 functions,
91 KB). Each tree is a real `git archive` of a release tag; `esp-lwip` is
Espressif's production fork as pinned by ESP-IDF.

| tree | truth | reported | exact | containment |
| --- | --- | --- | --- | --- |
| upstream 2.0.3 | 2.0.3 | 2.0.2~2.0.3 | yes | 1.000 |
| upstream 2.1.0 | 2.1.0 | 2.1.0~2.1.2 | yes | 1.000 |
| upstream 2.1.2 | 2.1.2 | 2.1.0~2.1.2 | yes | 1.000 |
| upstream 2.1.3 | 2.1.3 | 2.1.3 | yes | 1.000 |
| upstream 2.2.0 | 2.2.0 | 2.2.0 | yes | 1.000 |
| **Espressif fork of 2.2.0** | 2.2.0 | 2.2.0~2.2.1 | yes | **0.938** |

**6/6 exact.** Where a range is reported rather than a point, the releases in it
are genuinely indistinguishable by function content — 2.1.0 and 2.1.2 have
identical function sets, so narrowing further would be invention.

The fork is additionally reported as mixing releases: *"1157 are in 2.2.0, and 3
belong to other recorded versions — this tree mixes releases, which is what a
vendor fork looks like."* That sentence is the whole argument for function-level
matching. A whole-tree sketch scores the fork 0.949 and upstream 2.1.3 at 0.887,
and cannot tell you which is which.

## 1b. RTOS kernels inside Chinese vendor SDKs

Two generic rules added in 0.6:
* FreeRTOS-Kernel: 28 releases, 8.2.3 to 11.3.1, 1,168 functions.
* RT-Thread kernel: 27 releases, 3.0.0 to 5.3.0, 2,108 functions.

The test set is every copy of either kernel found in seven SDKs as published on
GitHub:
* Bouffalo Lab `bouffalo_sdk` and `bl_iot_sdk`;
* WCH `ch32v307`, `ch32v20x` and `ch583`;
* WinnerMicro `wm_iot_sdk`;
* Espressif `ESP8266_RTOS_SDK`.

The truth for each copy is the version string the vendor left in its own
header (`tskKERNEL_VERSION_NUMBER`, `RT_VERSION`/`RT_SUBVERSION`/`RT_REVISION`,
or the kernel's file banner). "From functions" is the version read from the
function signature alone.

| copy | truth | from functions | containment | reported by a scan |
| --- | --- | --- | --- | --- |
| ESP8266_RTOS_SDK `components/freertos/freertos` | 10.0.1 | 10.0.0~10.0.1 | 0.863 | 10.0.0~10.0.1 |
| wm_iot_sdk `components/freertos/src` | 10.4.1 | 10.4.0~10.4.2 | 0.909 | 10.4.0~10.4.2 |
| bl_iot_sdk `os/freertos_e907` | 10.4.1 | 10.4.0~10.4.2 | 0.991 | 10.4.1 |
| bl_iot_sdk `bl602/freertos_riscv` | 10.2.0 | 10.2.0~10.2.1 | 0.991 | 10.2.0~10.2.1 |
| bl_iot_sdk `bl602/freertos_riscv_ram` | 10.2.0 | 10.2.0~10.2.1 | 0.988 | 10.2.0~10.2.1 |
| bl_iot_sdk `bl702/bl702_freertos` | 10.2.0 | 10.2.0~10.2.1 | 0.995 | 10.2.0~10.2.1 |
| bl_iot_sdk `bl808_c906_freertos/Source` | 10.2.1 | 10.2.0~10.3.1 | 0.967 | 10.2.1 |
| bouffalo_sdk `os/freertos` | 10.6.2 | 10.6.0~10.6.2 | 0.942 | 10.6.2 |
| ch32v307 `FreeRTOS_Core/FreeRTOS` | 10.4.6 | 10.4.5~10.4.6 | 0.955 | 10.4.6 |
| ch32v20x `FreeRTOS_Core/FreeRTOS` | 10.4.6 | 10.4.5~10.4.6 | 0.955 | 10.4.6 |
| ch583 `FreeRTOS/FreeRTOS` | 10.5.1 | 10.5.1 | 1.000 | 10.5.1 |
| ch32v307 `RT-Thread/rt-thread` | 3.1.3 | 3.1.3 | 0.945 | 3.1.3 |
| ch32v20x `RT-Thread/rt-thread` | 3.1.3 | 3.1.3 | 0.945 | 3.1.3 |
| ch583 `RT-Thread/rt-thread` | 3.1.5 | 3.1.5 | 0.897 | 3.1.5 |

**All 14 copies are found and every reported version is right or a range
containing the truth.** None of these copies was found before 0.6:
* five sit in directories a vendor renamed (`freertos_riscv`, `bl702_freertos`);
* none carries a LICENSE file;
* the WCH ones are three levels inside an example tree.

The rules name marker files instead (`tasks.c` + `queue.c` + `list.c`;
`src/thread.c` + `src/ipc.c` + `include/rtthread.h`), and discovery finds
those wherever they are. Where a scan reports a range, the releases in it ship
the same kernel code: 10.2.0 and 10.2.1 differ only in ports. When the vendor
kept the version header where upstream has it, the probe narrows the range to
the stated release.

Mutation robustness, using the same harness as section 2:
* FreeRTOS 11.1.0 is identified under 8 of 9 mutations, with the version
  right under all 9. The exception is deleting half of a seven-file kernel,
  which removes `tasks.c` itself.
* RT-Thread 5.2.0 is identified under 9 of 9, with the version right under
  all 9. Renaming 50% of identifiers still leaves 0.81 containment at the
  abstract level.

Adding both rules moves scan time by no more than run-to-run noise (−0.09 s to
+0.12 s) and adds 0.7 to 2.4 MB of memory (4 jobs, same machine, back to back):

| SDK | before | after | memory | components |
| --- | --- | --- | --- | --- |
| bouffalo_sdk (1.6 GB) | 5.01 s | 5.13 s | 67.2 → 69.1 MB | 7 → 8 |
| bl_iot_sdk (6.7 GB) | 2.55 s | 2.67 s | 62.2 → 63.3 MB | 1 → 6 |
| wm_iot_sdk | 12.07 s | 11.98 s | 62.7 → 65.1 MB | 6 → 7 |
| ESP8266_RTOS_SDK | 1.51 s | 1.45 s | 38.9 → 40.8 MB | 3 → 4 |
| ch32v307 | 0.81 s | 0.79 s | 37.6 → 39.2 MB | 2 → 4 |
| ch32v20x | 0.84 s | 0.95 s | 37.7 → 39.5 MB | 2 → 4 |
| ch583 | 0.87 s | 0.92 s | 35.9 → 36.6 MB | 0 → 2 |

## 1c. Older national-crypto generations: GmSSL 2.x, BabaSSL/Tongsuo 8.1-8.3

Added to the rule base:
* `generic/gmssl-2`: GmSSL 2.0.0 to 2.5.4 (20 releases, 8,005 functions). A rule
  of its own, because the layout differs from 3.x (`crypto/sm3`, `crypto/sms4`,
  `include/openssl/*.h` against `src/` and `include/gmssl/`), so include globs,
  marker files, anchor file and probe all differ. Upstream never tagged 2.x;
  each version is pinned to the commit that first carries its
  `OPENSSL_VERSION_TEXT` (2.5.4 to the tip of the `GmSSL-v2` branch, as a commit id).
* Tongsuo 8.1.3, 8.2.0, 8.2.1, 8.3.0 to 8.3.3 (the BabaSSL-named releases) next
  to 8.4.0 and 8.5.0: nine releases, 24,737 functions.
* OpenSSL 1.1.0 to 1.1.0l and 1.1.1 to 1.1.1w, every release, next to the 3.x
  lines: 44 releases, 28,592 functions.

The OpenSSL addition is not optional. Both older generations are OpenSSL 1.1.x
forks, and with only the GmSSL and Tongsuo changes an **unmodified OpenSSL 1.1.1w
was reported as Tongsuo 8.1.3 (0.80) and OpenSSL 1.1.0l as GmSSL 2.0.0~2.1.0
(0.75)**. Before this change they were reported as nothing (1.1.0l) and as
"OpenSSL 3.0.22~3.1.8" (1.1.1w, wrong). With 1.1.x in the OpenSSL rule, the
functions shared with the forks count for none of them, as for 3.x.

Real trees, `git archive`-equivalent checkouts renamed to `vendored_lib`, scanned
with the whole shipped rule base. "stripped" deletes the version-bearing headers
(`opensslv.h`, `VERSION.dat`, `version.h`), so only the function level decides.

| tree | pristine | stripped (functions only) |
| --- | --- | --- |
| GmSSL 2.0.0 | gmssl-2 2.0.0 (0.95) | 2.0.0 (0.88) |
| GmSSL 2.3.3 | gmssl-2 2.3.3 (0.95) | 2.3.3~2.4.0 (0.88) |
| GmSSL 2.4.5 | gmssl-2 2.4.5 (0.95) | 2.4.4~2.5.0 (0.88) |
| GmSSL 2.5.0 | gmssl-2 2.5.0 (0.95) | 2.4.5~2.5.0 (0.88) |
| GmSSL 2.5.3 | gmssl-2 2.5.3 (0.95) | 2.5.3 (0.88) |
| GmSSL 2.5.4 | gmssl-2 2.5.4 (0.95) | 2.5.4 (0.88) |
| Tongsuo 8.1.3 | tongsuo 8.1.3 (0.95) | 8.1.3 (0.88) |
| Tongsuo 8.2.1 | tongsuo 8.2.1 (0.95) | 8.2.0~8.2.1 (0.88) |
| Tongsuo 8.3.3 | tongsuo 8.3.3 (0.95) | 8.3.0~8.3.3 (0.88) |
| GmSSL 3.0.0, 3.2.0 (regression) | gmssl, right version | right version |
| Tongsuo 8.4.0, 8.5.0 (regression) | tongsuo, right version | right version |
| OpenSSL 3.0.22, 3.5.9 (regression) | openssl, right version | right version |
| OpenSSL 1.1.0g, 1.1.0l | openssl 1.1.0g, 1.1.0l | 1.1.0g; 1.1.0j~1.1.0l |
| OpenSSL 1.1.1k, 1.1.1w | openssl 1.1.1k, 1.1.1w | 1.1.1h~1.1.1n; 1.1.1o~1.1.1w |

**19 of 19 trees are identified as exactly one component, the right one, with a
version equal to or a range containing the truth; no OpenSSL tree matches a fork
and no fork matches OpenSSL.** Where a range is reported, the releases in it have
the same functions (as in 1 and 1b). The GmSSL 2.x function level is weaker than
3.x: of 8,005 functions only 1,340 discriminate between releases, because most
of the code is OpenSSL 1.1.0d.

Mutation robustness, same harness as section 2, signature alone:

| tree | pristine | rename 10% | rename 50% | delete 50% of files | vendor-like | identified | version right |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GmSSL 2.5.4 | 1.000 | 0.851 | 0.786 | 0.495 | **0.092, no** | 8/9 | 9/9 |
| Tongsuo 8.3.3 | 1.000 | 0.989 | 0.539 | 0.549 | 0.694 | 9/9 | 8/9 |
| Tongsuo 8.5.0 (unchanged) | 1.000 | 0.943 | 0.592 | 0.528 | 0.530 | 9/9 | 9/9 |
| GmSSL 3.2.0 (unchanged) | 1.000 | 0.985 | 0.720 | 0.609 | **0.123, no** | 8/9 | 9/9 |

The vendor-like combination (rename 15%, delete 25%, add 20%, reformat) is not
identified for either GmSSL generation. That is not new: the untouched 3.2.0
signature fails it the same way, so it comes from GmSSL's few large files, not
from the added versions.

The existing disguise example (`examples/disguise.sh`) still reports GmSSL 3.0.0
at 0.88. Its evidence line moved from 1375 of 1604 functions (0.857) to 1280 of
1508 (0.849) because functions GmSSL 3.0.0 shares with the 2.x rule now count
for neither.

Not covered by this section: an NVD re-check of the CPE status (NVD was not
reachable from the session), and OSV records for the older versions.

## 1d. Third-party libraries inside Chinese vendor SDKs

Three generic rules added after 0.6, for the libraries the SDK survey found most
often (the survey itself is in the pull request, not repeated here):
* `generic/mbedtls`: 63 releases, 2.1.18 to 4.2.0 (2.16.x, 2.17 to 2.28.x and
  3.x complete), 11,896 functions, 351 KB.
* `generic/fatfs`: 20 releases, R0.10a to R0.16, 305 functions.
* `generic/littlefs`: 38 releases, 1.7.2 and 2.0.0 to 2.11.3, 455 functions.

None has a path glob, only marker files (`library/ssl_tls.c` + `library/x509_crt.c`
+ `include/mbedtls/ssl.h`; `ff.c` + `ff.h` + `diskio.h`; `lfs.c` + `lfs.h` +
`lfs_util.h`), so they find a copy under any directory name. The existing Zephyr
and ESP-IDF rules for the same libraries keep winning at their own paths.

Every copy in five SDKs as published on GitHub (Bouffalo Lab `bouffalo_sdk` and
`bl_iot_sdk`, WinnerMicro `wm_iot_sdk`, Espressif `ESP8266_RTOS_SDK`, WCH
`ch32v307`; `ch32v20x` and `ch583` carry none). Truth is the version the vendor
left in its own header (`MBEDTLS_VERSION_STRING`, the `FatFs - Generic FAT
Filesystem module R0.xx` banner, `LFS_VERSION`).

| copy | truth | reported | basis | containment |
| --- | --- | --- | --- | --- |
| ESP8266 `components/mbedtls/mbedtls` | 2.16.5 (Espressif fork) | 2.16.5, patched | header hash | 0.997 (1587/1591) |
| bl_iot_sdk `security/mbedtls_lts/mbedtls` | 2.28.1 | 2.28.1 | header hash | 1.000 |
| bl_iot_sdk `openthread/third_party/mbedtls/repo` | 2.28.0 | 2.28.0 | header hash | 1.000 |
| bouffalo_sdk `crypto/mbedtls/mbedtls` | 2.28.2 | 2.28.2, patched | header hash | 0.997 (2034/2040) |
| bouffalo_sdk `crypto/mbedtls/mbedtls_v3` | 3.6.5 | 3.6.5 | header hash | 1.000 |
| wm_iot_sdk `components/mbedtls/src` | 3.4.0 | 3.4.0 | header hash | 1.000 |
| ESP8266 `components/fatfs` | R0.13c | 0.13c, patched | functions | 0.922 (47/51) |
| bouffalo_sdk `fs/fatfs` | R0.15 | 0.15, patched | banner | 0.979 |
| wm_iot_sdk `fatfs/src` | R0.15 | 0.15, patched | header hash | 0.957 |
| ch32v307 `SDIO_SD_FATFS/FATFS` | R0.14b | 0.14b | banner | 1.000 |
| bouffalo_sdk `fs/littlefs/littlefs` | 2.11 | 2.11.3 | `lfs.c` hash | 1.000 |
| wm_iot_sdk `components/littlefs/src` | 2.10 | 2.10.2~2.11.1 | functions | 1.000 |

**12 of 12 copies are found and every version is right or a range containing
the truth.** The WinnerMicro littlefs is the one range: its functions are those
of 2.10.2, 2.11.0 and 2.11.1 alike (92 of 92 present), and its own header says
2.10, which is consistent with the range but narrower than what the functions
can show. The three FatFs copies other than WCH's are reported patched because the vendors
did change them: the Bouffalo and WinnerMicro banners say R0.15 and the code
differs from it by one or two functions, Espressif's by four.

Real releases, extracted under a neutral name (`vendored_lib`) and scanned with
the whole shipped rule base. "stripped" deletes the version headers
(`version.h`, `build_info.h`), so only functions can decide; "touched" appends
a comment to the source files, which breaks every byte-for-byte anchor.

| library | trees | right component | exact version | range containing truth | wrong |
| --- | --- | --- | --- | --- | --- |
| Mbed TLS 2.7.19, 2.16.12, 2.28.10, 3.1.0, 3.5.2, 3.6.7, 4.1.1 | 7 pristine | 7 | 7 | 0 | 0 |
| the same, stripped | 7 | 7 | 3 | 4 | 0 |
| FatFs 0.10c, 0.12c, 0.13c, 0.14b, 0.15a, 0.16 | 6 pristine, 6 touched | 12 | 12 | 0 | 0 |
| littlefs 2.0.5, 2.5.0, 2.9.1, 2.11.3 | 4 pristine, 4 touched | 8 | 6 | 2 | 0 |

**34 of 34 identified as the right component and nothing else; 28 exact, 6
ranges that contain the truth, 0 wrong.** The ranges are releases whose
function sets are identical (2.16.11 and 2.16.12, 2.28.8 to 2.28.10, 3.5.0 to
3.5.2, 4.1.1 and 4.2.0; littlefs 2.5.0 and 2.5.1, 2.9.0 to 2.9.2). Mbed TLS 4.x
is covered for the TLS and X.509 layer only; the cryptography moved to
TF-PSA-Crypto in 4.0 and is not part of this rule.

Who wins when a generic and a vendor rule both recognise a directory was wrong
before this section, and the measurements are what showed it. A pristine Mbed
TLS 4.1.1 was reported as Zephyr's Mbed TLS 4.1.0, patched; a pristine littlefs
2.11.3 as `git-e9a8638fc228`, a commit identifier no CVE range can be compared
with. Both rules reached the 0.95 ceiling and the vendor rule's greater
specificity broke the tie. The resolver now ranks, after identity and path
agreement, first by how many independent kinds of evidence back the claim, then
by whether its version can be ordered, and only then by specificity. At their
own paths the vendor rules still win: Zephyr's `modules/crypto/mbedtls`,
`modules/fs/littlefs`, `modules/fs/fatfs` and ESP-IDF's `components/mbedtls/mbedtls`
all resolve to the vendor rule (checked against the pinned forks those rules
were made from).

What this does not show: the tag styles the upstreams use are checked against
`normalize_tag` and the comparison (`mbedtls-2.28.0`, `v2.11.3`, `R0.14b`), but
no OSV or NVD record was available to this session, so matching a real advisory
against these versions has not been run.

## 1e. LVGL, libcoap and TinyCrypt

Three more generic rules, from the same survey as 1d:
* `generic/lvgl`: 54 releases, 6.0 to 9.6.0, 22,341 functions, 615 KB.
* `generic/libcoap`: 13 releases, 4.1.1 to 4.3.5b, 3,031 functions. Letter
  releases (4.3.4a, 4.3.5a, 4.3.5b) are pinned by commit; their tags would
  otherwise read as 4.3.4 and 4.3.5.
* `generic/tinycrypt`: 7 releases, 0.1.0 to 0.2.8, 221 functions.

Their CPE status is `unverified`: NVD was unreachable, so none was looked up.

| copy | truth | reported | basis | containment |
| --- | --- | --- | --- | --- |
| bouffalo_sdk `graphics/lvgl_v8` | 8.4.0 | 8.4.0, patched | `lvgl.h` | |
| bouffalo_sdk `graphics/lvgl_v9` | 9.5.0 | 9.5.0, patched | `lv_version.h` hash | |
| wm_iot_sdk `lvgl/lvgl/src` | 8.4.0 | 8.3.11~8.4.0, patched | functions | |
| wm_iot_sdk `coap/libcoap` | 4.3.4 | 4.3.2~4.3.4a, patched | functions | |
| bl_iot_sdk, bouffalo_sdk, wm_iot_sdk TinyCrypt (3 copies) | 0.2.7 (README) | 0.2.8, patched | functions | 0.916 |

**7 of 7 copies are found.** Six are right or a range containing the truth. The
TinyCrypt copies are the exception to read carefully: they state 0.2.7 (the
Zephyr fork's README names the exact upstream commit), but contain 6 of the 7
functions that changed in 0.2.8 and none of the 7 that 0.2.7 had. They are
0.2.7 with 0.2.8's fixes backported, and "0.2.8" is the better answer for
matching a CVE, though it is not the version the vendor states. ESP8266's
wolfSSL is a prebuilt `libwolfssl.a` with headers and has nothing to fingerprint.

Real releases under a neutral name, scanned with the whole rule base ("stripped"
deletes `lvgl.h` / `lv_version.h` or `ChangeLog`):

| library | trees | right component | exact | range containing truth | wrong |
| --- | --- | --- | --- | --- | --- |
| LVGL 7.11.0, 8.3.11, 8.4.0, 9.2.2, 9.5.0, 9.6.0 | 6 pristine, 6 stripped | 12 | 9 | 3 | 0 |
| libcoap 4.1.2, 4.2.1, 4.3.0, 4.3.4, 4.3.5 | 5 pristine, 5 stripped | 10 | 9 | 1 | 0 |
| TinyCrypt 0.2.5, 0.2.7, 0.2.8 | 3 pristine | 3 | 3 | 0 | 0 |

**25 of 25 identified as the right component, 21 exact, 4 ranges, 0 wrong, and
no pristine tree reported as patched.** LVGL needed its include and exclude globs
aligned with the signature (C and headers only, no `demos/` or `env_support/`),
or the C++ files LVGL bundles for 9.x made every pristine tree look modified.

## 1f. Chinese RTOS kernels: TencentOS-tiny

`generic/tencentos-tiny-kernel`: 13 releases, 2.1.0 to 2.5.2, 432 functions, 12 KB.
Upstream tagged only three of them (v2.1.0, v2.4.5, v2.5.0); the others are
pinned to the commit that first carries their `TOS_VERSION` in
`kernel/core/include/tos_version.h`. The tag `v2.4.5` is mislabelled: its header
says 2.4.3, and the commit declaring 2.4.5 is two months later. Markers are four
sources in `kernel/core` (`tos_task.c`, `tos_sys.c`, `tos_mutex.c`,
`tos_event.c`), not the headers, so a renamed or flattened directory is found.

Real copies: the only vendor SDKs found carrying TencentOS-tiny are WCH's
`openwch/ch32v307` and `openwch/ch32v20x` (`EVT/EXAM/TencentOS/...`).

| copy | truth (header) | reported by a scan | basis | containment |
| --- | --- | --- | --- | --- |
| ch32v307 `TencentOS_Tiny/kernel/core` | 2.4.5 | 2.4.5 | probe | 1.000 |
| ch32v20x `TencentOS_Tiny/kernel/core` | 2.4.5 | 2.4.5 | probe | 1.000 |
| same, `tos_version.h` deleted | 2.4.5 | 2.4.5 | functions | 1.000 |

Both WCH copies are unpatched. Every upstream release under a neutral name
(`tNN/rtos_x`, scanned with the whole rule base):

| trees | right component | exact | range containing truth | wrong |
| --- | --- | --- | --- | --- |
| 12 pristine | 12 | 12 | 0 | 0 |
| 12 stripped of `tos_version.h` | 12 | 5 | 7 | 0 |

Stripped, 2.2.0 to 2.4.3 are reported as `2.2.0~2.4.3` and 2.5.1/2.5.2 as
`2.5.1~2.5.2`: those releases changed no function of `kernel/core` that the
signature discriminates on. 2.1.0, 2.4.5 and 2.5.0 are exact either way.

Mutation robustness (2.5.0, same harness as section 2, signature alone):
identified under 8 of 9 mutations; the reported version contains the truth in
all 8 (exact in 3: the others are the range `2.4.5~2.5.0`). Renaming 10% or 25%
of identifiers leaves 0.992 containment at the abstract level, deleting 20% of
files 0.801, 50% 0.285, the vendor-like combination 0.615. **Renaming 50% of
identifiers is not identified (0.000).**

Regression: a pristine FreeRTOS-Kernel V11.1.0 and RT-Thread v5.2.0 side by side
in one tree produce no TencentOS-tiny finding, and the markers are tested
against both layouts in `tests/test_rtos_cn.py`.

NVD: the CPE `cpe:2.3:o:tencent:tencentos-tiny` exists, with a single record,
CVE-2021-27439, whose configuration names version **3.1.0**; upstream has never
published that version (tags end at v2.5.0, the header at 2.5.2), and the
record's only reference is a CISA advisory. The CPE is therefore kept, but it
will not match any copy this rule versions. OSV has no record for the repository.

## 1g. nghttp2, libwebsockets, Paho MQTT C, OpenThread and the AWS IoT Device SDK

Five more generic rules, from a survey of what `gangmu scan` left unidentified in
Bouffalo Lab's `bouffalo_sdk` and `bl_iot_sdk` and WinnerMicro's `wm_iot_sdk`:
* `generic/nghttp2`: 64 releases, 1.19.0 to 1.70.0, 1,308 functions.
* `generic/libwebsockets`: 63 releases, 3.0.0 to 4.5.8, 6,717 functions.
* `generic/paho-mqtt-c`: 23 releases, 1.0.1 to 1.3.16, 1,916 functions.
* `generic/openthread`: 11 releases (thread-reference 20191113 to 20250612 and
  v2026.06.0 to v2026.10.0), 2,300 functions. OpenThread has no version string,
  so the version always comes from the functions.
* `generic/aws-iot-device-sdk-c`: the v2 and v3 generation, 14 releases, 312
  functions. The 2020 and later releases are a bundle of separate libraries and
  are not covered. Upstream left `aws_iot_version.h` at 3.0.1 for the 3.1.x
  releases, so the rule does not probe it.

CPE status is `unverified` for all five: NVD was unreachable.

The signature builder also changed: a file wrapped in `extern "C" { ... }` (the
whole AWS SDK is) used to yield no functions, because everything sat one brace
deep. That block is now transparent.

| copy | truth | reported | basis |
| --- | --- | --- | --- |
| wm_iot_sdk `wm_httpclient/http2/nghttp2` | 1.59.0 (`configure.ac`) | 1.59.0, patched | probe |
| wm_iot_sdk `websockets/libwebsockets` | 4.3.3 (CMake) | 4.3.3, patched | probe |
| wm_iot_sdk `mqtt/paho.mqtt.c` | 1.3.11 (`CLIENT_VERSION`) | 1.3.11, patched | probe |
| bl_iot_sdk `3rdparty/aws-iot/...` | 3.0.1 (CHANGELOG) | 3.0.1, patched | functions |
| bl_iot_sdk `network/thread/openthread` | commit of 8 July 2022 | 20221027 | functions (763 of 763) |
| bouffalo_sdk `wireless/thread/openthread` | API version 512 | `espressif/esp-idf/openthread` git-43cc05a9 | anchor |

**6 of 6 copies are found.** Bouffalo's OpenThread is reported by the Espressif
rule, which wins at 0.95 on a byte-identical `version.cpp`; the generic rule's
functions match tag 20250612 exactly (1,059 of 1,059), so the two rules disagree
on the name of the version, not on the project. WinnerMicro's AWS IoT Device SDK
is the 2024 bundle and is not found by this rule. WinnerMicro's and Bouffalo's
`wpa_supplicant` (2.10) is still reported by the Zephyr hostap rule with no
version: hostap's upstream (`w1.fi`) was not reachable, so no generic hostap rule
was written.

Real releases under a neutral name, scanned with the whole rule base ("stripped"
deletes the version-bearing file the rule probes or anchors on: `configure.ac`,
`CMakeLists.txt`, `src/MQTTClient.c`, `aws_iot_version.h`):

| library | trees | right component | exact | range containing truth | wrong |
| --- | --- | --- | --- | --- | --- |
| nghttp2 1.20.0, 1.40.0, 1.52.0, 1.59.0, 1.66.0, 1.70.0 | 6 pristine | 6 | 6 | 0 | 0 |
| the same, stripped | 6 | 6 | 2 | 4 | 0 |
| libwebsockets 3.0.1, 3.2.2, 4.0.21, 4.1.6, 4.3.3, 4.5.8 | 6 pristine | 6 | 5 | 0 | 1 |
| the same, stripped | 6 | 6 | 1 | 5 | 0 |
| Paho MQTT C 1.1.0, 1.3.1, 1.3.11, 1.3.14, 1.3.16 | 5 pristine | 5 | 5 | 0 | 0 |
| the same, stripped | 5 | 4 | 3 | 1 | 0 |
| OpenThread 20191113, 20221027, 20230119, 20250612, v2026.09.0 | 5 pristine | 5 | 4 | 1 | 0 |
| AWS IoT Device SDK 2.0.0, 2.2.1, 3.0.1, 3.1.0, 3.1.5 | 5 pristine | 5 | 3 | 2 | 0 |
| the same, stripped | 5 | 5 | 3 | 2 | 0 |

**27 of 27 pristine trees are the right component, 23 exact, 3 ranges, 1 wrong; of
22 stripped trees, 21 are found, 9 exact and 12 ranges that contain the truth,
and Paho 1.1.0 is not found.** The one wrong
answer is libwebsockets v4.0.21, whose `CMakeLists.txt` at that tag already says
4.0.22 (upstream bumped it before tagging). The ranges are releases whose
functions are identical to a neighbour's.

## 1h. Chinese RTOS kernels: AliOS Things (Rhino)

`generic/alios-things-kernel`: 16 releases, 1.1.0 to 3.3.0, 905 functions, 27 KB.
Upstream tagged 1.1.0 to 2.1.0 (`aos1.1.0`, `aos1.1.1`, `v1.1.2` to `v1.3.4`,
`v2.0.0`, `v2.1.0`); the 3.x line exists only as branches (`rel_3.0.0`,
`rel_3.1.0`, `rel_3.3.0`), pinned by tip commit. The kernel moved twice
(`kernel/rhino/core`, then `kernel/rhino`, with `core/rhino` on `rel_3.1.0`), and
the signature covers all three. Markers are four sources: `k_task.c`, `k_sys.c`,
`k_mutex.c`, `k_event.c`.

There is no version probe. `RHINO_VERSION` reads 12000 from 1.x to 3.3.0, and
the release string (`SYSINFO_KERNEL_VERSION "AOS-R-x.y.z"`) sits outside the
kernel directory (`rhino.mk`, `include/aos/kernel.h`).

Real copies: **none found.** The public vendor SDKs I could check (Bouffalo,
WinnerMicro, WCH, the OpenHarmony hisilicon repositories) carry no Rhino copy,
and AliOS Things' own tree holds exactly one `k_task.c` per release. The only
evidence is therefore upstream releases, not vendor copies. Every release under
a neutral name, scanned with the whole rule base:

| trees | right component | exact | range containing truth | wrong |
| --- | --- | --- | --- | --- |
| 16 pristine | 16 | 11 | 5 | 0 |

The five ranges are 1.3.0 to 1.3.4, reported as `1.3.0~1.3.4`: those releases
carry the same kernel code. 1.1.0 to 1.2.2, 2.0.0, 2.1.0 and the three 3.x
releases are exact.

Mutation robustness (2.1.0, same harness as section 2, signature alone):
**identified under 9 of 9, version correct 9 of 9.** Renaming 50% of identifiers
still leaves 0.882 containment at the abstract level (version `2.1.0~3.0.0`),
deleting 50% of files 0.598, the vendor-like combination 0.828.

Regression: no AliOS finding in FreeRTOS, RT-Thread, TencentOS-tiny or the WCH
example trees, and nothing else claims an AliOS tree (tests in
`tests/test_rtos_cn.py`).

NVD has no CPE for AliOS Things (the vendor `alibaba` holds fastjson, druid,
nacos, tengine, open_code_review and three others) and no CVE keyword hit; OSV
has no record for the repository. The rule says so in `cpe_status`.

## 1i. Chinese RTOS kernels: Huawei LiteOS (M, A and 5.x)

Three rules, because the three kernels are three trees:
* `generic/liteos-m-kernel`: OpenHarmony `kernel_liteos_m`, `kernel/src` and
  `kernel/include`. 48 releases, 1.0 and 1.1.0 to 7.0, 724 functions, 22 KB.
* `generic/liteos-a-kernel`: OpenHarmony `kernel_liteos_a`, `kernel/base`,
  `common`, `extended`, `include`. 48 releases, 1.0 to 7.0, 3,659 functions, 109 KB.
* `generic/liteos-kernel`: Huawei's own `LiteOS/LiteOS`, 5.x layout (`kernel/base`
  flat), v5.0.0 and v5.1.0, anchors, a winnowed signature and (added 2026-10-05) a
  function signature: 1,149 functions, 32 KB.

Releases are OpenHarmony tags (Release and LTS; Beta, Canary and weekly tags
left out), spelled the way upstream tags them, so `OpenHarmony-v3.2-Release` is
`3.2`. That is not cosmetic: `in_tag_set` compares normalised strings, so a
label of `3.2.0` is never found in an OSV tag list. Many patch releases share a
commit or carry identical kernel code (LiteOS-M 4.0 to 7.0 differ in four kernel
files, 263 inserted lines of which 257 are one new header, and none of the
changes alters a function the signature sees), and are reported as ranges. The
source is Gitee, the primary repository (`upstream.source`, pinned to the tag
`OpenHarmony-v6.0-Release`, the newest Gitee has). Gitee has no tag for 6.0.0.1,
6.0.0.2, 6.1 or 7.0, so those four versions of each rule come from the GitHub
mirror, listed under `upstream.mirrors`; that the mirror's organisation is the
project's own could not be verified here. The 60 tags Gitee has exist on the
mirror at identical commits. LiteOS 5.x comes from Gitee too (the GitHub mirror
has no 5.x tags and a stale master). Gitee drops connections now and then
through the build proxy (about half of the `git ls-remote` and tag fetches in
the session that made this change needed a retry), so `gangmu rules verify`
retries its fetch.

Real copies. WCH's three SDKs carry LiteOS-M; no other public vendor SDK I
could check did (the HiSilicon, Allwinner, Rockchip and Goodix OpenHarmony
device repositories contain no `los_task.c`; a full Hi3861 tree was not
available to scan):

| copy | truth | reported | containment |
| --- | --- | --- | --- |
| ch583 `kernel_liteos_m/kernel` | 3.2.3 (WCH's readme: "OpenHarmony-3.2.3-Release") | 3.2~3.2.4, by functions | 1.000, unpatched (211 of 211 functions) |
| ch32v307 `LiteOS_m/LiteOS/kernel` | not stated | 3.0~3.0.3, patched | 0.689 (126 of 183; 252 functions here) |
| ch32v20x `LiteOS_m/LiteOS/kernel` | not stated | 3.0~3.0.3, patched | 0.689 |

Every release under a neutral name, scanned with the whole rule base:

| trees | right component | exact | range containing truth | wrong | not found |
| --- | --- | --- | --- | --- | --- |
| LiteOS-M, 48 | 48 | 2 | 46 | 0 | 0 |
| LiteOS-A, 48 | 48 | 2 | 46 | 0 | 0 |
| LiteOS 5.x, 2 + 2 with `base/los_task.c` edited | 4 | 4 | 0 | 0 | 0 |

The LiteOS-M and LiteOS-A rows are the function signature read back through
the version inference (each recorded release's own function set, with no scan of
a tree), rebuilt on 2026-10-04 with the current extractor. They were measured by
scanning the trees before that; the LiteOS-A result is the same (2 exact, 46
ranges). LiteOS-M 1.1.0 to 1.1.5 used to be the known gap: **every source file
of those releases, and of LiteOS 5.x, wraps its whole body in `extern "C" {`**,
and the extractor of the time looked at brace depth zero and saw nothing. `main`
since made the `extern "C"` block transparent (see 1g), and the signatures were
rebuilt with it: LiteOS-M 1.1.x now yields functions and is covered (347 to 724
functions; every function of the old file is still in the new one, for every
version both have). LiteOS 5.x yielded about 60 functions for the whole
kernel under the old extractor, so its rule had no function signature and used
only the winnowed sketch of v5.1.0 plus exact hashes of five kernel files (all
differ between the releases; verified by the pipeline for v5.1.0, computed from
the v5.0.0 tag for 5.0.0). With the current extractor it yields 891 and 920
functions and the rule now has a function signature too (below).
The mutation table below was re-run on 2026-10-04 with the rebuilt signatures
(trees: the 3.2 release of each repository from Gitee, `kernel/` without `arch/`
and test directories, as the rules select them; the previous signatures
reproduce the previous numbers on these trees to within 0.006, so the change is the signature's,
not the trees'). The real-copy table above was re-scanned the same day (`gangmu scan` of
the current default branch of each WCH repository, whole rule base): the ch583
result is unchanged and the two patched copies still read 3.0~3.0.3, patched;
their containment rose from 0.677 to 0.689 because the rebuilt signature sees
more functions of 3.0 (183 instead of 133). The LiteOS 5.x rows were re-measured on 2026-10-05: v5.0.0
and v5.1.0 from Gitee (`LiteOS/LiteOS` tags, `kernel/` under a neutral name),
each also with a line appended to `base/los_task.c`, scanned with the whole rule
base. All four are claimed by `generic/liteos-kernel` and none by another rule,
and all four read the right version (4 of 4 exact, 0 wrong, 0 not found; the
table row is unchanged).

The 5.x function signature was then built (`gangmu rules functions
https://gitee.com/LiteOS/LiteOS --tag v5.0.0 --tag v5.1.0 --subdir kernel`, 1,149
functions, 487 of them version-discriminating) and the same scans repeated,
plus a copy of each release with a line appended to **all five** files the hash
anchors cover. Every tree is now also matched at function level (674 of 674
functions of 5.0.0 in the 5.0.0 trees, 689 of 689 of 5.1.0 in the 5.1.0 trees,
discriminating functions agreeing 1.00). The all-five-files copies have no
anchor hash left and are still read as 5.0.0 and 5.1.0, at confidence 0.88; before
the function signature a copy like that was identified but its version unknown.
Appending a declaration changes no function, so none is flagged patched. The
unmodified 5.0.0 still reads 0.781 against the 5.1.0 sketch, and the earlier
caveat stands: the sketch is measured against 5.1.0 only, so a 5.0.0 copy
edited in one file is not flagged patched.

LiteOS 5.x under the mutation harness (5.1.0 tree, `gangmu eval --mutate`, the
function signature alone; the other tiers are not part of this harness):
rename 10% / 25% / 50% of identifiers (abstract) 0.970 / 0.773 / 0.000, delete
20% / 50% of files 0.863 / 0.620, vendor-like 0.702; identified and the version
right under 8 of 9 mutations. The miss is the 50% rename, where no function
hash survives (the winnowed sketch is the tier meant for that). Only two
versions are recorded, so "version right" is a weaker claim here than for
LiteOS-M and LiteOS-A.

Mutation robustness (3.2, same harness as section 2, signature alone):

| | LiteOS-M | LiteOS-A |
| --- | --- | --- |
| rename 10% / 25% / 50% of identifiers (abstract) | 0.859 / 0.802 / 0.797 | 0.978 / 0.909 / 0.229 |
| delete 20% / 50% of files | 0.968 / 0.345 | 0.796 / 0.572 |
| vendor-like | 0.915 | 0.659 |
| identified, version contains truth | 9/9, 9/9 | 9/9, 9/9 |

No version probe exists for any of them. LiteOS-A has `KERNEL_MAJOR/MINOR/PATCH/ITRE`
in `los_config.h`, but it reads 2.0.0.37 in every release from 1.1.5 to 7.0;
LiteOS-M states no version; LiteOS 5.x's `HW_LITEOS_VERSION` is empty in v5.0.0.

Regression: LiteOS-A, LiteOS-M and LiteOS 5.x trees are never claimed by one
another's rule or by FreeRTOS, RT-Thread, TencentOS-tiny or AliOS Things, and
vice versa (marker tests in `tests/test_rtos_cn.py`). One behaviour changes in
full OpenHarmony trees: a `kernel_liteos_a` or `kernel_liteos_m` repository
carries a `bundle.json` at its root, which the declared-ecosystem reader reports
as `liteos_a` / `liteos_m` (it reads 3.1.0 at the v3.2 tag), and the
new rule now also reports the kernel under `kernel/` (`3.2~3.2.4`). The two
are in different directories, so they are not merged and the version conflict is
not flagged. The declared finding itself is unchanged.

CPE: NVD has no CPE for LiteOS (dictionary: `huawei:liteos`, `liteos_a`,
`liteos_m`, `liteos_iot`, keyword `liteos`) and no CVE keyword hit for LiteOS,
Huawei LiteOS or LiteOS-M. Three CVEs name `kernel_liteos_a` (CVE-2022-41802,
CVE-2022-43662, CVE-2022-45126, OpenHarmony's 2022-12 disclosure, all kernel
stack disclosures through clock syscalls), filed under the OS-wide
`o:openatom:openharmony` (lts 1.1.0 to 1.1.5, 3.0 to 3.0.6) and
`a:openharmony:openharmony` (3.1.0 to 3.1.4). Those CPEs have 156 CVEs across
every subsystem; a kernel copy cannot be scoped to its three, so no CPE is set
and `cpe_status` names them. OSV has no record for any of the repositories. The
tag styles `OpenHarmony-v3.1.4-Release`, `OpenHarmony-v3.2-Release`,
`OpenHarmony-v6.0.0.1-Release` and `v5.1.0` normalise to the labels used
(tested); the thirteen `LiteOSV200R001C50B0xx` build tags normalise to the
number 200 and are not covered.

## 1j. Chinese RTOS kernels: SylixOS, why there is no rule

SylixOS (ACOINFO, 翼辉) was checked and **no rule was written**. This section
records what was found so the next person does not repeat the search.

* **An open release exists, and it is one.** `https://www.sylixos.com/download/sylixos-base-v183.zip`
  (57,107,460 bytes, 10,439 files, `Last-Modified` 2021-09-27, sha256
  `635daa28be9c6c675cfe30e8e3d4ff7b8af4abc5bd359680df81582ee2f79d3e`) contains
  `libsylixos/SylixOS`, the kernel, with `__SYLIXOS_VERSTR "1.8.3"` in
  `kernel/include/k_kernel.h`, plus bundled third-party code (OpenSSL, lwIP,
  Lua, SQLite, tcpdump, and others). Its `license/LICENSE` says the open-source
  edition is GPLv3 with BSD for the bundled code. The download link on the
  vendor's page is commented out of the HTML; the file is still served. Ten
  neighbouring names (`v180`, `v181`, `v182`, `v184`, `v185`, `v190`, `v200` and three
  spelling variants) return HTTP 500, so there is no second release to compare it with.
* **A signature built from one release cannot identify a version.** The point of
  the multi-version function signature is the version range (docs/ALGORITHMS.md);
  with one release every copy of any SylixOS version would report 1.8.3, and
  that is the confident wrong answer the rule base exists to avoid.
* **CI cannot re-derive it.** `gangmu rules verify` supports `source.kind: git`
  only (`tarball` parses but is refused), CONTRIBUTING.md requires a pinned tag
  or commit, and the archive has neither. A sha256-pinned archive would need
  tool support first.
* **No git source was found.** `github.com/SylixOS/sylixos` exists but is
  unrelated: a README of one sentence, one branch, no tags, and Estuary
  (an ARM server distribution) install scripts whose manifest points at
  `github.com/open-estuary`. `git.sylixos.com`, the vendor page's "Docs" link,
  is not a git host. Plain `http://git.sylixos.com/` is reachable from the build
  environment and answers `301` with `Location: https://docs.acoinfo.com/sylixos/about.html`
  for every path tried (`/`, `/explore`, `/users/sign_in`, `/sylixos`, `/gitweb`,
  `/cgit`, `/api/v4/projects`, and a git smart-HTTP
  `/sylixos/libsylixos.git/info/refs?service=git-upload-pack`; the query string
  is carried over, the path is not). HTTPS on that host answers `301` back to the
  `http://` root. The target, `docs.acoinfo.com/sylixos/`, is the vendor's
  documentation site (a 319 KB table-of-contents page: introduction, RealEvo-IDE,
  getting started); its text has no mention of git, source or download links, and
  no repository URL. `wiki.sylixos.com` redirects to the same site, and
  `www.acoinfo.com` dropped the tunnel on repeated requests. So no tags, branches
  or release history were found on the vendor's hosts, and a rule is **not
  feasible** now: the bar is several releases pinned by tag or commit that
  `gangmu rules verify` can fetch with git, and the only pinned thing is a single
  unlinked zip. Not checked: a git service on another hostname, and Gitee or other mirrors, which were not searched. If a git remote
  turns up, the kernel is at
  `libsylixos/SylixOS`, the version macro is `__SYLIXOS_VERSTR` in
  `kernel/include/k_kernel.h`, and the sources are GBK-encoded, which the
  tokenizer has not been tested against.
* **No vulnerability data.** NVD has no CPE and no CVE for `sylixos`, `sylix os` or
  `acoinfo`; OSV has no record for 1.8.3.

## 1k–1m. Vendor firmware libraries

Measurements of chip-vendor firmware-library rules (Nations Technologies, HDSC, Rockchip and others) are part of the commercial rule packs and are not published here.

## 1n. Allwinner SDKs: third-party libraries nothing recognised

Surveying two public Allwinner RTOS trees (`bhgv/Allwinner-R128S2-SDK-09`, `DongshanPI/D1s-Melis`; neither has a licence file or tags, so neither is a rule source and none of their source is committed) showed that the generic rules already found LVGL, Mbed TLS, FreeRTOS, TinyCrypt, littlefs, lwIP, FatFs and RT-Thread, while FreeType, Opus, libjpeg-turbo, giflib and OpenAMP were not recognised. Five generic rules were added for them (function level, version sidecars rebuilt from the upstream tags).

| rule | covers | source | licence | CPE |
| --- | --- | --- | --- | --- |
| `generic/freetype` | 48 releases, 2.4.0 to 2.14.3 | github.com/freetype/freetype | FTL or GPL-2.0+ | `freetype:freetype`, evidence CVE-2012-5668, -5669, -5670, CVE-2014-2240 |
| `generic/libjpeg-turbo` | 30 releases, 1.3.0 to 3.0.4 | github.com/libjpeg-turbo/libjpeg-turbo | BSD-3-Clause, IJG, Zlib | `libjpeg-turbo:libjpeg-turbo`, CVE-2017-15232, CVE-2018-1152, -14498, -19664 |
| `generic/giflib` | 26 releases, 4.1.4 to 6.1.3 | git.code.sf.net/p/giflib/code (SourceForge; GitHub copies are mirrors) | MIT | `giflib_project:giflib`, CVE-2016-3177, -3977, CVE-2020-23922, CVE-2021-40633 |
| `generic/opus` | 20 releases, v1.0.0 to v1.6.1 | github.com/xiph/opus | BSD-3-Clause | `opus-codec:opus`, CVE-2013-0899 |
| `generic/open-amp` | 14 releases, v2020.10.0 to v2026.04.0 | github.com/OpenAMP/open-amp | BSD-3-Clause | none: not in NVD |

| copy | truth | reported | basis |
| --- | --- | --- | --- |
| R128 `thirdparty/freetype` | 2.13.0 (`FREETYPE_MAJOR/MINOR/PATCH`) | 2.13.0, patched | `freetype.h` hash |
| R128 `thirdparty/giflib/giflib-5.2.1` | 5.2.1 (directory name) | 5.2.1 | `NEWS` hash |
| R128 `thirdparty/opus` | not written in the tree | 1.3.1, patched | `configure.ac` matches the 1.3.1 file byte for byte |
| R128 `thirdparty/libjpeg-turbo` | 2.1.5.1 (`jconfig.h`, tarball name) | **not found** | the tree holds headers and an unextracted tarball, no `.c` files |
| R128 and Melis OpenAMP (sunxi-adapted) | not written | 2021.10.0, 0.92 | 135 of 166 and 136 of 166 abstracted functions |

FreeType and giflib are exact against the vendor's own statement; Opus and OpenAMP are identified but their versions cannot be checked against anything the vendor wrote. libjpeg-turbo in R128 is not found (headers and an unextracted tarball only), and 3.1.0 and later are not covered. No CVE-based matching was run against these versions.

## 2. Robustness to vendor modification

The methodology the CENTRIS and V1SCAN papers use, applied to this tool. A
pristine lwIP 2.2.0 tree is mutated at a controlled rate, seeded so the run
reproduces. "exact" is the containment of exact function bodies; "abstract" is
the same with identifiers collapsed; the tool uses the better of the two and
scores an abstract-only match lower.

| mutation | exact | abstract | used | identified | version |
| --- | --- | --- | --- | --- | --- |
| pristine | 1.000 | 1.000 | 1.000 | yes | 2.2.0 |
| reformat (CRLF, tabs) | 0.997 | 0.997 | 0.997 | yes | 2.2.0 |
| rename 10% of identifiers | 0.480 | **0.876** | 0.876 | yes | 2.2.0~2.2.1 |
| rename 25% | 0.187 | **0.734** | 0.734 | yes | 2.2.0~2.2.1 |
| rename 50% | 0.058 | **0.636** | 0.636 | yes | 2.2.0~2.2.1 |
| delete 20% of files | 0.848 | 0.847 | 0.848 | yes | 2.2.0 |
| delete 50% of files | 0.507 | 0.501 | 0.507 | yes | 2.2.0 |
| add 30% vendor code | 1.000 | 1.000 | 1.000 | yes | 2.2.0 |
| **vendor-like**: rename 15%, delete 25%, add 20%, reformat | 0.211 | **0.590** | 0.590 | yes | 2.2.0~2.2.1 |

**Identified under 9/9 mutations; version correct 9/9.**

Three things are worth reading off that table:

* **Adding vendor code costs nothing** (1.000). Containment asks how much of
  upstream is present, not how similar the trees are — which is why a 4,000-
  function library inside a 200,000-function firmware is still found.
* **Deleting half the files still identifies** (0.507). A port layer that keeps
  only the drivers it needs does not become unrecognisable.
* **Renaming is what exact hashing cannot survive**, and the second abstraction
  level is what fixes it: 0.480 → 0.876 at a 10% rename rate. Without it the
  realistic vendor-like combination falls to 0.211 and would be reported as a
  weak, review-needed match rather than a confident one.

## 3. SBOM quality against the published standards

Scored by `gangmu sbom-score`, which implements the NTIA 2021 minimum elements
and the CISA 2026 update, and is deliberately comparable to Interlynk's
`sbomqs`. Stricter in one respect: a placeholder such as `NOASSERTION` counts as
absent, because an SBOM full of them passes a field-presence check while telling
a reader nothing.

| standard | score |
| --- | --- |
| NTIA 2021 minimum elements | **10.0 / 10** |
| CISA 2026 minimum elements | **10.0 / 10** |

The 2026 additions are the interesting ones. *Component Hash* is satisfied by the
digest of the directory's `(path, file digest)` pairs — a vendored source tree
has no package archive to hash, and this is the honest equivalent, reproducible
by re-running the scan. *SBOM Generation Context* records whether the document
came from a real build or from the source tree alone, which is exactly the
distinction that decides whether it over-reports.

## 4. Speed

296-file tree, two cores.

| pass | what it does | cost |
| --- | --- | --- |
| 1 | walk, sha256 each file, fold into one fileset digest | 0.04 s |
| 2a | tokenise + extract functions | 0.28 s |
| 2b | tokenise + winnow k-grams (fallback path only) | 0.59 s |

Pass 2 is lazy: a vendored copy byte-identical to the release a rule records
never reaches it. Whole-SDK numbers (ESP-IDF 5.4.2 in 11 s single-process,
2.1 s warm), the rule-count curve and the CI regression check are in
[PERFORMANCE.md](PERFORMANCE.md).

## 4b. OSV GIT ranges against real records

`gangmu vuln` matches OSV records that carry `ranges[type=GIT]` and the affected
tags in `versions` (the shape OSV's CVE import and OSS-Fuzz produce for C
projects). The first tests used records written from the schema; this section
is the check against the real ones, read on 2026-10-04 from `api.osv.dev` and
from OSV's GIT-ecosystem dump
(`osv-vulnerabilities.storage.googleapis.com/GIT/all.zip`, 111,561 records,
131,003 GIT ranges). Nothing from it is committed except five trimmed records
under `tests/fixtures/osv-real/` (libwebsockets CVE-2025-1866, libcoap
CVE-2025-59391 and CVE-2025-34468, nghttp2 CVE-2023-44487, OpenThread
OSV-2020-1292), used by `tests/test_osv_real.py`.

**What the real shapes are**

* CVE-imported records (`CVE-*`) have **no `package`**, a GIT range whose events
  are commit hashes (`introduced: 0`, `fixed: <sha>`), and the affected release
  tags in `versions`. This is the shape #11 assumed, and it is the common one:
  75,297 of the 83,364 GIT ranges on a GitHub, GitLab or Bitbucket repository
  list tags.
* OSS-Fuzz records (`OSV-*`) carry `package.purl = pkg:generic/<name>` (never
  `pkg:github/...`), a GIT range, and in most cases **no tags** (`versions` is
  empty). They address a project by commit only.
* Repository URLs, over all 131,003 ranges: plain, trailing `.git` (32,209),
  trailing `/` (16,104), capitalised such as `GmSSL` (2,082).
  `purl_from_repo` handled every `github.com` URL in the dump (0 misses). It
  returns `None` for hosts that have no purl type (git.kernel.org 44,826
  ranges, gitlab.gnome.org, sourceware.org, git.ffmpeg.org ...); those are out
  of reach by design.
* `database_specific.extracted_events` (OSV's own reading of the CVE's CPE
  ranges into version bounds) is present on 74,037 of the GitHub-style ranges.
  On 4,690 of them there are no tags but the bounds are plain versions.
* Tag spellings seen: `v1.56.0`, `4.3.1` and `v4.3.1` side by side, `v4.3.5a`
  (libcoap letter releases), `4.3.5-NA`, `release-0.2`, `v4.2-rc1`,
  `zephyr-v3.0.0`, `jetty-9.4.42.v20210604`, and non-releases: libwebsockets
  lists `v1.6.0-chrome48-firefox42`, `master-test-2015-11-19-1`,
  `support-chrome-20-firefox-12`, `support-protocol-v7`.

**What the records say about the projects in the rule base.** OSV has no
record, by purl, by repository, or anywhere in the dump, for GmSSL, Tongsuo,
LVGL or `littlefs-project/littlefs` (the only littlefs hits are NanaZip's
parser, `m2team/nanazip`), nor for any `zephyrproject-rtos/hal_*`. For those the
"match by purl via OSV" in the rule notes finds nothing today; the CPE channel
(or the vendor's own bulletins) is the only route, and for GmSSL there is none
(see its `cpe_status`). Records do exist for nghttp2 (8, all CVE), libcoap
(26: 15 CVE, 11 OSS-Fuzz), libwebsockets (4), OpenThread (53, all OSS-Fuzz, two
of them list tags), `eclipse-paho/paho.mqtt.embedded-c` (CVE-2021-41036) and the
Zephyr main repository.

**Matching hand-built SBOMs against those records** (`gangmu vuln` on a
CycloneDX document, compared with what the record says):

| component | record | state | agrees with the record |
|---|---|---|---|
| libwebsockets 4.3.3 | CVE-2025-1866, tags to v4.3.3, fixed | exploitable | yes |
| libwebsockets 4.3.2-vendor | same | exploitable | yes (suffix ignored) |
| libwebsockets 4.3.4, 4.5.1 | same | not affected | yes after fix 1 below (before: in triage) |
| nghttp2 1.56.0 / 1.57.0 | CVE-2023-44487, tags to v1.56.0, fixed 1.57.0 | exploitable / not affected | yes |
| nghttp2 1.55.1 | same, release not listed though inside the span | in triage | by design: the record does not say |
| libcoap 4.3.4a | CVE-2024-0962, tags `4.3.4`, `v4.3.4a` | exploitable | yes |
| libcoap 4.3.4 | CVE-2025-59391, listed | exploitable | yes |
| libcoap 4.3.5b | CVE-2026-29013, fixed 4.3.5b | not affected | yes |
| libcoap 4.3.4 / 4.3.5b | CVE-2025-34468, no tags, bounds <= 4.3.5 | exploitable / not affected | yes after fix 2 below (before: in triage) |
| OpenThread `git-2867f6883a12` or a release | OSV-2020-1292, commits only | in triage | undecidable from a version; the detail now says so |

**Defects found and fixed.**

1. *Junk tags stretch the span.* `normalize_tag` read `master-test-2015-11-19-1`
   as release `2015` and `support-protocol-v7` as `7`. Both set the end of the
   span of listed tags, so a release past the fix (libwebsockets 4.3.4) was
   "inside the span, unlisted" and went to triage instead of not-affected.
   Browser-compat and dated tags now have no normal form, and a bare integer
   never bounds the span when the list holds dotted releases. The LiteOS
   `LiteOSV200R001C50B039` build ids lose their old normal form `200` for the
   same reason.
2. *Tagless ranges with version bounds were always triage.* When a GIT range
   lists no tags and OSV's `extracted_events` hold plain version bounds, those
   are now used (`in_event_ranges`); a bound that is not a bare version
   (`<4.3.4`, a branch name) still leaves the answer open.
3. *`vuln-fetch` could not fetch these records.* OSV answers a `pkg:github/o/r`
   purl query with nothing, always (nghttp2: purl query 0 records; the same
   repository as `{"package": {"name": <repo url>, "ecosystem": "GIT"}}` 7).
   `fetch_osv` now also queries the GIT ecosystem for every
   `pkg:github|gitlab|bitbucket` purl. The URL is lower-cased, because the purl
   lost the capitalisation and OSV matches the URL exactly, so a repository
   registered as `.../GmSSL` is missed by this query. No record of this rule
   base is affected, but it is a limit.
4. A commit-only range now says it is commit-only, instead of "version cannot
   be ordered".

**What does not hold, and is not fixed.** A version inside the listed span but
absent from the list stays "in triage" (nghttp2 1.55.1 above): OSV derives the
list from the commit graph, so an unlisted release may be a gap or a branch. A
commit-pinned component (`git-<sha>`), and every OSS-Fuzz record, cannot be
placed by a version: all 53 OpenThread records are reported in triage whatever
the version, and resolving them needs the project's git history, which the SBOM
does not have. The 3,376 GIT ranges with neither tags nor extracted bounds (4%)
are of this kind. Records whose repository is on kernel.org, sourceware, GNOME
and similar hosts are not matched at all. `limit` events occur only on
kernel.org ranges in the dump and are not read.

## What these numbers do not show

* A dozen-odd component families (lwIP, FreeRTOS, RT-Thread, TencentOS-tiny,
  GmSSL, Tongsuo, OpenSSL, Mbed TLS, FatFs, littlefs, LVGL, libcoap, TinyCrypt,
  nghttp2, libwebsockets, Paho MQTT C, OpenThread, AWS IoT Device SDK) measured on
  a few hundred trees and copies, not a corpus of thousands. CENTRIS evaluated against 10,241 projects.
  The methodology is theirs; the scale is not.
* The mutation model is synthetic. Real vendor forks differ in ways a seeded
  mutator does not reproduce — which is why the Espressif fork is measured
  separately, as a real tree with known provenance.
* No comparison against another tool on the same input. The honest reason is
  that no other open tool identifies vendored C/C++ components at version
  granularity, so there is nothing to put in the other column yet.
* The domestic vulnerability databases were not checked for any of the Chinese
  RTOS rules: TencentOS-tiny (1f), AliOS Things (1h) and the three Huawei LiteOS
  rules (1i), nor for SylixOS (1j), which has no rule. The NVD and OSV statements
  in those sections hold; CNNVD and CNVD are an open gap for all four. On
  2026-10-04 `www.cnnvd.org.cn` answered, but its search API
  (`/cnnvdweb/homePage/searchVul`, `/cnnvdweb/vulnerability/queryLds`) rejected
  anonymous calls (`非法访问` / 401 `未登录`), and the browser route failed because
  the proxy CA is not trusted in Chromium. `www.cnvd.org.cn` returned 521 behind
  a JavaScript cookie challenge, then a connection reset. Neither was a
  network-policy block, and neither was worked around. So "no CNNVD/CNVD record" is **not**
  established for these products, and no CNNVD/CNVD id was compared against
  the version spellings the rules use. A manual search with a normal browser
  (TencentOS, AliOS, LiteOS, SylixOS, 翼辉, kernel_liteos) is the way to
  close it.
