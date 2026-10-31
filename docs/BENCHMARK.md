# Benchmark

> Version-identification accuracy on real upstream releases and vendor SDKs is run by [gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench); the rules these numbers depend on live in [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules). Every number on this page was measured with the current code (gangmu 0.15.0 plus this branch's engine changes, free rule base 2026.10.29, measured 2026-10-31) and can be re-run. Older measurements are not kept here; the CHANGELOG says what changed between releases.

## Why these numbers and not someone else's

The cross-tool SBOM benchmarks that exist — [sbomify's](https://github.com/sbomify/sbom-benchmarks),
and the quality scores behind [sbombenchmark.dev](https://github.com/interlynk-io/sbombenchmark.dev) —
cover Python, JavaScript, Java, Go, Rust and Docker. Every one of those
ecosystems has a lock file, and generating an SBOM for them is largely a matter
of reading it.

**None of them covers C/C++ or embedded.** The case where generation is actually
hard is the case nobody measures. So the numbers below are produced by
harnesses anyone can re-run, against real upstream releases and vendor SDKs
pinned by commit, with a fixed seed where anything is random.

```bash
# the whole source benchmark
git clone https://github.com/GANGMU-SBOM/gangmu-bench && cd gangmu-bench && python3 bench.py
# one rule against real trees and seeded mutations
gangmu eval --signature gangmu-rules/rules/generic/lwip.fnsig \
    --include 'src/**/*.c' --include 'src/**/*.h' \
    --tree /path/lwip-2.2.0=2.2.0 --tree /path/esp-lwip=2.2.0 \
    --mutate /path/lwip-2.2.0=2.2.0
# binaries
gangmu binary-eval --corpus /tmp/corpus
```

## 0. Precision, recall and version accuracy

What is counted:

| metric | definition |
| --- | --- |
| **recall** | expected components found by the right rule, whatever the version / expected components |
| **precision** | components reported that are really there / every component reported. "Every component" is the graded ones, plus every *other* code or binary finding in the tree: each was checked by hand and is either something the tree really carries (recorded in the case as `bundled:`) or a false positive. Dependencies a manifest in the tree declares are listed but not counted. |
| **version exact** | among found components whose true version is known: the reported version is exactly it |
| **version exact or range** | the same, counting a `low~high` range that contains the truth |

Truth is the release tag for an upstream tree, and for a vendor copy the version
the vendor wrote in its own files. A copy that states no version can only be
graded on the component ("identified").

### Source code

**gangmu-bench, 139 cases** ([results/latest.md](https://github.com/GANGMU-SBOM/gangmu-bench/blob/main/results/latest.md)):
upstream release trees pinned by tag or commit, put under a neutral directory
name, scanned pristine, with the version files deleted ("stripped") and with
every C file touched; vendor SDKs at pinned commits, every copy graded where it
sits; and two RISC-V firmware images.

| | recall | precision | version exact | version exact or range |
| --- | --- | --- | --- | --- |
| upstream release trees and images | 100.0% (207/207) | 100.0% (266/266) | 90.3% | 99.5% (of 207) |
| vendor SDK copies | 100.0% (57/57) | 100.0% (63/63) | 87.8% | 95.9% (of 49) |
| **all** | 100.0% (264/264) | 100.0% (329/329) | 89.8% | 98.8% (of 256) |

By section:

| section | graded | exact | range | identified | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 lwIP | 2 pristine | 2 | 0 | 0 | 0 | 0 | 0 |
| 1b FreeRTOS, RT-Thread | 1 pristine, 17 SDK copies | 15 | 2 | 1 | 0 | 0 | 0 |
| 1c GmSSL, Tongsuo, OpenSSL | 19 pristine, 19 stripped | 37 | 1 | 0 | 0 | 0 | 0 |
| 1d Mbed TLS, FatFs, littlefs | 2 firmware images, 18 pristine, 8 stripped, 8 touched, 18 SDK copies | 52 | 2 | 0 | 0 | 0 | 0 |
| 1e LVGL, libcoap, TinyCrypt | 14 pristine, 11 stripped, 7 SDK copies | 27 | 1 | 2 | 2 | 0 | 0 |
| 1f TencentOS-tiny | 13 pristine, 12 stripped, 2 SDK copies | 18 | 9 | 0 | 0 | 0 | 0 |
| 1g nghttp2, libwebsockets, Paho, OpenThread, AWS IoT | 37 pristine, 17 stripped, 5 SDK copies | 54 | 3 | 1 | 1 | 0 | 0 |
| 1h AliOS Things | 16 pristine | 13 | 3 | 0 | 0 | 0 | 0 |
| 1i LiteOS | 2 pristine, 2 touched, 3 SDK copies | 4 | 1 | 2 | 0 | 0 | 0 |
| 1n FreeType, giflib, Opus, libjpeg-turbo, OpenAMP | 5 SDK copies | 2 | 1 | 2 | 0 | 0 | 0 |
| 1o open62541, hostap, SOEM, CANopenNode, zlib | 6 pristine | 6 | 0 | 0 | 0 | 0 | 0 |

Verdicts over the 264 graded rows: 230 exact, 23 range, 8 identified, 3 known, 0 wrong, 0 missing.
Besides the graded components the scans report 65 components the trees really carry (the most frequent: `generic/zlib` 13, `generic/lodepng` 12, `generic/unity` 12, `generic/llhttp` 11, `generic/mbedtls` 6, `generic/jsmn` 5), 48 dependencies a manifest declares, and **0 false positives**.

Not exact and not a range containing the truth, every one:
* libwebsockets-4.0.21 `pristine`: truth 4.0.21, reported 4.0.22 (known).
* sdk-bl_iot_sdk `components/network/ble/blestack/src/common/tinycrypt`: truth 0.2.7, reported 0.2.8 (known).
* sdk-bouffalo_sdk `components/wireless/bluetooth/blestack/src/common/tinycrypt`: truth 0.2.7, reported 0.2.8 (known).

**Self-scan census, 227 rules**: each sampled rule's pinned upstream release,
fetched and scanned with the whole rule base. **Recall 98.7%** (224 find
themselves, 216 of them at the pinned version). Of the 60 code or binary
findings of *other* components, 2 are false positives (`nanostack-libservice`
claimed by the mbed-cloud-client rule, which bundles it; an iOS
`SDL3.framework` claimed by the SDL_net rule), 2 are the same tree under a
sibling rule, and 56 are components really there: over the 284 components
reported, **precision 99.3%**. Five of the real ones carry a wrong version:
pf-ring's `libpcap-1.10.1` read as `1.10.3~1.10.4` and both `tcpdump-4.99.x`
as 4.99.5, CMSIS-Core(A) 1.1 headers in Mbed OS read as CMSIS 6, and
btrfs-progs' xxhash 0.8.1 as 0.8.2.

### Prebuilt binaries

The full method and tables are in [BINARY-VALIDATION.md](BINARY-VALIDATION.md).
Cross-compiled corpus (`gangmu binary-eval`: 14 libraries, 15 builds, their
releases, 4 optimisation levels, stripped; references from one build identify
the images of every build; negative controls match every library's
fingerprints against every other library's images):

| reference → images | recall | precision | version exact | exact or range containing truth | negative-control hits |
| --- | --- | --- | --- | --- | --- |
| Cortex-M3 → Cortex-M3 | 78.2% | 95.0% | 43.3% | 99.3% | 28 / 9,776 |
| rv32imac → rv32imac | 76.6% | 99.8% | 37.6% | 99.2% | 1 / 9,776 |
| AArch64 → AArch64 | 81.2% | 100% | 42.5% | 96.7% | 0 / 11,200 |
| Xtensa → Xtensa | 72.3% | 100% | 46.5% | 99.6% | 0 / 9,118 |
| Cortex-M3 → rv32imac (strings only) | 35.8% | 100% | – | 98.4% | 0 / 9,776 |
| Cortex-M3 → AArch64 | 47.8% | 100% | – | 97.3% | 0 / 10,496 |
| Cortex-M3 → Xtensa | 55.3% | 98.4% | – | 95.9% | 6 / 9,440 |
| Xtensa → Cortex-M3 | 42.5% | 100% | – | 100% | 0 / 9,448 |

Inside real trees (the census above): 15 prebuilt files were identified (Lua
5.1.4 in premake4, libcurl 7.53.1 in premake5, zlib 1.3.1 and 1.2.3 in DLLs,
libogg, libopus 1.4, Mbed TLS in TF-M secure images), **all 15 real**; most
versions are coarse or absent.

**In short:** from source the tool almost never names a component that is not
there, finds nearly every one that is, and gives the exact version for most;
from binaries what it names is almost always right, but about a quarter of the
images on the same architecture get no answer and most get a range rather
than one version.

## 1. Version accuracy on real lwIP releases

The lwIP signature: 8 releases, 2.0.2 to 2.2.1, 3,195 functions. Each tree is a real checkout of a release tag
(`github.com/lwip-tcpip/lwip`, `STABLE-x_y_z_RELEASE`); `esp-lwip` is
Espressif's production fork, `github.com/espressif/esp-lwip` at `fc73c67`.

| tree | truth | reported | best match is the truth | containment |
| --- | --- | --- | --- | --- |
| upstream 2.0.3 | 2.0.3 | 2.0.3 | yes | 1.000 |
| upstream 2.1.0 | 2.1.0 | 2.1.0 | yes | 1.000 |
| upstream 2.1.2 | 2.1.2 | 2.1.2 | yes | 1.000 |
| upstream 2.1.3 | 2.1.3 | 2.1.3 | yes | 1.000 |
| upstream 2.2.0 | 2.2.0 | 2.2.0 | yes | 1.000 |
| **Espressif fork of 2.2.0** | 2.2.0 | 2.2.0~2.2.1 | yes | **0.943** |

**6/6: the five releases are reported as exactly their version, and the fork as a
range whose best match is 2.2.0.** A release is left out of the range when the
tree holds most of what the best one changed and none of what the other one
has instead, so releases a few functions apart are still told apart.

The fork is additionally reported as mixing releases: *"1230 are in 2.2.0, and 3
belong to other recorded versions -- this tree mixes releases, which is what a
vendor fork looks like (120 recorded function(s) of 2.2.0 are missing or altered)"*.
That sentence is the whole argument for function-level matching. A whole-tree
sketch scores the fork 0.949 and upstream 2.1.3 at 0.887, and cannot tell you which
is which.

## 1b. RTOS kernels inside Chinese vendor SDKs

* FreeRTOS-Kernel: 28 releases, 8.2.3 to 11.3.1, 1,195 functions.
* RT-Thread kernel: 27 releases, 3.0.0 to 5.3.0, 2,163 functions.

The test set is every copy of either kernel found in the vendor SDKs of the
benchmark (Bouffalo Lab `bouffalo_sdk` and `bl_iot_sdk`; WCH `ch32v307`,
`ch32v20x` and `ch583`; WinnerMicro `wm_iot_sdk`; Espressif
`ESP8266_RTOS_SDK`; the Allwinner R128 SDK). The truth for each copy is the
version string the vendor left in its own header (`tskKERNEL_VERSION_NUMBER`,
`RT_VERSION`/`RT_SUBVERSION`/`RT_REVISION`, or the kernel's file banner).

| SDK | copy | truth (vendor's own files) | reported | verdict |
| --- | --- | --- | --- | --- |
| allwinner-r128s2-sdk-09 | `lichee/dsp/kernel/FreeRTOS_xtensa_v1.7/FreeRTOS` | not stated | 10.2.0~10.2.1 | identified |
| allwinner-r128s2-sdk-09 | `lichee/rtos/kernel/FreeRTOS-orig/Source` | 10.4.3 | 10.4.3 | exact |
| allwinner-r128s2-sdk-09 | `lichee/rtos/kernel/FreeRTOS/Source` | 10.2.0 | 10.2.0 | exact |
| esp8266_rtos_sdk | `components/freertos/freertos` | 10.0.1 | 10.0.0~10.0.1 | range |
| bl_iot_sdk | `components/os/freertos_e907` | 10.4.1 | 10.4.1 | exact |
| bl_iot_sdk | `components/platform/soc/bl602/freertos_riscv` | 10.2.0 | 10.2.0 | exact |
| bl_iot_sdk | `components/platform/soc/bl602/freertos_riscv_ram` | 10.2.0 | 10.2.0 | exact |
| bl_iot_sdk | `components/platform/soc/bl702/bl702_freertos` | 10.2.0 | 10.2.0 | exact |
| bl_iot_sdk | `components/platform/soc/bl808/bl808_c906_freertos/Source` | 10.2.1 | 10.2.1 | exact |
| bouffalo_sdk | `components/os/freertos` | 10.6.2 | 10.6.2 | exact |
| ch32v20x | `EVT/EXAM/FreeRTOS/FreeRTOS_Core/FreeRTOS` | 10.4.6 | 10.4.6 | exact |
| ch32v20x | `EVT/EXAM/RT-Thread/rt-thread/rtthread` | 3.1.3 | 3.1.3 | exact |
| ch32v307 | `EVT/EXAM/FreeRTOS/FreeRTOS_Core/FreeRTOS` | 10.4.6 | 10.4.6 | exact |
| ch32v307 | `EVT/EXAM/RT-Thread/rt-thread/rtthread` | 3.1.3 | 3.1.3 | exact |
| ch583 | `EVT/EXAM/FreeRTOS/FreeRTOS` | 10.5.1 | 10.5.1 | exact |
| ch583 | `EVT/EXAM/RT-Thread/rt-thread` | 3.1.5 | 3.1.5 | exact |
| wm_iot_sdk | `components/freertos/src` | 10.4.1 | 10.4.0~10.4.1 | range |

Every copy is found. The ranges are releases that ship the same kernel code.
The Allwinner R128 SDK keeps two FreeRTOS kernels side by side
(`kernel/FreeRTOS/Source` 10.2.0 and `kernel/FreeRTOS-orig/Source` 10.4.3);
each is reported on its own, at its own version. Its DSP kernel states no
version and is graded on the component only.

The copies sit in directories a vendor renamed (`freertos_riscv`,
`bl702_freertos`), carry no LICENSE file, and the WCH ones are three levels
inside an example tree. The rules name marker files instead (`tasks.c` +
`queue.c` + `list.c`; `src/thread.c` + `src/ipc.c` + `include/rtthread.h`),
and discovery finds those wherever they are. Where a scan reports a range, the
releases in it ship the same kernel code (10.2.0 and 10.2.1 differ only in
ports); when the vendor kept the version header where upstream has it, the
probe narrows the range to the stated release.

Mutation robustness (`gangmu eval --mutate`, the same harness and seed as
section 2, signature alone):

| | FreeRTOS 11.1.0 | RT-Thread 5.2.0 |
| --- | --- | --- |
| rename 10% / 25% / 50% of identifiers (abstract) | 1.000 / 1.000 / 1.000 | 0.965 / 0.924 / 0.890 |
| delete 20% / 50% of files | 0.839 / 0.345 | 0.930 / 0.542 |
| vendor-like | 0.842 | 0.823 |
| identified, version right | 9/9, 9/9 | 9/9, 9/9 (`5.2.0~5.2.1`) |

## 1c. National-crypto libraries: GmSSL, BabaSSL/Tongsuo, and OpenSSL

* `generic/gmssl-2`: 20 releases, 2.0.0 to 2.5.4, 8,115 functions. A rule of its own, because the layout
  differs from 3.x (`crypto/sm3`, `crypto/sms4`, `include/openssl/*.h` against
  `src/` and `include/gmssl/`). Upstream never tagged 2.x; each version is
  pinned to the commit that first carries its `OPENSSL_VERSION_TEXT`.
* `generic/gmssl`: 4 releases, 3.0.0 to 3.2.0, 3,988 functions.
* Tongsuo: 9 releases, 8.1.3 to 8.5.0, 25,203 functions (8.1.3 to 8.3.3 are the BabaSSL-named releases).
* OpenSSL: 44 releases, 1.1.0 to 3.6.5, 28,592 functions, every 1.1.0 and 1.1.1 release next to the 3.x lines.

OpenSSL 1.1.x has to be in the rule base: both older generations are OpenSSL
1.1.x forks, and without it the functions they share with OpenSSL would make an
unmodified OpenSSL 1.1.1 look like Tongsuo 8.1.3. With it, those functions count
for none of them.

Real trees renamed to `vendored_lib`, scanned with the whole rule base.
"stripped" deletes the version-bearing headers (`opensslv.h`, `VERSION.dat`,
`version.h`), so only the function level decides.

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 19 pristine | 19 | 19 | 0 | 0 | 0 | 0 |
| 19 stripped | 19 | 18 | 1 | 0 | 0 | 0 |

Trees: gmssl-2.0.0, gmssl-2.3.3, gmssl-2.4.5, gmssl-2.5.0, gmssl-2.5.3, gmssl-2.5.4, gmssl-3.0.0, gmssl-3.2.0, openssl-1.1.0g, openssl-1.1.0l, openssl-1.1.1k, openssl-1.1.1w, openssl-3.0.22, openssl-3.5.9, tongsuo-8.1.3, tongsuo-8.2.1, tongsuo-8.3.3, tongsuo-8.4.0, tongsuo-8.5.0.
Ranges: gmssl-2.3.3 stripped → `2.3.3~2.3.4`.

No OpenSSL tree matches a fork and no fork matches OpenSSL. The GmSSL 2.x
function level is weaker than 3.x: most of its code is OpenSSL 1.1.0d, so few of
its functions discriminate between releases.

Mutation robustness, signature alone:

| tree | rename 10% | rename 50% | delete 50% of files | vendor-like | identified | version right |
| --- | --- | --- | --- | --- | --- | --- |
| GmSSL 2.5.4 | 0.988 | 0.966 | 0.477 | 0.730 | 9/9 | 9/9 |
| GmSSL 3.2.0 | 0.986 | 0.933 | 0.607 | 0.824 | 9/9 | 9/9 |
| Tongsuo 8.3.3 | 0.992 | 0.970 | 0.553 | 0.738 | 9/9 | 9/9 (deletions give `8.3.0~8.3.3`) |
| Tongsuo 8.5.0 | 0.989 | 0.961 | 0.510 | 0.751 | 9/9 | 9/9 |

The README's disguise example (`examples/disguise.sh`: GmSSL 3.0.0 renamed,
version header deleted, a third of the SM3/SM4 identifiers prefixed, vendor
functions added, eight files removed) reports GmSSL 3.0.0 at 0.88, 1296 of 1524
functions present (0.850).

## 1d. Third-party libraries inside Chinese vendor SDKs

* `generic/mbedtls`: 63 releases, 2.1.18 to 4.2.0, 12,316 functions. 4.x is covered for the TLS and X.509
  layer only; the cryptography moved to TF-PSA-Crypto in 4.0.
* `generic/fatfs`: 20 releases, 0.10a to 0.16, 305 functions.
* `generic/littlefs`: 38 releases, 1.7.2 to 2.11.3, 479 functions.

None has a path glob, only marker files (`library/ssl_tls.c` + `library/x509_crt.c`
+ `include/mbedtls/ssl.h`; `ff.c` + `ff.h` + `diskio.h`; `lfs.c` + `lfs.h` +
`lfs_util.h`), so they find a copy under any directory name. The Zephyr and
ESP-IDF rules for the same libraries still win at their own paths. Truth for a
copy is the version the vendor left in its own header (`MBEDTLS_VERSION_STRING`,
the `FatFs - Generic FAT Filesystem module R0.xx` banner, `LFS_VERSION`).

| SDK | copy | truth (vendor's own files) | reported | verdict |
| --- | --- | --- | --- | --- |
| allwinner-r128s2-sdk-09 | `lichee/rtos/components/thirdparty/elmfat/src` | 0.13c | 0.13c | exact |
| allwinner-r128s2-sdk-09 | `lichee/rtos/components/thirdparty/lfs/littlefs-2.2.1` | 2.2 | 2.2.1 | exact |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/network/mbedtls-2.16.0` | 2.16.0 | 2.16.0 | exact |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/network/mbedtls-2.7.0` | 2.7.0 | 2.7.0 | exact |
| d1s-melis | `ekernel/components/thirdparty/dfs/filesystems/elmfat` | 0.12b | 0.12b | exact |
| d1s-melis | `ekernel/components/thirdparty/dfs/filesystems/littlefs` | 2.1 | 2.1.3 | exact |
| d1s-melis | `ekernel/components/thirdparty/net/rt-thread/lwip/src/apps/mbedtls` | 2.7.0 | 2.7.0 | exact |
| esp8266_rtos_sdk | `components/fatfs/src` | 0.13c | 0.13c | exact |
| bl_iot_sdk | `components/network/thread/openthread/third_party/mbedtls/repo` | 2.28.0 | 2.28.0 | exact |
| bl_iot_sdk | `components/security/mbedtls_lts/mbedtls` | 2.28.1 | 2.28.1 | exact |
| bouffalo_sdk | `components/fs/fatfs` | 0.15 | 0.15 | exact |
| bouffalo_sdk | `components/fs/littlefs/littlefs` | 2.11 | 2.11.3 | exact |
| bouffalo_sdk | `components/crypto/mbedtls/mbedtls` | 2.28.2 | 2.28.2 | exact |
| bouffalo_sdk | `components/crypto/mbedtls/mbedtls_v3` | 3.6.5 | 3.6.5 | exact |
| ch32v307 | `EVT/EXAM/SDIO/SDIO_SD_FATFS/FATFS` | 0.14b | 0.14b | exact |
| wm_iot_sdk | `components/fatfs/src` | 0.15 | 0.15 | exact |
| wm_iot_sdk | `components/littlefs/src` | 2.10 | 2.10.2 | exact |
| wm_iot_sdk | `components/mbedtls/src` | 3.4.0 | 3.4.0 | exact |

Real releases under a neutral name ("stripped" deletes `version.h` /
`build_info.h`; "touched" appends a comment to every source file, which breaks
every byte-for-byte anchor), plus two RISC-V firmware images built from
upstream releases:

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 2 firmware images | 2 | 1 | 1 | 0 | 0 | 0 |
| 18 pristine | 18 | 18 | 0 | 0 | 0 | 0 |
| 8 stripped | 8 | 7 | 1 | 0 | 0 | 0 |
| 8 touched | 8 | 8 | 0 | 0 | 0 | 0 |

Trees: fatfs-0.10c, fatfs-0.12c, fatfs-0.13c, fatfs-0.14b, fatfs-0.15a, fatfs-0.16, littlefs-2.0.5, littlefs-2.11.3, littlefs-2.4.0-riscv32, littlefs-2.5.0, littlefs-2.9.1, mbedtls-2.16.12, mbedtls-2.28.10, mbedtls-2.7.19, mbedtls-3.1.0, mbedtls-3.4.0-riscv32, mbedtls-3.5.2, mbedtls-3.6.4, mbedtls-3.6.7, mbedtls-4.1.1.
Ranges: littlefs-2.4.0-riscv32 riscv32-O2 → `2.0.4~2.11.0`; mbedtls-4.1.1 stripped → `4.1.1~4.2.0`.

The ranges are releases whose function sets are identical (for example Mbed
TLS 4.1.1 and 4.2.0).

## 1e. LVGL, libcoap and TinyCrypt

* `generic/lvgl`: 54 releases, 6.0 to 9.6.0, 24,146 functions.
* `generic/libcoap`: 13 releases, 4.1.1 to 4.3.5b, 3,031 functions. Letter releases (4.3.4a, 4.3.5a, 4.3.5b)
  are pinned by commit; their tags would otherwise read as 4.3.4 and 4.3.5. The
  version is read from `configure.ac` as well as the ChangeLog, because some
  tags never bumped the ChangeLog.
* `generic/tinycrypt`: 7 releases, 0.1.0 to 0.2.8, 226 functions.

| SDK | copy | truth (vendor's own files) | reported | verdict |
| --- | --- | --- | --- | --- |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/littlevgl-8/lvgl` | 8.1.0 | 8.1.0 | exact |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/bluetooth/zephyr/src/tinycrypt` | not stated | 0.2.8 | identified |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/tinycrypt` | not stated | 0.2.8 | identified |
| bl_iot_sdk | `components/network/ble/blestack/src/common/tinycrypt` | 0.2.7 | 0.2.8 | known |
| bouffalo_sdk | `components/wireless/bluetooth/blestack/src/common/tinycrypt` | 0.2.7 | 0.2.8 | known |
| wm_iot_sdk | `components/coap/libcoap` | 4.3.4 | 4.3.4 | exact |
| wm_iot_sdk | `components/lvgl/lvgl` | 8.4.0 | 8.4.0 | exact |

The TinyCrypt copies are the case to read carefully: they state 0.2.7 (the
Zephyr fork's README names the exact upstream commit) but contain 0.2.8's
changed functions and none of the ones 0.2.7 had. They are 0.2.7 with 0.2.8's
fixes backported; "0.2.8" is the better answer for matching a CVE, though it is
not the version the vendor states, so the benchmark grades it as **known**: a
deliberate disagreement with the stated version, not counted as exact.

Real releases under a neutral name ("stripped" deletes `lvgl.h` /
`lv_version.h` or `ChangeLog`):

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 14 pristine | 14 | 14 | 0 | 0 | 0 | 0 |
| 11 stripped | 11 | 10 | 1 | 0 | 0 | 0 |

Trees: libcoap-4.1.2, libcoap-4.2.1, libcoap-4.3.0, libcoap-4.3.4, libcoap-4.3.5, lvgl-7.11.0, lvgl-8.3.11, lvgl-8.4.0, lvgl-9.2.2, lvgl-9.5.0, lvgl-9.6.0, tinycrypt-0.2.5, tinycrypt-0.2.7, tinycrypt-0.2.8.
Ranges: lvgl-9.2.2 stripped → `9.2.1~9.2.2`.

## 1f. Chinese RTOS kernels: TencentOS-tiny

`generic/tencentos-tiny-kernel`: 13 releases, 2.1.0 to 2.5.2, 432 functions. Upstream tagged
only three of them (v2.1.0, v2.4.5, v2.5.0); the others are pinned to the commit
that first carries their `TOS_VERSION` in `kernel/core/include/tos_version.h`.
The tag `v2.4.5` is mislabelled: its header says 2.4.3. Markers are four sources
in `kernel/core`, not the headers, so a renamed or flattened directory is found.
The only vendor SDKs found carrying it are WCH's `ch32v307` and `ch32v20x`.

| SDK | copy | truth (vendor's own files) | reported | verdict |
| --- | --- | --- | --- | --- |
| ch32v20x | `EVT/EXAM/TencentOS/TencentOS/TencentOS_Tiny/kernel/core` | 2.4.5 | 2.4.5 | exact |
| ch32v307 | `EVT/EXAM/TencentOS/TencentOS/TencentOS_Tiny/kernel/core` | 2.4.5 | 2.4.5 | exact |

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 13 pristine | 13 | 13 | 0 | 0 | 0 | 0 |
| 12 stripped | 12 | 3 | 9 | 0 | 0 | 0 |

Trees: tencentos-tiny-kernel-2.1.0, tencentos-tiny-kernel-2.2.0, tencentos-tiny-kernel-2.2.1, tencentos-tiny-kernel-2.3.1, tencentos-tiny-kernel-2.4.0, tencentos-tiny-kernel-2.4.1, tencentos-tiny-kernel-2.4.2, tencentos-tiny-kernel-2.4.3, tencentos-tiny-kernel-2.4.4, tencentos-tiny-kernel-2.4.5, tencentos-tiny-kernel-2.5.0, tencentos-tiny-kernel-2.5.1, tencentos-tiny-kernel-2.5.2.
Ranges: tencentos-tiny-kernel-2.2.0 stripped → `2.2.0~2.4.3`; tencentos-tiny-kernel-2.2.1 stripped → `2.2.0~2.4.3`; tencentos-tiny-kernel-2.3.1 stripped → `2.2.0~2.4.3`; tencentos-tiny-kernel-2.4.0 stripped → `2.2.0~2.4.3`; tencentos-tiny-kernel-2.4.1 stripped → `2.2.0~2.4.3`; tencentos-tiny-kernel-2.4.2 stripped → `2.2.0~2.4.3`; tencentos-tiny-kernel-2.4.3 stripped → `2.2.0~2.4.3`; tencentos-tiny-kernel-2.5.1 stripped → `2.5.1~2.5.2`; tencentos-tiny-kernel-2.5.2 stripped → `2.5.1~2.5.2`.

Stripped, 2.2.0 to 2.4.3 are reported as `2.2.0~2.4.3` and 2.5.1/2.5.2 as
`2.5.1~2.5.2`: those releases changed no function of `kernel/core` that the
signature discriminates on.

Mutation robustness (2.5.0, signature alone): identified under 9 of 9; renaming
10%, 25% or 50% of identifiers leaves 1.000 containment at the abstract level,
deleting 20% of files 0.801, 50% 0.285, the vendor-like combination 0.615. The
version is exact in 6 of 9; the three with files deleted give the range
`2.4.4~2.5.0`, which contains it.

NVD: the CPE `cpe:2.3:o:tencent:tencentos-tiny` exists, with a single record,
CVE-2021-27439, whose configuration names version **3.1.0**, which upstream has
never published (tags end at v2.5.0, the header at 2.5.2). The CPE is kept, but
it will not match any copy this rule versions. OSV has no record for the
repository.

## 1g. nghttp2, libwebsockets, Paho MQTT C, OpenThread and the AWS IoT Device SDK

* `generic/nghttp2`: 64 releases, 1.19.0 to 1.70.0, 1,308 functions.
* `generic/libwebsockets`: 63 releases, 3.0.0 to 4.5.8, 6,717 functions.
* `generic/paho-mqtt-c`: 23 releases, 1.0.1 to 1.3.16, 1,916 functions.
* `generic/openthread`: 11 releases (thread-reference 20191113 to 20250612 and
  v2026.06.0 to v2026.10.0), 15,474 functions. OpenThread has no version string,
  so the version always comes from the functions.
* `generic/aws-iot-device-sdk-c`: the v2 and v3 generation, 14 releases, 2.0.0 to 3.1.5, 312 functions.
  The 2020 and later releases are a bundle of separate libraries with rules of
  their own. Upstream left `aws_iot_version.h` at 3.0.1 for the 3.1.x releases,
  so the rule does not probe it.

| SDK | copy | truth (vendor's own files) | reported | verdict |
| --- | --- | --- | --- | --- |
| bl_iot_sdk | `components/3rdparty/aws-iot/aws-iot-device-sdk-embedded-C` | 3.0.1 | 3.0.1 | exact |
| bl_iot_sdk | `components/network/thread/openthread` | not stated | 20221027 | identified |
| wm_iot_sdk | `components/websockets/libwebsockets` | 4.3.3 | 4.3.3 | exact |
| wm_iot_sdk | `components/wm_httpclient/http2/nghttp2` | 1.59.0 | 1.59.0 | exact |
| wm_iot_sdk | `components/mqtt/paho.mqtt.c` | 1.3.11 | 1.3.11 | exact |

Real releases under a neutral name ("stripped" deletes the version-bearing file
the rule probes: `configure.ac`, `CMakeLists.txt`, `src/MQTTClient.c`):

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 37 pristine | 37 | 34 | 2 | 1 | 0 | 0 |
| 17 stripped | 17 | 16 | 1 | 0 | 0 | 0 |

Trees: aws-iot-device-sdk-c-2.0.0, aws-iot-device-sdk-c-2.2.1, aws-iot-device-sdk-c-3.0.1, aws-iot-device-sdk-c-3.1.0, aws-iot-device-sdk-c-3.1.5, libwebsockets-3.0.1, libwebsockets-3.2.2, libwebsockets-4.0.21, libwebsockets-4.1.4, libwebsockets-4.1.6, libwebsockets-4.3.3, libwebsockets-4.5.8, nghttp2-1.20.0, nghttp2-1.40.0, nghttp2-1.44.0, nghttp2-1.52.0, nghttp2-1.59.0, nghttp2-1.64.0, nghttp2-1.66.0, nghttp2-1.70.0, openthread-20191113, openthread-20200818, openthread-20221027, openthread-20230119, openthread-20230706, openthread-20250612, openthread-2026.06.0, openthread-2026.07.0, openthread-2026.08.0, openthread-2026.09.0, openthread-2026.10.0, paho-mqtt-c-1.1.0, paho-mqtt-c-1.3.1, paho-mqtt-c-1.3.11, paho-mqtt-c-1.3.14, paho-mqtt-c-1.3.16, paho-mqtt-c-1.3.5.
Ranges: nghttp2-1.52.0 stripped → `1.50.0~1.52.0`; aws-iot-device-sdk-c-3.1.0 pristine → `3.1.0~3.1.2`; aws-iot-device-sdk-c-3.1.5 pristine → `3.1.4~3.1.5`.

libwebsockets' `v4.0.21` tag already says 4.0.22 in its own `CMakeLists.txt`
(upstream bumped it before tagging), so 4.0.22 is what any tool reading the
tree should say; the benchmark grades it as **known**.

## 1h. Chinese RTOS kernels: AliOS Things (Rhino)

`generic/alios-things-kernel`: 16 releases, 1.1.0 to 3.3.0, 905 functions. Upstream tagged 1.1.0
to 2.1.0; the 3.x line exists only as branches (`rel_3.0.0`, `rel_3.1.0`,
`rel_3.3.0`), pinned by tip commit. The kernel moved twice (`kernel/rhino/core`,
then `kernel/rhino`, with `core/rhino` on `rel_3.1.0`), and the signature covers
all three. Markers are four sources: `k_task.c`, `k_sys.c`, `k_mutex.c`,
`k_event.c`. There is no version probe: `RHINO_VERSION` reads 12000 from 1.x to
3.3.0, and the release string sits outside the kernel directory.

No public vendor SDK checked (Bouffalo, WinnerMicro, WCH, the OpenHarmony
HiSilicon repositories) carries a Rhino copy, so the evidence is upstream
releases only:

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 16 pristine | 16 | 13 | 3 | 0 | 0 | 0 |

Trees: alios-things-kernel-1.1.0, alios-things-kernel-1.1.1, alios-things-kernel-1.1.2, alios-things-kernel-1.2.0, alios-things-kernel-1.2.1, alios-things-kernel-1.2.2, alios-things-kernel-1.3.0, alios-things-kernel-1.3.1, alios-things-kernel-1.3.2, alios-things-kernel-1.3.3, alios-things-kernel-1.3.4, alios-things-kernel-2.0.0, alios-things-kernel-2.1.0, alios-things-kernel-3.0.0, alios-things-kernel-3.1.0, alios-things-kernel-3.3.0.
Ranges: alios-things-kernel-1.3.0 pristine → `1.3.0~1.3.3`; alios-things-kernel-1.3.1 pristine → `1.3.0~1.3.3`; alios-things-kernel-1.3.2 pristine → `1.3.2~1.3.3`.

The ranges are within 1.3.0 to 1.3.4, releases that carry the same kernel code.

Mutation robustness (2.1.0, signature alone): **identified under 9 of 9, version
right 9 of 9.** Renaming 50% of identifiers leaves 0.941 containment at the
abstract level, deleting 50% of files 0.598, the vendor-like combination 0.843.

NVD has no CPE for AliOS Things and no CVE keyword hit; OSV has no record for
the repository. The rule says so in `cpe_status`.

## 1i. Chinese RTOS kernels: Huawei LiteOS (M, A and 5.x)

Three rules, because the three kernels are three trees:
* `generic/liteos-m-kernel`: OpenHarmony `kernel_liteos_m`, `kernel/src` and
  `kernel/include`. 48 releases, 1.0 to 7.0, 724 functions.
* `generic/liteos-a-kernel`: OpenHarmony `kernel_liteos_a`, `kernel/base`,
  `common`, `extended`, `include`. 48 releases, 1.0 to 7.0, 3,659 functions.
* `generic/liteos-kernel`: Huawei's own `LiteOS/LiteOS`, 5.x layout, v5.0.0 and
  v5.1.0: anchors, a winnowed sketch and a function signature of 1,149 functions.

Releases are OpenHarmony tags (Release and LTS), spelled the way upstream tags
them, so `OpenHarmony-v3.2-Release` is `3.2`: `in_tag_set` compares normalised
strings, so a label of `3.2.0` would never be found in an OSV tag list. Many
patch releases carry identical kernel code and are reported as ranges. The
primary source is GitCode, where OpenHarmony moved in September 2025, with Gitee
and GitHub as mirrors at identical commits. Every source file of LiteOS-M 1.1.x
and of LiteOS 5.x wraps its body in `extern "C" {`, which the function extractor
reads through.

WCH's three SDKs carry LiteOS-M; no other public vendor SDK checked did.

| SDK | copy | truth (vendor's own files) | reported | verdict |
| --- | --- | --- | --- | --- |
| ch32v20x | `EVT/EXAM/HarmonyOS/LiteOS_m/LiteOS/kernel` | not stated | 3.0~3.0.3 | identified |
| ch32v307 | `EVT/EXAM/HarmonyOS/LiteOS_m/LiteOS/kernel` | not stated | 3.0~3.0.3 | identified |
| ch583 | `EVT/EXAM/HarmonyOS/kernel_liteos_m/kernel` | 3.2.3 | 3.2~3.2.4 | range |

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 2 pristine | 2 | 2 | 0 | 0 | 0 | 0 |
| 2 touched | 2 | 2 | 0 | 0 | 0 | 0 |

Trees: liteos-kernel-5.0.0, liteos-kernel-5.1.0.

"touched" appends a line to all five files the 5.x hash anchors cover, so no
anchor is left and only the function level decides.

LiteOS-M and LiteOS-A, every release (48 each), read back through version
inference from each release's own function set: 2 exact and 46 ranges
containing the truth for each, 0 wrong.

Mutation robustness (signature alone):

| | LiteOS-M 3.2 | LiteOS 5.1.0 |
| --- | --- | --- |
| rename 10% / 25% / 50% of identifiers (abstract) | 1.000 / 0.983 / 0.955 | 0.973 / 0.904 / 0.871 |
| delete 20% / 50% of files | 0.968 / 0.343 | 0.863 / 0.620 |
| vendor-like | 0.910 | 0.749 |
| identified, version contains truth | 9/9, 9/9 | 9/9, 9/9 |

No version probe exists for any of them. LiteOS-A has `KERNEL_MAJOR/MINOR/PATCH/ITRE`
in `los_config.h`, but it reads 2.0.0.37 in every release from 1.1.5 to 7.0;
LiteOS-M states no version; LiteOS 5.x's `HW_LITEOS_VERSION` is empty in v5.0.0.
In a full OpenHarmony tree the `bundle.json` at a kernel repository's root is
also read, as `liteos_a` / `liteos_m` with the version it declares (3.1.0 at the
v3.2 tag); that finding and the kernel's are in different directories and are
not merged.

CPE: NVD has no CPE for LiteOS and no CVE keyword hit for LiteOS, Huawei LiteOS
or LiteOS-M. Three CVEs name `kernel_liteos_a` (CVE-2022-41802, CVE-2022-43662,
CVE-2022-45126), filed under the OS-wide `o:openatom:openharmony` and
`a:openharmony:openharmony`, which have 156 CVEs across every subsystem; a kernel
copy cannot be scoped to its three, so no CPE is set and `cpe_status` names them.
OSV has no record for any of the repositories.

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
  only, CONTRIBUTING.md requires a pinned tag or commit, and the archive has
  neither.
* **No git source was found.** `github.com/SylixOS/sylixos` is unrelated (Estuary
  install scripts). `git.sylixos.com` is not a git host: every path tried,
  including a git smart-HTTP `info/refs`, answers `301` to
  `docs.acoinfo.com/sylixos/about.html`, the vendor's documentation site, which
  mentions no repository. Not checked: a git service on another hostname, and
  Gitee or other mirrors. If a git remote turns up, the kernel is at
  `libsylixos/SylixOS`, the version macro is `__SYLIXOS_VERSTR` in
  `kernel/include/k_kernel.h`, and the sources are GBK-encoded.
* **No vulnerability data.** NVD has no CPE and no CVE for `sylixos`, `sylix os` or
  `acoinfo`; OSV has no record for 1.8.3.

## 1k–1m. Vendor firmware libraries

Measurements of chip-vendor firmware-library rules (Nations Technologies, HDSC, Rockchip and others) are part of the commercial rule packs and are not published here.

## 1n. Allwinner SDKs

Two public Allwinner RTOS trees (`bhgv/Allwinner-R128S2-SDK-09`,
`DongshanPI/D1s-Melis`; neither has a licence file or tags, so neither is a rule
source and none of their source is committed). Five generic rules cover the
media and IPC libraries they carry:

| rule | covers | source | licence | CPE |
| --- | --- | --- | --- | --- |
| `generic/freetype` | 48 releases, 2.4.0 to 2.14.3, 9,350 functions | github.com/freetype/freetype | FTL or GPL-2.0+ | `freetype:freetype` |
| `generic/libjpeg-turbo` | 30 releases, 1.3.0 to 3.0.4, 2,496 functions | github.com/libjpeg-turbo/libjpeg-turbo | BSD-3-Clause, IJG, Zlib | `libjpeg-turbo:libjpeg-turbo` |
| `generic/giflib` | 26 releases, 4.1.4 to 6.1.3, 253 functions | git.code.sf.net/p/giflib/code | MIT | `giflib_project:giflib` |
| `generic/opus` | 20 releases, 1.0.0 to 1.6.1, 2,498 functions | github.com/xiph/opus | BSD-3-Clause | `opus-codec:opus` |
| `generic/open-amp` | 14 releases, 2020.10.0 to 2026.04.0, 465 functions | github.com/OpenAMP/open-amp | BSD-3-Clause | none: not in NVD |

Every copy of a covered library in the two trees:

| SDK | copy | truth (vendor's own files) | reported | verdict |
| --- | --- | --- | --- | --- |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/freetype` | 2.13.0 | 2.13.0 | exact |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/giflib/giflib-5.2.1` | 5.2.1 | 5.2.1 | exact |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/libjpeg-turbo/source` | 2.1.5.1 | 2.1.5~2.1.5.1 | range |
| allwinner-r128s2-sdk-09 | `lichee/rtos-components/thirdparty/opus` | not stated | 1.3.1 | identified |
| bouffalo_sdk | `components/ipc/open-amp/open-amp` | not stated | 2025.10.0 | identified |

FreeType, giflib and libjpeg-turbo agree with what the vendor wrote
(libjpeg-turbo's `2.1.5~2.1.5.1` contains the `jconfig.h` version). Opus and
OpenAMP are identified, but the trees state no version to check them against.
3.1.0 and later of libjpeg-turbo are not covered. No CVE-based matching was run
against these versions.

## 1o. Protocol and fieldbus libraries

Single upstream releases under a neutral name, each with the whole rule base:

| trees | right component | exact | range containing truth | known | wrong | missed |
| --- | --- | --- | --- | --- | --- | --- |
| 6 pristine | 6 | 6 | 0 | 0 | 0 | 0 |

Trees: canopennode-2.0, canopennode-4.0, hostap-2.10, open62541-1.4.4, soem-1.4.0, zlib-1.3.1.

## 2. Robustness to vendor modification

The methodology the CENTRIS and V1SCAN papers use, applied to this tool. A
pristine lwIP 2.2.0 tree is mutated at a controlled rate, seeded so the run
reproduces. "exact" is the containment of exact function bodies; "abstract" is
the same with identifiers collapsed; the tool uses the abstracted bodies, for the
match and for the version, when the exact ones fall short of a strong match and
the abstracted ones cover at least 0.05 more, and scores that match lower. The
rename step renames names only, never C keywords.

Same signature and seed as section 1:

| mutation | exact | abstract | used | identified | version |
| --- | --- | --- | --- | --- | --- |
| pristine | 1.000 | 1.000 | 1.000 | yes | 2.2.0 |
| reformat (CRLF, tabs) | 0.998 | 0.997 | 0.998 | yes | 2.2.0 |
| rename 10% of identifiers | 0.462 | **0.807** | 0.807 | yes | 2.2.0 |
| rename 25% | 0.154 | **0.727** | 0.727 | yes | 2.2.0 |
| rename 50% | 0.058 | **0.640** | 0.640 | yes | 2.2.0~2.2.1 |
| delete 20% of files | 0.847 | 0.847 | 0.847 | yes | 2.2.0 |
| delete 50% of files | 0.502 | 0.502 | 0.502 | yes | 2.2.0 |
| add 30% vendor code | 1.000 | 1.000 | 1.000 | yes | 2.2.0 |
| **vendor-like**: rename 15%, delete 25%, add 20%, reformat | 0.260 | **0.632** | 0.632 | yes | 2.2.0~2.2.1 |

**Identified under 9/9 mutations; version correct 9/9.**

What to read off that table:

* **Adding vendor code costs nothing** (1.000). Containment asks how much of
  upstream is present, not how similar the trees are — which is why a 4,000-
  function library inside a 200,000-function firmware is still found.
* **Deleting half the files still identifies** (0.502). A port layer that keeps
  only the drivers it needs does not become unrecognisable.
* **Renaming is what exact hashing cannot survive**, and the second abstraction
  level is what fixes it: 0.462 → 0.807 at a 10% rename rate. Without it the
  realistic vendor-like combination falls to 0.260 and would be reported as a
  weak, review-needed match rather than a confident one.
* **The version survives renaming too.** It is read from the abstracted bodies
  once the match is. Up to a quarter of the names renamed it stays 2.2.0; at half,
  and in the vendor-like mix, it is the pair 2.2.0~2.2.1: those two releases differ
  only in names, and with that many renamed the tree no longer shows which names it
  has.

## 3. SBOM quality against the published standards

Scored by `gangmu sbom-score`, which implements the NTIA 2021 minimum elements
and the CISA 2026 update, and is deliberately comparable to Interlynk's
`sbomqs`. Stricter in one respect: a placeholder such as `NOASSERTION` counts as
absent, because an SBOM full of them passes a field-presence check while telling
a reader nothing.

| SBOM | NTIA 2021 | CISA 2026 |
| --- | --- | --- |
| `examples/output/sbom.cdx.json` (the README's disguised GmSSL fork, one component) | **10.0 / 10** | **10.0 / 10** |
| ESP-IDF v5.4.2, the whole tree, scanned from source alone (203 components) | **6.1 / 10** | **7.0 / 10** |

The example is the case the format is designed for. A real SDK is not: 183 of
ESP-IDF's 203 components are Espressif's own prebuilt archives (`libbtdm_app.a`,
the Wi-Fi and PHY libraries) that no rule identifies, so the SBOM lists them as
files with a hash and nothing else, which is honest and costs supplier, version,
identifier and licence on each. Of the 20 components a rule identified, all 20
have a purl or CPE, 19 a version and 18 a supplier (FatFs and the bootloader
have none in their rules). The score therefore measures how much of the tree the
rule base covers, not how the identified components are written up.

The 2026 additions are the interesting ones. *Component Hash* is satisfied by the
digest of the directory's `(path, file digest)` pairs — a vendored source tree
has no package archive to hash, and this is the honest equivalent, reproducible
by re-running the scan. *SBOM Generation Context* records whether the document
came from a real build or from the source tree alone, which is exactly the
distinction that decides whether it over-reports.

## 4. Speed

lwIP 2.2.0, 296 files, one process, median of three runs (4-core machine,
calibration about 0.07 s, so slower than the CI runners).

| pass | what it does | cost |
| --- | --- | --- |
| 1 | walk, sha256 each file, fold into one fileset digest | 0.04 s |
| 2a | tokenise + extract functions (2,097 functions) | 0.37 s |
| 2b | tokenise + winnow k-grams (105,405 fingerprints; fallback path only) | 0.82 s |

Pass 2 is lazy: a vendored copy byte-identical to the release a rule records
never reaches it. Whole-SDK numbers, the rule-count curve and the CI
regression check are in [PERFORMANCE.md](PERFORMANCE.md).

## 4b. OSV GIT ranges against real records

`gangmu vuln` matches OSV records that carry `ranges[type=GIT]` and the affected
tags in `versions` (the shape OSV's CVE import and OSS-Fuzz produce for C
projects). This is checked against real records from `api.osv.dev` and OSV's
GIT-ecosystem dump (`osv-vulnerabilities.storage.googleapis.com/GIT/all.zip`,
111,561 records, 131,003 GIT ranges). Five trimmed records are committed under
`tests/fixtures/osv-real/` (libwebsockets CVE-2025-1866, libcoap CVE-2025-59391
and CVE-2025-34468, nghttp2 CVE-2023-44487, OpenThread OSV-2020-1292), and
`tests/test_osv_real.py` checks every row of the table below on each CI run.

**What the real shapes are**

* CVE-imported records (`CVE-*`) have **no `package`**, a GIT range whose events
  are commit hashes (`introduced: 0`, `fixed: <sha>`), and the affected release
  tags in `versions`. It is the common shape: 75,297 of the 83,364 GIT ranges on
  a GitHub, GitLab or Bitbucket repository list tags.
* OSS-Fuzz records (`OSV-*`) carry `package.purl = pkg:generic/<name>` (never
  `pkg:github/...`), a GIT range, and in most cases **no tags**. They address a
  project by commit only.
* Repository URLs, over all 131,003 ranges: plain, trailing `.git` (32,209),
  trailing `/` (16,104), capitalised such as `GmSSL` (2,082).
  `purl_from_repo` handles every `github.com` URL in the dump. It returns `None`
  for hosts that have no purl type (git.kernel.org 44,826 ranges,
  gitlab.gnome.org, sourceware.org, git.ffmpeg.org ...); those are out of reach
  by design.
* `database_specific.extracted_events` (OSV's own reading of the CVE's CPE
  ranges into version bounds) is present on 74,037 of the GitHub-style ranges.
  On 4,690 of them there are no tags but the bounds are plain versions, and
  those bounds are used.
* Tag spellings seen: `v1.56.0`, `4.3.1` and `v4.3.1` side by side, `v4.3.5a`
  (libcoap letter releases), `4.3.5-NA`, `release-0.2`, `v4.2-rc1`,
  `zephyr-v3.0.0`, `jetty-9.4.42.v20210604`, and non-releases such as
  libwebsockets' `v1.6.0-chrome48-firefox42` and `master-test-2015-11-19-1`,
  which have no normal form and never bound the span of listed tags.

**What the records say about the projects in the rule base.** OSV has no
record, by purl, by repository, or anywhere in the dump, for GmSSL, Tongsuo,
LVGL or `littlefs-project/littlefs`, nor for any `zephyrproject-rtos/hal_*`. For
those the CPE channel (or the vendor's own bulletins) is the only route, and for
GmSSL there is none (see its `cpe_status`). Records do exist for nghttp2 (8, all
CVE), libcoap (26: 15 CVE, 11 OSS-Fuzz), libwebsockets (4), OpenThread (53, all
OSS-Fuzz, two of them list tags), `eclipse-paho/paho.mqtt.embedded-c`
(CVE-2021-41036) and the Zephyr main repository. `vuln-fetch` queries the GIT
ecosystem for every `pkg:github|gitlab|bitbucket` purl, because OSV answers a
`pkg:github/o/r` purl query with nothing.

**Matching SBOMs against those records** (`gangmu vuln` on a CycloneDX
document, compared with what the record says):

| component | record | state | agrees with the record |
|---|---|---|---|
| libwebsockets 4.3.3 | CVE-2025-1866, tags to v4.3.3, fixed | exploitable | yes |
| libwebsockets 4.3.2-vendor | same | exploitable | yes (suffix ignored) |
| libwebsockets 4.3.4, 4.5.1 | same | not affected | yes |
| nghttp2 1.56.0 / 1.57.0 | CVE-2023-44487, tags to v1.56.0, fixed 1.57.0 | exploitable / not affected | yes |
| nghttp2 1.55.1 | same, release not listed though inside the span | in triage | by design: the record does not say |
| libcoap 4.3.4a | CVE-2024-0962, tags `4.3.4`, `v4.3.4a` | exploitable | yes |
| libcoap 4.3.4 | CVE-2025-59391, listed | exploitable | yes |
| libcoap 4.3.5b | CVE-2026-29013, fixed 4.3.5b | not affected | yes |
| libcoap 4.3.4 / 4.3.5b | CVE-2025-34468, no tags, bounds <= 4.3.5 | exploitable / not affected | yes |
| OpenThread `git-2867f6883a12` or a release | OSV-2020-1292, commits only | in triage | undecidable from a version, and the detail says so |

**What does not hold.** A version inside the listed span but absent from the
list stays "in triage" (nghttp2 1.55.1 above): OSV derives the list from the
commit graph, so an unlisted release may be a gap or a branch. A commit-pinned
component (`git-<sha>`), and every OSS-Fuzz record, cannot be placed by a
version: all 53 OpenThread records are reported in triage whatever the version,
and resolving them needs the project's git history, which the SBOM does not
have. The 3,376 GIT ranges with neither tags nor extracted bounds (4%) are of
this kind. Records whose repository is on kernel.org, sourceware, GNOME and
similar hosts are not matched at all. `limit` events occur only on kernel.org
ranges in the dump and are not read. The URL is lower-cased for the GIT query,
because the purl lost the capitalisation, so a repository registered as
`.../GmSSL` is missed.

## What these numbers do not show

* A few dozen component families measured on a few hundred trees and copies,
  plus a self-scan of 227 rules' upstream releases, not a corpus of thousands.
  CENTRIS evaluated against 10,241 projects. The methodology is theirs; the
  scale is not.
* The mutation model is synthetic. Real vendor forks differ in ways a seeded
  mutator does not reproduce — which is why the vendor SDK copies and the
  Espressif fork are measured separately, as real trees with known provenance.
* No comparison against another tool on the same input. No other open tool
  identifies vendored C/C++ components at version granularity, so there is
  nothing to put in the other column yet.
* Binaries were measured on a self-built corpus, not on real vendor firmware or
  on clang-built images (see BINARY-VALIDATION.md).
* The domestic vulnerability databases were not checked for any of the Chinese
  RTOS rules: TencentOS-tiny (1f), AliOS Things (1h) and the three Huawei LiteOS
  rules (1i), nor for SylixOS (1j), which has no rule. CNNVD's search API
  rejects anonymous calls (`非法访问` / 401 `未登录`) and CNVD answers 521
  behind a JavaScript cookie challenge, so "no CNNVD/CNVD record" is **not**
  established for these products. A manual search with a normal browser
  (TencentOS, AliOS, LiteOS, SylixOS, 翼辉, kernel_liteos) is the way to close it.
