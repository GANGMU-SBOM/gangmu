# Changelog

What each release added and what was measured at the time, newest first. For the current capabilities see the [README](../README.en.md); for Chinese-ecosystem coverage see [CHINA.md](CHINA.md).

## Unreleased
* **Improved: binary release scoring now counts contradicting evidence, and wrong answers drop sharply.** The old score was the share of matched functions a release explains, and a two-feature print matching by chance counted as a full piece of counter-evidence. Now each matched print the release lacks is one contradiction, weighted by its feature count (1 from four features up, 1/3 at two), and releases within 2 of the best are reported as a span. On our own cross-compiled corpus (7 libraries, 20 releases, 4 optimisation levels) wrong answers go: Cortex-M3 7 to 1, AArch64 4 to 2, Cortex-M3 references against AArch64 images 7 to 0; negative controls stay 0/1920. The cost: 17 fewer unique answers on Cortex-M3 (52 to 35), 13 more on AArch64 (34 to 47). The span of 2 was chosen against all three corpora (the smallest span with at most 2 wrong in each), not the best point of any one; neighbouring values are tabulated in `docs/BINARY-VALIDATION.md`. Not re-measured on real firmware. The old score is still available with `gangmu binary-eval --tie-share 0.85`.
* **New: reachability reads `compile_commands.json` (`gangmu vuln --source DIR --compile-db FILE`).** A `.c`/`.cpp` file the database does not list was not compiled, so a vulnerable function defined only there is "absent"; each listed file's `#if`s are evaluated with its own `-D`/`-U` flags (before, only the global `--config`/`-D` applied). When the database names none of the files under `--source` (written on another machine with a different layout) it is ignored with a note instead of treating the whole tree as uncompiled; the same tree under another path prefix still matches by relative path. A macro with no `-D` stays unknown, since a header may define it, and its branch is kept.
* **New: reads Arduino libraries' `library.properties` and the ESP-IDF component manager's `dependencies.lock`.** Arduino libraries (name, version, URL, author as supplier; libraries inside a PlatformIO project stay with the PlatformIO reader and are skipped here). From `dependencies.lock`, each locked registry component with its exact version, plus the ESP-IDF release itself (`idf`); a component with sources under `managed_components/` points there, one locked but not downloaded has no directory. A registry component's version is the registry package's, which wraps an upstream library and is not the upstream release, so it is not reported as an upstream version. No network. Module: `declared_deps.py`.
* **Improved: rule YAML is parsed with libyaml's C loader when PyYAML has it.** A rule directory without a precompiled index (a git checkout used with `--rules`, developers, CI) parses every YAML file on each load, and PyYAML's pure-Python loader was most of that cost. PyPI's PyYAML wheels ship libyaml; `CSafeLoader` builds the same objects as `SafeLoader` for the same input (a test compares all 98 installed rules), and without libyaml (some distro packages) the old loader is used. On PyYAML 6.0.3 with libyaml, parsing the 98 rule files drops from 0.47 s to 0.047 s; this machine's system PyYAML has no libyaml, so no end-to-end scan speedup is claimed. Wheel installs, which already ship the index, are unaffected. Module: `core/yamlfast.py`.
* **New: function-level reachability now understands conditional compilation; a function the configuration compiles out is "absent".** `#if 0`, `#ifdef CONFIG_X` and `#if !defined(MBEDTLS_X)` branches all used to feed the call graph, so a vulnerable function that the current configuration never builds was reported as "defined" or even "reachable". `gangmu vuln --source` now evaluates those conditions against the build configuration (three-valued: a branch is dropped only when the condition is definitely false under what is known; an unknown macro, `__has_include` or a function-like macro call keeps it). A function that exists only in a dropped branch is reported `absent` ("in the source, but the build configuration compiles it out"), and `--reachability-vex` writes it as `not_affected / code_not_present`. Configuration comes from `--config` (a Kconfig `sdkconfig`/`.config`, or a C header such as `mbedtls_config.h` or `sdkconfig.h`; by default the `sdkconfig`/`.config` and `sdkconfig.h`/`autoconf.h` under `--source` are found), `-D NAME[=VALUE]`, and `--assume-undefined-off` (a macro nothing mentions is off; right when the product's config header is named with `--config`). A `#define` elsewhere in the tree is not taken as fact: a tree often carries alternative configurations (Mbed TLS's `configs/config-*.h`), so only unconditional defines in the headers `--config` names count, and a name defined or `#undef`-ed anywhere else is unknown. Checked on real Mbed TLS 3.6.2 source: under the default `mbedtls_config.h` the functions compiled out are restartable ECP, LMS signing, the memory-buffer allocator and the experimental `mbedtls_mpi_mod_*`, which is what the default configuration leaves off; AES, GCM, RSA and the SSL handshake stay. Module: `ifdef.py`.
* **New: a version probe can give only major.minor to narrow the span the functions give, and can read hexadecimal and an optional suffix.** WinnerMicro's littlefs header says `LFS_VERSION 0x0002000a` (2.10) while the functions only said `2.10.2~2.11.1`; the probe now reads 2.10 and the span narrows to 2.10.2. When the functions already name a more exact release, a coarser probe no longer overwrites it. A probe pattern named `hex_*` is read as hexadecimal and shown in decimal, and one named `dash_*` gets a `-` prefix when non-empty (Zephyr's `EXTRAVERSION = rc2` now reads `4.5.0-rc2`; the suffix was dropped before). On the rules side libcoap gains a `ChangeLog` probe (WinnerMicro's libcoap source has no version macro; it is now 4.3.4).
* **Fixed: a version definition (e.g. `build_info.h`) naming a release the rule does not record now wins over the anchor version.** An anchor only proves the files equal a release's, and the next release may ship them unchanged: Zephyr's Mbed TLS says 4.1.1 in its header, the rule records only 4.1.0, and it was reported as 4.1.0. A version the rule does record is unaffected (three Mbed TLS tags did not bump their header, so the anchor still wins there).
* **Fixed: a version probe now also looks one level up when the component was found at its `src` directory.** WinnerMicro's LVGL is found at `lvgl/src` (whose own `lvgl.h` has no version macro) with the real `lvgl.h` one level up, so it could only say `8.3.11~8.4.0`; FreeRTOS keeps its header in `freertos/include` and was `10.4.0~10.4.2`. They are now 8.4.0 and 10.4.1, matching their headers. It applies only to directories named `src`, `source`, `lib` or `library`, and only when the file name is unique within the parent.
* **New: when the closest match is the oldest (or newest) release a rule records and much of that release's code is missing or altered, the finding now says the tree may be older (newer).** libsodium in the ESP8266 RTOS SDK is 1.0.12 (`port_include/sodium/version.h` says `1.0.12-idf`), the rule records 1.0.17 onwards, so it was reported as 1.0.17 with no hint, and older releases have many more advisories. Now, when the best match is the oldest (newest) recorded release and at least 25% of its functions are missing or altered, the evidence says "this tree may be older (newer) than any release the rule records" and the terminal note reads `vendor-modified (or older than known releases)`. The version itself is unchanged. Across real scans of the pico-sdk, ESP-IDF, STM32CubeG4, Bouffalo SDK and ESP8266 RTOS SDK it fires once, on this component, with no false flags. The root fix is for the rule to record the older releases (here libsodium 1.0.12 to 1.0.16), which belongs in gangmu-rules.
* **Docs: aligned with the current CLI and rule base.** The free rule base is quoted at its actual 98 rules (53 with a CPE, 45 without) and the `gangmu rules index` load time was re-measured on 98 rules; the READMEs now list `binary-eval`, `binary-functions`, `cbom --fail-on legacy` and the `aibom` options, and the English README gains `merge` and `license-check`; the repositories section says the commercial content lives in private repositories (gangmu-rules-pro, gangmu-policy-pro, gangmu-enterprise); EDITIONS adds merge, licence triage and the newer declaration readers; llms.txt and docs/index.md list all related repositories; the example outputs are marked as generated by 0.6.x.
* **Fixed: a version header under a namespacing directory was never read, so a weak match stayed unasserted.** The FreeRTOS rule reads `include/task.h`; ESP-IDF's fork puts it at `include/freertos/task.h`, which the fixed path never found, so ESP-IDF's FreeRTOS 10.5.1 stayed "possible" (0.52, only the function range `10.5.0~10.5.1`, left out of the SBOM). The lookup now also finds the file by name within four levels, accepting it only when exactly one candidate exists (a probe's pattern needs the component's own version macro, so an unrelated file of the same name yields nothing). And a directory that resembles the component only weakly yet defines that component's version macro now gets identity 0.75, where it stayed at 0.50, "needs review"; the protection for a matching anchor in an otherwise unlike directory is unchanged. In ESP-IDF's `components`, the FreeRTOS fork moves from "possible" to `10.5.1` (0.77) and nothing else changes; gangmu-bench's 25 rows are unchanged (21 exact, 4 range, 0 wrong).
* **Fixed: version probes and anchor files are found when a vendor wraps the library in one more directory.** A rule records `src/include/lwip/init.h`; BTstack ships lwIP as `lwip/core/src/include/lwip/init.h`, which a fixed path never found, so the version came from the functions alone and a development snapshot whose header says 2.2.0 was reported as `2.1.0~2.1.3` (older than it is, which keeps advisories fixed only in 2.2.0 alive). When the fixed path is missing the lookup now goes one or two directories down, and accepts the file only when exactly one candidate exists; two are not guessed between. Found by scanning the Raspberry Pi pico-sdk (five submodules, each checked against its header); mbedtls 3.6.6, TinyUSB 0.18.0 and lwIP 2.2.1 all matched theirs.
* **Fixed: an STM32 HAL driver's version was read as the entry below the newest; the version macros in its source file are now read first.** The STM32WB `Release_Notes.html` heads its newest entry with a lowercase `v1.3.0`, and the pattern accepted only a capital `V`, so it reported the entry beneath, 1.2.0 (older than the truth). The match now ignores case and takes the highest entry, not the first. The reader also takes `__STM32xx_HAL_VERSION_MAIN/SUB1/SUB2/RC` from `Src/stm32*xx_hal.c` (the macros are in the source file, not a header, as the earlier text said), preferring them, with a release candidate shown as `-rcN`. F4's macros agree with its notes (1.8.5); the H7 and G0 sources no longer carry them and are still read from the notes. Found on the STM32WB HAL BTstack bundles in the pico-sdk.
* **CI: mypy type checking.** `src` had 96 type errors; all are fixed and CI gains a `types` job (`mypy`, version pinned, settings in `[tool.mypy]` of `pyproject.toml`). Most were an Optional that was never narrowed, or one variable given different types in different branches. Two writes that would raise `AttributeError` at an edge (`patchtest` with an empty-string `workdir`; the gitmodules importer's "no pinned commit" branch passing something that is not a `VendoredProject`) are corrected along the way. Behaviour is otherwise unchanged and the test suite passes.
* **New: `gangmu license-check SBOM` triages the licences in a CycloneDX document.** Components are sorted into permissive, weak copyleft (LGPL, MPL, EPL, CDDL), strong copyleft (GPL), network copyleft (AGPL) and unknown (an `OR` expression is classed by its most permissive choice; a `WITH` exception is noted, not trusted). It lists the copyleft components, pairs the FSF licence list says cannot be combined into one work (Apache-2.0 with GPL-2.0-only, GPL-2.0-only with GPL-3.0-only, the advertising-clause licences and CDDL or EPL-1.0 with GPL), components with no licence, and prebuilt binaries with none. A pair is "possible" because an SBOM does not say how two components are combined. `--fail-on copyleft|incompatible|unlicensed`, `--format json`. Run on a scan of 21 real release trees it listed SOEM (GPL-2.0-only) against Mbed TLS and CANopenNode (Apache-2.0) and 11 prebuilt `.lib`/`.a`/`.bin` files. A triage for a person, not a legal conclusion.
* **Fixed: an anchor file that several releases ship unchanged no longer pins the first of them.** The rule base records each release's hash of an anchor file, and in open62541 1.4.3 and 1.4.4 `ua_server.c` is byte-identical; the engine took the first matching release, so a 1.4.4 tree was reported as 1.4.3 at anchor confidence (0.98), exact, even though its `CMakeLists.txt` said 1.4.4. Now, when several releases share the hash, a version probe or the function signature picks among them, and with neither the version is the span (`1.4.3~1.4.4`, source `anchor-shared`, confidence 0.88). Found by running gangmu-bench on 12 new cases (11 were exact); the same case now reports 1.4.4. Any rule whose anchors cover patch releases with unchanged files was affected.
* **New: the package database of an unpacked root filesystem is read.** `var/lib/dpkg/status` (installed packages only), opkg's `var/lib/opkg/status` or `usr/lib/opkg/status` (Yocto `-r0` revisions cut to the upstream release, git snapshots left without a version) and Alpine's `lib/apk/db/installed`. Checked against this build container's own dpkg database: 827 packages read, the count `dpkg-query` gives. dpkg and apk versions carry the distribution's revision and backported fixes, so they are reported as given, not as upstream releases, with no upstream CPE. Images are not unpacked; point it at an unpacked tree. Module: `declared_rootfs.py`.
* **New: `gangmu merge` joins CycloneDX documents.** A product's SBOM often comes from several tools (the Yocto build, the vendor, Conan, this tool's source scan). Components are the same when the purl matches, else name and version; the first document wins every field it has and later ones only fill gaps (with a `gangmu:alsoIn` property). Two documents giving one component different versions keep both and are reported as a disagreement; `bom-ref` collisions are renamed and the dependency graph follows; vulnerabilities (VEX) are joined by id with the more cautious analysis state kept; `--fail-on-disagreement` exits 1 on either kind of conflict. The merged document validates against the CycloneDX 1.6 schema. CycloneDX JSON only: no SPDX input, and a nested component of a component is carried through but not de-duplicated.
* **New: STM32Cube packages and CMSIS-Packs state their own release and are read.** The CMSIS device header's `__STM32xx_CMSIS_VERSION_*` macros (else the newest entry of the `Release_Notes.html` beside it), the newest entry of an ST HAL driver's `Release_Notes.html` (current HAL headers carry no version macro), and the vendor, name and newest `<release>` of a CMSIS-Pack `*.pdsc`. Checked against the real ST repositories (F1, F4, G0 and H7 HAL and CMSIS device trees); no CPE is claimed. Module: `declared_packs.py`.
* **New: dependencies declared in CMake, vcpkg, Meson and Cargo files are read.** `FetchContent_Declare`, `ExternalProject_Add` and CPM's `CPMAddPackage` (a release tag or a versioned archive name is a version; a branch, a commit or a `${VARIABLE}` is reported without one), `vcpkg.json` (`overrides` pin a version, `version>=` is a minimum and is not reported as one, `host` dependencies are left out), `subprojects/*.wrap` and the `*-sys` crates of `Cargo.lock` (the ones that bind or bundle a C library; the crate version is not claimed as the library's). Nothing is fetched. Module: `declared_deps.py`.

## 0.10.0

* **Fixed: the `performance` baseline is re-recorded on the CI machines.** One run on `main` failed with warm x1 at 1.61x the baseline, just past the 1.6x limit. It was not calibration jitter: the CI runners come in several speeds (calibration about 0.033, 0.045 or 0.060 s), and a scan has a fixed cost of about half a second that does not shrink with the CPU, so the same code reads 20 to 30% dearer in calibration units on the fast runners, and the old baseline, recorded on a laptop, sat outside that spread. The baseline is now the median of 11 CI runs (largest work counters); the worst of those 11 reads 1.32x against it, and 6 runs from earlier days that were not used to build it all pass. The old baseline's memory was also too loose (82 rules against 90 now, a 609.6 MB peak at x16 against about 224 MB on CI, so memory had to grow 2.7x before the check noticed); the 1.35x limit now actually bites. Re-record with `benchmarks/rebaseline.py`. The limits (1.6x, 1.35x) are unchanged. The entry above, the median of nine rounds measured before and after the scans, stays and makes the calibration steadier, but it did not fix this failure (I had put it down to the fastest of three rounds being lucky; that was wrong, since on a 0.045 s machine the new method measures 0.045 s too).
* **Improved: the `performance` check's calibration is the median of nine rounds, measured before and after the scans and averaged** (the ratio of the two is recorded as `calibration_drift`); it used to be the fastest of three. On a quiet machine the call-to-call variation falls from about 28% to about 9%. It makes the calibration steadier but was not the cause of the intermittent failure (see the entry above).
* **New: libplctag is recognised.** Its native libraries are identified by their `plc_tag_*` exported symbols (no version; the SONAME's 2.6 series is quoted in the evidence text), and all ten libraries carved from `libplctag.NativeImport.dll` are named. A .NET assembly takes no part in exported-symbol matching: the same names in its metadata are P/Invoke declarations, so it is never reported as containing libplctag.
* **New: native binaries embedded in other files are carved out and analysed.** ELF, PE and Mach-O files are found by their headers inside another file (the per-platform native libraries of a .NET assembly, an installer with an appended payload, firmware with an embedded ELF), sized from each format's own tables, and each is analysed as an entry of its own by the same pipeline, so a banner or a toolchain is credited to the binary it is in and the outer file no longer carries the embedded library's toolchain. In the SBOM they are separate components with `gangmu:containedIn`, `gangmu:offsetInContainer` and `gangmu:architecture`, and SPDX has the outer file contain them; libraries in .NET resources are named by their resource name. On `libplctag.NativeImport.dll` the ten carved match its managed resource table one for one. Static libraries (`.a`, `.lib`) and `.o` files are not carved, and nesting is followed two levels. Carving is not recognising: which library it is still takes a rule. See [BINARY-SBOM.md](BINARY-SBOM.md).
* **New: SBOMs from Windows `.exe` and `.dll` files.** Reads the PE import and export tables, version resource and PDB path. Dependency lists the Go (`debug/buildinfo`) and Rust (`cargo auditable`) toolchains write into the file enter the SBOM at their exact versions as `pkg:golang` and `pkg:cargo` purls, and a Go `replace` is marked modified. For .NET it reads assembly references and the `*.deps.json` beside the program for exact NuGet package versions. The kinds of evidence differ in strength: toolchain lists 0.90, `deps.json` 0.85, version resource 0.70, imports and .NET references 0.50 (the "possible" tier). **An import now says only that a binary needs a library at run time, no longer that it embeds it** (the SBOM now separates `gangmu:embeddedLibrary`, `gangmu:importedLibrary`, `gangmu:declaredDependency` for `deps.json` and `gangmu:identifiedAs` for a managed DLL's own identity). No NuGet purl is made for a program's own assemblies. Checked against real Go, Rust, MSVC and NuGet samples, with Go agreeing with `go version -m` field for field; packers, installers and statically linked programs with no banner are still not recognised. Evidence, research and what is not done: [BINARY-SBOM.md](BINARY-SBOM.md).
* **Fixed: ESP-IDF's `managed_components/` is no longer skipped.** The component manager puts every registry dependency there and it is compiled into the firmware; discovery skipped the directory by name, so those components were missing from the SBOM even when the compile database showed them built.
* **Fixed: CVSS ratings from OSV records.** Real OSV records carry a vector string in `severity[].score`; it was copied into the CycloneDX rating's `severity` (which allows only level names), so the VEX failed the bom-1.6 schema, the score was empty (sorting as 0), and the MIIT and CRA reports showed a vector as the severity. A v3 vector is now scored with the specification's formula; a v4 vector is kept as is with GHSA's `database_specific.severity` as the level; vector and method go in their own rating fields. NVD records scored only in `cvssMetricV40` now get a score and level.
* **Fixed: one vulnerability is counted once.** An NVD CVE and the GHSA record aliasing it, or one record reaching a component through both CPE and PURL, were two findings, counted twice by `--fail-on`, CycloneDX and CSAF. There is now one per vulnerability and component, the more serious state winning, with the other record's id in `aliases`. `vuln coverage` still counts per channel.
* **Fixed: a `git describe` version is no longer called not affected.** `0.2-265-gad902ca` was compared with the hash's digits as a version number and came out not affected by a fix in 0.2.1; 265 commits past 0.2 may or may not carry it. It is now ordered only where its tag decides, and goes to triage otherwise.
* **Fixed: `vuln-fetch --product ... --since` older than 120 days is no longer cut to the last 119 days without a word**; the span is fetched in windows the API accepts.
* **Fixed: an unreadable NVD year shard no longer loses the year.** It was treated as empty and one incremental run overwrote it with that run's records. It is now moved to `*.unreadable` with a warning and the watermark is dropped, so the next run (without `--since`) is a full download.
* **Reproducible output: with `SOURCE_DATE_EPOCH` set, the same input gives byte-identical documents.** The time is that moment and the document id (CycloneDX `serialNumber`, SPDX namespace, OpenVEX `@id`) is a uuid5 of the content, for SBOM, VEX, CBOM, AIBOM and the evidence manifest; without it nothing changes.
* **Fixed: `gangmu binary-eval` caches features as JSON (`.features.json`).** It unpickled `.features.pickle` from the corpus directory, which runs whatever a corpus from someone else puts there; an old pickle is no longer read.
* **Fixed: CPEs with an escaped colon (`acme\:labs`).** Six places split on every colon, shifting vendor, product and version: the match key, an advisory CPE's pinned version, the rule validator (which rejected a well-formed name), coverage, the `sbom.yml` reader and version splicing. They now split as the specification binds the name, and a spliced version is quoted.
* **Tree walkers share one set of never-content directories** (`.git`, `node_modules`, `__pycache__`, `.venv`, `venv`) and add only what is out of scope for their purpose; licence and declaration walks now skip Python environments too. Fingerprinting (dirprint) is unchanged so the rule base stays valid.
* **Internal: `cli.py` is split by command group into `gangmu/commands/`; behaviour unchanged.** Moved names are still importable from `gangmu.cli`, so plug-ins need no change; a new test builds `--help` for each of the 35 subcommands.
* **CI:** gangmu-rules is pinned to a commit (v2026.10.11); `ruff check src tests` (unused and undefined names only) runs, and the existing findings are fixed.

## 0.9.0

* **New command `gangmu policy check`: read a CBOM or AIBOM against policies written as data, with a status and a date per check.** Policies live in `policies/*.yaml` of a rule pack of kind `policy`: they select CBOM assets by algorithm key or quantum status, or AIBOM models with a missing licence or training data, and carry `deprecated-after` / `disallowed-after` dates. A check ends `ok`, `due`, `deprecated` or `fail` as of `--as-of`; `--fail-on` is the CI gate; output is a table, Markdown or JSON. It gives no legal conclusion and does not inspect key sizes. See the [policy guide](guides/policy.md) (Chinese).
* **`gangmu aibom --rules`: the model-format and inference-runtime tables can be extended with a rule pack.** A pack of `kind` `aibom` holds `formats/*.yaml` and `runtimes/*.yaml`; a rule with the key of a built-in replaces it, a new key adds one; installed aibom packs are read automatically. The seed is [gangmu-aibom-rules](https://github.com/GANGMU-SBOM/gangmu-aibom-rules), an exact export of the built-in tables.
* **`gangmu aibom` reads a declaration file for training data, licence, intended use and metrics.** `gangmu-aibom.yaml` at the root (or `--declarations FILE`) is matched to models by path glob or SHA-256 and merged into the CycloneDX licence, datasets, `modelCard.considerations` and metrics; an entry that matches nothing is kept as a declaration-only component; everything is marked as declared by a person and not checked. `--require-declarations` exits 1 when a model has no declared licence or training data. See the [AIBOM guide](guides/aibom.md#声明文件) (Chinese).
* **New command `gangmu aibom`: a minimal AI bill of materials (CycloneDX 1.6).** It lists the machine-learning models in a tree (by file signature or extension: TensorFlow Lite, GGUF, ExecuTorch, ONNX, safetensors, PyTorch and others, each with a SHA-256; a GGUF file's architecture is read; TensorFlow Lite models compiled into a C array are found too) and the inference runtimes (TFLite Micro, CMSIS-NN, Edge Impulse, ONNX Runtime, llama.cpp and others). PyTorch pickle files carry a note that loading them can run code. Training data and licence are not read, and build facts are not used. See the [AIBOM guide](guides/aibom.md) (Chinese).
* **`gangmu cbom --format readiness`: a post-quantum migration summary (Markdown).** It groups the inventory into migrate / replace now / already post-quantum / symmetric and names the NIST replacement; weakly evidenced hits and ones the build facts rule out are listed apart. See the [CBOM guide](guides/cbom-post-quantum.md) (Chinese).
* **`gangmu cbom --libraries`: derive algorithms from the identified libraries and their versions.** It runs the SBOM scan first, then, from the `libraries/*.yaml` capability tables of a CBOM rule pack, adds the algorithms that version's source provides, as evidence of kind `library` with confidence at most 0.6 (providing is not calling). A version that is missing or outside every span is listed in the notes, not guessed.
* **Internal: `gangmu.core` split out, ready to be shared by CBOM and AIBOM; behaviour unchanged.** Plug-in entry points, rule packs and manifests, evidence types (`Technique`, `Evidence`), path globbing, firmware container unpacking and signing moved into `gangmu/core/`. The old import paths (`gangmu.plugins`, `gangmu.signing`, `gangmu.globbing`, `gangmu.unpack`, `gangmu.rules.packs`) stay as aliases of the same modules, so external plug-ins need no change. `tests/test_architecture.py` checks that core imports no engine.
* **The `gangmu cbom` algorithm table can be extended or replaced by rule packs.** A pack whose manifest says `"kind": "cbom"` carries `algorithms/*.yaml`; name one with `--rules DIR`, or install it and it is read by default. A pack entry with a built-in's key replaces it, a new key adds an algorithm.
* **A rule pack manifest may say `kind`.** Without it the kind is `sbom` (component fingerprints, as before); packs of another kind (for example `cbom`) are skipped by the SBOM scan instead of being parsed as component rules. Directories named explicitly with `--rules` or `GANGMU_RULES` are unaffected.
* **Fixed built-in CBOM patterns:** `mbedtls_sha384_*` no longer counts as SHA-3, `MBEDTLS_ECP_DP_CURVE448` no longer counts as Ed25519, and SM2 also matches OpenSSL 3's `ossl_sm2_*` names.

## 0.8.0

* **Function-level binary identification covers more architectures and was checked on real firmware.** A fingerprint file now records the architecture it was built for; when the reference and the image differ only string literals are compared (derived constants vary by compiler and were the source of every wrong release). Cortex-M3 references against rv32imac, AArch64 and ESP32 (Xtensa) images: 0 wrong among the answers, 0 false positives in the negative controls, but many libraries are not recognised. Older `.fnprint` files still load; regenerate them to record the architecture.
* **Xtensa (ESP32, ESP8266) is supported.** Capstone has no Xtensa decoder, so a minimal one ships: it finds function starts from `entry` instructions and recovers the literals `l32r` loads. It is not a disassembler and has been validated against one `xtensa-esp32-elf-gcc` version only.
* **Releases are scored by how much of the matched code they explain.** Firmware usually links only part of a library (`--gc-sections`), and the old Jaccard score favoured releases with fewer functions. Across five corpora wrong answers are equal or fewer (Cortex-M3: 14 down to 6 with images cut to 25% of their functions), with 0 false positives in the negative controls; the cost is more spans instead of a single release when the image holds the whole library. Results with coverage under 50% now say the release is only the nearest fingerprinted one.
* **On real firmware (Zephyr 4.1, Cortex-M7) the result is weaker than the self-test, and [BINARY-VALIDATION.md](BINARY-VALIDATION.md) says so.** littlefs is recognised but its release is wrong (the true release is not among the fingerprinted ones); Mbed TLS now gets a span that contains the true release, but a wide one. Zephyr's configuration cuts the number of matched functions sharply. A self-test that passes does not carry over to other configurations, forks or releases the rule does not cover.
* **Link maps:** TI armlnk added and Arm armlink parsing corrected, checked on public real maps.
* **Rules:** littlefs and mbedtls carry function fingerprints (`identity.binary_functions`); the rule pack needs `requires_gangmu >= 0.8.0`.
* **Tried and not merged (documented):** call-graph corroboration, position clustering of matches, relaxed thresholds: none gave a net benefit.

## 0.7.0

* **New command `gangmu cbom`: a cryptographic bill of materials (CycloneDX 1.6 CBOM).** It reads algorithm names (AES, RSA, ECDSA, ECDH, SM2/3/4, the SHA family, ML-KEM and others) from sources, build configuration, prebuilt libraries and firmware images, and writes each algorithm as a `cryptographic-asset` component with file and line evidence, a confidence and a quantum status (`gangmu:quantumStatus`). With a compile database or link map only source files the build compiled and linked count (headers are declarations only; uncompiled sources become `not-linked`); without them every asset is marked `unverified` and the output says it lists what the tree contains, not what the firmware contains. A built firmware image in the scanned directory adds an `IMAGE` check (`gangmu:imageCheck`): `no` means "look at it" (compiled out, or named by a macro that leaves no symbol), not "absent". AES carries key size and mode. `--fail-on quantum-vulnerable|legacy` fails CI. The output is validated against the official CycloneDX 1.6 schema in the tests. Measured once, on Mbed TLS built natively with gcc: 42 algorithms from the tree, 40 with the compile database, 39 with the link map; five of those are not in the image's symbols. Limits: detection is by name, not behaviour; hand-written algorithms, key lengths and protocols are not covered. See the [CBOM guide](guides/cbom-post-quantum.md) (Chinese).
* **The table's `vendor-modified` note now reads `vendor-modified (or newer than known releases)`.** Measured on ST's STM32CubeF1: the HAL commit its submodule pins differs from the v1.1.10 tag in 26 files and was flagged `vendor-modified`, while a clean copy of the v1.1.10 tag is not. The flag is right (the tree matches no recorded release) but reads as "a customer changed it", so the note names the other common cause: an upstream commit newer than the recorded versions. Terminal table text only; SBOM and VEX output are unchanged.
* **With a link map, firmware images that are not this build's product no longer count as shipped.** Scanning the whole of
  STM32CubeF1, the examples' `.bin` files and `audio.bin` (5 images) went into the SBOM as `required`, because a link map names link
  inputs and never images, so there was nothing to judge them by. Now, when a link map is given, only an image that shares the map's
  stem (`fw.map` and `fw.elf`/`fw.bin`, the build's own output) is linked; every other image is marked not linked, and CycloneDX gives it
  `scope: excluded`, like an unlinked prebuilt library. Without a link map nothing changes (unknown).
  Checked on the same whole-repo scan: only the HAL and lwIP stay `required`; all 10 prebuilt files are `excluded`.
* **Four problems found by scanning a real project** (ST's STM32CubeF1 LwIP echo-server example).
  1. An IAR (`.ewp`) or Eclipse/CCS project given to `--project` by a relative path had its source
     paths joined to the project directory twice, so every source went missing: 0 components, while the
     scan still printed "61 sources built". Paths are now made absolute first; a project whose listed
     sources are all missing is an error, and a partly missing one is noted.
  2. `--project` with a `.cproject` file itself failed with "unsupported project file" (a dot-file has
     no suffix). It works now.
  3. `gangmu wrap` shimmed only cc, gcc, g++, clang and clang++, so a cross compiler such as
     `arm-none-eabi-gcc` recorded nothing, and `scan` then marked every component "not linked". It now
     also shims every `<triple>-gcc`, `-g++` and `-clang` on PATH, and `scan` exits with an error when the
     compile database has no source under the scanned tree.
  4. In a GNU ld map built with `--gc-sections`, an object whose sections were all discarded was still
     named on a `LOAD` line and counted as linked. Only objects that contribute bytes to an image
     section now count; with LTO, or a map that shows no contributions, every named object is still
     kept. In that example 20 of 62 objects are now reported as dropped at link time.

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
