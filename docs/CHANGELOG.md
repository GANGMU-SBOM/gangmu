# 更新记录

这里记录各版本新增的能力和当时的评测结果，按版本倒序。当前能力总览见 [README](../README.md)，各家国产生态的覆盖见 [CHINA.md](CHINA.md)。

## 0.7.0

* **新命令 `gangmu cbom`：固件密码物料清单（CycloneDX 1.6 CBOM）。** 读源码、配置文件、预编译库和固件镜像里的算法名（AES、RSA、ECDSA、ECDH、SM2/3/4、SHA 系列、ML-KEM 等），
  每个算法写成 `cryptographic-asset` 组件，带文件和行号证据、置信度和量子风险（`gangmu:quantumStatus`）。给了编译数据库或链接 map 时只统计真正编译、链接的源文件
  （头文件只算声明，未编译的源文件记为 `not-linked`）；没有时每项标 `unverified`，并在输出里说明这是“树里有什么”而不是“固件里有什么”。AES 带密钥长度和模式。
  `--fail-on quantum-vulnerable|legacy` 可在 CI 里失败。输出用官方 CycloneDX 1.6 schema 在测试里校验（schema 放在 `tests/fixtures/schemas/`）。
  局限：按名字识别，不识别手写算法，不判断密钥长度和协议；用 Mbed TLS 的 PSA 接口名只识别部分。见 [CBOM 指南](guides/cbom-post-quantum.md)。
* **表格里的 `vendor-modified` 改为 `vendor-modified (or newer than known releases)`。** 用 ST 官方 STM32CubeF1 实测：子模块锁定的 HAL 提交比 v1.1.10 标签多改了 26 个文件，
  被标 `vendor-modified`；同一个 v1.1.10 标签的纯净副本不会被标。标记本身没错（树与已记录的发布版不一致），但容易被读成“客户改过”，所以说明另一种常见原因：比已记录版本更新的上游提交。仅改终端表格文字，SBOM 与 VEX 输出不变。
* **有链接 map 时，不属于本次构建的固件镜像不再算“已出货”。** 整库扫描 STM32CubeF1 时，示例工程的 `.bin`、音频文件 `audio.bin` 等 5 个镜像曾以 `required` 进 SBOM，
  而链接 map 只列链接输入，从不列镜像，所以此前没法判断。现在给了链接 map 时，只有与 map 同名的镜像（`fw.map` 对 `fw.elf`、`fw.bin`，即这次构建自己的产物）
  算已链接，其余记为未链接，CycloneDX 里 `scope` 为 `excluded`（和未链接的预编译库一致）。没有链接 map 时行为不变（未知）。
  核对：同一个 STM32CubeF1 整库扫描，`required` 只剩 HAL 和 lwIP 两项，10 个预编译文件全部 `excluded`。
* **新输出格式：SPDX 3.0.1、OpenVEX 0.2.0、CSAF 2.0（csaf_vex）。** `gangmu scan --format spdx3` 写 SPDX 3.0.1 JSON-LD（Software 配置：
  供应商是独立的 Agent、组件哈希进 `verifiedUsing`、许可证是元素并用关系挂接）；`gangmu vuln --format openvex|csaf` 把同一份分析写成 OpenVEX 或 CSAF。
  三种格式都用官方 JSON schema 在测试里校验（schema 放在 `tests/fixtures/schemas/`）。SPDX 2.3 仍是 `--format spdx`，默认输出不变。
  OpenVEX 和 CSAF 要求声明者，所以必须传 `--publisher`（CSAF 还要 `--publisher-url`），工具不替人编一个；
  CSAF 文档状态是 `draft`，`affected` 的补救措施写 `none_available`（工具只知道版本命中，不知道修复版本）。
  同一条公告被 CPE 和 PURL 两条通道同时命中时只写一条语句，取需要处理最多的状态。
* **组件维护状态与停止支持日期。** FDA 上市前网络安全指南要求 SBOM 里每个组件写明厂商维护支持级别和停止支持日期。
  来源有两个：规则里的 `upstream.support` 块，或 `gangmu scan --support FILE`（JSON / YAML）；文件里的条目优先。
  没有人声明的组件写 `unknown`，不留空，也不猜。CycloneDX 写成 `gangmu:supportStatus` / `gangmu:endOfSupport` 属性，
  SPDX 2.3 写 `validUntilDate`，SPDX 3 写 `supportLevel` 和 `validUntilTime`。状态取值：`maintained`、`limited`（只修安全问题）、
  `no_longer_maintained`、`abandoned`、`unknown`。
* **用真实固件（Zephyr、FreeRTOS、ESP-IDF）跑出的四个问题，已修。**
  1. `gangmu vuln` 对“在树里但没链接进镜像”的组件仍写 `exploitable`。现在读 SBOM 的 `gangmu:linkedIntoImage=false`（或扫描结果），降为 `in_triage` 并写明原因；
     确认后加 `--unlinked-vex` 记为 `not_affected` / `code_not_present`。这些组件在 CycloneDX 里 `scope` 为 `excluded`，SPDX 里有一行说明。
  2. 单体仓库里别的板子的预编译库被当成组件。有链接图时，没被链接图点名的预编译库标 `excluded` 并在扫描结果里给出数量。
  3. 厂商规则在它自己写的路径之外命中时（ESP-IDF 的 FatFs 被 Zephyr 的规则认出），不再把规则里的厂商写成供应商，也不沿用该厂商的 fork 说明。
  4. 规则新增可选字段 `upstream.advisory_scope: subsystem`，给 Zephyr 这类 OS/SDK 树用：公告每条只涉及一个子系统，版本区间命中只写 `in_triage`，不写 `exploitable`。
     免费规则库补上 Zephyr 内核规则（gangmu-rules#7）后，Zephyr 4.1.0 能被识别，它的 189 条版本命中因此不会被误报为可利用。
* **GitLab CI 与 Jenkins 模板**（`examples/ci/`），GitHub Action 新增 `spdx3` 格式和 `support` 输入。模板没有在真实的 GitLab 或 Jenkins 上运行过，
  只验证了 YAML 语法和参数拼装。
* **用真实工程（ST 官方 STM32CubeF1 的 LwIP 示例）验证后修了四个问题。**
  1. IAR（`.ewp`）和 Eclipse/CCS 工程用相对路径传给 `--project` 时，源文件路径被拼了两次，结果是 0 个组件，
     却仍打印“已构建 61 个源文件”。现在先转成绝对路径；工程里列出的源文件全部不存在时直接报错，部分不存在时给出提示。
  2. `--project` 直接传 `.cproject` 文件会报“不支持 .cproject”（点文件没有后缀）。现在可以。
  3. `gangmu wrap` 默认只拦截 cc、gcc、g++、clang、clang++，`arm-none-eabi-gcc` 这类交叉编译器记录 0 步，
     之后 `scan` 还会把所有组件标成“未链接”。现在默认同时拦截 PATH 上所有 `<triple>-gcc`、`-g++`、`-clang`；
     编译数据库里没有任何属于被扫描目录的源文件时，`scan` 报错退出。
  4. GNU ld 的 map 里，开了 `--gc-sections` 后整个目标文件被丢光，但仍出现在 `LOAD` 行，被算作“已链接”。
     现在只有在映像段里实际贡献了字节的目标文件才算已链接；LTO 或 map 里看不到贡献时仍保守地全部保留。
     在该示例里 62 个目标文件有 20 个被判为已被链接器丢掉。

* **`--link-map` 读 IAR ilink、Arm armlink 和 lld 的 map，并能与 IAR、Keil、CCS 工程配合。** 以前链接 map 只认 GNU ld，
  IDE 工程又不记录目标文件路径，所以这几类工程拿不到“编译了但被链接器丢掉”的信息。现在格式自动识别，
  IDE 工程按“源文件名 + .o / .obj”生成目标文件名，与 map 里的 `init.c.obj`、`init.o` 按主干名对齐。
  版式按厂商文档手写测试，尚未用真实工程验证，见 [LIMITS.md](LIMITS.md)。

## 0.6.2

* **GitHub Action 与 pre-commit 钩子。** 根目录 `action.yml`（`uses: GANGMU-SBOM/gangmu@v0`）在 CI 里生成 SBOM；
  `.pre-commit-hooks.yaml` 提供 `gangmu-scan` 钩子。
* **文档。** 按任务组织的指南（ESP-IDF、Zephyr、RT-Thread / OpenHarmony、国密库、魔改组件识别、CRA 与工信部报送）、
  与同类工具的对比页、`examples/output/` 示例产物、FAQ 的 FAQPage 结构化数据。
* 发布工作流只在 `vX.Y.Z` 形式的 tag 上触发，滚动 tag `v0` 不再触发 PyPI 发布。


准确率与噪声。用真实上游版本按 SDK 的摆法摆好再扫（lwIP、Mbed TLS、libcoap、littlefs、FreeRTOS-Kernel、nanopb、
miniz、TinyCrypt、cJSON、wolfSSL、LVGL、RT-Thread，共 12 个真实上游版本，放进两个模拟 SDK）。修复前：第一个 SDK 里
9 份未改动的上游副本有 7 份被标成 `vendor-modified`；nanopb 被报了三次（其中两个是它自己 `examples/` 里的幻影）；
第二个 SDK 丢了 RT-Thread 内核，FatFs 也报在错的目录上。

* **`vendor-modified` 现在只表示"已记录的代码缺失或被改动"。** 以前只要出现签名没见过的函数就触发，而在未改动的
  目录里这指的是签名没覆盖的头文件、移植层和宏（lwIP 2,092 个里有 136 个，FreeRTOS 1,743 个里有 1,487 个），
  `multi_version` 也会被未改动的 lwIP 触发。`vendor_patched` 会进入漏洞匹配的 `is_fork`，所以每个误标都会把真实
  通告降成待研判。现在：9 份未改动副本 0 份被标；改动 3 个 lwIP 函数则被标出，证据里带着个数。只"新增"代码的副本不会被标：
  新增并不改变有漏洞的代码是否还在。
* **已识别组件内部 example / test 目录里的清单不再当作组件。** 即 nanopb 的 `examples/conan_dependency`（多出一个
  0.4.6 的 nanopb）和 `examples/platformio`（再多一个没版本的）。项目自己的 `examples/` 目录照常读取，扫描会说明忽略了几条。
* **组件归到真正存放它的目录。** 函数包含度在每一层祖先目录都会触发，"每目录一个胜者"曾让它把父目录从真正的
  内核手里抢走（RT-Thread 输给了它自己里面的 FatFs）。现在子目录说了同样的话，就丢掉祖先的那条；更弱的嵌套匹配、
  或根目录精确版本对内层区间，都不会顶掉根目录。

* **补丁存在性检测。** `gangmu patch-build CVE` 记录一条公告的修复提交改动了哪些函数（提交号从 OSV 记录读，或用 `--repo`
  和 `--fix` 指定），`gangmu vuln --source ROOT --patches FILE` 看代码而不是看版本：有修复后的函数体就 `resolved`，
  仍是修复前的函数体就确认为 `exploitable`，被厂商改过的留给人判断。魔改的 fork 只报告它所基于的版本号，
  过去每条之后才修复的公告都会让它永远停在 `in_triage`，现在不会了。见 [ALGORITHMS.md](ALGORITHMS.md#patch-presence)。
* **补丁存在性的近似匹配。** 厂商改过的函数以前只能报 `modified`，没有下文。现在记录里还保存修复新增和删去的
  token 窗口，改过的副本可以被报成 `likely_fixed` 或 `likely_vulnerable`，并附上依据的比例。
  只有加 `--patch-near-vex` 才会改 VEX 状态。在 cJSON 的历史上（112 个安全修复 × 49 个发布版）
  它在 1,166 条精确结论之外又给出 853 条正确结论，没有一条错误。
  没有用到识别上：在一个真实 fork 里，98.9% 的函数本来就精确匹配。
* **补丁记录随规则包一起发布。** `gangmu vuln --source ROOT` 会读取已安装规则包里的 `patches/*.json`，社区包的记录
  不用手动指定就生效（`--no-pack-patches` 关闭，`--rules DIR` 指向别的规则目录）。`gangmu patch-verify` 按记录里写明的
  上游提交重新生成并比对；`patch-build --first-parent` 用来记录以 pull request 合入的修复。
  同时修了验证真实记录时发现的两个问题：同一函数有多个修复提交，以及相邻提交的拉取把修复提交留在浅克隆边界上。
* **SBOM 记录每个组件是由哪个规则包识别的。** CycloneDX 组件新增属性 `gangmu:rulePack` 与 `gangmu:rulePackVersion`
  （规则包 `rulebase.json` 里的 `name` 与 `version`；没有清单时用入口点名或目录名，且不带版本），SPDX 的组件备注里写
  “from rule pack …”，`gangmu scan --format json` 的每个发现多出 `rule_pack`、`rule_pack_version`。同一条规则被后加载的包
  覆盖时，记的是后者。来自构建声明或二进制字符串、不经规则识别的组件不带这两个字段。这样团队能看出一份 SBOM 里有多少
  组件是靠哪个规则包识别的，也是商业规则包“价值报告”的数据来源。

## 0.6.1

在干净环境里从 PyPI 验证 0.6.0 时发现并修复的问题。

* **`gangmu init DIR` 在 `DIR` 不存在时不再崩溃。** 现在会自动创建目录；目标写不进去时只打印一行错误，不再抛
  Python traceback。
* **测试输入不再被当作固件。** 名为 `test`、`tests`、`testdata`、`test_data`、`fuzz`、`fixtures` 的目录之下的
  `.bin`、`.elf`、`.axf` 文件（比如 lwIP 的 `test/fuzz/inputs/*.bin`，其实是模糊测试的数据包）不再被列为预编译镜像，
  也就不会出现在 SBOM 里，或者变成 `gangmu vuln` 无法查询的组件。`.a`、`.lib`、`.so` 在任何目录里都照常列出。

## 0.6

### 快：整棵 SDK 十秒级，规则再多也不线性变慢

纲目要放进每一次固件构建的 CI，扫描一棵完整 SDK 就不能是"去喝杯咖啡"的事。4 核机器，ESP-IDF v5.4.2 带全部子模块：

| 设置 | 0.5 | 0.6 |
| --- | --- | --- |
| 单进程，无缓存 | 72.5 s / 366 MB | **11.0 s / 123 MB** |
| 4 进程，冷缓存 | 35.8 s | **5.5 s** |
| 4 进程，再扫一遍 | 10.2 s | **2.1 s** |

两个版本识别结果逐条一致，另外 6 棵本地树也逐条比对过。做法是：每个文件按内容哈希只分析一次；用精确的分文件 bottom-k 草图，结果与原算法完全相同；SQLite 增量缓存，键里带分析代码的摘要，代码一改缓存自动失效；规则预筛，把不可能命中的规则直接跳过。

性能也进了 CI。`gangmu perf --check benchmarks/perf-baseline.json` 会把识别结果、分词次数、匹配次数、耗时（校准单位）和峰值内存与基线比较，有任何一项退步，PR 就不能合并。详见 [docs/PERFORMANCE.md](PERFORMANCE.md)。

### FreeRTOS 与 RT-Thread：厂商把内核挪到哪里都能找到

国产芯片 SDK 几乎都带一份 RTOS 内核，但常常改了目录名（`freertos_riscv`、`bl702_freertos`），不带 LICENSE，有时还藏在三层深的示例目录里。0.6 的规则改用"标志文件"来定位：`tasks.c` + `queue.c` + `list.c` 同时出现，就是 FreeRTOS；`src/thread.c` + `src/ipc.c` + `include/rtthread.h` 同时出现，就是 RT-Thread。找到目录后，再用函数签名判断版本。FreeRTOS 的签名覆盖 28 个发布版，RT-Thread 覆盖 27 个。

测试对象是博流、沁恒、联盛德、乐鑫共 7 个 SDK 里的 14 份内核副本，**14/14 全部找到**。报告的版本要么正好是厂商头文件里写的那个，要么是一个包含它的区间，区间里的几个发布版内核代码相同。这 14 份在 0.5 里一份都找不到。加上这两条规则后，扫描耗时的变化在测量噪声以内。

### Mbed TLS、FatFs、littlefs：不再只认 Zephyr 和 ESP-IDF 的目录

这三个库原有的规则只认 Zephyr（`modules/crypto/mbedtls`）和 ESP-IDF（`components/mbedtls/mbedtls`）的布局。国产 SDK 里它们却到处都是，而且这是漏洞所在：博流、联盛德、乐鑫 ESP8266 的 SDK 里，Mbed TLS 的 CVE 远多于厂商自己的 HAL。现在各有一条通用规则，用标志文件定位，不管目录叫什么：

* `generic/mbedtls`：63 个发布版，2.1.18 到 4.2.0（2.16.x、2.17 到 2.28.x、3.x 逐版齐全）；
* `generic/fatfs`：R0.10a 到 R0.16 共 20 个发布版；
* `generic/littlefs`：1.7.2 和 2.0.0 到 2.11.3 共 38 个发布版。

在 5 套 SDK 里找到的 12 份副本（Mbed TLS 6 份，FatFs 4 份，littlefs 2 份）**全部识别，版本全部正确或是包含正确版本的区间**。另外用 34 棵真实上游发布版目录（改名、删掉版本头文件、改动源文件三种方式）测试，34 棵都识别为正确的组件，28 棵版本精确，6 棵是包含正确版本的区间，0 棵错误。详见 [docs/BENCHMARK.md](BENCHMARK.md#1d-third-party-libraries-inside-chinese-vendor-sdks)。

后续又加入 LVGL（54 个发布版，6.0 到 9.6.0）、libcoap（13 个）和 TinyCrypt（7 个）。其中 LVGL、libcoap、TinyCrypt 的 CPE 状态是"未核实"：写规则时 NVD 不可达，没有猜测。5 套 SDK 里的 7 份副本全部识别，另用 25 棵真实发布版目录测试，25 棵都识别为正确的组件，21 棵版本精确，4 棵是包含正确版本的区间，0 棵错误。

这一步暴露并修复了两个问题：同一目录被通用规则和 Zephyr/ESP 规则同时认出时，原来按规则的"具体程度"裁决，于是一份原版 Mbed TLS 4.1.1 被报成"Zephyr 的 4.1.0，已改动"，原版 littlefs 2.11.3 被报成 `git-e9a8638fc228`（这种版本号无法和 CVE 的版本范围比较）。现在证据种类多的一方、版本可比较的一方优先，厂商规则在自己的路径上仍然胜出。另外版本比较此前忽略末尾字母，`1.1.1k` 与 `1.1.1n` 比较为相等（在 1.1.1n 修复的 CVE，因此被判为不影响 1.1.1k），FatFs 的标签 `R0.14b` 被当成 beta；两处都已修正并加了测试。

### CPE 从 NVD 证据里来，全量 NVD 直接读

`gangmu rules cpe-evidence --nvd DIR` 逐条检查 CVE：只要它的参考链接指向某条规则的上游仓库或官网，这条 CVE 配置里写的 vendor:product 就算作证据。工具按证据多少排序，交给人工确认。这次查出的结果：

- FreeRTOS、RT-Thread、OpenThread、FatFs 有了 CPE；
- cJSON 有 13 条 CVE 登记在 `davegamble:cjson` 下，原规则只写了 `cjson_project:cjson`，以前全部漏掉；
- 每个新 CPE 都在规则里用 `cpe_evidence` 列出所依据的 CVE。

`gangmu vuln` 现在能直接读完整的 NVD 镜像，包括压缩的 `.json.xz`，同一份 SBOM 从 200.8 s、3.9 GB 降到 8.9 s、25 MB。在 8 个 SDK 上，漏洞比对结果从 133 条增加到 243 条。沁恒的 3 个 SDK 和 ESP8266 SDK 以前是 0 条，现在各有 12 到 17 条。

### OpenHarmony：部件和依赖关系，直接读 `bundle.json`

OpenHarmony 的每个部件都带一份 `bundle.json`，里面写着部件名、子系统、版本、许可证，以及它依赖哪些部件和第三方库。这是源码树里唯一记录"谁用了谁"的地方，而一个 CVE 出来后，大家最先问的就是这个问题。纲目现在会读取它：

- OpenHarmony 自身的部件作为组件列入 SBOM；
- 第三方目录在 `README.OpenSource` 给出的上游身份之外，再加上部件名；
- 依赖关系写进 CycloneDX 的 `dependencies` 和 SPDX 的 `DEPENDS_ON`；
- 声明了、但在树里找不到的依赖，会在组件属性里列出，不会悄悄丢掉。

在海思 Hi3861 轻量系统的整机代码上测试（官方清单 `default_mini.xml` 的 43 个仓库，18 万个文件），识别出的组件从 15 个增加到 45 个，依赖边从 0 条增加到 89 条，扫描耗时不变（28.9 s）。现在能直接看出 Mbed TLS 被 device_auth、huks、dsoftbus、init 等 6 个部件用到。

## 0.4–0.5

### RT-Thread 与 OpenHarmony：有包管理器，就直接读声明

声明式信息比任何相似度都准。国产生态在这一点上反而比国际生态更好做，
因为声明就躺在源码树里：

| 生态 | 读什么 | 声明的是 |
| --- | --- | --- |
| RT-Thread | `.config` 中的 `CONFIG_PKG_USING_*` / `_PATH` / `_VER`，以及 `packages/pkgs.json` | **软件包**的版本 |
| OpenHarmony | 各第三方目录下的 `README.OpenSource`；0.6 起还读各部件的 `bundle.json` | **上游**名称、版本、许可证、地址；部件名与依赖关系 |
| Yocto / OpenEmbedded | 构建产物 `tmp*/deploy/licenses/*/license.manifest`（没有就读 `images/*/*.manifest`；都没有，才读 `local.conf` / 镜像配方里 `IMAGE_INSTALL` 选中的 `.bb`） | **上游**名称、版本、许可证；`_git.bb` 这类跟踪分支的配方没有发布版本，只报名称 |
| PlatformIO | `.pio/libdeps/*/*/library.json`（已下载，版本确切，目录也会照常做指纹识别）；其次是 `platformio.ini` 的 `lib_deps` | **上游**名称与版本；`^1.2` 这类版本范围不当作版本，只报名称 |
| Conan | `conan.lock`（确切版本），其次 `conanfile.txt` 的 `[requires]`、`conanfile.py` 的 `requires` / `self.requires()`；`tool_requires` 不算（跑在构建机上，不在固件里） | **上游**名称与版本；`[>=3.0 <4]` 这类范围不当作版本 |
| Bazel | `MODULE.bazel` 的 `bazel_dep`（去掉 `.bcr.N` 得到上游版本），以及 `WORKSPACE` 的 `http_archive` / `git_repository`（版本取自 `strip_prefix`、URL 或 tag）；开发依赖和 `rules_*` 工具链模块不算 | **上游**名称与版本；读不出版本的只报名称 |

两者的差别直接影响 CVE 匹配，所以处理方式不同：

- OpenHarmony 声明的是上游版本，规则库里的 CPE 可以直接套用；
- RT-Thread 的 `v1.0.2` 是软件包自己的标签，**绝不拼进上游 CPE**。gangmu 会照常对该目录做指纹识别，
  由规则库给出里面真正的上游版本，软件包声明作为证据附上；
- `.config` 里选了但还没下载的包，会作为提示列出，而不是悄悄消失。

```
$ gangmu scan rt-thread-bsp/ --format table
CONF  COMPONENT  VERSION  SRC    DIRECTORY              NOTES
----  ---------  -------  -----  ---------------------  -----
0.75  cJSON      1.7.17   probe  packages/cJSON-v1.0.2

note: rt-thread: package webclient v2.2.0 is selected in .config but not downloaded
```

声明与代码不一致时（比如 `README.OpenSource` 写 1.4.0、锚点文件证明是 1.4.2），
以代码为准，并把分歧写进证据交给人工判断。用 `--no-declared` 可以关闭这一层。

### 国密库识别

商用密码合规审查必查，国际 SBOM 工具完全不认识这些组件。

| 组件 | 覆盖版本 | 识别方式 |
| --- | --- | --- |
| GmSSL 3.x | 3.0.0、3.1.0、3.1.1、3.2.0 | 逐版本锚点 + 四版本函数签名 + 版本探针 |
| GmSSL 2.x（独立规则 `generic/gmssl-2`） | 2.0.0–2.5.4，共 20 个版本 | 逐版本锚点 + 20 版本函数签名 + 版本探针；上游没有 2.x 标签，固定到提交 |
| 铜锁 Tongsuo（含 BabaSSL 时期） | 8.1.3、8.2.0、8.2.1、8.3.0–8.3.3、8.4.0、8.5.0 | 逐版本锚点 + 九版本函数签名 + 版本探针 |
| OpenSSL | 1.1.0–1.1.0l、1.1.1–1.1.1w 全部版本，及 3.0–3.6 各线最新补丁版 | 逐版本锚点 + 44 版本函数签名 + 版本探针 |

铜锁是 OpenSSL 3.0 的分支，两者共享上万个函数。同时加载两条规则时，共享的函数
对谁都不算身份证据（CENTRIS 的代码分割），各自只靠自己独有的代码被认出来。

这里抓到过一个真问题：分割原本只做在精确哈希层，抗重命名的抽象层漏掉了。结果一棵
原版 OpenSSL 3.0.22 通过共享代码以 0.90 的身份置信度「也像铜锁」，反过来也一样。
0.5 把分割同时做到抽象层之后，每棵树只匹配自己的规则。

### 国产芯片 HAL

用已有的 west 导入器，从 Zephyr 4.4 的锁定提交直接生成，全部能从上游逐字节复现：

博流智能 BL60x/BL70x、沁恒 CH32（ch32fun）、思澈科技 SiFli、泰凌微 TLSR9、瑞昱 Ameba/Bee，
加上此前的兆易 GD32。

### Zephyr 模块自带的安全声明

Zephyr 模块可以在 `zephyr/module.yml` 的 `security.external-references` 里声明 CPE 和 PURL，
Mbed TLS、nanopb、hostap、TF-M 都这样做了。gangmu 现在把它当作厂商清单读取，扫描和规则导入都用得上。

据此重新导入后，纠正了一条旧规则的错误判断：Zephyr 的 `modules/crypto/mbedtls` 不是一层构建胶水，
而是 Mbed TLS 4.1.0 本体，现在带着正确的 CPE 与 PURL。同时新增了 hostap（wpa_supplicant / hostapd），
它是 Zephyr Wi-Fi 的基础，也是漏洞高发组件。
