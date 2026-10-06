# 更新记录

这里记录各版本新增的能力和当时的评测结果，按版本倒序。当前能力总览见 [README](../README.md)，各家国产生态的覆盖见 [CHINA.md](CHINA.md)。

## 未发布

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
