# 纲目 Gangmu：嵌入式固件 SBOM 与 CRA 合规工具

**面向嵌入式 C/C++ 的构建期 SBOM 工具，配一份社区共建的芯片 SDK 组件识别规则库。**

识别被芯片原厂改名、魔改、静态链接后的开源组件（包括国产芯片 SDK 与国密库），
生成 CycloneDX / SPDX 软件物料清单和 VEX，对照欧盟《网络弹性法案》（CRA）自查，
并起草 CRA 与工信部的漏洞报送材料。

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rules: CDLA-Permissive-2.0](https://img.shields.io/badge/rules-CDLA--Permissive--2.0-blue.svg)](https://github.com/GANGMU-SBOM/gangmu-rules/blob/main/rules/LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6-green.svg)](https://cyclonedx.org/)
[![SPDX 2.3](https://img.shields.io/badge/SPDX-2.3-green.svg)](https://spdx.dev/)

[English](README.en.md) · [规则库 gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) · [评测 gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench) · [常见问题](docs/FAQ.md) · [术语表](docs/GLOSSARY.md) · [规则格式](docs/RULE-FORMAT.md) · [评测基准](docs/BENCHMARK.md) · [CRA 对标](docs/CRA.md) · [国内合规](docs/CHINA.md)

> **名称由来**：「纲目」取自李时珍《本草纲目》。那部书把近两千种药物按「纲」分部、按「目」列种，
> 每一味都写明出处、形态与性味，后世才能辨认、比对、追溯。
> 固件里的第三方代码需要的正是这件事：被改了名、换了位置的组件，也要能认出它是哪个上游项目的哪个版本，
> 并且每一条结论都附上可以复核的证据。

---

## 先看一个例子

拿一份真实的 GmSSL 3.0.0，照着芯片原厂 SDK 的常见做法处理一遍：

- 改名：目录换成 `components/crypto_sm`；
- 删掉版本头文件 `include/gmssl/version.h`；
- 把三分之一源文件里的 `sm3_` / `sm4_` 前缀改成 `vendor_sm3_` / `vendor_sm4_`；
- 往这些文件里塞进厂商自己的函数；
- 再删掉 8 个源文件。

然后问 gangmu 这是什么：

```
$ gangmu scan firmware/ --format table
CONF  COMPONENT  VERSION  SRC        DIRECTORY             NOTES
----  ---------  -------  ---------  --------------------  ---------------
0.88  GmSSL      3.0.0    functions  components/crypto_sm  vendor-modified

  - 1280 of 1508 functions of GmSSL 3.0.0 are present (0.849 containment, strong)
  - 758 version-discriminating function(s) matched; 758 are in 3.0.0 (agreement 0.85);
    35 function(s) match no recorded version at all (vendor additions, ...)
```

名字对，版本对，并且明确标出这是**被厂商改过的副本**，不是上游原版。
上面每一行都可以复现：`./examples/disguise.sh`。

这就是嵌入式 SBOM 的真实难点，也是这个项目要解决的问题。

## 为什么 C/C++ 嵌入式的 SBOM 做不好

Python、JavaScript、Go、Rust 都有锁文件，生成 SBOM 基本就是读文件。嵌入式 C/C++
没有，而且还会再抹掉四层证据：

1. **没有包管理器**，第三方源码直接拷进工程；
2. **芯片原厂改名魔改**，ESP-IDF 里的 lwIP 是乐鑫的分支，不是上游 2.2.0；
3. **全部静态链接**，产物里没有任何依赖信息；
4. **编译的远多于出货的**，源码树里有、链接时被丢掉的代码比比皆是。

只扫源码树会**多报**，只分析二进制会**少报**。gangmu 读的是**构建过程**：
`compile_commands.json` 说明编译了什么，链接 map 说明最终留下了什么，
组件身份则对照一份任何人都能贡献的外部规则库来判定。

## 关键数字

除标注「需商业版规则包」的行外，全部可以用仓库里的工具复现，方法和数据见 [docs/BENCHMARK.md](docs/BENCHMARK.md) 与 [docs/PERFORMANCE.md](docs/PERFORMANCE.md)。

| 指标 | 结果 |
| --- | --- |
| 区分「厂商 fork」与「换了个版本」 | 目录级相似度只差 **0.06**；函数级拉开到 **0.25**（四倍） |
| 真实 lwIP 发布版的版本识别 | **6/6 精确**（其中乐鑫生产 fork 一行需商业版规则包） |
| 合成厂商修改下的识别 | **9/9 识别、9/9 版本正确**（改名、删文件、加代码、重排版） |
| 重命名 10% 标识符后的保留率 | 精确哈希 0.480 → 抽象层 **0.876** |
| SBOM 最小要素 | NTIA 2021 与 CISA 2026 均 **10.0 / 10** |
| 匹配开销 | 函数集比 winnowing 指纹小 **54 倍**，0.28 s vs 0.59 s |
| 整棵 ESP-IDF v5.4.2（10,767 个源文件；含商业版乐鑫规则包） | 单进程 72.5 s → **11.0 s**，内存 366 → 123 MB；4 进程再扫一遍 **2.1 s** |
| 规则从 27 条扩到 432 条（含商业版规则包） | 扫描 3.2 s → 6.8 s（0.5 是 21.3 s → 56.8 s） |
| 国产 SDK 里的 RTOS 内核 | 7 个 SDK 中 **14/14** 份 FreeRTOS / RT-Thread 副本全部找到，版本全对或区间包含真值 |
| 读完整 NVD 镜像做漏洞比对 | 200.8 s / 3.9 GB → **8.9 s / 25 MB**，结果逐条一致 |

为什么换到函数级：一个厂商 fork 往往**同时包含多个上游版本的函数**。
在整棵树的相似度上，它恰好落在两个相邻版本之间，任何阈值都分不开；
在函数级上，版本来自「这些函数属于哪几个发布版」，而不是来自一个距离。
算法参考 CENTRIS（ICSE 2021）与 TIVER（ICSE 2025），细节见
[docs/ALGORITHMS.md](docs/ALGORITHMS.md)。

## 快速上手

需要 Python 3.9+。

```bash
pip install gangmu-sbom      # 或 pipx install gangmu-sbom；加 [fast] 启用可选 numpy，结果逐值一致（会一并装上规则库 gangmu-rules）
gangmu init          # 生成 gangmu.yaml：产品名、制造商、销售市场、支持期限
```

必填项填一次，之后所有命令都读这份配置。CI 和开发机产出同一份文档，
没有人需要在凌晨两点把产品版本号手打进报送表单。

### 生成 SBOM

```bash
# 只看源码树（会多报）
gangmu scan ~/esp/my-project

# 结合构建事实（推荐）
gangmu scan ~/esp/my-project \
    --compile-db build/compile_commands.json \
    --link-map   build/my-project.map \
    --format cyclonedx -o sbom.json

# 没有 compile_commands.json：读 IDE 工程，或者旁观一次真实构建
gangmu scan ~/proj --project app.ewp --configuration Release   # IAR / Keil / CCS
gangmu wrap -o compile_commands.json -- make -j8

# 只有 sdkconfig 或 Zephyr 的 .config：配置里关掉的组件不进 SBOM（自动读取根目录或 build/ 下的，
# 也可以用 --kconfig 指定；只对规则里声明了 config_symbols 的组件生效，配置没提到的选项不会删掉任何东西）
gangmu scan ~/esp/my-project --kconfig sdkconfig
```

```
build facts: {'compiled': 19, 'linked': 17, 'droppedAtLink': 2, 'ambiguousObjects': 0}

CONF  COMPONENT  VERSION  SRC     DIRECTORY                NOTES
----  ---------  -------  ------  -----------------------  ---------------
0.95  cJSON      1.7.19   anchor  components/json/cJSON
0.95  cJSON      1.7.19   anchor  components/legacy/cJSON  not linked
0.95  lwIP       2.2.0    anchor  components/lwip/lwip     vendor-modified

1 candidate director(ies) unidentified: components/lwip
```

这段输出里有三件事是只扫源码的工具做不到的：

- **`not linked`**：这份 cJSON 编译过，但链接时被丢掉了。写进 SBOM，就要白白追它三年的 CVE。
- **`vendor-modified`**：ESP-IDF 带的是乐鑫的 lwIP 分支。SBOM 在 `pedigree` 里如实写明祖先版本和厂商补丁。
- **`unidentified`**：有个目录像组件，但没有规则认得它。明确告诉你，比悄悄漏掉有用得多。

许可证以规则里记录的上游许可证为准；同时读组件目录里的 `SPDX-License-Identifier` 文件头和顶层 LICENSE / COPYING，
看到规则没提的许可证时，在 SBOM 里加 `gangmu:observedLicenses` 和 `gangmu:licenseDiffersFromRule` 两个属性，不替你选。
规则没有许可证的组件，用目录里自己声明的。LICENSE 文本只认 Apache-2.0、MIT、BSD、ISC、Zlib、MPL-2.0、BSL-1.0 这几种措辞明确的，
GPL 类只信 SPDX 文件头。`--no-licenses` 关闭。

### 漏洞比对与合规

```bash
gangmu vuln-fetch --db advisories/ --sbom sbom.json    # 有网的机器上：只拉这份 SBOM 用得到的 NVD / OSV 记录
gangmu vuln sbom.json --db advisories/ -o vex.json     # NVD / OSV 本地镜像（可直接用 .json.xz 全量库），输出 CycloneDX VEX
gangmu vuln sbom.json --db advisories/ --cn-db cnnvd/  # 加上国内漏洞库通道
gangmu cra-check --sbom sbom.json --vex vex.json       # 逐条对照 CRA，有阻塞缺口时返回非零
gangmu evidence --out cra-evidence/                    # 十年留存的技术文档包
```

漏洞暴露后：

```bash
# 欧盟 CRA 第 14 条：24 小时预警草稿
gangmu report CVE-2027-12345 --stage early-warning --vex vex.json \
    --aware-at 2027-05-14T08:12Z -o 24h-draft.md

# 工信部《网络产品安全漏洞管理规定》第七条：2 日内报送的中文草稿
gangmu report CVE-2027-12345 --regime cn-miit --vex vex.json \
    --aware-at "2027-05-14 08:12" --scope "全系列，出货约 4.2 万台"
```

缺的字段明确标 `MISSING`，绝不编造。

多个产品型号、多条时限需要团队协作跟踪时，可以使用[商业版的报送工作台](docs/EDITIONS.md)。

## 近期新增（0.6）

### 快：整棵 SDK 十秒级，规则再多也不线性变慢

纲目要放进每一次固件构建的 CI，扫描一棵完整 SDK 就不能是"去喝杯咖啡"的事。4 核机器，ESP-IDF v5.4.2 带全部子模块：

| 设置 | 0.5 | 0.6 |
| --- | --- | --- |
| 单进程，无缓存 | 72.5 s / 366 MB | **11.0 s / 123 MB** |
| 4 进程，冷缓存 | 35.8 s | **5.5 s** |
| 4 进程，再扫一遍 | 10.2 s | **2.1 s** |

两个版本识别结果逐条一致，另外 6 棵本地树也逐条比对过。做法是：每个文件按内容哈希只分析一次；用精确的分文件 bottom-k 草图，结果与原算法完全相同；SQLite 增量缓存，键里带分析代码的摘要，代码一改缓存自动失效；规则预筛，把不可能命中的规则直接跳过。

性能也进了 CI。`gangmu perf --check benchmarks/perf-baseline.json` 会把识别结果、分词次数、匹配次数、耗时（校准单位）和峰值内存与基线比较，有任何一项退步，PR 就不能合并。详见 [docs/PERFORMANCE.md](docs/PERFORMANCE.md)。

### FreeRTOS 与 RT-Thread：厂商把内核挪到哪里都能找到

国产芯片 SDK 几乎都带一份 RTOS 内核，但常常改了目录名（`freertos_riscv`、`bl702_freertos`），不带 LICENSE，有时还藏在三层深的示例目录里。0.6 的规则改用"标志文件"来定位：`tasks.c` + `queue.c` + `list.c` 同时出现，就是 FreeRTOS；`src/thread.c` + `src/ipc.c` + `include/rtthread.h` 同时出现，就是 RT-Thread。找到目录后，再用函数签名判断版本。FreeRTOS 的签名覆盖 28 个发布版，RT-Thread 覆盖 27 个。

测试对象是博流、沁恒、联盛德、乐鑫共 7 个 SDK 里的 14 份内核副本，**14/14 全部找到**。报告的版本要么正好是厂商头文件里写的那个，要么是一个包含它的区间，区间里的几个发布版内核代码相同。这 14 份在 0.5 里一份都找不到。加上这两条规则后，扫描耗时的变化在测量噪声以内。

### Mbed TLS、FatFs、littlefs：不再只认 Zephyr 和 ESP-IDF 的目录

这三个库原有的规则只认 Zephyr（`modules/crypto/mbedtls`）和 ESP-IDF（`components/mbedtls/mbedtls`）的布局。国产 SDK 里它们却到处都是，而且这是漏洞所在：博流、联盛德、乐鑫 ESP8266 的 SDK 里，Mbed TLS 的 CVE 远多于厂商自己的 HAL。现在各有一条通用规则，用标志文件定位，不管目录叫什么：

* `generic/mbedtls`：63 个发布版，2.1.18 到 4.2.0（2.16.x、2.17 到 2.28.x、3.x 逐版齐全）；
* `generic/fatfs`：R0.10a 到 R0.16 共 20 个发布版；
* `generic/littlefs`：1.7.2 和 2.0.0 到 2.11.3 共 38 个发布版。

在 5 套 SDK 里找到的 12 份副本（Mbed TLS 6 份，FatFs 4 份，littlefs 2 份）**全部识别，版本全部正确或是包含正确版本的区间**。另外用 34 棵真实上游发布版目录（改名、删掉版本头文件、改动源文件三种方式）测试，34 棵都识别为正确的组件，28 棵版本精确，6 棵是包含正确版本的区间，0 棵错误。详见 [docs/BENCHMARK.md](docs/BENCHMARK.md#1d-third-party-libraries-inside-chinese-vendor-sdks)。

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

## 此前新增（0.4–0.5）

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

免费规则库 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) 现有 **60 条**规则；只跟某一家公司绑定的规则属于商业版规则包，见 [docs/EDITIONS.md](docs/EDITIONS.md)。

## 规则库才是核心

生成器一个周末就能重写；「哪个目录是哪个上游的哪个版本」是数据，只能靠很多人一起积累。
所以规则放在单独的仓库 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)，用更宽松的 CDLA-Permissive-2.0 授权，任何项目和产品都能直接使用。
规则按日期独立发布，`pip install -U gangmu-rules` 就能拿到新规则，不用等工具发版。
自有 BSP 或未公开 SDK 的规则可以放在自己的目录里，用多个 `--rules` 叠加在社区规则之上。

规则分两部分：免费的 gangmu-rules 放被各家 SDK 拷贝最多的通用开源组件、Zephyr 及其 HAL 模块和社区贡献的规则；
只跟某一家公司绑定的规则（这家公司自己的 SDK、固件库，或它 fork 过的开源组件）属于商业版规则包，需要请联系我们（见文末）。规则 id 两边一致，装上商业版规则包后自动叠加。

一条规则的贡献和审核成本都接近于零：

```bash
# 从一个干净的上游发布版生成识别块
gangmu rules fingerprint cJSON --version 1.7.19 \
    --include 'cJSON.c' --include 'cJSON.h' --anchor cJSON.h

# 或者从 SDK 自己的锁定信息批量导入（在 gangmu-rules 的检出目录里运行）
gangmu rules import https://github.com/espressif/esp-idf \
    --vendor espressif --sdk esp-idf --out rules/espressif/esp-idf/
```

向 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) 提交 PR 后，CI 会克隆规则声明的那个上游版本，把所有证据重新算一遍：

```
$ gangmu rules verify --rule generic/gmssl
ok   generic/gmssl
       + anchor include/gmssl/version.h matches 3.2.0
       + fileset hash reproduces exactly (190 files)
       + signature reproduces exactly (similarity 1.0000)
       + probe on include/gmssl/version.h yields 3.2.0
```

对不上就直接拒绝，并给出差异。第一条 cJSON 规则就是这样被拦下的：
用仓库 HEAD 取指纹却声称是 v1.7.19，相似度 0.9922，期望 1.0。

**规则库不猜 CPE。** 免费规则库 60 条里有 29 条带 CPE。新加的 CPE 都附有 NVD 里的 CVE 作为证据（`cpe_evidence`）。另外 31 条没有 CPE，每条都写明原因，多数是在完整的 NVD 镜像里确实查无记录。
写错一个字的 CPE 匹配不到任何 CVE，SBOM 看起来却是干净的，这是规则出错最昂贵的方式。
所以 PURL / OSV 是一等通道，不是兜底。

当前覆盖：

| 来源 | 组件 |
| --- | --- |
| 通用 | lwIP、cJSON、OpenSSL、GmSSL（3.x 与 2.x）、铜锁、FreeRTOS 内核、RT-Thread 内核、TencentOS-tiny 内核、AliOS Things 内核、LiteOS-M / LiteOS-A / LiteOS 5.x 内核、Mbed TLS、TF-PSA-Crypto、FatFs、littlefs、LVGL、libcoap、TinyCrypt、nghttp2、libwebsockets、Paho MQTT C、OpenThread、AWS IoT Device SDK |
| Zephyr | Mbed TLS 4.1、TF-PSA-Crypto、hostap、FatFs、littlefs、MCUboot、nanopb、zcbor、uOSCORE/uEDHOC |
| 国产与亚太芯片 HAL | 兆易、博流、沁恒、思澈、泰凌微、瑞昱 |

覆盖的国产厂商与项目（含商业版规则包；规则或 SDK 识别至少有一项，覆盖深度各不相同）：

<p><img src="docs/vendors/espressif.svg" alt="乐鑫 Espressif"> <img src="docs/vendors/bouffalo.svg" alt="博流 Bouffalo"> <img src="docs/vendors/winnermicro.svg" alt="联盛德 WinnerMicro"> <img src="docs/vendors/wch.svg" alt="沁恒 WCH"> <img src="docs/vendors/gigadevice.svg" alt="兆易 GigaDevice"> <img src="docs/vendors/hdsc.svg" alt="华大 HDSC"> <img src="docs/vendors/nationstech.svg" alt="国民技术 Nations"> <img src="docs/vendors/rockchip.svg" alt="瑞芯微 Rockchip"> <img src="docs/vendors/allwinner.svg" alt="全志 Allwinner"> <img src="docs/vendors/telink.svg" alt="泰凌微 Telink"> <img src="docs/vendors/realtek.svg" alt="瑞昱 Realtek"> <img src="docs/vendors/sifli.svg" alt="思澈 SiFli"> <img src="docs/vendors/openluat.svg" alt="合宙 openLuat"> <img src="docs/vendors/huawei.svg" alt="华为 LiteOS / OpenHarmony"> <img src="docs/vendors/tencent.svg" alt="腾讯 TencentOS-tiny"> <img src="docs/vendors/alibaba.svg" alt="阿里 AliOS Things"> <img src="docs/vendors/rt-thread.svg" alt="睿赛德 RT-Thread"> <img src="docs/vendors/gmssl.svg" alt="北大 GmSSL"> <img src="docs/vendors/tongsuo.svg" alt="蚂蚁 Tongsuo"></p>

这些是文字标识，不是厂商 logo；仓库里没有放任何厂商的图形标志，因为没有逐家核对它们的品牌使用条款。
各家具体覆盖了什么，见 [docs/CHINA.md](docs/CHINA.md)。

贡献规则见 [gangmu-rules 的贡献指南](https://github.com/GANGMU-SBOM/gangmu-rules/blob/main/CONTRIBUTING.md) 与 [docs/RULE-FORMAT.md](docs/RULE-FORMAT.md)；改工具本身见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 两套报送义务

对出口欧盟的国内厂商，CRA 不是唯一的报送义务，也不是触发最频繁的那个。

| | 《网络产品安全漏洞管理规定》第七条 | CRA 第 14 条 |
| --- | --- | --- |
| 触发 | **发现**漏洞 | 漏洞**被积极利用** |
| 时限 | **2 日内** | 24 小时 / 72 小时 / 14 天 |
| 平台 | 工信部 cstis.cn | ENISA 单一报告平台 |

还有一处工具不该替人下结论的张力：该规定第九条第（七）项禁止向境外组织提供未公开漏洞信息，
未设例外；而 CRA 要求 24 小时内向 ENISA 报送未公开漏洞。gangmu 在生成欧盟草稿时
就把这一点摆出来，明确说明这是法务判断，而不是让团队在倒计时第 20 小时才第一次想到。
详见 [docs/CHINA.md](docs/CHINA.md)。

`gangmu cra-check` 同样克制：CRA 相关的十个条款里，有五个只会返回 partial、declared
或 out of scope。配置文件里的一个 URL 不是政策被执行的证据，扫描也不是安全测试。
详见 [docs/CRA.md](docs/CRA.md)。

## 能力边界

坦白列出来，因为缺口就是路线图：

- **不做深度二进制分析。** 没有源码也没有构建，指纹比对和构建事实都无从下手；对 `.a`、`.lib`、`.so`、
  `.elf`、`.axf`、`.bin` 只做清单（路径、SHA-256、大小）、解开 HEX、S-record、UF2 和 gzip/xz/bzip2/zlib/zip 封装、读版本横幅和导出符号（ELF 会解析符号表并标注是否已剥离），作为较低置信度的补充证据。
  装了可选依赖 Capstone（`pip install 'gangmu-sbom[disasm]'`）后，还能从 ELF 和带 Cortex-M 向量表的 `.bin` 里恢复函数边界（`gangmu binary-functions`，支持 Thumb、ARM、AArch64、RISC-V、x86；**不支持 Xtensa**，即 ESP32 经典款和 ESP8266，因为 Capstone 没有 Xtensa 解码器）。在此之上还有逐函数指纹（`gangmu rules binary-prints`，规则里的 `identity.binary_functions`；生成命令会先用作者提供的、同一版本的多个构建互相验证，没通过就不写文件，规则里必须带验证结果）：每个函数引用的字符串和用到的显著常量，从机器码里还原。真实固件上的验证（Cortex-M3、rv32imac 和 AArch64 三种架构，各 7 个库、20 个版本、4 个优化级别，`gangmu binary-eval` 可复现）见 [docs/BINARY-VALIDATION.md](docs/BINARY-VALIDATION.md)：参考库必须用**和固件同一种架构**编译，且只含库自己的代码；负对照 1920 对 0 次误报；给出答案的里约 2.6% 是错的，多数答案是 `低~高` 区间；有指纹的函数太少的小库（inih、heatshrink、cJSON）认不出来。
  这是有意的取舍：对剥离过符号的 MCU 镜像，这种办法能恢复名字、偶尔恢复版本，却填不满 CRA 要求的字段。
- **评测规模有限。** 实测覆盖 lwIP、FreeRTOS、RT-Thread、国密与 OpenSSL 系列、Mbed TLS、FatFs、
  littlefs、LVGL、libcoap、TinyCrypt、TencentOS-tiny、nghttp2 等十几个组件族，共约一百多棵真实上游树
  和国产 SDK 里的几十份副本（见 [docs/BENCHMARK.md](docs/BENCHMARK.md)）；
  CENTRIS 的评测集是 10,241 个项目。方法是对的，规模还不是。
- **规则还少。** 引擎和导入器能承载上千条，数据还没到。全志 Tina Linux 的 SDK（RTOS SDK 已覆盖）
  不在 Zephyr 上游，需要单独导入。
- **递归导入对两种清单都可用，但 west 只支持常用的 `import` 写法。** `gangmu rules import --recursive`
  对 `.gitmodules` 会沿着子模块里的子模块导入；对 west 清单（`--manifest west`）会跟随项目和 `manifest: self:` 里的
  `import:`（`true`、文件/目录路径、带 `name/path-allowlist`、`name/path-blocklist`、`path-prefix` 的映射及其列表），
  深度上限 4 层，按项目名和 (url, 提交) 防环。`import-flags`、通过 west 扩展命令的导入不支持。
- **`gangmu vuln` 本身不联网。** 很多固件团队在内网开发，一份必须联网才能出的报告，
  在工厂内网里出不来，在漏洞披露后的 24 小时里也出不来。联网的一步单独做成
  `gangmu vuln-fetch`：在有网的机器上跑，把目录带进内网即可。
- **编译器包装器只能拦截按名字查找的编译器。** Makefile 里写死绝对路径（`CC=/opt/gcc/bin/gcc`）会绕过 PATH 上的 shim；
  Windows 下 shim 是由 pip 自带的 distlib 启动器生成的 `gcc.exe`（CI 已在 windows-latest 上验证：MinGW gcc 下 `cmd /c`、`mingw32-make` 的简单配方均可记录，MSVC `cl.exe` 的 `/c`、`/Fo` 也可记录，交叉编译器 `arm-none-eabi-gcc`（Chocolatey 的 gcc-arm-embedded）经 `cmd /c` 与 `mingw32-make` 均可记录，clang 同样可以）；找不到启动器时退回 `.cmd`，只有经 `cmd.exe` 启动编译器才可见。MSYS/Git `sh` 里的构建未验证。
  此时 `gangmu wrap` 会提示“nothing was recorded”，请改用 `--compiler` 指定构建实际使用的名字，或用 `--project`。

## 同类工具

[Interlynk lynkctl](https://www.interlynk.io/solutions/embedded-cpp) 是面向嵌入式 C/C++ 的闭源商业产品，
支持 STM32、Infineon、NXP 等。
[乐鑫 esp-idf-sbom](https://github.com/espressif/esp-idf-sbom) 做得很好，但只覆盖一个 SDK；
gangmu 把它的 `sbom.yml` 当作一等输入，而不是竞争对象。
ONEKEY、Finite State、Cybellum、NetRise 面向大型企业做固件二进制分析。

空着的那一块，是一份**跨厂商、社区共有的「SDK 目录 → 上游组件身份」映射**，也就是 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)。

## 命令一览

| 命令 | 作用 |
| --- | --- |
| `gangmu init` | 生成项目配置 |
| `gangmu scan ROOT` | 识别组件，输出 `cyclonedx` / `spdx` / `json` / `table` |
| `gangmu wrap -- make` | 以编译器垫片运行构建，生成编译数据库 |
| `gangmu vuln-fetch --db DIR` | 联网填充漏洞库目录：`--sbom` 只拉相关产品（秒级），`--all` 全量 NVD（按年分片，之后增量）；`--threat` 另外下载 CISA KEV 和 EPSS 到 `DIR/threat/`，`gangmu vuln` 会据此按「已被利用 → EPSS → CVSS」排序，`--fail-on kev` 遇到已被利用的漏洞就失败（Article 14 的 24 小时报送由「已被积极利用」触发） |
| `gangmu vuln SBOM --db DIR --source ROOT` | 函数级可达性：按每条 CVE 的漏洞函数（`--symbols FILE` 给出；没有就从公告文字里猜）判断它在你的源码里是「不存在 / 已定义但无人引用 / 可达」。调用图按名字、宏、函数指针表做保守的过近似，看不到二进制库和汇编，所以默认只标注；加 `--reachability-vex` 才把不存在/不可达的写成 `not_affected`（`code_not_present` / `code_not_reachable`） |
| `gangmu rules index DIR` | 预编译规则目录，写出 `DIR/.rule-index.json`，加载时不再解析 YAML（125 条规则 0.67 秒 → 0.02 秒）。每条按文件哈希校验，规则改了或索引过期只会变慢，不会读错；规则包在打包时运行一次 |
| `gangmu keygen` / `gangmu sign FILE --key K` / `gangmu sign-verify FILE --pubkey P` | 给 SBOM 或证据包的 `manifest.json` 做 Ed25519 分离签名并校验（`pip install gangmu-sbom[sign]`；密钥是标准 PEM，OpenSSL 可直接验）。只证明“这把密钥签过”，不含时间戳和密钥托管；要时间戳或免密钥签名，对同一文件用 `cosign sign-blob` |
| `gangmu vuln SBOM --db DIR` | 漏洞比对，输出 CycloneDX VEX |
| `gangmu cn-db-check DIR` | 检查 CNNVD / CNVD 导出目录：每个文件能读出多少条，读不了的明确报出来 |
| `gangmu cra-check` | 对照 CRA 条款审查产物 |
| `gangmu report CVE` | 生成 CRA 或工信部报送草稿 |
| `gangmu evidence --out DIR` | 汇总十年留存技术文档包 |
| `gangmu rules lint / import [--recursive] / fingerprint / verify / functions` | 规则校验、导入、生成、复现、函数签名。`--rules` 可重复，后面的目录覆盖前面同名的规则；不写则用已安装的规则包 |
| `gangmu rules cpe-evidence --nvd DIR` | 从本地 NVD 镜像里找出组件登记用的 CPE，并列出引用其上游仓库的 CVE 作为证据 |
| `gangmu perf [--check BASELINE]` | 性能基线：规则数与耗时、内存，CI 回归检查 |
| `gangmu sbom-score` / `eval` / `bench` / `diff` | 质量评分、评测基准、性能、召回率对比 |

## 仓库

纲目由三个公开仓库组成，各自独立发版：

| 仓库 | 内容 | 许可证 |
| --- | --- | --- |
| **[gangmu](https://github.com/GANGMU-SBOM/gangmu)**（本仓库） | 识别引擎、命令行、构建期采集、SBOM 与 VEX 输出、漏洞比对、CRA 与工信部报送草稿 | Apache-2.0 |
| **[gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)** | 免费规则库：被各家 SDK 拷贝最多的通用开源组件、Zephyr 及其 HAL，按日期发版，`pip install -U gangmu-rules` | CDLA-Permissive-2.0 |
| **[gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench)** | 评测基准：固定的真实上游版本和正确答案，加评分脚本，任何人都能复现 | Apache-2.0 |

商业版（规则包、持续监测、报送工作台等）不在这些仓库里，见 [docs/EDITIONS.md](docs/EDITIONS.md)。

`pip install gangmu-sbom` 会自动装上 gangmu-rules。问题提到哪里：
识别错了或缺某个 SDK 的规则，提到 gangmu-rules；扫描崩溃、命令行或输出格式的问题，提到本仓库；
想补评测用例，提到 gangmu-bench。

## 参与规则共建，联系我们

规则是这个项目最值钱的部分，也最需要大家一起积累：一条规则只需要一个干净的上游版本和一次 `gangmu rules verify`。

- **通用开源组件、Zephyr 与 HAL、国产 SDK 里常见的第三方库**：直接向 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) 提 issue 或 PR，见[贡献指南](https://github.com/GANGMU-SBOM/gangmu-rules/blob/main/CONTRIBUTING.md)；
- **想认领某个芯片 SDK、不确定规则该放哪里、手上有真实固件样本愿意帮忙验证**：先联系我，避免重复劳动，我会告诉你怎么做最省力；
- **厂商专属规则、私有 BSP、商业版规则包**：同样联系我。

联系方式：邮箱 64031875@qq.com，或扫码进「CRA 合规群」（二维码有有效期，扫不出来请发邮件）。

![CRA 合规群二维码](docs/assets/cra-wechat-group.jpg)

你贡献的规则按 gangmu-rules 的许可证（CDLA-Permissive-2.0）授权；开源仓库里已有的内容不会撤回，也不会收费。

## 商业版与服务

开源版能让一个团队完整走通一遍流程。如果需要长期运营这条流程，我们提供：

- **漏洞持续监测**：多源合并去重，按产品型号推送，VEX 判定有专人复核；
- **报送工作台**：CRA 与工信部四条时限并行跟踪，版本级 SBOM 归档，十年留存；
- **商业版规则包**：芯片原厂与厂商专属的固件库规则，按需订阅；
- **规则库企业服务**：离线镜像、有时限承诺的规则更新、为您的私有 BSP 建立私有规则；
- **私有化部署与信创适配**，以及构建接入、规则编写培训和合规流程咨询。

核心能力（识别引擎、构建期采集、SBOM 与 VEX 输出、漏洞比对、报送草稿、评测基准和免费规则库）会一直开源，
商业版以插件和规则包的形式叠加在开源版之上，不改变开源版的任何功能。两者的完整对比见 [docs/EDITIONS.md](docs/EDITIONS.md)。
技术咨询与商务合作见文末的[联系方式](#参与规则共建联系我们)，也可以提一个标题以「商业版」开头的 issue。

## 许可

- 工具（本仓库）：Apache-2.0
- 规则（[gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)）：CDLA-Permissive-2.0
- 商业版规则包：专有，见 [docs/EDITIONS.md](docs/EDITIONS.md)
- 评测（[gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench)）：Apache-2.0

## 开发

```bash
git clone https://github.com/GANGMU-SBOM/gangmu-rules
pip install -e ./gangmu-rules -e ".[dev]"
pytest -q
```

评测准确率用 [gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench)（`python bench.py`）。

测试不需要网络：大部分测试的规则在运行时从 `tests/fixtures/upstream/` 生成，顺带验证了规则的编写路径；
另有一部分测试用真实规则库扫描样例，没装 gangmu-rules 时会跳过。测试只依赖免费规则库。
