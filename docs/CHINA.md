# 中国市场：被忽略的那一半义务

对出口欧盟的中国厂商，CRA 不是唯一的报送义务，**也不是触发最频繁的那个**。
一个只做 CRA 的工具会让团队漏掉本土那条。

## 两套义务的差别是实质性的

| | 《网络产品安全漏洞管理规定》第七条 | CRA 第 14 条 |
| --- | --- | --- |
| 生效 | 2021 年 9 月 1 日 | 2026 年 9 月 11 日 |
| 触发条件 | **发现**漏洞 | 漏洞**被积极利用** |
| 时限 | **2 日内** | 24 小时预警 / 72 小时通报 / 14 天最终报告 |
| 平台 | 工信部网络安全威胁和漏洞信息共享平台（cstis.cn） | ENISA 单一报告平台 |
| 必填 | 产品名称、型号、版本；技术特点、危害程度、影响范围 | 产品名称与版本、成员国、知悉时间 |

触发条件的差别最要紧：本土那条不以"被积极利用"为前提，所以触发得更频繁。

```bash
gangmu report CVE-2027-12345 --regime cn-miit --vex vex.json \
    --aware-at "2027-05-14 08:12" --scope "全系列，出货约 4.2 万台"
```

草稿是中文的，字段按第七条的要求排列，"受影响的开源组件及版本"直接取自 SBOM
——这一项正是手工填报时最花时间、也最容易填错的。

## 一个工具不该替人下的法律结论

《网络产品安全漏洞管理规定》第九条第（七）项：不得将未公开的网络产品安全
漏洞信息，向网络产品提供者之外的境外组织或者个人提供。**该条未设例外情形。**

CRA 第 14 条要求向 ENISA 与成员国 CSIRT 报送尚未公开的漏洞。

同时在中国境内提供并出口欧盟的产品，这两项义务可能在同一事件上同时触发。
本工具**不判断是否构成冲突，也不建议处理方式**——这是法务判断。工具做的是在
生成欧盟报送草稿时把它摆到桌面上，而不是让团队在 24 小时倒计时的第 20 小时
才第一次想到。配置里标了 `market.member_states` 或 `china.exports_to_eu`，
提示就会出现在草稿里。

## 国内漏洞库是第三条通道

NVD 和 OSV 都不收国内厂商自报的漏洞。国产芯片 SDK、国产 RTOS、国产密码库的
条目往往只在 CNNVD 或 CNVD 里。

```bash
gangmu vuln sbom.json --db advisories/ --cn-db cnnvd-export/
```

### 能读什么格式

`--cn-db` 目录里放你自己从平台导出的文件，格式按扩展名识别：

| 扩展名 | 读什么 |
| --- | --- |
| `.json` | 条目数组，或包在 `data` / `records` / `list` 等键里 |
| `.xml` | CNNVD 的 NVD 风格 `<entry>`（`vuln-id`、`vuln-descript`、`other-id/cve-id`……），CNVD 的 `<vulnerability>` 通报（`number`、`cveNumber`、`serverity`、`products/product`……） |
| `.csv` | 中文表头（漏洞编号、漏洞名称、CVE编号、危害等级、影响产品……），UTF-8 或 GBK |

字段名不区分大小写、分隔符和中英文；来源（CNNVD / CNVD / NVDB）优先按条目编号前缀判断，其次才看文件名。
`.xlsx` 不读，请另存为 CSV。

**CNNVD 的 XML 已经拿真实导出验证过，CNVD 没有。** 2026-10-05 用公开镜像里 CNNVD 的年度 XML 导出
（1999 至 2019，23 个文件，13.9 万条，解压后约 1 GB）跑了 `cn-db-check`：全部能读，不丢条目；
带 CVE 编号的占 94%，其余 8,237 条没有 CVE。抽查 2017 至 2019 三个文件里的 1,442 条无 CVE 条目：1,393 条是“漏洞详情暂不公开”的占位条目，全部没有影响产品信息，所以这类条目只能按产品名做候选，不可能做版本匹配。
带 CVE 的条目里有 `vulnerable-configuration` 和 `vuln-software-list` 的 CPE 列表，会进入“影响产品”。
这份快照停在 2019 年，所以它能验证格式，不能代表现在的 CNNVD 内容。CNVD 拒绝匿名访问，
CNVD 的夹具（`tests/fixtures/cn/`）仍是按公开资料合成的，只能证明解析器的行为，不能证明你手上的那份导出能被读懂。
一份真实的 CNNVD 条目（OpenSSL 一条加一条占位）保存在 `tests/fixtures/cn-real/`。

体量：整套 CNNVD 要读 1 GB 的 XML，最初的实现把所有条目留在内存里，要 172 秒、3.5 GB。现在 XML 流式解析，
`gangmu vuln --cn-db` 只保留这份 SBOM 用得上的条目（已匹配 CVE 的，以及没有 CVE 但名字提到某个组件的），
同一份数据 66 秒、40 MB；条目总数仍然全部统计。截断的 XML 会报错而不是悄悄少读。

因此读不了的东西不会被悄悄跳过：

```bash
gangmu cn-db-check cnnvd-export/
```

逐个文件列出格式、条目数、解析成功数、带 CVE 编号的条数，读不了的文件和解析不出编号的条目会连同
没认出来的字段名一起报出来。目录里一条都读不到时 `gangmu vuln --cn-db` 会明确警告“这不是干净的结果”。
如果你的导出读不出来，把几条脱敏样本和 `cn-db-check` 的输出发 issue，格式就能补上。

结构差异必须正视：CNNVD/CNVD 条目通常**没有 CPE 也没有 PURL**，影响范围是
中文产品名字符串，做不了版本区间匹配。所以工具分两档处理：

* 带 CVE 编号的，按编号与已有匹配**合并**，补中文描述与国内定级。两边定级
  不一致时会单独列出——这本身就是要给人看的信息。
* 不带 CVE 编号的，只能按产品名关键字给出**待确认候选**，并明确标注为候选。
  把关键字命中当成确认匹配会制造大量误报。

## 国产生态：已覆盖与未覆盖

> 通用开源组件、国密库、国产内核（RT-Thread、LiteOS、AliOS Things、TencentOS-tiny）以及 Zephyr 里的国产芯片 HAL 在免费的 gangmu-rules；
> 只跟一家公司绑定的规则（芯片原厂自己的 SDK 或固件库）属于商业版规则包，没有装时不会被识别出来。

当前的识别结果（每个组件、每份副本报出的版本和判定）只在 [BENCHMARK.md](BENCHMARK.md) 里，用当前版本测。下面只列覆盖了什么、怎么认、有什么局限。

### 声明式读取

* **国产 RTOS 的包声明** —— RT-Thread 的 `.config` 与 `packages/pkgs.json`，
  OpenHarmony 的 `README.OpenSource`。**有包管理器就不该靠指纹**：声明式读取比任何
  相似度都准。RT-Thread 声明的是软件包版本而非上游版本，所以该目录仍做指纹识别，
  上游身份由规则库给出，声明作为证据附上。
* **OpenHarmony 部件声明与依赖关系** —— 除了第三方目录的 `README.OpenSource`，还读
  每个部件的 `bundle.json`：部件名、子系统、版本、许可证，以及它声明依赖的部件和第三方库。
  OpenHarmony 自身的部件作为组件列入 SBOM，供应方为开放原子开源基金会（OpenHarmony 项目）。
  依赖关系写进 CycloneDX 的 `dependencies` 和 SPDX 的 `DEPENDS_ON`。
  声明了、但在这棵树里找不到的依赖，会在组件属性里列出，不会悄悄丢掉。
* **Linux 类 SDK** —— 全志 Tina（OpenWrt）、瑞芯微 / Luckfox（Buildroot）这类 SDK 是 Linux 内核、U-Boot、BusyBox 加几百个软件包，
  构建系统本身就写明了装什么、什么版本，所以不靠指纹。Buildroot 读 `.config` 的 `BR2_PACKAGE_*=y` 与 `package/*/*.mk` 的 `*_VERSION`；
  OpenWrt / Tina 读 `.config` 的 `CONFIG_PACKAGE_*=y` 与配方 Makefile 的 `PKG_VERSION`；Linux 内核、U-Boot、BusyBox 读顶层 Makefile 的
  `VERSION/PATCHLEVEL/SUBLEVEL`。只报 `.config` 选中的包，版本是计算出来的（`$(...)`）的配方跳过而不是猜。
  内核与 U-Boot 一律标为厂商分支（厂商内核回移植了大量修复，版本号不等于 CVE 状态），漏洞比对时进入待确认而不是直接判定受影响。
  约 45 个常见软件包（zlib、curl、dropbear、dnsmasq、OpenSSH、wolfSSL 等）带有 CPE，每个都对照 NVD 确认过该 vendor:product 下有 CVE。
  验证用的是真实的 buildroot、openwrt、busybox、u-boot 仓库；没有拿到任何一家国产 Linux SDK 的完整树。Yocto 的构建产物清单和镜像选中的配方由 `declared_build` 读取，但没有在国产 Linux SDK 上验证过。
* **厂商 SDK 本身作为组件** —— SDK 自己写在固定位置的版本号会被读出来，列为 CycloneDX 的 `framework` 组件（带供应方、许可证和 PURL），
  SDK 目录下的库挂在它的依赖之下。已覆盖：博流 Bouffalo SDK（`VERSION`）、博流 bl_iot_sdk（`version.mk` 的 `BL_SDK_VER`，形如 `1.6.39-238-gf5ba0a7ee`）、
  联盛德 WM IoT SDK（`version`）、乐鑫 ESP8266 RTOS SDK（`esp_idf_version.h`）、合宙 LuatOS（`luat_base.h`）、
  阿里 Link SDK / iotkit-embedded（`src/infra/infra_defs.h` 的 `IOTX_SDK_VERSION`）、涂鸦 IoTOS 嵌入式 SDK（`CHANGELOG.md` 最新的标题；
  该仓库没有许可证文件，所以不声明许可证），都在真实仓库上验证过。
  标志文件必须同时存在，单独一个 `VERSION` 文件不会被当成 SDK。新增一家只需在 `declared_sdk.SDKS` 里加一项数据和一个测试。
  未覆盖：沁恒 CH32/CH58x EVT 包里没有 SDK 级的版本号，只有每个源文件头部各自的 `Version: V1.0.0`，那是文件版本，不是发布版本。
  涂鸦的其他 SDK（TuyaOS 的其他芯片版本）和阿里 Link SDK 的 4.x 没有样本，没有核对。

### 国产与亚太内核

* **国产 SDK 里的 RTOS 内核** —— FreeRTOS（8.2.3–11.3.1，28 个版本）与 RT-Thread
  （3.0.0–5.3.0，27 个版本）的函数级规则。评测用的是博流 bouffalo_sdk 和 bl_iot_sdk，沁恒 CH32V307、CH32V20x 和 CH583，
  联盛德 wm_iot_sdk，乐鑫 ESP8266_RTOS_SDK 里能找到的全部内核副本
  （结果见 [BENCHMARK.md](BENCHMARK.md#1b-rtos-kernels-inside-chinese-vendor-sdks)）。
  这些副本的目录常被厂商改了名、没有 LICENSE、藏在示例目录深处，所以规则声明标记文件，例如 FreeRTOS 的 `tasks.c` + `queue.c` + `list.c`，
  发现阶段不管目录在哪里、叫什么，都能找到它。
* **腾讯 TencentOS-tiny 内核** —— 13 个版本（2.1.0–2.5.2，上游只打了 3 个标签，其余按版本头文件首次出现的提交固定；
  标签 v2.4.5 实际头文件写的是 2.4.3）。评测副本在沁恒 CH32V307 / CH32V20x 的示例里。
  NVD 里 CPE `tencent:tencentos-tiny` 只有一条记录（CVE-2021-27439），影响版本写作上游从未发布的 3.1.0；
  国内的 CNNVD/CNVD 尚未核对（CNNVD 接口拒绝匿名访问，CNVD 返回 521 后断连）。
* **阿里 AliOS Things（Rhino 内核）** —— 16 个版本（1.1.0–3.3.0）。上游给 1.1.0–2.1.0 打了标签，3.x 只有
  发布分支（rel_3.0.0、rel_3.1.0、rel_3.3.0），一律按提交固定。内核目录三次搬家（`kernel/rhino/core`、
  `kernel/rhino`、`core/rhino`），标志文件 `k_task.c` + `k_sys.c` + `k_mutex.c` + `k_event.c` 都能找到。
  Rhino 自己的 `RHINO_VERSION` 从 1.x 到 3.3.0 一直是 12000，发行版本号在内核目录之外，所以版本只靠函数签名，
  可能是区间（1.3.0–1.3.4 内核代码相同）。NVD 里没有 AliOS Things 的 CPE，OSV 也没有记录。
  公开的厂商 SDK 里没有找到 Rhino 副本，评测只用了上游发布版。
* **华为 LiteOS 系列内核** —— 三条规则：LiteOS-M（OpenHarmony 1.0、1.1.0–7.0，48 个版本）、LiteOS-A
  （1.0–7.0，48 个版本）、LiteOS 5.x（v5.0.0、v5.1.0，来自 Gitee 主仓库）。版本按 OpenHarmony 发布名，写法与上游标签一致
  （`3.2`，不是 `3.2.0`）。沁恒 CH583、CH32V307 / CH32V20x 里带着 LiteOS-M 副本。
  LiteOS-M 1.1.x 和 LiteOS 5.x 的每个源文件整体包在 `extern "C" {` 里，函数提取器会穿透它。
  NVD 里没有 LiteOS 的 CPE；只有 3 条 CVE 点名 `kernel_liteos_a`（CVE-2022-41802、-43662、-45126），登记在
  整个 OpenHarmony 的 CPE 下，规则不据此设 CPE。国内的 CNNVD/CNVD 尚未核对。
* **OpenHarmony 代码在 GitCode** —— OpenHarmony 在 2025 年 9 月迁到 `gitcode.com/openharmony`，Gitee 上的 openharmony 成了镜像
  （`kernel_liteos_m` 最后一次提交是 2025-09-08，`kernel_liteos_a` 是 2025-08-20，6.0 之后没有标签）。LiteOS-M 与 LiteOS-A 两条规则的主源是 GitCode，
  GitCode 与 GitHub 镜像都固定在 `OpenHarmony-v7.0-Release` 的提交上，Gitee 留作镜像。漏洞比对里 gitcode.com / atomgit.com 的仓库地址与 Gitee 一样映射到 `pkg:generic/openharmony/...`。
  LiteOS 5.x（`LiteOS/LiteOS`）不是 OpenHarmony 的一部分，仍在 Gitee。
* **Zephyr 上游中的国产与亚太芯片 HAL** —— 兆易、博流、沁恒（ch32fun）、思澈、
  泰凌微、瑞昱。

### 密码学库

* **国密库** —— GmSSL 3.0.0–3.2.0 与 2.0.0–2.5.4（2.x 独立成规则 `generic/gmssl-2`，上游没有 2.x 标签，按提交固定）、铜锁 Tongsuo 8.1.3–8.5.0（8.1–8.3 为 BabaSSL 时期版本）、OpenSSL 1.1.0–1.1.1w 与 3.x（含函数签名，与 OpenSSL 规则互相做代码分割，不会互相误认）。
* **Mbed TLS、wolfSSL、TinyCrypt** —— Mbed TLS 63 个发布版，用标志文件定位，目录叫什么都能找到；
  wolfSSL 的函数签名覆盖 3.12.0–5.9.4 的稳定版（46 个），CPE `wolfssl:wolfssl`；TinyCrypt 7 个版本。
  局限：乐鑫 ESP8266 SDK 的 wolfSSL 只带头文件和预编译的 `libwolfssl.a`，与完整源码签名的相似度低于报告下限，所以这份副本认不出
  （`libwolfssl.a` 里读不到版本横幅），要靠头文件签名或预编译库的字符串另做。
  TinyCrypt 在 NVD 的 CPE 字典里没有条目，OSV 也没有记录，所以没有可用的漏洞比对通道；
  国产 SDK 里的 TinyCrypt 副本多半被厂商改过，基准里按“已知”记（见 BENCHMARK.md）。
* **libsrtp** —— 1.5.0–2.8.1（18 个），CPE `cisco:libsrtp`。

### 国产 SDK 里的第三方库

国产 SDK 里的 CVE 主要在这类第三方库，而不在厂商自己的 HAL。下面每条都是通用规则，用标志文件定位；评测副本在博流、联盛德、沁恒、乐鑫 ESP8266、合宙 LuatOS 和全志 RTOS 的 SDK 里（结果见 [BENCHMARK.md](BENCHMARK.md#1d-third-party-libraries-inside-chinese-vendor-sdks)）。

* **文件系统与存储** —— FatFs 20 个发布版，littlefs 38 个；FlashDB、SFUD（NVD 里都没有登记；SFUD 上游只有一个标签，所以只能确认是它，区分不了版本）。
* **图形与媒体** —— LVGL 54 个发布版（NVD、OSV 都没有记录，没有可用的漏洞比对通道）；FreeType、libjpeg-turbo、giflib、Opus；
  LodePNG（上游没有标签也没有版本号，只在 `lodepng.h` 横幅里写一个日期，规则按横幅日期把 50 个提交固定为版本，2017-09-17 起，
  版本写成 NVD 的 `2022-07-17` 形式而不是 `20220717`，这样 CPE `lodev:lodepng` 才比得上）。在 LVGL 目录里面的 LodePNG 副本算在 LVGL 的结果内。
* **网络与协议** —— libcoap 13 个版本（`libcoap:libcoap`）、nghttp2 64 个（`nghttp2:nghttp2`）、libwebsockets 63 个、Paho MQTT C 23 个、MQTT-C 1.0.0–1.1.6（11 个）、
  OpenThread 11 个（`o:google:openthread`，NVD 把它登记为操作系统类）、AWS IoT Device SDK 14 个、
  hostap（wpa_supplicant / hostapd）2.0–2.12（只取 `src/`，所以像联盛德那样删掉了 `wpa_supplicant/` 与 `hostapd/` 目录的 SDK 也能认出；
  没有版本头的副本，例如博流 wifi4 与 bl_wpa_supplicant，认不出）。
  libwebsockets、AWS IoT Device SDK、MQTT-C 在 NVD 没有登记（MQTT-C 的 CVE-2026-54412 没有 CPE，不能据此写一个）；
  Paho C 唯一的 CPE（`eclipse:paho_mqtt_c/c++_client`）下的 CVE 指向 paho.mqtt.embedded-c，是另一个项目，所以不用（见 BENCHMARK.md 1g）。
* **蓝牙与 USB** —— NimBLE 1.0.0–1.10.0（11 个，只取主机协议栈，`apache:nimble`）；CherryUSB 0.7.0–1.6.1（21 个）。
  LuatOS 的 `components/nimble` 只是 Lua 胶水层，不是 NimBLE 本体，规则不会（也不应该）报它。
* **压缩、序列化与其他** —— miniz 1.14–3.1.2（19 个，`miniz_project:miniz`；`MZ_VERSION` 是 zlib 兼容号而不是发布号，所以版本只靠函数签名）、
  nanopb 0.3.6–0.4.92（29 个，`nanopb_project:nanopb`；`pb.h` 放进 `include/` 的布局也能读到 `NANOPB_VERSION`）、
  LibYAML 0.0.1–0.2.5（13 个，`pyyaml:libyaml`）、FastLZ 0.4.0–0.5.0、XZ Embedded（上游只有 2024 年之后的标签，更早的快照只能作为“可能”项，`--include-possible`）、
  libmetal v2020.01.0–v2026.04.0（15 个；`VERSION` 文件落后于代码，所以不设版本探针）、OpenAMP、TinyCBOR（NVD 没有登记产品，按 purl 走 OSV；没有在国产 SDK 里找到可测的副本）。
* **lwIP** —— 扁平目录（合宙 LuatOS 的 `components/network/lwip22` 把上游的 `src/` 一层去掉了）也能认。几条规则指向同一个签名文件时，签名不会被当成“多条规则共有的代码”相互剔除。
* **CMSIS-Core** —— 两条规则（`generic/cmsis5-core` 13 个版本、`generic/cmsis6-core` 5 个版本，只靠函数签名定版本，因为 `cmsis_version.h` 里的数字是 Core 版本，不是 CMSIS 发布号）；NVD 里只有 `arm:cmsis-rtos`，对应的是 RTOS 接口而不是 Core 头文件，所以不设 CPE。
* **仍认不出**：博流的 TJpgDec（ChaN 只发 zip）、TLSF、libpeer、MicroQuickJS，合宙的 TJpgDec。

全志、国民技术、华大、瑞芯微等原厂自己的 HAL 与驱动库规则属于商业版规则包。

### 只有二进制的库

国产 SDK 的 Wi-Fi、蓝牙、射频、音频栈常以 `.a` / `.lib` / `.so` 形式提供，没有源码，源码指纹看不见。
每个预编译库都会进 SBOM：路径、SHA-256、大小、是否出现在链接 map 里（有 map 时）、编译器横幅，并标明“无源码”。
同时从字节里读版本横幅：开源库自己编进去的字符串（例如博流 bouffalo_sdk 的 libopus、libvorbis、Speex、Sonic），以及厂商组件自带的 `component_version_<名>_<版本>`（例如博流的 fhost、macsw、lmac154）。
读到横幅的开源库作为组件列出，置信度 0.70/0.60，来源标为 `binary-string`——说明库在里面，不说明是未改动的上游副本。
没有横幅、也没有规则带函数指纹的库（aacdec、amrnb 等）只作为文件清单列出。`--no-binaries` 可关闭。
带函数指纹的库的准确率和召回率见 [BINARY-VALIDATION.md](BINARY-VALIDATION.md)。

仍未覆盖，按出口量与影响面排序，这是路线图而不是辩解：

1. **不在 Zephyr 上游的国产芯片 SDK** —— 全志 Tina（全志 RTOS SDK 的 HAL 已覆盖，Tina Linux 没有可用的开源 SDK；部分原厂 HAL 与驱动库属于商业版规则包）。
   这些 SDK 里的 RTOS 内核已经能识别，厂商自己的 HAL 和驱动还需要逐家建规则。
2. **国密分支的 mbedTLS** —— 各家对 Mbed TLS 加 SM2/SM3/SM4 的分支，需要逐个建规则。
3. **GB 44495-2024《汽车整车信息安全技术要求》** —— 2026 年 1 月 1 日起对
   新车型强制实施，与 UN R155 / ISO 21434 对应。汽车电子的组件清单要求需要
   单独对标。
4. **翼辉 SylixOS** —— 没有建规则，原因见 [BENCHMARK.md](BENCHMARK.md#1j-chinese-rtos-kernels-sylixos-why-there-is-no-rule)：
   厂商官网只提供 GPLv3 的 `sylixos-base-v183.zip` 一个版本（页面上的下载链接已被注释掉，文件仍可下载），
   没有标签、没有 Git 历史，多版本函数签名无从谈起，规则的 CI 也无法从压缩包复现证据；
   `git.sylixos.com` 并不是 Git 服务器：所测路径（含 git `info/refs`）全部 301 跳转到厂商文档站 `docs.acoinfo.com/sylixos/`，该站未提到 Git 或源码仓库，因此没有找到标签、分支或发布历史。其他主机名、Gitee 等镜像未检查。NVD、OSV 里没有 SylixOS 的记录。
5. **信创 / 自主可控标注** —— 组件来源国与供应链风险标注，党政采购要求。

## 离线是前提，不是选项

国内很多固件团队在内网开发，拿不到公网。所以漏洞比对读的是本地目录
（`--db` / `--cn-db`），抓取是单独的一步，在有网的地方做：NVD 与 OSV 用 `gangmu vuln-fetch`；
CNNVD / CNVD 目前需要自行从平台导出。一份必须联网才能
产出的报告，在工厂内网里产不出来，在漏洞披露后的 24 小时里也产不出来。
