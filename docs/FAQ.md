# 常见问题

[English](FAQ.en.md) · [README](../README.md) · [术语表](GLOSSARY.md)

每个问题的第一句就是答案，后面是依据。数字都可以用仓库里的工具复现，方法见
[BENCHMARK.md](BENCHMARK.md)。

## 纲目（Gangmu）是什么？

纲目是一个开源的嵌入式 C/C++ 构建期 SBOM（软件物料清单）工具，附带一份社区共建的芯片 SDK
组件识别规则库。它从源码树和构建过程中识别第三方开源组件，输出 CycloneDX 1.6 或 SPDX 2.3，
比对漏洞并输出 CycloneDX VEX，对照欧盟《网络弹性法案》（CRA）逐条自查，并起草 CRA 第 14 条
与工信部《网络产品安全漏洞管理规定》第七条的报送材料。工具采用 Apache-2.0 许可，
规则数据采用 CDLA-Permissive-2.0 许可。命令行名为 `gangmu`，Python 包名为 `gangmu-sbom`。

## 为什么叫「纲目」？

名字取自李时珍的《本草纲目》。那部书把近两千种药物分门别类、逐一注明出处与性状，
让后人能够辨认和核对。纲目对固件里的第三方代码做同样的事：把每个组件归到「上游项目、版本、
是否被厂商修改」之下，并给出可以复核的证据。

## 为什么嵌入式 C/C++ 很难生成 SBOM？

因为 C/C++ 没有锁文件，而嵌入式开发又抹掉了剩下的证据。具体有四点：

1. 没有包管理器，第三方源码直接拷进工程；
2. 芯片原厂会改名、修改上游组件，比如 ESP-IDF 里的 lwIP 是乐鑫的分支；
3. 固件全部静态链接，产物里没有依赖信息；
4. 编译的远多于最终出货的，链接时丢弃的代码在源码树里照样存在。

所以只扫源码树会多报，只分析二进制会少报。纲目读的是构建过程：`compile_commands.json`
说明编译了什么，链接 map 说明最终留下了什么。

## 纲目怎么识别被改名、被修改过的开源组件？

纲目在函数级比对代码，而不是比较文件名或整棵目录的相似度。组件身份看「上游的函数有多少出现在这里」
（containment），版本看「这些函数属于哪几个发布版」。方法参考 CENTRIS（ICSE 2021）和
TIVER（ICSE 2025）。

一个可复现的例子：把 GmSSL 3.0.0 改目录名、删掉版本头文件、给三分之一文件里的函数加厂商前缀、
塞进厂商函数、再删掉 8 个源文件，纲目仍然识别为 GmSSL 3.0.0，标记为 vendor-modified，
置信度 0.88。脚本是 `examples/disguise.sh`。

在 lwIP 上，整棵目录的相似度只能把「厂商 fork」和「换了个版本」拉开 0.06，函数级拉开到 0.25。
真实 lwIP 发布版的版本识别 6/6 精确，合成修改场景 9/9 识别、9/9 版本正确。

## 支持哪些芯片 SDK，包括哪些国产芯片？

免费的 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) 现有 60 条规则（Zephyr 及其 HAL、通用开源组件）。主要覆盖：

- **Zephyr**：Mbed TLS 4.1、TF-PSA-Crypto、hostap（wpa_supplicant / hostapd）、FatFs、littlefs、MCUboot、nanopb、zcbor、uOSCORE/uEDHOC；
- **国产与亚太芯片 HAL**（取自 Zephyr 4.4 的锁定提交）：兆易创新 GD32、博流智能 BL60x/BL70x、沁恒 CH32、
  思澈科技 SiFli、泰凌微 TLSR9、瑞昱 Ameba/Bee；

厂商专属的固件库规则（芯片原厂 SDK、fork 组件）属于商业版规则包，需要请联系我们，见 [EDITIONS.md](EDITIONS.md)。
- **通用组件**：lwIP、cJSON、OpenSSL、GmSSL、铜锁、Mbed TLS、TF-PSA-Crypto、FatFs、littlefs、LVGL、libcoap、TinyCrypt、nghttp2、libwebsockets、Paho MQTT C、OpenThread、AWS IoT Device SDK，以及 FreeRTOS、RT-Thread、TencentOS-tiny、AliOS Things、LiteOS-M / LiteOS-A / LiteOS 5.x 内核（按标志文件定位，博流、沁恒、联盛德、乐鑫 7 个 SDK 里的 14 份内核副本、12 份 Mbed TLS/FatFs/littlefs 副本全部找到）。

全志 Tina Linux 的 SDK（RTOS SDK 已覆盖） 不在 Zephyr 上游，还需要单独导入，欢迎贡献。

## 能识别国密库吗？

能。GmSSL 支持 3.0.0–3.2.0 与 2.0.0–2.5.4（2.x 是独立规则）；铜锁（Tongsuo）支持 8.1.3–8.5.0
（8.1–8.3 是 BabaSSL 时期的版本）；同时覆盖 OpenSSL 1.1.0–1.1.1w 全部版本，以及 3.0 到 3.6 各线的最新补丁版。
三者都用逐版本锚点、多版本函数签名和版本探针识别。
铜锁是 OpenSSL 3.0 的分支，两者共享上万个函数；同时加载两条规则时，共享的函数对谁都不算身份证据，
各自只靠独有的代码被认出来，所以原版 OpenSSL 不会被误认成铜锁。国密分支 mbedTLS 还没有覆盖。

## 支持 RT-Thread 和 OpenHarmony 吗？

支持，而且是直接读生态自己的声明。RT-Thread 读 `.config` 和 `packages/pkgs.json`，
OpenHarmony 读各第三方目录下的 `README.OpenSource`，以及每个部件的 `bundle.json`：
OpenHarmony 自身的部件也会列入 SBOM，部件之间、部件与第三方库之间的依赖关系写进
CycloneDX 和 SPDX 的依赖图。声明与代码不一致时以代码为准，
分歧写进证据。RT-Thread 软件包的版本号是软件包自己的标签，不会被拼进上游组件的 CPE。
Zephyr 模块在 `zephyr/module.yml` 里声明的 CPE 和 PURL 也会被读取。

## 支持哪些构建系统和 IDE？

支持 `compile_commands.json`（CMake、ESP-IDF、Zephyr 等）、GNU ld、lld、IAR ilink、Arm armlink 链接 map、IAR `.ewp`、
Keil `.uvprojx`、TI CCS 与 Eclipse 工程。没有编译数据库时，可以用 `gangmu wrap -- make`
旁观一次真实构建来生成。编译器包装器在 POSIX 和 Windows 下都可用，但只能拦截按名字查找的编译器：Makefile 里写死绝对路径（如 `CC=/opt/gcc/bin/gcc`）会绕过它，Windows 下 shim 是真正的 `gcc.exe`，`mingw32-make` 的简单配方和 MSVC `cl.exe`、clang 和 `arm-none-eabi-gcc` 也能记录（CI 已验证）；MSYS/Git `sh` 下的构建未验证。这种情况请用 `--project` 读 IDE 工程。

## 输出什么格式？满足 NTIA 和 CISA 的最小要素吗？

输出 CycloneDX 1.6（默认）和 SPDX 2.3，也可以输出 JSON 和表格。厂商 fork 写在 CycloneDX 的
`pedigree` 里，每种识别技术及其置信度写在 `evidence.identity` 里，置信度上限 0.95。
`gangmu sbom-score` 按 NTIA 2021 和 CISA 2026 最小要素评分，纲目自己的输出两项都是 10.0/10。

## 欧盟 CRA 对 SBOM 有什么要求？纲目覆盖了哪些？

CRA（Regulation (EU) 2024/2847）Annex I Part II(1) 要求制造商用通用的机器可读格式编制 SBOM，
至少覆盖顶层依赖，收入技术文档，市场监管机构索要时提供，不要求公开。
纲目生成这份 SBOM，`gangmu cra-check` 逐条对照 Annex I Part II 的八项以及第 13(8) 条、第 14 条。
十项里有五项只会返回 partial、declared 或 out of scope：扫描不是安全测试，配置文件里的一个 URL
也不是漏洞披露政策被执行的证据。详见 [CRA.md](CRA.md)。

## CRA 的漏洞报告时限是什么？纲目能自动提交吗？

制造商的漏洞报告义务自 2026 年 9 月 11 日起适用，其余义务自 2027 年 12 月 11 日起适用。
被积极利用的漏洞要在 24 小时内预警、72 小时内正式通报、纠正措施可用后 14 天内提交最终报告，
都经 ENISA 单一报告平台提交。纲目不能自动提交，因为该平台首发版本没有 API；
`gangmu report --stage early-warning` 从 SBOM 和项目配置预填表单字段，缺的字段标 `MISSING`，
由人复制到平台。

## 国内的漏洞报送有什么要求？和 CRA 有冲突吗？

《网络产品安全漏洞管理规定》第七条要求发现漏洞后 2 日内报送工信部网络安全威胁和漏洞信息共享平台。
它不以「被积极利用」为前提，所以比 CRA 触发得更频繁。`gangmu report --regime cn-miit` 生成中文草稿。
该规定第九条第（七）项禁止向境外组织提供未公开的漏洞信息，而 CRA 要求 24 小时内向 ENISA 报送，
两者可能在同一事件上同时触发。纲目在生成欧盟草稿时提示这一点，但不替你下结论，这属于法务判断。
详见 [CHINA.md](CHINA.md)。

## 能在内网或离线环境使用吗？

能。`gangmu vuln` 不联网，只读本地目录中的 NVD、OSV 镜像以及 CNNVD/CNVD 数据，
测试套件也不需要网络。填充这些目录是单独的 `gangmu vuln-fetch` 命令：在有网的机器上跑
（`--sbom` 只拉这份 SBOM 用得到的产品，`--all` 拉全量 NVD 并在之后增量更新），再把目录带进内网。
`vuln-fetch` 只抓 NVD 和 OSV；CNNVD/CNVD 的数据需要自行从对应平台导出。

## 和 esp-idf-sbom、二进制分析工具有什么区别？

乐鑫的 esp-idf-sbom 只覆盖 ESP-IDF，纲目把它的 `sbom.yml` 当作一等输入。
ONEKEY、Finite State 等固件二进制分析产品面向没有源码的场景。纲目需要源码或构建过程，
只对预编译库和固件镜像（`.a`/`.lib`/`.so`/`.elf`/`.axf`/`.bin`）读版本横幅与导出符号，不做反汇编和函数级比对；换来的是能区分「编译了但没链接」的代码、能给出厂商 fork 的祖先版本，
以及一份任何人都能复核的开放规则库。

## 纲目不做什么？

- 不做深度二进制分析（只读横幅和导出符号）；
- 不做安全测试或渗透测试；
- 不替你下法律结论；
- 不替代 ENISA 或工信部的官方报送平台；
- 不猜 CPE：免费规则库 60 条里 29 条带 CPE，新增的都附有 NVD 里的 CVE 作为证据（`cpe_evidence`）；另外 31 条写明了没有 CPE 的原因。PURL 和 OSV 是一等匹配通道。

## 怎么贡献一条规则？

从干净的上游发布版用 `gangmu rules fingerprint` 生成识别块，或者用 `gangmu rules import`
从 SDK 的 `.gitmodules`、west manifest 批量导入，然后提 PR。CI 会克隆规则声明的上游版本，
把所有证据重新算一遍，对不上就拒绝。步骤见 [CONTRIBUTING.md](../CONTRIBUTING.md)
和 [RULE-FORMAT.md](RULE-FORMAT.md)；也可以提一个「组件识别请求」issue，告诉我们缺哪个组件。

## 有商业版吗？

有。核心能力会一直开源；需要长期运营这条流程的团队，可以使用商业版的漏洞持续监测、
报送工作台、规则库企业服务和私有化部署。对比见 [EDITIONS.md](EDITIONS.md)。

<script type="application/ld+json">
{
 "@context": "https://schema.org",
 "@type": "FAQPage",
 "inLanguage": "zh-CN",
 "mainEntity": [
  {
   "@type": "Question",
   "name": "纲目（Gangmu）是什么？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "纲目是一个开源的嵌入式 C/C++ 构建期 SBOM（软件物料清单）工具，附带一份社区共建的芯片 SDK 组件识别规则库。它从源码树和构建过程中识别第三方开源组件，输出 CycloneDX 1.6 或 SPDX 2.3， 比对漏洞并输出 CycloneDX VEX，对照欧盟《网络弹性法案》（CRA）逐条自查，并起草 CRA 第 14 条 与工信部《网络产品安全漏洞管理规定》第七条的报送材料。工具采用 Apache-2.0 许可， 规则数据采用 CDLA-Permissive-2.0 许可。命令行名为 gangmu，Python 包名为 gangmu-sbom。"
   }
  },
  {
   "@type": "Question",
   "name": "为什么叫「纲目」？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "名字取自李时珍的《本草纲目》。那部书把近两千种药物分门别类、逐一注明出处与性状， 让后人能够辨认和核对。纲目对固件里的第三方代码做同样的事：把每个组件归到「上游项目、版本、 是否被厂商修改」之下，并给出可以复核的证据。"
   }
  },
  {
   "@type": "Question",
   "name": "为什么嵌入式 C/C++ 很难生成 SBOM？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "因为 C/C++ 没有锁文件，而嵌入式开发又抹掉了剩下的证据。具体有四点："
   }
  },
  {
   "@type": "Question",
   "name": "纲目怎么识别被改名、被修改过的开源组件？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "纲目在函数级比对代码，而不是比较文件名或整棵目录的相似度。组件身份看「上游的函数有多少出现在这里」 （containment），版本看「这些函数属于哪几个发布版」。方法参考 CENTRIS（ICSE 2021）和 TIVER（ICSE 2025）。"
   }
  },
  {
   "@type": "Question",
   "name": "支持哪些芯片 SDK，包括哪些国产芯片？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "免费的 gangmu-rules 现有 60 条规则（Zephyr 及其 HAL、通用开源组件）。主要覆盖："
   }
  },
  {
   "@type": "Question",
   "name": "能识别国密库吗？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "能。GmSSL 支持 3.0.0–3.2.0 与 2.0.0–2.5.4（2.x 是独立规则）；铜锁（Tongsuo）支持 8.1.3–8.5.0 （8.1–8.3 是 BabaSSL 时期的版本）；同时覆盖 OpenSSL 1.1.0–1.1.1w 全部版本，以及 3.0 到 3.6 各线的最新补丁版。 三者都用逐版本锚点、多版本函数签名和版本探针识别。 铜锁是 OpenSSL 3.0 的分支，两者共享上万个函数；同时加载两条规则时，共享的函数对谁都不算身份证据， 各自只靠独有的代码被认出来，所以原版 OpenSSL 不会被误认成铜锁。国密分支 mbedTLS 还没有覆盖。"
   }
  },
  {
   "@type": "Question",
   "name": "支持 RT-Thread 和 OpenHarmony 吗？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "支持，而且是直接读生态自己的声明。RT-Thread 读 .config 和 packages/pkgs.json， OpenHarmony 读各第三方目录下的 README.OpenSource，以及每个部件的 bundle.json： OpenHarmony 自身的部件也会列入 SBOM，部件之间、部件与第三方库之间的依赖关系写进 CycloneDX 和 SPDX 的依赖图。声明与代码不一致时以代码为准， 分歧写进证据。RT-Thread 软件包的版本号是软件包自己的标签，不会被拼进上游组件的 CPE。 Zephyr 模块在 zephyr/module.yml 里声明的 CPE 和 PURL 也会被读取。"
   }
  },
  {
   "@type": "Question",
   "name": "支持哪些构建系统和 IDE？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "支持 compile_commands.json（CMake、ESP-IDF、Zephyr 等）、GNU ld、lld、IAR ilink、Arm armlink 链接 map、IAR .ewp、 Keil .uvprojx、TI CCS 与 Eclipse 工程。没有编译数据库时，可以用 gangmu wrap -- make 旁观一次真实构建来生成。编译器包装器在 POSIX 和 Windows 下都可用，但只能拦截按名字查找的编译器：Makefile 里写死绝对路径（如 CC=/opt/gcc/bin/gcc）会绕过它，Windows 下 shim 是真正的 gcc.exe，mingw32-make 的简单配方和 MSVC cl.exe、clang 和 arm-none-eabi-gcc 也能记录（CI 已验证）；MSYS/Git sh 下的构建未验证。这种情况请用 --project 读 IDE 工程。"
   }
  },
  {
   "@type": "Question",
   "name": "输出什么格式？满足 NTIA 和 CISA 的最小要素吗？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "输出 CycloneDX 1.6（默认）和 SPDX 2.3，也可以输出 JSON 和表格。厂商 fork 写在 CycloneDX 的 pedigree 里，每种识别技术及其置信度写在 evidence.identity 里，置信度上限 0.95。 gangmu sbom-score 按 NTIA 2021 和 CISA 2026 最小要素评分，纲目自己的输出两项都是 10.0/10。"
   }
  },
  {
   "@type": "Question",
   "name": "欧盟 CRA 对 SBOM 有什么要求？纲目覆盖了哪些？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "CRA（Regulation (EU) 2024/2847）Annex I Part II(1) 要求制造商用通用的机器可读格式编制 SBOM， 至少覆盖顶层依赖，收入技术文档，市场监管机构索要时提供，不要求公开。 纲目生成这份 SBOM，gangmu cra-check 逐条对照 Annex I Part II 的八项以及第 13(8) 条、第 14 条。 十项里有五项只会返回 partial、declared 或 out of scope：扫描不是安全测试，配置文件里的一个 URL 也不是漏洞披露政策被执行的证据。详见 CRA.md。"
   }
  },
  {
   "@type": "Question",
   "name": "CRA 的漏洞报告时限是什么？纲目能自动提交吗？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "制造商的漏洞报告义务自 2026 年 9 月 11 日起适用，其余义务自 2027 年 12 月 11 日起适用。 被积极利用的漏洞要在 24 小时内预警、72 小时内正式通报、纠正措施可用后 14 天内提交最终报告， 都经 ENISA 单一报告平台提交。纲目不能自动提交，因为该平台首发版本没有 API； gangmu report --stage early-warning 从 SBOM 和项目配置预填表单字段，缺的字段标 MISSING， 由人复制到平台。"
   }
  },
  {
   "@type": "Question",
   "name": "国内的漏洞报送有什么要求？和 CRA 有冲突吗？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "《网络产品安全漏洞管理规定》第七条要求发现漏洞后 2 日内报送工信部网络安全威胁和漏洞信息共享平台。 它不以「被积极利用」为前提，所以比 CRA 触发得更频繁。gangmu report --regime cn-miit 生成中文草稿。 该规定第九条第（七）项禁止向境外组织提供未公开的漏洞信息，而 CRA 要求 24 小时内向 ENISA 报送， 两者可能在同一事件上同时触发。纲目在生成欧盟草稿时提示这一点，但不替你下结论，这属于法务判断。 详见 CHINA.md。"
   }
  },
  {
   "@type": "Question",
   "name": "能在内网或离线环境使用吗？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "能。gangmu vuln 不联网，只读本地目录中的 NVD、OSV 镜像以及 CNNVD/CNVD 数据， 测试套件也不需要网络。填充这些目录是单独的 gangmu vuln-fetch 命令：在有网的机器上跑 （--sbom 只拉这份 SBOM 用得到的产品，--all 拉全量 NVD 并在之后增量更新），再把目录带进内网。 vuln-fetch 只抓 NVD 和 OSV；CNNVD/CNVD 的数据需要自行从对应平台导出。"
   }
  },
  {
   "@type": "Question",
   "name": "和 esp-idf-sbom、二进制分析工具有什么区别？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "乐鑫的 esp-idf-sbom 只覆盖 ESP-IDF，纲目把它的 sbom.yml 当作一等输入。 ONEKEY、Finite State 等固件二进制分析产品面向没有源码的场景。纲目需要源码或构建过程， 只对预编译库和固件镜像（.a/.lib/.so/.elf/.axf/.bin）读版本横幅与导出符号，不做反汇编和函数级比对；换来的是能区分「编译了但没链接」的代码、能给出厂商 fork 的祖先版本， 以及一份任何人都能复核的开放规则库。"
   }
  },
  {
   "@type": "Question",
   "name": "纲目不做什么？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "- 不做深度二进制分析（只读横幅和导出符号）； - 不做安全测试或渗透测试； - 不替你下法律结论； - 不替代 ENISA 或工信部的官方报送平台； - 不猜 CPE：免费规则库 60 条里 29 条带 CPE，新增的都附有 NVD 里的 CVE 作为证据（cpe_evidence）；另外 31 条写明了没有 CPE 的原因。PURL 和 OSV 是一等匹配通道。"
   }
  },
  {
   "@type": "Question",
   "name": "怎么贡献一条规则？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "从干净的上游发布版用 gangmu rules fingerprint 生成识别块，或者用 gangmu rules import 从 SDK 的 .gitmodules、west manifest 批量导入，然后提 PR。CI 会克隆规则声明的上游版本， 把所有证据重新算一遍，对不上就拒绝。步骤见 CONTRIBUTING.md 和 RULE-FORMAT.md；也可以提一个「组件识别请求」issue，告诉我们缺哪个组件。"
   }
  },
  {
   "@type": "Question",
   "name": "有商业版吗？",
   "acceptedAnswer": {
    "@type": "Answer",
    "text": "有。核心能力会一直开源；需要长期运营这条流程的团队，可以使用商业版的漏洞持续监测、 报送工作台、规则库企业服务和私有化部署。对比见 EDITIONS.md。"
   }
  }
 ]
}
</script>
