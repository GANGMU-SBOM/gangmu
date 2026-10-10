# 开源版与商业版

[English](#open-source-and-commercial-editions)

gangmu 的核心能力全部开源，并会一直开源：识别引擎、构建期采集、SBOM 输出、漏洞比对、
评测基准、报送草稿生成，以及免费规则库 gangmu-rules（通用开源组件、Zephyr 及其 HAL、社区贡献的规则），
都可以免费使用、修改和再分发。

规则库分成两部分。免费的 gangmu-rules 放被各家 SDK 拷贝最多的通用组件和社区贡献的规则。
只跟某一家公司绑定的规则（这家公司自己的 SDK、固件库，或它 fork 过的开源组件）属于商业版规则包。

一个团队靠开源版就能完整走通一遍：从构建生成 SBOM，比对漏洞，对照 CRA 自查，
再生成报送草稿。商业版和服务面向的是另一类需求：要**长期运营**这条流程，
要**有人对判断负责**，或者要在**内网、信创环境**里交付。

## 开源版

工具采用 Apache-2.0，免费规则库的规则数据采用 CDLA-Permissive-2.0。

| 能力 | 说明 |
| --- | --- |
| 免费规则库 gangmu-rules | 被各家 SDK 拷贝最多的上游组件（lwIP、Mbed TLS、FreeRTOS、LVGL 等）、Zephyr 及其 HAL 和社区贡献的规则，每条都能从上游复现 |
| 函数级识别引擎 | 多版本函数签名、自适应版本区间、厂商修改检测 |
| 构建期采集 | `compile_commands.json`、链接 map、IAR / Keil / CCS 工程、编译器包装器 |
| 生态声明直读 | RT-Thread、OpenHarmony、ESP-IDF 的组件声明 |
| SBOM 输出与评分 | CycloneDX 1.6、SPDX 2.3 与 3.0.1，NTIA 2021 与 CISA 2026 最小要素评分；组件维护状态与停止支持日期字段 |
| 漏洞比对 | 本地 NVD / OSV / 国内漏洞库目录，输出 CycloneDX VEX、OpenVEX、CSAF 2.0 VEX |
| CRA 自查与技术文档包 | `cra-check`、`evidence` |
| 报送草稿 | CRA 第 14 条与工信部《网络产品安全漏洞管理规定》第七条 |
| 评测基准 | `gangmu eval`，可复现 |
| 密码物料清单与 AI 物料清单 | `gangmu cbom`（含后量子迁移摘要、`--libraries`）、`gangmu aibom`，以及规则仓库 gangmu-cbom-rules |
| 策略检查 | `gangmu policy check` 与策略格式（`policies/*.yaml`），自己写策略包不需要商业版 |
| CI 模板 | GitHub Action（本仓库的 SBOM 版，和 gangmu-action 的 SBOM + CBOM + 迁移摘要版）、GitLab CI、Jenkinsfile（`examples/ci/`） |

## 商业版与服务

| 能力 | 解决什么问题 |
| --- | --- |
| **漏洞持续监测** | NVD、GHSA、OSV、CNNVD、CNVD 多源合并去重，新漏洞出现时按产品型号推送；VEX 判定由专人复核并留痕 |
| **报送工作台** | CRA 24 小时 / 72 小时 / 14 天与工信部 2 日四条时限并行跟踪；版本级 SBOM 归档，十年留存；审批与留痕 |
| **商业版规则包** | 芯片原厂与厂商专属的固件库、fork 组件规则，按需订阅，装上后自动叠加在免费规则库之上 |
| **合规策略包** | 维护好的法规与标准映射，如 NIST IR 8547 的算法过渡期限，随法规更新，仓库 gangmu-policy-pro |
| **规则库企业服务** | 离线镜像、带响应时限的规则更新、为您自有 BSP 和私有 SDK 建立的私有规则 |
| **中欧双重报送台账** | 同一事件同时触发两套义务时的流程、审批与记录 |
| **芯片原厂规则包认证** | 为原厂出具可交付给下游客户的官方组件清单规则包 |
| **私有化部署** | 内网交付、信创环境适配、与现有 CI 和制品库集成 |
| **技术支持与集成** | 构建系统接入、规则编写培训、合规流程咨询 |

## 我们不做的事

无论开源版还是商业版，以下事项都不在范围内：

- **替您下法律结论。** 例如中欧两套义务在同一事件上是否冲突、如何处理，属于法务判断。工具负责提示，服务负责流程，结论由您的法务作出。
- **安全测试与渗透。** CRA Annex I Part II(3) 要求的安全测试不是 SBOM 工具能替代的。
- **替代官方通报平台。** 工信部平台与 ENISA 单一报告平台是唯一的正式渠道，我们只做填报准备。

## 联系我们

需要商业版、试用，或者想参与规则共建、认领某个芯片 SDK，可以发邮件到 64031875@qq.com，或者扫码加入「CRA 合规群」；也可以在 GitHub 提一个 issue，标题以「商业版」开头。技术咨询和商务合作都走这几个渠道。

<img src="assets/cra-wechat-group.png" alt="CRA 合规群二维码" width="200">

二维码有有效期，扫不出来或已过期请发邮件。

---

## Open-source and commercial editions

gangmu's core is open source and will stay that way: the identification engine,
build-time collection, SBOM output, vulnerability matching, the benchmark, the
reporting drafts and the free rule base gangmu-rules (general open-source
components, Zephyr and its HALs, community contributions) are all free to use,
modify and redistribute.

The rule base comes in two parts. The free gangmu-rules holds the general
components vendor SDKs copy most and community contributions. Rules tied to a
single company (its own SDK, its firmware library, or an open-source component it forked) belong to the commercial rule packs.

The commercial edition and services are for teams that need to **run** the
process over the long term, need **someone accountable** for the judgement
calls, or need delivery **inside an air-gapped or domestic-IT environment**:

- **Continuous vulnerability monitoring:** multi-source (NVD, GHSA, OSV, CNNVD, CNVD), de-duplicated, per product model, with reviewed VEX decisions.
- **Reporting workbench:** the CRA 24h / 72h / 14-day clocks and China's 2-day clock tracked in parallel, versioned SBOM archive, ten-year retention.
- **Commercial rule packs:** vendor-specific firmware-library and fork rules, subscribed to as needed and overlaid automatically on the free rule base.
- **Rule base enterprise service:** offline mirror, rule updates with a response-time commitment, private rules for your own BSPs and SDKs.
- **Dual-obligation register** for incidents that trigger both the EU and the Chinese duty.
- **Silicon-vendor rule-pack certification.**
- **On-premises deployment**, integration and support.

Not offered in either edition: legal conclusions, security testing, or a
replacement for the official reporting platforms.

**Contact:** to try the commercial edition, or to take part in rule building or claim a chip SDK: email 64031875@qq.com, or join the "CRA compliance group" on WeChat (QR code above, it expires; email if it does not scan). You can also open a GitHub issue whose title starts with "Commercial".
