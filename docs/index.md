---
title: 纲目 Gangmu：嵌入式固件 SBOM 与 CRA 合规工具
description: 纲目（Gangmu）是面向嵌入式 C/C++ 固件的开源构建期 SBOM 工具，配社区共建的芯片 SDK 组件识别规则库，支持国产芯片 SDK、国密库识别、CycloneDX/SPDX、VEX、欧盟 CRA 与工信部漏洞报送草稿。
---

# 纲目 Gangmu

**面向嵌入式 C/C++ 的构建期 SBOM 工具，配一份社区共建的芯片 SDK 组件识别规则库。**

纲目识别被芯片原厂改名、魔改、静态链接后的开源组件，生成 CycloneDX / SPDX 软件物料清单和 VEX，
对照欧盟《网络弹性法案》（CRA）自查，并起草 CRA 第 14 条与工信部《网络产品安全漏洞管理规定》
第七条的漏洞报送材料。工具采用 Apache-2.0，免费规则库采用 CDLA-Permissive-2.0。

名字取自李时珍《本草纲目》：把每一味药分门别类、注明出处，后人才能辨认和核对。
纲目对固件里的第三方代码做同样的事。

- 源码与安装：[GitHub](https://github.com/GANGMU-SBOM/gangmu)
- [常见问题](FAQ.md) · [FAQ (English)](FAQ.en.md) · [术语表](GLOSSARY.md)
- [CRA 对标](CRA.md) · [国内合规](CHINA.md) · [算法](ALGORITHMS.md) · [评测基准](BENCHMARK.md) · [规则格式](RULE-FORMAT.md)
- [能力边界](LIMITS.md) · [更新记录](CHANGELOG.md) · [开源版与商业版](EDITIONS.md)
- 按任务查：[ESP-IDF](guides/esp-idf-sbom.md) · [Zephyr](guides/zephyr-sbom.md) · [IAR / Keil / CCS](guides/iar-keil-ccs-sbom.md) · [STM32 / NXP / Nordic](guides/stm32-nxp-nordic-sbom.md) · [RT-Thread / OpenHarmony](guides/rt-thread-sbom.md) · [国密库 GmSSL / 铜锁](guides/gmssl-tongsuo-sbom.md) · [魔改组件识别](guides/vendor-modified-components.md) · [密码清单 CBOM 与后量子](guides/cbom-post-quantum.md) · [CRA 与工信部报送](guides/cra-and-miit-reporting.md) · [医疗器械 FDA SBOM](guides/medical-device-fda-sbom.md) · [工控 IEC 62443 与 CRA](guides/industrial-iec62443-cra-sbom.md) · [联网设备 CRA 与 RED](guides/iot-cra-red-sbom.md) · [与 Syft / Trivy 等的区别](COMPARE.md)
- 示例产物：[SBOM、CRA 自查、报送草稿](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/output)
- 相关仓库：[gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules)（免费规则库，识别不出通用组件去这里；厂商专属规则属于商业版）· [gangmu-bench](https://github.com/GANGMU-SBOM/gangmu-bench)（识别准确率评测）

## 能做什么

| 场景 | 命令 |
| --- | --- |
| 从源码树与构建过程生成 SBOM | `gangmu scan` |
| 读 IAR / Keil / CCS 工程，或旁观一次构建 | `gangmu scan --project`、`gangmu wrap` |
| 联网填充漏洞库目录（NVD、OSV；有网的机器上运行） | `gangmu vuln-fetch` |
| 离线漏洞比对，输出 VEX | `gangmu vuln` |
| 逐条对照 CRA | `gangmu cra-check` |
| CRA 24 小时预警与工信部 2 日报送草稿 | `gangmu report` |
| 十年留存技术文档包 | `gangmu evidence` |
| 规则生成、导入与复现 | `gangmu rules` |

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareSourceCode",
  "name": "Gangmu",
  "alternateName": ["纲目", "gangmu-sbom"],
  "description": "Open-source build-time SBOM tool for embedded C/C++ firmware with a community rule base for chip-vendor SDK components; CycloneDX, SPDX, VEX, EU Cyber Resilience Act checks and vulnerability report drafts.",
  "codeRepository": "https://github.com/GANGMU-SBOM/gangmu",
  "programmingLanguage": "Python",
  "runtimePlatform": "Python 3.9+",
  "license": "https://www.apache.org/licenses/LICENSE-2.0",
  "keywords": "SBOM, embedded, firmware, C/C++, Cyber Resilience Act, CRA, CycloneDX, SPDX, VEX, ESP-IDF, Zephyr, RT-Thread, OpenHarmony, GmSSL, Tongsuo, SM2, SM3, SM4, 软件物料清单, 固件合规, 国产芯片, 国密",
  "inLanguage": ["zh-CN", "en"]
}
</script>
