---
title: 医疗器械固件怎么做 FDA 要求的 SBOM（524B、组件支持状态）
description: 为医疗器械嵌入式固件生成 FDA 上市前提交要求的 SBOM：机器可读格式、每个组件的维护支持级别与停止支持日期、已知漏洞；用纲目的 --support、SPDX 3 和 VEX 输出。含 Zephyr + nRF52840 的真实样例与目前的缺口。
---

# 医疗器械固件怎么做 FDA 要求的 SBOM

> **Summary (English).** FDA's premarket cybersecurity guidance (issued 2026-02-03, superseding the 2025-06-27 version) asks for a machine-readable SBOM that meets the NTIA minimum elements, plus, for each component, the level of support from its maintainer and its end-of-support date, and the known vulnerabilities. `gangmu scan --support FILE` records the support facts you can cite and writes `unknown` for the rest; `--format spdx3` and `gangmu vuln --format openvex|csaf` give the formats. A real Zephyr 4.1.0 + nRF52840 example is in `examples/industry/medical-zephyr-nrf52840/`. Not covered yet: IEC 62304 SOUP register format, eSTAR attachment templates, and rules for the Zephyr kernel itself.

## FDA 要什么

下面都出自 FDA《Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions》，
**2026-02-03 发布，替代 2025-06-27 版**（[FDA 原文](https://www.fda.gov/media/119933/download)，第 V.A.4 节和第 VII.C.3 节）：

- 联网的“网络设备”（cyber device）必须提交 SBOM，范围含商业、开源和现成软件组件，依据 FD&C 法案第 524B(b)(3) 条。
- 建议提供机器可读的 SBOM，满足 NTIA 2021 的最低要素；**每个组件另加两项**：厂商提供的监测与维护的支持级别（例如在维护、不再维护、已弃用），和该组件的停止支持日期。
- 提交时还要列出器械及其软件组件的已知漏洞。
- 无法提供 SBOM 信息时，要说明理由。
- 上市后，SBOM 或等价能力要作为配置管理的一部分持续更新；标签里要向用户提供机器可读的 SBOM 信息。

欧盟 MDR 的条文本身不要求 SBOM，是咨询机构认为它属于“最新技术水平”（[Johner Institute](https://blog.johner-institute.com/iec-62304-medical-software/sbom-software-bill-of-materials/)，是观点不是条文）。
中国国家药监局有《医疗器械网络安全注册审查指导原则（2022 年修订版）》，技术考虑含现成软件（[通告目录](https://www.secrss.com/articles/40158)），正文里是否使用“软件物料清单”一词我们**没有核实**。

## 步骤

```bash
pip install gangmu-sbom
# 1. 真实构建，保留 compile_commands.json、链接 map、Kconfig
# 2. 写一份 support.yaml：只写你能给出来源的
gangmu scan . --compile-db build/compile_commands.json --link-map build/zephyr/zephyr.map \
    --kconfig build/zephyr/.config --support support.yaml \
    --app-name my-device-fw --app-version 1.2.0 --format cyclonedx -o sbom.cdx.json
gangmu scan . ... --format spdx3 -o sbom.spdx3.json         # 同样的内容，SPDX 3.0.1
gangmu vuln-fetch --db advisories --sbom sbom.cdx.json       # 联网的一步，在有网的机器上做
gangmu vuln sbom.cdx.json --db advisories --format openvex --publisher "你的公司"   # 或 --format csaf --publisher-url ...
```

`support.yaml`：

```yaml
components:
  - name: Mbed TLS
    status: maintained            # maintained | limited | no_longer_maintained | abandoned
    end_of_support: 2027-03-31
    source: https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md
    as_of: 2026-10-06
```

没有人声明的组件，SBOM 里写 `unknown`，不会留空，也不会猜。CycloneDX 里是 `gangmu:supportStatus`、`gangmu:endOfSupport` 属性，
SPDX 2.3 是 `validUntilDate`，SPDX 3 是 `supportLevel` 和 `validUntilTime`。规则作者也可以在规则的 `upstream.support` 里写，见 [RULE-FORMAT](../RULE-FORMAT.md)。

## 样例

[`examples/industry/medical-zephyr-nrf52840/`](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/industry/medical-zephyr-nrf52840)：
Zephyr 4.1.0 的蓝牙心率外设，在 nRF52840 上真实构建。它不是医疗器械，只是这类技术栈的代表。里面有 CycloneDX、SPDX 3、三种格式的 VEX 和复现命令。

## 目前的缺口

- **Zephyr 内核本身没有规则**，免费库认不出它；RTOS 恰恰是提交里最该有的组件。
- **没有 IEC 62304 的 SOUP 清单格式**，也没有 FDA eSTAR 的附件模板。
- **支持级别没有自动来源**：没有“上游项目现在是否还在维护”的数据库，只能由人填并给出来源。
- 纲目不下法律结论，不替代安全测试，也不替代 FDA 的任何提交流程。
