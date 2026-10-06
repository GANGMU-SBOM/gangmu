---
title: 工控与 IIoT 固件的第三方组件清单：IEC 62443-4-1 与欧盟 CRA 怎么用 SBOM
description: 工业控制设备固件的 SBOM 怎么做：IEC 62443-4-1 对第三方组件清单和风险管理的要求（SM-9、SM-10）、CRA 对 PLC 与工业网关的分级、用纲目生成并留存证据。含 FreeRTOS 的真实最小样例与规则缺口。
---

# 工控与 IIoT 固件的第三方组件清单

> **Summary (English).** IEC 62443-4-1 asks product suppliers to keep an inventory of third-party components and manage their security risks (practices SM-9 and SM-10); it does not name SBOM or a format, but SBOM is the usual way to meet it. Under the EU Cyber Resilience Act, PLCs, robot controllers and industrial IoT gateways are listed in the important-products Class II and need a notified body. `gangmu scan` with the build's compile database and linker map shows what actually shipped. A minimal real FreeRTOS example is in `examples/industry/industrial-freertos/`. Missing: rules for the industrial protocol stacks and runtimes.

## 要求

这一节的条文我们**没有读到标准原文**，下面来自二手解读，写进合规文件前请对照标准：

- IEC 62443-4-1：建议有第三方组件的清单，并要有流程识别和管理外部提供组件的安全风险（SM-9、SM-10）；**不明文要求 SBOM 或指定格式**，SBOM 是满足这些条款的常见做法。
  来源：[ISASecure](https://isasecure.org/an-overview-of-isa/iec-62443-4-1-and-its-supply-chain-requirements)、[presencis](https://presencis.com/regulations/iec-62443/article-4-5-supply-chain/)。
- 欧盟 CRA 实施条例 2025/2392 的重要产品分级：工业 PLC 或机器人控制器、带安全区的微控制器、工业 IoT 网关属 Class II，必须公告机构评估；通用微控制器属 Class I。
  来源：[eucybersecurity.org](https://eucybersecurity.org/en/product-classification)、[FOSSA](https://fossa.com/blog/cra-product-classification/)，是二手页，要对照条例原文。
- CRA 附件 I 第 II 部分第 1 条要求按常用、机器可读的格式编制 SBOM，至少覆盖顶层依赖（[eucybersecurity.org](https://eucybersecurity.org/en/glossary/sbom)）。
- 中国工控领域有没有点名 SBOM 的强制条文，**未核实**。

## 步骤

```bash
gangmu wrap -- make -j8                  # 没有 compile_commands.json 时，用垫片记录真实构建
gangmu scan . --compile-db compile_commands.json --link-map build/firmware.map \
    --no-binaries --app-name plc-gateway --app-version 3.1.0 --format cyclonedx -o sbom.cdx.json
gangmu vuln-fetch --db advisories --sbom sbom.cdx.json
gangmu vuln sbom.cdx.json --db advisories -o vex.cdx.json --format cyclonedx
gangmu evidence --out cra-evidence/      # 十年留存的技术文档包
```

- 链接 map 能区分“编译了但被链接器丢掉”的目标文件，这是第三方组件清单最容易多报的地方。
- 单体仓库里，其他板子的预编译库会被当成组件列出来（标 `gangmu:linkedIntoImage=false`），扫整个仓库时加 `--no-binaries`。
- 持续集成：[GitLab CI 与 Jenkins 模板](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/ci)。

## 样例

[`examples/industry/industrial-freertos/`](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/industry/industrial-freertos)：
FreeRTOS 官方仓库的 MPS2 演示，只含内核。整个仓库有几十个演示，进固件的只有内核 11.3.1，且漏洞快照里对它没有匹配。
它**不是**一台工控网关，不含网络栈、TLS 或 Modbus。

## 目前的缺口

- 免费规则库里没有工控常见的协议栈和运行时（Modbus、OPC UA 的开源实现等），这是最需要社区补的规则。
- 没有 62443-4-1 SM-9、SM-10 的证据包导出格式，目前只有 CRA 的技术文档包。
- 没有 Yocto 构建事实的对账，Yocto 自己默认产 SPDX 3.0（见 [COMPARE.md](../COMPARE.md)）。
- 纲目不替代 62443 的审核和认证，也不下法律结论。
