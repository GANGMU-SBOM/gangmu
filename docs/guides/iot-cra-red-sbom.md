---
title: 出口欧盟的联网设备固件：CRA 与 RED（EN 18031）下怎么做 SBOM
description: 面向出口欧盟的 Wi-Fi、蓝牙等联网设备：RED 授权法案与 EN 18031 不要求 SBOM，CRA 要求；用纲目在 ESP-IDF 工程上生成 SBOM、VEX 和 CRA 自查。含 ESP-IDF 5.4.1（ESP32-C3）的真实样例。
---

# 出口欧盟的联网设备固件：CRA 与 RED 下怎么做 SBOM

> **Summary (English).** The EU Radio Equipment Directive delegated act (2022/30, applying from 2025-08-01) and the EN 18031 standards cover wireless devices but, in the sources checked, do not ask for an SBOM; the Cyber Resilience Act does (Annex I Part II(1)). So for a connected product the SBOM duty comes from CRA. A real ESP-IDF 5.4.1 / ESP32-C3 example, with CycloneDX, SPDX 3, VEX in three formats and a `cra-check` result, is in `examples/industry/iot-esp-idf/`.

## RED 与 CRA 的分工

- **RED 授权法案（欧盟 2022/30）**：2025-08-01 起适用于联网、处理个人数据或涉及支付的无线设备，协调标准 EN 18031-1/-2/-3 于 2025-01-28 在官方公报公布引用。
  要求里有固件“安全且经验证的更新”，我们检索到的材料里**没有 SBOM 要求**（乐鑫的合规指南同样没有）。
  来源：[Espressif 指南](https://developer.espressif.com/blog/2025/04/esp32-red-da-en18031-compliance-guide/)、[TÜV SÜD](https://www.tuvsud.com/en-us/services/product-certification/ce-marking/radio-equipment-directive/cybersecurity-for-radio-equipment-directive)。
- **CRA（条例 2024/2847）**：附件 I 第 II 部分第 1 条要求按常用、机器可读的格式编制 SBOM，至少覆盖顶层依赖；
  报送义务自 2026-09-11 起适用，其余自 2027-12-11 起（见 [CRA.md](../CRA.md)）。
- 所以对联网设备，SBOM 的动力来自 CRA，不是 RED。【推断，依据上面两条】

## 步骤（ESP-IDF 为例）

```bash
idf.py set-target esp32c3 && idf.py build
B=build
gangmu scan $IDF_PATH --compile-db $B/compile_commands.json --link-map $B/<app>.map \
    --kconfig sdkconfig --no-binaries --app-name my-iot-device --app-version 1.0.0 \
    --format cyclonedx -o sbom.cdx.json
gangmu scan $IDF_PATH ... --format spdx3 -o sbom.spdx3.json
gangmu vuln-fetch --db advisories --sbom sbom.cdx.json
gangmu vuln sbom.cdx.json --db advisories --format openvex --publisher "你的公司"
gangmu cra-check --scan scan.json --sbom sbom.cdx.json --vex vex.cdx.json --no-fail
```

更多细节：[ESP-IDF 指南](esp-idf-sbom.md)、[CRA 与工信部报送](cra-and-miit-reporting.md)。

## 样例

[`examples/industry/iot-esp-idf/`](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/industry/iot-esp-idf)：
ESP-IDF 5.4.1 的 Wi-Fi Station，在 ESP32-C3 上真实构建。免费规则库认出 Mbed TLS、lwIP、cJSON、FatFs 四个组件，
其中 cJSON 与 FatFs 在树里但没链接进镜像（SBOM 里标为 `excluded`，漏洞不会写成 `exploitable`）；FreeRTOS 与 hostap 只到“可能”，没有写进 SBOM。样例里有三种格式的 VEX 和 `cra-check` 结果。

## 目前的缺口

- ESP-IDF 自己的 fork 靠乐鑫的规则包才认得全，免费库只认出四个。
- 链接图看不出 LTO 和运行时加载的代码，所以“没链接”的组件只是被降为 `in_triage`；确认后用 `gangmu vuln --unlinked-vex` 才会写成 `not_affected`。
- ESP-IDF 里 FatFs 的供应商和 fork 说明现在留空（不借用 Zephyr 的规则），要写准需要乐鑫的规则包。
- 纲目不下法律结论，也不替代 ENISA 单一报告平台。
