---
title: Zephyr 固件怎么生成 SBOM：west build 后用纲目扫描
description: 为 Zephyr 应用生成 CycloneDX / SPDX SBOM：读 west build 产生的 compile_commands.json、zephyr.map 和 .config，识别 Mbed TLS、hostap、MCUboot 以及兆易、博流、沁恒等国产芯片 HAL。
---

# Zephyr 固件怎么生成 SBOM

> **Summary (English).** After `west build`, point `gangmu scan` at the build's `compile_commands.json`, `zephyr.map` and `.config`. Components disabled in Kconfig are dropped; Zephyr module metadata (`zephyr/module.yml` CPE/PURL) is read; rules cover Mbed TLS, TF-PSA-Crypto, hostap, MCUboot, nanopb and HALs for GigaDevice, Bouffalo, WCH, SiFli, Telink and Realtek.

Zephyr 的第三方代码分布在 `modules/` 下，是否进入固件由 Kconfig 决定。纲目读 `west build` 留下的构建事实，
只把真正编译、链接的模块写进 SBOM。

## 步骤

```bash
pip install gangmu-sbom
west build -b <board> app

gangmu init
gangmu scan . \
    --compile-db build/compile_commands.json \
    --link-map   build/zephyr/zephyr.map \
    --kconfig    build/zephyr/.config \
    --format cyclonedx -o sbom.cdx.json
```

`build/zephyr/.config` 在默认位置时会被自动读取，`--kconfig` 用来显式指定。

## 能识别什么

- Mbed TLS 4.1、TF-PSA-Crypto、hostap（wpa_supplicant / hostapd）、FatFs、littlefs、MCUboot、nanopb、zcbor、uOSCORE/uEDHOC。
- 国产与亚太芯片 HAL：兆易创新 GD32、博流智能 BL60x/BL70x、沁恒 CH32、思澈 SiFli、泰凌微 TLSR9、瑞昱 Ameba/Bee。这些规则取自 Zephyr 4.4 的锁定提交，可从上游逐字节复现。
- Zephyr 模块在 `zephyr/module.yml` 的 `security.external-references` 里声明的 CPE 和 PURL 会被读取。

## 注意

- Zephyr 里的 Mbed TLS 不是构建胶水，而是 Zephyr Wi-Fi 的基础，也是漏洞高发组件，不要因为它在 `modules/crypto/` 下就忽略。
- 规则库不猜 CPE：没有可靠 CPE 的组件靠 PURL / OSV 匹配漏洞，规则里写明了原因。

## 下一步

```bash
gangmu vuln sbom.cdx.json --db advisories/ -o vex.json
gangmu cra-check --sbom sbom.cdx.json --vex vex.json
```

- [示例产物](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/output) · [CRA 对标](../CRA.md) · [国产生态覆盖](../CHINA.md)
- 其他 SDK：[ESP-IDF](esp-idf-sbom.md) · [RT-Thread](rt-thread-sbom.md)
