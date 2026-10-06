---
title: STM32、NXP、Nordic、TI 固件怎么生成 SBOM：Zephyr HAL 与 IDE 工程
description: STM32CubeIDE、MCUXpresso、nRF Connect SDK、Zephyr 工程用纲目生成 SBOM：哪些 HAL 目录有规则，哪些只能靠构建事实，以及现在不覆盖什么。
---

# STM32、NXP、Nordic、TI 固件怎么生成 SBOM

> **Summary (English).** Gangmu has rules for the Zephyr-distributed HAL modules of STMicroelectronics, NXP, Nordic, TI, Renesas, Silicon Labs and Infineon (`modules/hal/*`). It has no rules for the vendors' own standalone SDK packages (STM32Cube packages, the MCUXpresso SDK, the nRF5 SDK); for those it still reads build facts and identifies the generic open-source components inside. Check each release for current coverage.

## 先说覆盖范围

| 你的工程 | 纲目能做什么 | 不能做什么 |
| --- | --- | --- |
| Zephyr 或 nRF Connect SDK（west + CMake） | 读 `compile_commands.json`、链接 map、Kconfig，识别 Mbed TLS、hostap、MCUboot 等通用组件；`modules/hal/` 下 STM32、NXP、Nordic、TI、Renesas、Silicon Labs、Infineon 的 HAL 目录有规则（见下） | HAL 规则按 Zephyr 的锁定提交生成，目录被厂商再改过时只报告为已修改的 HAL |
| STM32CubeIDE（Eclipse CDT） | 用 `--project` 读 `.cproject`，用 GNU ld 的 map 区分链接与否，识别 FreeRTOS、lwIP、Mbed TLS、FatFs 等通用组件 | 没有 STM32Cube 软件包本身的规则；Cube 里的 HAL 驱动不会被当作已识别组件 |
| MCUXpresso IDE（Eclipse CDT） | 同上 | 没有 MCUXpresso SDK 本身的规则 |
| nRF5 SDK、Keil / IAR 工程 | 见 [IAR、Keil、TI CCS](iar-keil-ccs-sbom.md) | 同上，没有 nRF5 SDK 的规则 |

厂商自己的完整 SDK 规则属于规则库的商业版；Zephyr 项目分发的 HAL 模块在免费库里。
覆盖范围以当前发布的 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) 为准。

## Zephyr / nRF Connect SDK

```bash
west build -b <board> app
gangmu scan . \
    --compile-db build/compile_commands.json \
    --link-map   build/zephyr/zephyr.map \
    --kconfig    build/zephyr/.config \
    --format cyclonedx -o sbom.cdx.json
```

HAL 规则来自 Zephyr 的锁定提交：`stm32`、`nxp`、`nordic`、`ti`、`renesas`、`silabs`、`infineon` 七个目录。
这些规则目前没有 CPE，漏洞比对靠 PURL / OSV，规则里写明了原因。详见 [Zephyr 指南](zephyr-sbom.md)。

## STM32CubeIDE、MCUXpresso IDE

两者都是 Eclipse CDT 工程，纲目读 `.cproject` 和 `.project`：

```bash
gangmu scan . --project . --configuration Release \
    --link-map Release/app.map --format cyclonedx -o sbom.cdx.json
```

- 工程里的链接资源（把 SDK 目录挂进工程）会被读到；
- 配置里排除的文件不算编译过；
- 这两个 IDE 的 map 通常是 GNU ld 格式，可直接用。

我们还没有在真实的 STM32CubeIDE 或 MCUXpresso 工程上做过逐个验证；如果结果不对，请[提 issue](https://github.com/GANGMU-SBOM/gangmu/issues) 附上脱敏的 `.cproject`。

## 下一步

```bash
gangmu vuln sbom.cdx.json --db advisories/ -o vex.json
gangmu cra-check --sbom sbom.cdx.json --vex vex.json
```

- 其他任务：[ESP-IDF](esp-idf-sbom.md) · [Zephyr](zephyr-sbom.md) · [IAR、Keil、CCS](iar-keil-ccs-sbom.md)
