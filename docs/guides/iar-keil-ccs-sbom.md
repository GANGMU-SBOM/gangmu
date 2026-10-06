---
title: IAR、Keil、TI CCS 固件怎么生成 SBOM：读工程文件加链接 map
description: 没有 compile_commands.json 的 IAR Embedded Workbench、Keil MDK、TI Code Composer Studio 工程，用纲目读 .ewp / .uvprojx / .cproject 加上链接 map 生成 CycloneDX / SPDX SBOM，区分编译过的和真正链接进固件的。
---

# IAR、Keil、TI CCS 固件怎么生成 SBOM

> **Summary (English).** IAR, Keil and CCS projects do not produce `compile_commands.json`. `gangmu scan --project <file>` reads the project's file list and excluded files per configuration; adding `--link-map` (IAR ilink, Arm armlink, GNU ld or lld) separates what was compiled from what reached the image. The IAR and armlink map parsers were written to the vendors' documented layouts and tested on hand-written samples, not yet on real projects.

这三类工程把文件清单放在自己的 XML 里，不经过 CMake，所以拿不到编译数据库。纲目直接读工程文件，
再拿链接 map 校对“编译了”和“链接后留下了”。

## 步骤

```bash
pip install gangmu-sbom

# IAR：Project > Options > Linker > List > Generate linker map file
# Keil：Options for Target > Listing > Linker Listing（会生成 .map）
# CCS：Linker 选项里打开 map 文件输出（-m）
gangmu scan . \
    --project app.ewp --configuration Release \
    --link-map Release/List/app.map \
    --format cyclonedx -o sbom.cdx.json
```

- `--project` 接受 IAR `.ewp`、Keil `.uvprojx` / `.uvproj`、CCS 的 `.cproject` / `.project`，或包含它们的目录。
- `--configuration` 选工程里的配置或目标，不写就用第一个，扫描会提示用了哪个。
- 每个配置里被排除的文件（IAR 的 `excluded`、Keil 的 `IncludeInBuild=0`、CCS 的 `excluding`）不算编译过。
- CCS 通过 `.project` 里的链接资源（`PARENT-n-PROJECT_LOC`）引入的 SDK 目录会被读到。

## 链接 map 带来什么

没有 map 时，工程里列了的源文件都当作出货，会多报。有 map 时：

| 工具链 | map 里读什么 |
| --- | --- |
| IAR ilink | `MODULE SUMMARY`：按来源文件分组的模块清单，来自 `.a` / `.lib` 的当作库成员 |
| Arm armlink（Keil） | `Image component sizes` 和 `Memory Map of the image` 里的目标文件，`Removing Unused input sections` 里被丢掉的段 |
| GNU ld、lld | `archive(member)` 写法，以及 GNU ld 的 `Discarded input sections` |

工程不记录目标文件路径，纲目按“源文件名 + `.o` / `.obj`”推出目标文件名，再和 map 里的名字按主干名对齐。

## 注意

- IAR 不打印被丢弃的模块：工程里有、map 里没出现的源文件会被判为未链接。
- 不同目录里同名的源文件（两个 `main.c`）会按保守处理保留，扫描会列出这种歧义。
- TI 自带链接器的 map 没有专门解析。
- IAR 与 armlink 的解析按厂商文档的版式编写，测试用手写样例，尚未用大量真实工程验证。遇到读不出来的 map，请[提 issue](https://github.com/GANGMU-SBOM/gangmu/issues) 并附上脱敏的 map 片段。
- 没有 map、只有工程时，纲目会说明没有咨询过链接器。

## 下一步

```bash
gangmu vuln sbom.cdx.json --db advisories/ -o vex.json
gangmu cra-check --sbom sbom.cdx.json --vex vex.json
```

- [能力边界](../LIMITS.md) · [CRA 对标](../CRA.md)
- 其他任务：[ESP-IDF](esp-idf-sbom.md) · [Zephyr](zephyr-sbom.md) · [STM32 / NXP / Nordic](stm32-nxp-nordic-sbom.md)
