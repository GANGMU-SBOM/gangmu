---
title: RT-Thread 与 OpenHarmony 固件怎么生成 SBOM
description: 纲目直接读 RT-Thread 的 .config 与 packages/pkgs.json、OpenHarmony 的 README.OpenSource 和 bundle.json，再用函数级指纹识别 RT-Thread 内核版本，输出 CycloneDX / SPDX。
---

# RT-Thread 与 OpenHarmony 固件怎么生成 SBOM

> **Summary (English).** For ecosystems with their own package declarations, gangmu reads them first (RT-Thread `.config` and `packages/pkgs.json`, OpenHarmony `README.OpenSource` and `bundle.json`) and cross-checks against code. RT-Thread kernel versions 3.0.0 to 5.3.0 are identified by function-level signatures wherever a vendor SDK moved the directory.

有包管理器就不该靠指纹：声明式读取比任何相似度都准。纲目因此先读生态自己的声明，再用代码核对，
两者不一致时以代码为准，并把分歧写进证据。

## RT-Thread

```bash
pip install gangmu-sbom
gangmu init
gangmu scan ~/proj/rt-thread-bsp --format cyclonedx -o sbom.cdx.json
```

- 读 `.config` 里的 `CONFIG_PKG_USING_*` / `_PATH` / `_VER`，以及 `packages/pkgs.json`。
- 软件包版本号是软件包自己的标签，**不会**被当成上游组件的版本拼进 CPE。该目录仍做指纹识别，上游身份由规则库给出，声明作为证据附上。
- RT-Thread 内核本身用 `src/thread.c` + `src/ipc.c` + `include/rtthread.h` 这组标志文件定位，不依赖目录名；版本由函数签名判断，覆盖 3.0.0–5.3.0 共 27 个发布版。
- 没有 `compile_commands.json` 时，可以用编译器包装器旁观一次构建：`gangmu wrap -o compile_commands.json -- scons`（包装器只能拦截按名字查找的编译器，Makefile 里写死绝对路径会绕过它）。

## OpenHarmony

- 读各第三方目录下的 `README.OpenSource` 和每个部件的 `bundle.json`。
- OpenHarmony 自身的部件也会列入 SBOM，部件之间、部件与第三方库之间的依赖关系写进 CycloneDX / SPDX 的依赖图。

## 国产 SDK 里的 RTOS 内核

博流、沁恒、联盛德等国产 SDK 几乎都带一份 FreeRTOS 或 RT-Thread，常常改了目录名、去掉 LICENSE、藏在示例目录深处。
评测用 7 套 SDK 里找到的全部 14 份内核副本，14 份全部识别，版本正确或给出包含正确版本的区间。
方法与数字见 [BENCHMARK](../BENCHMARK.md#1b-rtos-kernels-inside-chinese-vendor-sdks)。

- [示例产物](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/output) · [国产生态覆盖](../CHINA.md)
- 其他 SDK：[ESP-IDF](esp-idf-sbom.md) · [Zephyr](zephyr-sbom.md)
