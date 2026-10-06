---
title: 纲目 gangmu 与 Syft、Trivy、cdxgen、esp-idf-sbom、商业 SCA 的区别
description: 嵌入式 C/C++ 固件的 SBOM 工具怎么选？对比纲目（gangmu）与 Syft、Trivy、cdxgen、esp-idf-sbom、Black Duck、FOSSA、Interlynk 和固件二进制分析产品，按输入、输出、嵌入式适配和许可证列出。
---

# 纲目与其他 SBOM 工具的区别

> **Summary (English).** Most SBOM generators (Syft, Trivy, cdxgen) read package manifests and lockfiles; embedded C/C++ firmware usually has none. Gangmu targets that gap: it identifies vendored, renamed and vendor-modified components by function-level matching, reads build facts (compile database, linker map, IDE projects) to separate compiled-and-linked from merely present, and covers CRA and China MIIT reporting. It is not a binary-analysis or security-testing product.

**一句话区别：** 通用 SBOM 工具读的是包管理器留下的清单；嵌入式 C/C++ 往往没有清单，第三方代码直接拷进工程、被芯片原厂改名魔改、最后静态链接。
纲目读的是源码和构建过程，识别"这个目录其实是哪个上游的哪个版本"。

## 对照表

下面对其他工具的描述基于它们各自公开文档的一般定位，功能会变化，选型前请以各项目当前文档为准。

| 工具 | 主要输入 | 擅长 | 对嵌入式 C/C++ 拷贝式依赖 | 许可 |
| --- | --- | --- | --- | --- |
| **纲目 gangmu** | 源码树 + `compile_commands.json` / 链接 map / IAR、Keil、CCS 工程 | 识别被改名魔改的组件，区分编译与链接，CRA 自查与报送草稿，国内漏洞库通道 | 核心场景：函数级匹配，给出 vendor-modified 与祖先版本 | 工具 Apache-2.0，规则 CDLA-Permissive-2.0 |
| Syft | 镜像、文件系统、包管理器清单 | 容器与通用软件包的 SBOM | 依赖清单与已知包元数据，源码拷贝式依赖通常不在其视野内 | 开源 |
| Trivy | 镜像、仓库、清单 | 漏洞、配置、密钥扫描，兼出 SBOM | 同上，侧重清单可见的依赖 | 开源 |
| cdxgen | 多语言项目清单 | 多语言 CycloneDX 生成 | C/C++ 依赖主要来自 Conan 等声明 | 开源 |
| esp-idf-sbom | ESP-IDF 工程的 `sbom.yml` 与构建产物 | ESP-IDF 官方，乐鑫组件元数据 | 只覆盖 ESP-IDF 一个 SDK；纲目把它的 `sbom.yml` 当一等输入 | 开源 |
| Black Duck、FOSSA 等商业 SCA | 源码、构建、片段匹配 | 企业级许可证与漏洞治理 | 有片段匹配能力，闭源商业产品 | 商业 |
| Interlynk lynkctl | 嵌入式 C/C++ | 面向 STM32、Infineon、NXP 等 | 闭源商业产品 | 商业 |
| ONEKEY、Finite State、Cybellum、NetRise | 固件二进制 | 无源码场景的二进制分析 | 面向大型企业的二进制分析产品 | 商业 |

## 什么时候选纲目

- 手里有源码或能跑一次构建，目标是**出货固件**的 SBOM，而不是源码仓库里"存在过什么"。
- 依赖多半是拷进来的芯片 SDK 组件（lwIP、Mbed TLS、FreeRTOS、RT-Thread、国密库等），而且被原厂改过。
- 需要把结果直接用于 CRA 技术文档、24 小时预警，或工信部 2 日报送草稿。
- 需要离线或内网环境（`gangmu vuln` 不联网）。
- 想要一份能复核、能贡献的开放规则库，而不是黑盒匹配。

## 什么时候不选纲目

- 只有编译好的固件镜像、没有源码也没法重现构建：纲目只对预编译库和镜像读版本横幅与导出符号，不做反汇编和函数级比对，请用二进制分析产品。
- 要做渗透测试或安全测试：纲目不做。
- 要自动提交 ENISA 或工信部平台：纲目只起草，提交由人完成。
- 要得出法律结论：纲目不替你下。

更多边界见 [能力边界](LIMITS.md)，评测方法与数字见 [评测基准](BENCHMARK.md)，同类工具的更多背景见 [README](../README.md#同类工具)。

- 几个常见任务：[ESP-IDF](guides/esp-idf-sbom.md) · [Zephyr](guides/zephyr-sbom.md) · [RT-Thread / OpenHarmony](guides/rt-thread-sbom.md) · [国密库](guides/gmssl-tongsuo-sbom.md) · [CRA 与工信部报送](guides/cra-and-miit-reporting.md)
