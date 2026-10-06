---
title: ESP-IDF 固件怎么生成 SBOM（CycloneDX / SPDX）
description: 用开源工具纲目（gangmu）为 ESP-IDF 工程生成 SBOM：读 compile_commands.json、链接 map 和 sdkconfig，区分编译了但没链接的组件，标出乐鑫修改过的 lwIP 等 vendor fork。
---

# ESP-IDF 固件怎么生成 SBOM

> **Summary (English).** Run `gangmu scan` on an ESP-IDF project with the build's `compile_commands.json`, linker map and `sdkconfig` to get a CycloneDX 1.6 or SPDX 2.3 SBOM that lists only what was compiled and linked, and marks Espressif's forks (lwIP, Mbed TLS, ...) as vendor-modified instead of reporting an upstream version.

ESP-IDF 工程的 SBOM 难在三点：`components/` 里有很多第三方源码拷贝，乐鑫的 lwIP、Mbed TLS 等是自己的分支而不是上游发布版，
`sdkconfig` 里关掉的组件源码仍然躺在目录里。只扫源码树会把这些全算进去。
纲目读构建事实来回答"最终固件里到底有什么"。

## 步骤

```bash
pip install gangmu-sbom
cd ~/esp/my-project
idf.py build                       # 生成 build/compile_commands.json 与 build/<项目名>.map

gangmu init                        # 一次性：产品名、制造商、销售市场
gangmu scan . \
    --compile-db build/compile_commands.json \
    --link-map   build/my-project.map \
    --kconfig    sdkconfig \
    --format cyclonedx -o sbom.cdx.json
```

- `--compile-db`：哪些源文件真的被编译。
- `--link-map`：哪些目标文件真的被链进固件，编译了但被链接器丢弃的组件会标成 `not linked`。
- `--kconfig`：`sdkconfig` 里关掉的组件不进 SBOM（只对规则里声明了 `config_symbols` 的组件生效；根目录或 `build/` 下的 `sdkconfig` 会被自动读取）。
- 输出 SPDX 2.3 把 `--format` 换成 `spdx`。

## 输出里要看哪几行

```
CONF  COMPONENT  VERSION  SRC     DIRECTORY                NOTES
0.95  lwIP       2.2.0    anchor  components/lwip/lwip     vendor-modified
```

- `vendor-modified`：这是乐鑫的分支，不是上游 2.2.0。CycloneDX 的 `pedigree` 里写明祖先版本，漏洞比对时按"可能被改过"处理，而不是直接认定受影响或不受影响。
- `not linked`：编译了但没链接，不要为它追 CVE。
- `unidentified`：有个目录看起来像组件，但没有规则认识。纲目会明确列出，而不是悄悄漏掉。

## 与 esp-idf-sbom 的关系

乐鑫官方的 [esp-idf-sbom](https://github.com/espressif/esp-idf-sbom) 读各组件的 `sbom.yml`。纲目把 `sbom.yml` 当作一等输入，
并补上它不管的部分：非乐鑫组件、被改名的拷贝、链接事实，以及 CRA 自查与报送草稿。

## 下一步

```bash
gangmu vuln-fetch --db advisories/ --sbom sbom.cdx.json     # 有网的机器上
gangmu vuln sbom.cdx.json --db advisories/ -o vex.json      # 输出 CycloneDX VEX
gangmu cra-check --sbom sbom.cdx.json --vex vex.json        # 逐条对照 CRA
```

- 一份真实的输出长什么样：[examples/output](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/output)
- 欧盟 CRA 要求什么：[CRA 对标](../CRA.md)
- 被厂商魔改的组件怎么识别：[识别原理](vendor-modified-components.md)
- 其他 SDK：[Zephyr](zephyr-sbom.md) · [RT-Thread](rt-thread-sbom.md)
