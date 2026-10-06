# 样例：FreeRTOS 内核 11.3.1 的 MPS2 演示固件（工控类栈的最小样例）

> 真实固件、真实构建。这是 FreeRTOS 官方仓库里的 `CORTEX_MPS2_QEMU_IAR_GCC` 演示，**只含内核，没有网络栈、TLS 或 Modbus**，
> 不能代表一台工控网关。选它是因为它能在不依赖厂商 SDK 的情况下干净地展示“整个仓库很大，真正进固件的很少”。

## 被测对象与复现

| 项 | 内容 |
| --- | --- |
| 源码 | `FreeRTOS/FreeRTOS` 主仓库（`--recurse-submodules --depth 1`，2026-10-06 的 HEAD），内核子模块版本字符串 `V11.3.1` |
| 构建 | `FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC/build/gcc`，arm-none-eabi-gcc 13.2.1，`make`，text 23552 B |
| 构建事实 | 用 `gangmu wrap -- make` 记录 69 个编译步骤；GNU ld map 里 68 个源文件编译，30 个目标文件被链接，38 个被链接器丢掉 |
| 规则 | 免费库 gangmu-rules |

```bash
cd freertos/FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC/build/gcc
gangmu wrap -o compile_commands.json -- make -j8
cd -
gangmu scan freertos --rules gangmu-rules/rules --compile-db compile_commands.json \
    --link-map freertos/FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC/build/gcc/output/RTOSDemo.map \
    --no-binaries --app-name freertos-mps2-demo --app-version 202411.00 --format cyclonedx -o sbom.cyclonedx.json
```

产物：`sbom.cyclonedx.json`、`sbom.spdx3.json`（通过官方 schema 校验，也能被 SPDX 项目的 Python 模型读入）。

## 结果

| 组件 | 版本 | 识别依据 | 链接 | 支持级别 |
| --- | --- | --- | --- | --- |
| FreeRTOS-Kernel | 11.3.1 | 探针（版本字符串 `tskKERNEL_VERSION_NUMBER`），版本置信度 0.85；与头文件里的 `V11.3.1` 一致 | 是 | **unknown** |

- **漏洞**：对该版本，2026-10-06 的 NVD 与 OSV 快照里没有匹配项，`gangmu vuln` 报“no findings”。这是“该快照里没有”，不是“没有漏洞”。
  OpenVEX 和 CSAF 不能表达空文档，所以这份样例没有这两个文件，`gangmu vuln --format openvex|csaf` 在无结果时只打一行说明，不写文件。
- **支持级别写 unknown 是有意的**：AWS 的说明是 FreeRTOS LTS 版本至少两年内获得安全与关键缺陷修复，202406 LTS 随附的是内核 11.1
  （[AWS 公告](https://aws.amazon.com/about-aws/whats-new/2024/07/freertos-long-term-support-version)）。11.3.1 不是那个 LTS 里的版本，
  它的支持期要由产品团队与 AWS 确认（AWS 另有付费的扩展维护计划），工具没有可引用的来源，不替人写。
- **其他板子的预编译库**：整个仓库里有 61 个预编译库（`libdriver.a` 之类）。有链接图时，工具现在只把链接图点名的预编译库当作进了镜像，
  其余 40 个仍列在 SBOM 里，但 CycloneDX `scope` 是 `excluded`，并在扫描结果里提示数量，单体仓库里别的板子不会再被读成“已交付”。
  这份样例仍加了 `--no-binaries`，让 SBOM 只有这个镜像的 1 个组件；不加的话，那 61 个会作为带 `excluded` 标记的条目出现在文件里。
- 仓库里还有 FreeRTOS-Plus-Trace 等目录，没有规则，列为未识别；它们没有被这个演示构建，所以不影响这份 SBOM。
- 工控客户真正关心的网络栈、TLS、Modbus、OPC UA 实现，这份样例**没有覆盖**，规则库里对应条目也很少，见 `docs/guides/industrial-iec62443-cra-sbom.md`。
