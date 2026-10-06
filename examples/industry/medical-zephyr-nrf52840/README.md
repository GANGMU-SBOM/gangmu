# 样例：Zephyr 4.1.0 心率外设（nRF52840）的 FDA 风格 SBOM

> 这是**真实固件、真实构建、真实漏洞库**跑出来的结果，不是医疗器械，也不是合规结论。样例固件是 Zephyr 官方的蓝牙心率外设示例，
> 选它是因为蓝牙加 Nordic SoC 加 Zephyr 是可穿戴和医疗周边设备常见的一类技术栈【推断，未找到统计】。

## 被测对象与复现

| 项 | 内容 |
| --- | --- |
| 固件 | `zephyr/samples/bluetooth/peripheral_hr`，板子 `nrf52840dk/nrf52840` |
| 源码 | Zephyr v4.1.0（`west init --mr v4.1.0`），模块只拉了 `hal_nordic cmsis cmsis_6 mbedtls tinycrypt picolibc` |
| 构建 | arm-none-eabi-gcc 13.2.1，`ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb`，真实构建：FLASH 175304 B（16.7%），RAM 27312 B |
| 规则 | 免费库 gangmu-rules（67 条）。**没有用付费的厂商规则包** |
| 漏洞库 | 2026-10-06 用 `gangmu vuln-fetch --sbom` 拉的 NVD 与 OSV 快照，之后的新漏洞不在里面 |

```bash
west build -b nrf52840dk/nrf52840 zephyr/samples/bluetooth/peripheral_hr -d hr-build -- -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
gangmu scan zep --rules gangmu-rules/rules \
    --compile-db hr-build/compile_commands.json --link-map hr-build/zephyr/zephyr.map \
    --kconfig hr-build/zephyr/.config --support support.yaml --no-binaries \
    --app-name peripheral-hr --app-version 4.1.0 --format cyclonedx -o sbom.cyclonedx.json   # 再来一遍 --format spdx3
gangmu vuln-fetch --db advisories --sbom sbom.cyclonedx.json
gangmu vuln sbom.cyclonedx.json --db advisories --format cyclonedx|openvex|csaf \
    --publisher "Example Co (sample, not a real publisher)" --publisher-url https://example.invalid
```

产物：`sbom.cyclonedx.json`、`sbom.spdx3.json`、`vex.cyclonedx.json`、`vex.openvex.json`、`vex.csaf.json`、`support.yaml`。
SPDX 3、OpenVEX、CSAF 三份都通过官方 JSON schema 校验，SPDX 3 还能被 SPDX 项目自己的 Python 模型读入。

## FDA 指南要求的字段，这份样例给到什么程度

FDA 指南（2026-02-03 版，第 V.A.4 节）要求：机器可读 SBOM、NTIA 最低要素，另加每个组件的维护支持级别和停止支持日期，并列出已知漏洞。

| 组件 | 版本 | 识别依据 | 链接进镜像 | 支持级别 | 停止支持 |
| --- | --- | --- | --- | --- | --- |
| Mbed TLS | 3.6.2 | 锚点文件哈希，置信度 0.95，**Zephyr 的修改版（vendor-modified）** | 是，编译 108 个文件 | maintained（3.6 LTS 分支） | 2027-03（项目写“until March 2027”，文件里取月末 2027-03-31，这是产品团队的取舍） |
| Nordic nrfx HAL | 无法判定 | 路径与特征，置信度 0.77，版本置信度 0 | 是，编译 8 个文件 | **unknown** | 无 |

支持级别的来源：[Mbed TLS BRANCHES.md](https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md) 写明 3.6 LTS 维护到 2027 年 3 月。
其余组件没有找到可引用的来源，所以写 `unknown`，没有猜。

## 结果与没做到的地方

- **漏洞**：22 条（CycloneDX VEX 里 23 条，其中 1 条被 CPE 和 PURL 两条通道各匹配一次，OpenVEX 与 CSAF 合并为一条），全部是 Mbed TLS 的，状态都是 `in_triage`，
  原因是它是 Zephyr 的修改版，版本区间命中不等于受影响，需要人看修改。这份样例没有人复核，所以没有任何一条被写成 `not_affected`。
- **Zephyr 内核本身没有被识别**：免费规则库没有 Zephyr 内核的规则，它出现在“未识别目录”里（还有 picolibc、`zephyr/soc/nordic`、Nordic 蓝牙控制器）。
  对医疗提交来说，RTOS 才是最该写进 SBOM 的组件，这是现在最大的缺口，需要补规则。
- **nrfx 没有版本**：只认出组件，认不出版本，漏洞库因此对它查不了（它也没有 CPE，只能靠 PURL）。
- 没有 IEC 62304 的 SOUP 清单格式，也没有 FDA eSTAR 的提交附件模板，这两项还没做。
- 所有判断按 SBOM 工具的边界读：不是法律结论，也不替代安全测试。
