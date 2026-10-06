# 样例：ESP-IDF 5.4.1 Wi-Fi Station（ESP32-C3）的 CRA 流程

> 真实固件、真实构建。固件是 ESP-IDF 自带的 `examples/wifi/getting_started/station`。不是一个商品，也不是合规结论。

## 被测对象与复现

| 项 | 内容 |
| --- | --- |
| 源码 | ESP-IDF v5.4.1（`--recurse-submodules --depth 1`） |
| 构建 | `idf.py set-target esp32c3 && idf.py build`，工具链由 `install.sh esp32c3` 安装，镜像 0xb49d0 B |
| 构建事实 | compile_commands.json 858 个源文件编译，439 个目标文件被链接，419 个被链接器丢掉；sdkconfig 1391 个选项 |
| 规则 | 免费库 gangmu-rules。**没有用乐鑫的付费规则包**，所以 ESP-IDF 自己的 fork 识别得不全 |
| 漏洞库 | 2026-10-06 的 NVD 与 OSV 快照 |

```bash
B=esp-idf/examples/wifi/getting_started/station/build
gangmu scan esp-idf --rules gangmu-rules/rules --compile-db $B/compile_commands.json \
    --link-map $B/wifi_station.map --kconfig esp-idf/examples/wifi/getting_started/station/sdkconfig \
    --support support.yaml --no-binaries --app-name wifi-station --app-version 5.4.1 --format cyclonedx -o sbom.cyclonedx.json
gangmu vuln-fetch --db advisories --sbom sbom.cyclonedx.json
gangmu vuln sbom.cyclonedx.json --db advisories --format cyclonedx|openvex|csaf --publisher "..." --publisher-url ...
gangmu cra-check --scan scan.json --sbom sbom.cyclonedx.json --vex vex.cyclonedx.json --no-fail
```

产物：`sbom.cyclonedx.json`、`sbom.spdx3.json`、`scan.json`、`vex.cyclonedx.json`、`vex.openvex.json`、`vex.csaf.json`、`cra-check.txt`、`support.yaml`。
SPDX 3、OpenVEX、CSAF 都通过官方 schema 校验。

## 结果

| 组件 | 版本 | 链接 | 说明 |
| --- | --- | --- | --- |
| Mbed TLS | 3.6.2 | 是 | 乐鑫的修改版；支持级别 maintained，至 2027-03（来源同医疗样例） |
| lwIP | 2.2.0 | 是 | 乐鑫的修改版；支持级别 unknown |
| cJSON | 1.7.18 | **否** | 在树里，但没有链接进镜像 |
| FatFs | R0.15 | **否** | 同上 |

另有两个“可能”项没有写进 SBOM：FreeRTOS-Kernel（ESP-IDF 的 fork，置信度 0.52）和 hostap（0.52）。置信度不够就不断言，这正是乐鑫规则包要补的地方。

- **漏洞**：CycloneDX VEX 36 条，OpenVEX 与 CSAF 合并后 35 条。其中 6 条（cJSON）是 `exploitable`（OpenVEX 写成 `affected`），29 条是 `in_triage`。
- **一个需要人看的问题**：这 6 条 cJSON 的组件并没有链接进镜像。现在的 `gangmu vuln` 只比较版本，不看“未链接”，所以仍写 `exploitable`。
  若产品团队确认 cJSON 没有进入固件，可以在 VEX 里改为 `not_affected` 并注明 `code_not_present`；工具目前不会替你判断。这是一个值得改进的点。
- **`cra-check` 的结论**（见 `cra-check.txt`）：顶层覆盖不能声称（14 个目录看起来像组件但没有识别）；30 条漏洞仍待处理；
  没有声明 CVD 政策、漏洞联系方式、技术文档保存期限，所以多项 FAIL。样例没有 `gangmu.yaml`，这是工具在严格执行，不是 bug。
- 一个顺手发现：FatFs 是被 Zephyr 的规则（`zephyrproject/zephyr/fatfs`）认出来的，所以供应商写成 “Zephyr Project (fork of ChaN FatFs)”，
  也被标成 vendor-modified，这些都是按 Zephyr 的 fork 写的。ESP-IDF 自己的 `components/fatfs` 与它未必是同一个 fork，这两个字段在这里不一定准确，
  需要有人对照 ESP-IDF 的 FatFs 来源，要么补一条 ESP-IDF 的规则，要么修正规则的适用范围。
