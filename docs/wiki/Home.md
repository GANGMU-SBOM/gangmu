# 纲目 Gangmu Wiki

纲目是面向嵌入式 C/C++ 固件的开源构建期 SBOM 工具，配一份社区共建的芯片 SDK 组件识别规则库。
Gangmu is an open-source build-time SBOM tool for embedded C/C++ firmware.

正式文档放在仓库的 `docs/` 目录，随代码一起评审和版本化；Wiki 用于导航和社区笔记。
The canonical documentation lives in the repository's `docs/` directory.

- [README（中文）](https://github.com/GANGMU-SBOM/gangmu/blob/main/README.md) · [README (English)](https://github.com/GANGMU-SBOM/gangmu/blob/main/README.en.md)
- [常见问题](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/FAQ.md) · [FAQ](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/FAQ.en.md)
- [术语表 · Glossary](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/GLOSSARY.md)
- [规则格式 · Rule format](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/RULE-FORMAT.md)
- [贡献规则 · Contributing](https://github.com/GANGMU-SBOM/gangmu/blob/main/CONTRIBUTING.md)
- [CRA 对标](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/CRA.md) · [国内合规](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/CHINA.md)
- [算法](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/ALGORITHMS.md) · [评测基准](https://github.com/GANGMU-SBOM/gangmu/blob/main/docs/BENCHMARK.md)

## 规则覆盖路线 · Rule coverage roadmap

| 状态 | SDK / 组件 |
| --- | --- |
| 已覆盖（免费） | Zephyr（含 Mbed TLS、hostap 与国产芯片 HAL）、OpenSSL、GmSSL（3.x 与 2.x）、铜锁、FreeRTOS / RT-Thread / TencentOS-tiny / AliOS Things / LiteOS 内核、通用 Mbed TLS / FatFs / littlefs / LVGL / libcoap / TinyCrypt / nghttp2 / libwebsockets / Paho MQTT C / OpenThread / AWS IoT Device SDK、RT-Thread 与 OpenHarmony 声明；芯片原厂专属规则见商业版规则包 |
| 欢迎贡献 | 全志 Tina Linux、国密分支 mbedTLS，以及你手上的芯片 SDK：先发邮件 64031875@qq.com 说一声 |

想认领一个 SDK，请提一个「组件识别请求」issue，或先发邮件到 64031875@qq.com 说一声，避免重复劳动。
