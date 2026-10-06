---
title: 国密库 GmSSL、铜锁（Tongsuo）怎么进 SBOM
description: 固件里的国密库（GmSSL 2.x/3.x、铜锁 Tongsuo、OpenSSL）常被改名静态链接。纲目用逐版本锚点和函数签名区分它们，输出 CycloneDX / SPDX 并按 PURL / OSV 匹配漏洞。
---

# 国密库 GmSSL、铜锁怎么进 SBOM

> **Summary (English).** Gangmu identifies GmSSL 3.0.0–3.2.0 and 2.0.0–2.5.4, Tongsuo 8.1.3–8.5.0 and OpenSSL 1.1.0–1.1.1w and 3.x with per-version anchors, multi-version function signatures and version probes. Tongsuo is an OpenSSL 3.0 fork sharing tens of thousands of functions, so shared functions are not counted as evidence for either and stock OpenSSL is never mistaken for Tongsuo.

## 覆盖范围

| 库 | 版本 | 说明 |
| --- | --- | --- |
| GmSSL 3.x | 3.0.0–3.2.0 | 逐版本锚点、多版本函数签名、版本探针 |
| GmSSL 2.x | 2.0.0–2.5.4 | 独立规则 `generic/gmssl-2`；上游没有 2.x 标签，按提交固定 |
| 铜锁 Tongsuo | 8.1.3–8.5.0 | 8.1–8.3 是 BabaSSL 时期版本 |
| OpenSSL | 1.1.0–1.1.1w，3.0 到 3.6 各线最新补丁版 | 与铜锁互相做代码分割 |

国密分支 mbedTLS 目前**没有**覆盖。

## 为什么铜锁和 OpenSSL 不会互相误认

铜锁是 OpenSSL 3.0 的分支，两者共享上万个函数。同时加载两条规则时，共享的函数对谁都不算身份证据，
各自只靠独有的代码被认出来，所以原版 OpenSSL 不会被误认成铜锁。

## 用法

```bash
pip install gangmu-sbom
gangmu init
gangmu scan firmware/ --format cyclonedx -o sbom.cdx.json
```

即使厂商把 GmSSL 放在 `components/crypto_sm`、删掉 `version.h`、改了一部分函数前缀，也能识别并标为 `vendor-modified`，见 [实验与输出](vendor-modified-components.md)。

## 漏洞匹配

国密库的 CVE 在 NVD、OSV 里并不总有 CPE，规则库不猜 CPE，PURL / OSV 是一等匹配通道。
国内厂商自报的漏洞往往只在 CNNVD / CNVD 里，可以加 `--cn-db` 作为第三条通道：

```bash
gangmu vuln sbom.cdx.json --db advisories/ --cn-db cnnvd-export/ -o vex.json
```

- [国内合规](../CHINA.md) · [术语表（SM2/SM3/SM4）](../GLOSSARY.md)
