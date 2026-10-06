---
title: CRA 24 小时预警与工信部 2 日报送：固件团队怎么同时满足
description: 出口欧盟的国内厂商同时面对欧盟 CRA 第 14 条（24 小时/72 小时/14 天）和工信部《网络产品安全漏洞管理规定》第七条（2 日）。对比触发条件、时限、平台，并用 gangmu report 生成两份草稿。
---

# CRA 24 小时预警与工信部 2 日报送：固件团队怎么同时满足

> **Summary (English).** Manufacturers selling in both China and the EU face two reporting duties: CRA Article 14 (24 h early warning, 72 h notification, 14 d final report, only for actively exploited vulnerabilities, via the ENISA platform) and MIIT's vulnerability rules Article 7 (2 days, triggered on discovery, via cstis.cn). `gangmu report --regime eu-cra|cn-miit` drafts both from the SBOM, VEX and project config; missing fields are marked `MISSING`, never invented. Not legal advice.

## 两套义务对比

| | 《网络产品安全漏洞管理规定》第七条 | CRA 第 14 条 |
| --- | --- | --- |
| 生效 | 2021 年 9 月 1 日 | 报送义务 2026 年 9 月 11 日，其余 2027 年 12 月 11 日 |
| 触发 | **发现**漏洞 | 漏洞**被积极利用**（或严重事件） |
| 时限 | **2 日内** | 24 小时预警 / 72 小时通报 / 纠正措施可用后 14 天最终报告 |
| 平台 | 工信部网络安全威胁和漏洞信息共享平台（cstis.cn） | ENISA 单一报告平台 |
| 必填 | 产品名称、型号、版本；技术特点、危害程度、影响范围 | 产品名称与版本、成员国、知悉时间 |

本土那条不以"被积极利用"为前提，所以触发得更频繁。

## 一处需要法务判断的张力

《网络产品安全漏洞管理规定》第九条第（七）项禁止向境外组织提供未公开的漏洞信息，未设例外；CRA 要求 24 小时内向 ENISA 报送未公开漏洞。
两者可能在同一事件上同时触发。gangmu **不判断是否构成冲突，也不建议处理方式**，只在欧盟草稿里把这一点摆出来，让团队在倒计时开始前就想到它。

## 用 gangmu 起草

```bash
# 欧盟 CRA 第 14 条：24 小时预警草稿
gangmu report CVE-2027-12345 --regime eu-cra --stage early-warning \
    --vex vex.json --aware-at 2027-05-14T08:12Z -o 24h-draft.md

# 工信部第七条：2 日内报送的中文草稿
gangmu report CVE-2027-12345 --regime cn-miit --vex vex.json \
    --aware-at "2027-05-14 08:12" --scope "全系列，出货约 4.2 万台" -o miit-draft.md
```

- "受影响的开源组件及版本"直接取自 SBOM，这是手工填报时最花时间也最容易填错的一项。
- 缺的字段标 `MISSING`，绝不编造；两个平台都由人提交（ENISA 平台首发版本没有 API）。
- `--stage` 可选 `early-warning`、`notification`、`final`。

草稿样例见 [examples/output](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/output)。

## 平时就该备好的

```bash
gangmu cra-check --sbom sbom.cdx.json --vex vex.json   # 逐条对照 CRA，有阻塞缺口时返回非零
gangmu evidence --out cra-evidence/                    # 十年留存的技术文档包
```

`cra-check` 对十个条款里的五个只会返回 partial、declared 或 out of scope：扫描不是安全测试，配置里的一个 URL 也不是政策被执行的证据。

- [CRA 对标](../CRA.md) · [国内合规](../CHINA.md) · [常见问题](../FAQ.md)
