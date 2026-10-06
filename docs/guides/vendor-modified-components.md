---
title: 被芯片厂改名魔改的开源组件怎么识别（lwIP、Mbed TLS、GmSSL）
description: 芯片 SDK 把开源库改目录名、改函数前缀、删版本头文件后，SBOM 工具怎么还能认出它是哪个上游的哪个版本？纲目用函数级包含度识别身份和版本，并给出可复现的实验。
---

# 被芯片厂改名魔改的开源组件怎么识别

> **Summary (English).** Gangmu identifies a renamed or modified open-source copy by function-level containment: identity is "how many of the upstream's functions are here", version is "which releases do the matched functions belong to". Method follows CENTRIS (ICSE 2021) and TIVER (ICSE 2025). A reproducible experiment turns GmSSL 3.0.0 into a vendor-style fork and still identifies it as GmSSL 3.0.0, vendor-modified.

## 问题

芯片原厂拷贝开源库时常做这几件事：改目录名、删掉版本头文件、给函数加厂商前缀、塞进自己的函数、删掉用不到的文件。
结果是文件名、目录名、版本字符串这三类常用线索全部失效，按 `lwIP 2.2.0` 查 CVE 的做法要么漏报，要么把厂商的分支当成上游。

## 纲目的做法

1. **找目录。** 先用清单、LICENSE 和规则声明的标志文件（例如 FreeRTOS 的 `tasks.c` + `queue.c` + `list.c`）找到候选目录，不依赖目录名。
2. **定身份。** 比较函数而不是比较整棵目录：上游的函数有多少出现在这里（containment）。整棵目录的相似度在 lwIP 上只能把"厂商 fork"和"换了个版本"拉开 0.06，函数级拉开到 0.25。
3. **定版本。** 匹配到的函数各属于哪几个发布版，投票得出版本或包含正确版本的区间。
4. **标记改动。** 已记录的代码缺失或被改动才标 `vendor-modified`；只是新增代码不标，因为新增不改变有漏洞的代码是否还在。
5. **给证据。** 每条结论附带可以复核的证据，置信度上限 0.95。

## 一个能复现的实验

拿真实的 GmSSL 3.0.0，改目录名、删版本头文件、把三分之一源文件里的 `sm3_` / `sm4_` 改成 `vendor_sm3_` / `vendor_sm4_`、塞进厂商函数、再删掉 8 个源文件：

```
CONF  COMPONENT  VERSION  SRC        DIRECTORY             NOTES
0.88  GmSSL      3.0.0    functions  components/crypto_sm  vendor-modified
```

脚本是 [`examples/disguise.sh`](https://github.com/GANGMU-SBOM/gangmu/blob/main/examples/disguise.sh)，产出的 SBOM 见 [examples/output](https://github.com/GANGMU-SBOM/gangmu/tree/main/examples/output)。

## 改过的副本怎么查漏洞

魔改的 fork 只报告它所基于的版本号，每条之后才修复的公告都会让它永远停在待研判。
纲目的补丁存在性检测看代码而不是看版本：有修复后的函数体就判 `resolved`，仍是修复前的函数体就确认 `exploitable`，被厂商改过的留给人判断。
见 [算法说明](../ALGORITHMS.md#patch-presence)。

- [评测基准](../BENCHMARK.md) · [能力边界](../LIMITS.md) · [常见问题](../FAQ.md)
