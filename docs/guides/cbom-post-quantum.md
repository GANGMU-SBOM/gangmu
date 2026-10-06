---
title: 固件密码物料清单（CBOM）：后量子迁移从哪一步开始
description: 用 gangmu cbom 列出固件里实际用到的密码算法，输出 CycloneDX 1.6 CBOM，标出哪些会被量子计算机破解、哪些已经不安全；有编译数据库或链接 map 时只统计真正编进固件的。
---

# 固件密码物料清单（CBOM）

> **Summary (English).** `gangmu cbom` inventories the cryptographic algorithms in a source tree or firmware and writes a CycloneDX 1.6 CBOM (`cryptographic-asset` components). With a compile database or link map it counts only what the build compiled and linked; without them it lists what the tree contains and marks every asset `unverified`. Each asset carries a quantum status (RSA, ECDSA, ECDH, DH, Ed25519, X25519, SM2 are quantum-vulnerable), file and line evidence, and a confidence. Detection is by name (API symbols, config macros, algorithm strings), not by behaviour.

## 为什么需要

后量子迁移的第一步是清点：产品里用了哪些公钥算法、哪些对称算法的密钥太短。SBOM 只说“用了 mbedTLS”，
但同一个库的源码里有它提供的全部算法，固件实际用到的只是其中几个。CBOM 回答的是后一个问题。

背景（来自公开资料，细节以原文为准）：NIST 已发布 ML-KEM（FIPS 203）、ML-DSA（FIPS 204）、SLH-DSA（FIPS 205）；
NIST IR 8547 草案提出 RSA、ECDSA、ECDH 等在 2030 年后弃用、2035 年后禁用；CNSA 2.0 对固件签名点名 SP 800-208 的有状态哈希签名。
CycloneDX 1.6 起原生支持 CBOM。

## 用法

```bash
# 没有构建事实：列出树里有什么（所有项标 unverified）
gangmu cbom path/to/firmware-src

# 只统计这次构建真正编译、链接的
gangmu cbom . --compile-db build/compile_commands.json --link-map build/fw.map

# 输出 CycloneDX 1.6 CBOM，并在 CI 里遇到公钥算法就失败
gangmu cbom . --compile-db build/compile_commands.json \
  --format cyclonedx -o cbom.json --fail-on quantum-vulnerable
```

输出的每个算法有：位置证据（文件、行号、命中的符号）、`gangmu:linkage`（`linked` / `not-linked` / `unverified`）、
`gangmu:quantumStatus`（`vulnerable` 被 Shor 算法破解；`symmetric` 对称强度减半，建议 256 位密钥和 SHA-384 以上；
`pqc` 后量子算法；`broken` 经典攻击下已经不安全；`-` 与量子无关）。AES 会带上密钥长度和模式（如 `AES-256-GCM`）。

## 它看什么

- C、C++、汇编源码，以及 Kconfig、sdkconfig、`.conf` 等配置文件；
- 预编译库（`.a`、`.lib`、`.so`）和固件镜像（`.elf`、`.axf`、`.bin`）里的符号名与字符串；
- 有编译数据库时，头文件只算声明，不计入（密码库的头文件会列出它提供的所有算法）；
- 默认跳过 `test`、`fixtures`、`doc` 一类目录，`--include-tests` 可打开测试目录。

## 一次实测：Mbed TLS（本机 gcc 构建，不是嵌入式目标）

对象：Mbed TLS 提交 `6bdf4e1`（含 tf-psa-crypto 子模块），本机 gcc 构建 `ssl_client1`，用它的 `compile_commands.json` 和链接 map。数字是这一次运行的结果，不是准确率。

| 输入 | 统计到的算法数 | 说明 |
| --- | --- | --- |
| 只给源码树 | 42 | 全部标 `unverified`，含 ML-KEM、ML-DSA（后量子驱动在树里，但没编译） |
| + 编译数据库 | 40 | ML-KEM、ML-DSA 变成 `not-linked`，不再计入 |
| + 链接 map | 39 | 再去掉 1 项 |
| 只读构建出的 ELF（符号名与字符串） | 34 | 没有 ECDH、Ed25519、LMS/XMSS、ML-KEM/ML-DSA |

怎么读：构建事实确实把“树里有但没进产品”的后量子驱动排除了。但**两种读法都不是真值**：源码读法会把进了编译的文件里的配置宏和常量也算进去（Mbed TLS 的 PSA 接口用 `PSA_ALG_ECDH` 这类宏，编译后不留符号，所以 ELF 读法漏掉 ECDH，而源码读法可能多报）。
另外 `compile_commands.json` 列出整个构建的所有目标，不只是这个可执行文件；链接 map 只对应一个目标，同名目标文件（本次有 29 个）按保守处理为已链接。
所以结果适合当“待核对清单”，不能直接当最终结论。

## 它不做什么

- **按名字识别，不按行为识别。** 自己手写、没用常见名字的算法看不到；
- 不判断密钥长度、密钥存放位置、协议用法，只列算法，TLS 版本等协议资产没有输出；
- 没有构建事实时是“树里有什么”，不是“固件里有什么”，所以每一项标 `unverified`；
- 硬件加密引擎的调用只识别少数 HAL 名字（如 STM32 的 `HAL_CRYP`、ESP 的 `esp_aes_`），其余厂商需要补规则；
- 置信度是按证据类型给的经验值，不是统计出来的概率。

## 与 SBOM 的关系

CBOM 是另一份文档，不改变 `gangmu scan` 的输出。同一个固件可以先 `gangmu scan` 出 SBOM，再 `gangmu cbom` 出 CBOM，一起交给客户或审核方。
