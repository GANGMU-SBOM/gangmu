# 术语表 · Glossary

[README](../README.md) · [常见问题](FAQ.md) · [FAQ (English)](FAQ.en.md)

纲目文档和输出里用到的术语，中英对照。

## 法规与报送 · Regulation and reporting

| 术语 | English | 含义 |
| --- | --- | --- |
| 网络弹性法案（CRA） | Cyber Resilience Act | 欧盟法规 (EU) 2024/2847，对带数字元素的产品规定网络安全要求。制造商的漏洞报告义务自 2026-09-11 起适用，其余义务自 2027-12-11 起适用。 |
| Annex I Part II | Annex I Part II | CRA 附件一第二部分，制造商的漏洞处理义务，其中第 (1) 项要求编制 SBOM。 |
| 第 14 条报送 | Article 14 reporting | 被积极利用的漏洞：24 小时预警、72 小时通报、纠正措施可用后 14 天最终报告。 |
| 单一报告平台（SRP） | ENISA Single Reporting Platform | CRA 报送的唯一渠道，2026-09-11 上线，首发版本没有 API。 |
| 协调标准 | Harmonised standard | 发表在欧盟官方公报后可提供符合性推定的标准。 |
| 《网络产品安全漏洞管理规定》 | MIIT vulnerability regulation | 第七条要求发现漏洞后 2 日内向工信部平台报送，不以被利用为前提。 |
| 工信部漏洞平台 | CSTIS | 工业和信息化部网络安全威胁和漏洞信息共享平台。 |
| CNNVD / CNVD | CNNVD / CNVD | 国家信息安全漏洞库 / 国家信息安全漏洞共享平台，条目通常不带 CPE 或 PURL。 |
| GB 44495-2024 | GB 44495-2024 | 《汽车整车信息安全技术要求》，对新车型强制。 |

## SBOM 与漏洞数据 · SBOM and vulnerability data

| 术语 | English | 含义 |
| --- | --- | --- |
| 软件物料清单（SBOM） | Software Bill of Materials | 产品中所有软件组件及其版本、来源、许可证的机器可读清单。 |
| CycloneDX | CycloneDX | OWASP 的 SBOM 格式，纲目默认输出 1.6 版。 |
| SPDX | SPDX | Linux 基金会的 SBOM 格式（ISO/IEC 5962），纲目输出 2.3 版。 |
| VEX | Vulnerability Exploitability eXchange | 说明某个漏洞是否真正影响产品的声明，纲目以 CycloneDX VEX 输出。 |
| CPE | Common Platform Enumeration | NVD 用来标识产品的名称，写错一个字就匹配不到任何 CVE。 |
| PURL | Package URL | 跨生态的组件标识，OSV 用它匹配漏洞；纲目把它当作与 CPE 并列的一等通道。 |
| NTIA / CISA 最小要素 | NTIA / CISA minimum elements | 美国对 SBOM 必备字段的定义，2021 年版与 2026 年版。 |
| pedigree | pedigree | CycloneDX 中记录组件祖先版本与补丁的字段，纲目用它描述厂商 fork。 |

## 识别方法 · Identification

| 术语 | English | 含义 |
| --- | --- | --- |
| 拷贝代码 | Vendored code | 直接复制进工程而不经包管理器的第三方源码。 |
| 厂商分支 | Vendor fork | 芯片原厂修改过的上游组件，如 ESP-IDF 中的 lwIP。 |
| 规则 | Rule | 「某个目录是哪个上游项目的哪个版本」的声明，加上能让机器复核的证据，存放在 [gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules) 仓库。 |
| 锚点 | Anchor | 跨版本不变或逐版本可区分的文件哈希，如版本头文件。 |
| 文件集哈希 | Fileset hash | 参考版本所有文件 path+sha256 的汇总，用于精确判定「是否被改过」。 |
| 函数签名 | Function signature | 组件各发布版的函数集合，用于函数级身份与版本识别。 |
| 包含度 | Containment | 上游组件的函数有多少出现在被检目录中，不受厂商新增代码影响。 |
| 版本探针 | Version probe | 从源码中的版本宏等直接读出版本号。 |
| 编译数据库 | Compilation database | `compile_commands.json`，记录每个源文件的编译命令。 |
| 链接 map | Linker map | 链接器输出的映射文件，说明哪些目标文件进入了最终镜像。 |
| west manifest | west manifest | Zephyr 的多仓库清单，纲目从中导入锁定版本的规则。 |

## 密码与 AI 清单 · CBOM and AIBOM

| 术语 | English | 含义 |
| --- | --- | --- |
| 密码物料清单（CBOM） | Cryptographic BOM | 固件里用到的密码算法清单，CycloneDX 1.6 的 `cryptographic-asset`；`gangmu cbom` 生成。 |
| 后量子密码 | Post-quantum cryptography | 能抵抗量子计算机的算法，如 ML-KEM（FIPS 203）、ML-DSA（FIPS 204）、SLH-DSA（FIPS 205）；RSA、ECDSA、ECDH、SM2 会被 Shor 算法破解。 |
| 库能力表 | Library capability table | 「某库的某版本源码提供哪些算法」，放在 CBOM 规则包的 `libraries/*.yaml`；提供不等于调用，所以可信度不超过 0.6。 |
| AI 物料清单（AIBOM） | AI BOM | 固件里的机器学习模型和推理运行时清单；`gangmu aibom` 生成最小版，不含训练数据和许可证。 |

## 国密 · Chinese commercial cryptography

| 术语 | English | 含义 |
| --- | --- | --- |
| 国密算法 | SM2 / SM3 / SM4 | 国家商用密码算法：SM2 公钥算法、SM3 杂凑算法、SM4 分组密码。 |
| GmSSL | GmSSL | 北京大学发起的开源国密库，纲目支持 3.0.0 至 3.2.0。 |
| 铜锁 | Tongsuo | 基于 OpenSSL 3.0 的开源密码库，支持国密，纲目支持 8.4.0 与 8.5.0。 |
| 代码分割 | Code segmentation | 多条规则共有的函数对谁都不算身份证据，避免把 OpenSSL 认成铜锁这类分支混淆。 |
