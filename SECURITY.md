# 安全政策 · Security Policy

[English below](#english)

## 报告纲目自身的安全漏洞

如果你发现的是纲目这个工具本身的安全问题（例如解析恶意工程文件时的代码执行、路径穿越），
请**不要**公开提 issue，而是通过本仓库的
[私密漏洞报告](https://github.com/GANGMU-SBOM/gangmu/security/advisories/new)提交。
我们会在 5 个工作日内确认收到，并与你协调修复和公开的时间。

## 规则错误也按安全问题对待

规则库里写错的 CPE、错标的版本或漏认的厂商 fork，会让 SBOM 看起来是干净的，实际却漏掉了漏洞。
这类问题请用「组件识别请求」issue 模板公开报告，并附上能复现的上游版本；它们会被优先处理。

## 支持的版本

只有最新的次版本会收到安全修复。

## 你的产品里的漏洞

如果你要处理的是自己产品里的漏洞，`gangmu report` 可以起草 CRA 第 14 条和工信部第七条的报送材料，
见 [README](README.md)。

---

## English

**Vulnerabilities in Gangmu itself** (for example code execution or path
traversal while parsing a hostile project file): please do not open a public
issue. Use this repository's
[private vulnerability reporting](https://github.com/GANGMU-SBOM/gangmu/security/advisories/new).
We acknowledge within five working days and coordinate a fix and disclosure date
with you.

**Rule errors are treated as security issues.** A wrong CPE, a mislabelled
version or a missed vendor fork makes an SBOM look clean while hiding
vulnerabilities. Report these publicly with the component identification issue
template and a reproducible upstream release; they are prioritised.

**Supported versions:** only the latest minor release receives security fixes.
