# 策略检查：把 CBOM、AIBOM 对照法规和内部要求

`gangmu cbom` 和 `gangmu aibom` 回答“固件里有什么”。`gangmu policy check` 回答下一个问题：**这些东西按某份法规或内部要求还让不让用，到什么时候不让用。**

策略是数据，放在 `kind` 为 `policy` 的规则包的 `policies/*.yaml` 里。一份法规的算法期限表，就是一个带出处的文件，不是代码。

## 用法

```bash
gangmu policy check firmware/ --policy path/to/policy-pack          # 表格
gangmu policy check firmware/ --format markdown -o policy.md        # 给人看的报告
gangmu policy check firmware/ --format json                         # 给机器读
gangmu policy check firmware/ --as-of 2031-01-01                    # 按某一天判断期限
gangmu policy check firmware/ --fail-on deprecated                  # CI 里卡严一点
```

不写 `--policy` 时读取已安装的、`kind` 为 `policy` 的规则包；`--id` 只跑其中某一份策略。检查会自己扫 CBOM 和 AIBOM（需要的话），读已安装的 cbom、aibom 规则包，以及目录里的 `gangmu-aibom.yaml` 声明文件。有编译数据库或链接 map 时用 `--compile-db`、`--link-map`，没被编译进固件的算法不计入。

## 结果的四种状态

| 状态 | 含义 |
| --- | --- |
| `ok` | 没有命中 |
| `due` | 命中了，但第一个日期还没到：这是迁移清单，`DUE` 列给出下一个日期 |
| `deprecated` | 已过 `deprecated-after`：不鼓励继续用，但还没禁止 |
| `fail` | 已过 `disallowed-after`，或者命中了一条没有日期的检查（直接禁用） |

默认任何 `fail` 让命令退出码为 1；`--fail-on deprecated` 或 `--fail-on due` 把门槛放低。日期当天仍算允许，次日起才算过期。

## 策略文件

```yaml
policies:
  - id: demo
    name: 示例迁移策略
    source: {title: "某份文件", url: "https://example.org/doc", status: "initial public draft"}
    note: 只按算法名判断，不看密钥长度。
    checks:
      - id: rsa
        title: RSA / ECDSA
        subject: cbom                       # cbom 或 aibom
        match: {algorithms: [rsa, ecdsa]}   # CBOM 的算法 key；也可以写 quantum: [vulnerable]
        deprecated-after: 2030-12-31        # 可选
        disallowed-after: 2035-12-31        # 可选；两个日期都不写，命中就是 fail
        reference: "Table 2"
        remediation: "ML-DSA (FIPS 204)"
      - id: model-licence
        title: 模型许可证已声明
        subject: aibom
        match: {missing: [license]}         # license 或 training-data，见 AIBOM 声明文件
```

* `cbom` 检查在**计入**的资产里按算法 key（`rsa`、`ecdsa`、`md5` 等，见 [CBOM 指南](cbom-post-quantum.md)）和量子状态（`vulnerable`、`broken`、`symmetric`、`pqc`、`neutral`）选；两个都写时要同时满足。
* `aibom` 检查选出缺许可证或训练数据的模型。没有声明文件时，所有模型都算缺。
* 文件写错（日期格式不对、`deprecated-after` 晚于 `disallowed-after`、检查 id 重复、未知的 `subject`）会报出位置和原因并退出 2。
* 同 id 的策略，后加载的替换先加载的。

## 它不做什么

* **不下法律结论。** 它列出命中了什么、策略怎么写；这算不算违规、对谁违规，由产品负责人和法务判断。策略文件里的 `source` 说明依据，`status` 说明依据本身是否定稿。
* **不看密钥长度和协议。** 算法是按名字找到的，所以“RSA-2048 到 2030 年弃用、更长的到 2035 年禁用”这类按强度区分的条款，只能按较晚的日期写，并在 `note` 里说清楚。
* **只和扫描结果一样可靠。** 扫描漏掉的算法，策略也看不到。

维护好的策略包（NIST IR 8547 过渡期限等）见 [gangmu-policy-pro](https://github.com/GANGMU-SBOM/gangmu-policy-pro)（商业版）；格式和引擎是开源的，自己写策略包不需要它。
