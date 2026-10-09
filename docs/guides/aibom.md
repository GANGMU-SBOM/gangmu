# AIBOM：固件里的机器学习模型和推理库

`gangmu aibom` 列出一个源码树或固件目录里的 **机器学习模型** 和 **推理运行时**，输出 CycloneDX 1.6 的 AIBOM。它自己只回答“里面有什么”；“训练自什么数据、能不能商用”读不出来，要由人写进一个[声明文件](#声明文件)，工具把它并进输出。

## 用法

```bash
gangmu aibom .                                   # 表格
gangmu aibom . --format cyclonedx -o aibom.json  # CycloneDX 1.6
```

## 它找什么

**模型**，按文件签名或扩展名：

| 格式 | 判断依据 |
| --- | --- |
| TensorFlow Lite | 文件头 `TFL3`（偏移 4）；`.tflite` |
| GGUF | 文件头 `GGUF`；会读出 `general.architecture` 和 `general.name` 写进模型卡 |
| ExecuTorch | 文件头 `ET12`（偏移 4）；`.pte` |
| ONNX、safetensors、Core ML、RKNN、MNN、Keras/HDF5 | 扩展名（输出里标 `by extension`） |
| PyTorch（`.pt`、`.pth`、`.ckpt`） | 扩展名；附一条提示：这是 pickle 格式，加载时可能执行代码，优先用 safetensors |

另外，**编译进 C 数组的 TensorFlow Lite 模型**（`xxd -i` 或 TFLite Micro 示例的写法，数组里有 `0x54, 0x46, 0x4c, 0x33`）也会列出，带文件和行号。

每个模型文件都有 SHA-256，写在组件的 `hashes` 里，可以拿来对账。

**运行时**，按源码里的标识符：TensorFlow Lite 和 Micro、ONNX Runtime、CMSIS-NN、Edge Impulse、microTVM、NNoM、ExecuTorch、llama.cpp/ggml、ncnn、MNN、ESP-DL、STM32Cube.AI、RKNN、TensorFlow C。每项给命中次数和前 20 处位置。

## 输出里的组件

* 模型是 `machine-learning-model`，运行时是 `library`，都挂在 `firmware` 下。
* GGUF 的架构写进 `modelCard.modelParameters.architectureFamily`。
* `gangmu:detectedBy` 说明是靠文件签名、扩展名还是 C 数组认出的。
* 有声明文件时，许可证进 `licenses`，数据集进 `modelCard.modelParameters.datasets`，用途和限制进 `modelCard.considerations`，评测进 `quantitativeAnalysis`。

## 扩充识别规则

模型格式和推理库的识别表是数据：内置一份，也可以用规则包补充或覆盖。

```bash
gangmu aibom . --rules path/to/pack          # 指定规则包目录，可重复
pip install git+https://github.com/GANGMU-SBOM/gangmu-aibom-rules.git   # 已安装且 kind 为 aibom 的包自动读取
```

规则包目录里放 `rulebase.json`（`"kind": "aibom"`）、`formats/*.yaml` 和 `runtimes/*.yaml`。同名 `key` 替换内置项，新 `key` 新增；写错的规则（坏正则、缺字段、扩展名不带点）会报出文件和原因并退出 2。格式见 [gangmu-aibom-rules](https://github.com/GANGMU-SBOM/gangmu-aibom-rules) 的 README。需要读内容才能认的（编进 C 数组的 TFLite 模型、GGUF 头里的架构）仍在工具里。

## 声明文件

训练数据、许可证、用途和评测结果不在 `.tflite` 或 `.gguf` 里。把它们写在目录根的 `gangmu-aibom.yaml`（也可以是 `.yml` 或 `.json`，或用 `--declarations FILE` 指定），`gangmu aibom` 会并进它认出的模型：

```yaml
version: 1
models:
  - path: models/kws.tflite          # 相对根目录的路径，可用通配符；或者写 sha256
    name: Keyword spotter
    version: "1.2"
    supplier: ACME Audio
    license: Apache-2.0              # SPDX 编号；其它写法会原样作为许可证名称
    description: 唤醒词检测
    intended-use: 在 Cortex-M4 上做唤醒词检测    # 文字或列表
    users: 智能音箱终端用户
    limitations: [只支持英语, 噪声超过 70 dB 时下降]
    ethical-considerations: 常开麦克风，只在本地处理
    base-model: 自研
    url: https://example.com/models/kws
    datasets:
      - name: Speech Commands v2
        url: https://example.org/speech-commands
        license: CC-BY-4.0
        personal-data: true          # 写 true 会标成 sensitiveData: personal data
    metrics:
      - {type: accuracy, value: "0.94", unit: top-1}
```

* 按 `path`（通配符）或 `sha256` 对应到扫描到的模型；编进 C 数组的模型用那个 `.cc` 文件的路径对应。
* 条目对不上任何模型时（比如运行时才下载的模型），保留成一个“仅声明”的组件（`gangmu:detectedBy` 为 `declaration only`），并在标准错误上警告。
* 输出里这些内容都是**人写的，不是工具验证的**：组件带 `gangmu:declaredBy` 属性，metadata 里的说明也这样写。
* `--require-declarations`：有模型没有声明许可证或训练数据时退出码为 1，并逐个列出；用在 CI 里卡住“没人写清楚来源”的模型。没有声明文件时用这个选项会报错（退出码 2）。表格输出也会列出这些缺口。
* 文件格式错了（缺 `path`/`sha256`、`sha256` 不是 64 位十六进制、数据集没有名字等）会报出位置并退出 2，不会悄悄跳过。

## 它不做什么

* **不读训练数据、许可证、用途、评测。** 这些读不出来，没有声明文件时就不填，也不猜；有声明文件时照人写的填，不核对。
* **不看构建事实。** 源码里提到某个运行时，不等于它编进了固件；CBOM 的 `--compile-db`/`--link-map` 机制还没接到这里。
* **不解析模型内部。** 不看层、算子、量化方式和参数量（GGUF 的两个字段除外）。
* **按名字识别。** 改名后的模型文件如果没有签名、扩展名也被改掉，会漏。
* 目前不读二进制固件镜像里的字符串，只看目录里的文件。
