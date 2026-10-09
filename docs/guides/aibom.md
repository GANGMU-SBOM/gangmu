# AIBOM：固件里的机器学习模型和推理库

`gangmu aibom` 列出一个源码树或固件目录里的 **机器学习模型** 和 **推理运行时**，输出 CycloneDX 1.6 的 AIBOM。这是最小版：只回答“里面有什么”，不回答“它训练自什么数据、能不能商用”。

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

## 它不做什么

* **不读训练数据、许可证、用途、评测。** 这些读不出来，所以不填，也不猜。要放进 AIBOM 的话需要人工提供，后续版本会加声明文件。
* **不看构建事实。** 源码里提到某个运行时，不等于它编进了固件；CBOM 的 `--compile-db`/`--link-map` 机制还没接到这里。
* **不解析模型内部。** 不看层、算子、量化方式和参数量（GGUF 的两个字段除外）。
* **按名字识别。** 改名后的模型文件如果没有签名、扩展名也被改掉，会漏。
* 目前不读二进制固件镜像里的字符串，只看目录里的文件。
