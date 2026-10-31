# 二进制识别的验证：准确率、召回率与误报

没有源码、只有编译好的库或固件镜像时，纲目用逐函数指纹认库和版本：从机器码里还原每个函数引用的字符串和显著常量，与规则自带的参考指纹比对（`identity.binary_functions`，由 `gangmu rules binary-prints` 生成）。这一页是这套方法在交叉编译基准上的结果，全部可以用仓库里的工具复现。数字是 2026-10-31 用当前的 `main` 测的。

## 方法

- **语料**（`benchmarks/binary/build_corpus.py`，库的清单在 `benchmarks/binary/libs.yaml`）：14 个库、15 组构建，每个库若干个发布版，每个版本用 `-Os -O2 -O1 -O0` 四个优化级别编译，链接成 ELF 再 `strip -s`。库是 zlib、cJSON、littlefs、lz4、inih、heatshrink、Mbed TLS（只有密码学部分的 `mbedtls`，和再加 TLS 与 X.509 层的 `mbedtls-full`）、Lua、zstd、bzip2、libdeflate、Brotli、yyjson、PCRE2；AArch64 上还有 libpng。expat 和其他架构上的 libpng 在这些交叉编译器下没有编出来，不在结果里。**只链接库自己的代码，不带 libc 和 libgcc**：参考指纹里混进 libc 的 `printf`、`malloc`，认出来的就是 libc 而不是库。**不带 `assert()`**：assert 的字符串会让参考指纹在作者自己的构建上虚高，出货的固件一般不带。
- **四种架构**：Cortex-M3（`arm-none-eabi-gcc 13.2.1 -mcpu=cortex-m3 -mthumb`）、rv32imac（`riscv64-unknown-elf-gcc`）、AArch64（`aarch64-linux-gnu-gcc 13.3.0`）、Xtensa ESP32（乐鑫的 `xtensa-esp32-elf-gcc 13.2.0`）。
- **评测**（`gangmu binary-eval --corpus DIR`）：对每个库，用一个优化级别的构建做参考指纹，去识别所有优化级别、所有版本的剥离符号的镜像。每个单元格是一个镜像，结果是四种之一：`exact`（版本唯一且正确）、`range`（`低~高` 区间，含真实版本）、`wrong`（认出了这个库，但版本或区间不含真值）、`none`（没认出这个库）。
- **负对照**：把每个库的参考指纹拿去匹配其他每个库的每个镜像，任何匹配都是误报。同一个库的两种构建（`mbedtls` 与 `mbedtls-full`）不互为负对照。
- **共有函数**：几个库共有的函数（lz4 和 zstd 都带着 xxHash）对哪个库都不算证据。评测和扫描用同一套做法（`fprint.segment_prints`）：每个库的参考指纹与其他库所有优化级别的参考指纹比较，共有的函数从两边都去掉；只有一个库几乎整个都在另一个库里时，它是被打包进去的那个，保留自己的函数，由宿主让出。`--no-segment` 关掉这一步。
- **跨架构**（`--images` 另一种架构的语料）：参考指纹和镜像不是同一种 CPU 时只比字符串，编译器生成的常量在不同架构之间不一样。这时只报库，版本给规则覆盖的整个区间。

### 指标

| 指标 | 定义 |
| --- | --- |
| 召回率 | 认出了库的镜像（exact + range + wrong）/ 全部镜像 |
| 精确率 | 认对的库（上面那些）/（认对的库 + 负对照里的误报） |
| 版本完全正确 | exact / 认出了库的镜像 |
| 版本正确或区间含真值 | (exact + range) / 认出了库的镜像 |
| 负对照命中率 | 负对照误报 / 负对照对数 |

## 结果

同一种架构（参考指纹和镜像是同一种 CPU，比较字符串和常量）：

| 架构 | exact | range | wrong | none | 召回率 | 精确率 | 版本完全正确 | 版本正确或区间含真值 | 负对照命中 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Cortex-M3 | 233 | 301 | 4 | 150 | 78.2% | 95.0% | 43.3% | 99.3% | 28 / 9,776 |
| rv32imac | 198 | 325 | 4 | 161 | 76.6% | 99.8% | 37.6% | 99.2% | 1 / 9,776 |
| AArch64 | 254 | 324 | 20 | 138 | 81.2% | 100% | 42.5% | 96.7% | 0 / 11,200 |
| Xtensa | 217 | 248 | 2 | 179 | 72.3% | 100% | 46.5% | 99.6% | 0 / 9,118 |

跨架构（只比字符串）：

| 参考 → 镜像 | exact | range | wrong | none | 召回率 | 精确率 | 版本正确或区间含真值 | 负对照命中 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Cortex-M3 → rv32imac | 122 | 120 | 4 | 442 | 35.8% | 100% | 98.4% | 0 / 9,776 |
| Cortex-M3 → AArch64 | 118 | 202 | 9 | 359 | 47.8% | 100% | 97.3% | 0 / 10,496 |
| Cortex-M3 → Xtensa | 140 | 212 | 15 | 297 | 55.3% | 98.4% | 95.9% | 6 / 9,440 |
| Xtensa → Cortex-M3 | 111 | 171 | 0 | 382 | 42.5% | 100% | 100% | 0 / 9,448 |

怎么读：

- **认出的库几乎都对**：同架构精确率 95% 到 100%。
- **版本多半是区间**：区间含真值的比例在 96.7% 以上，但能唯一定到一个版本的只有 37% 到 47%。相邻版本改动的函数少，指纹能分辨的就少；`-O0` 构建的参考指纹去认 `-Os`/`-O2` 的镜像时尤其如此（`-O0` 不内联，大函数的特征和优化后的差得远）。
- **约四分之一的镜像认不出**：有指纹的函数太少的小库（cJSON、inih、heatshrink）几乎全认不出，库至少要有 5 个函数匹配上才会被报出。
- **剩下的误报**：Cortex-M3 上的 28 次全部来自 zstd 和 Brotli 很小的指纹（2 到 5 个常量、没有字符串），在 Mbed TLS 和 yyjson 的镜像里碰巧凑够了 5 个函数。去掉共有函数之前，四种架构上的负对照命中是 91、70、87、48 次。
- **跨架构召回率只有 36% 到 55%**，因为只剩字符串可比；认出的仍然几乎都对。

## 真实源码树里的预编译文件

227 条规则钉定的上游发布版（源码树）里，扫描认出了 15 个预编译文件：premake4 里的 Lua 5.1.4、premake5 里的 libcurl 7.53.1、几个 DLL 里静态链接的 zlib（1.3.1、1.2.3）、libogg、libopus 1.4，以及 TF-M 安全镜像里的 Mbed TLS。**15 个都是真的**；版本多半只有区间或没有。

## 这一轮没有测的

下面这些能力都在，但这一轮没有在当前版本上重新测，所以这里不给数字：

- 真实厂商固件（例如 Zephyr 自己的构建）。参考构建和真实固件的配置不同（配置宏、是否带 assert）时，匹配上的函数会明显变少，版本区间更宽。
- clang 编译的镜像对 gcc 编译的参考指纹。
- Windows PE（含 Windows CE）、Mach-O、MIPS32 的函数指纹，以及 Linux 发行版里的库（Ubuntu 的包、OpenWrt 的包）。

## 复现

```
python benchmarks/binary/build_corpus.py --out /tmp/corpus --target arm   # 也可以 riscv32、aarch64、xtensa
gangmu binary-eval --corpus /tmp/corpus                                      # 需要 pip install 'gangmu-sbom[disasm]'
gangmu binary-eval --corpus /tmp/corpus-arm --images /tmp/corpus-riscv32     # 跨架构
```

需要 git、网络和对应的交叉编译器。构建 Mbed TLS 最慢；`--lib` 可以只建一部分库，`--relink` 复用上次编译的目标文件。
