# 性能

[English](#performance-in-english)

纲目要放进每一次固件构建的 CI，扫描一棵完整 SDK 就不能是"去喝杯咖啡"的事。这一页记录性能基线、复现方法和 CI 里的回归检查。所有数字都可以用仓库里的工具重新测出来。

## 整棵 SDK：ESP-IDF v5.4.2

测试对象是 ESP-IDF v5.4.2，带全部子模块，共 10,767 个 `.c`/`.h` 文件。扫描时有 266 个候选目录，识别出 11 个组件。测试机器为 4 核，Python 3.11，没有提供构建信息（这是最慢的情形）。

| 设置 | 0.5 | 0.6 | 0.6，不装 numpy |
| --- | --- | --- | --- |
| 单进程，无缓存 | 72.5 s / 366 MB | **11.0 s / 123 MB** | 17.9 s / 134 MB |
| 4 进程，冷缓存 | 35.8 s / 369 MB | **5.5 s / 74 MB**（工作进程 92 MB） | |
| 4 进程，热缓存（再扫一遍） | 10.2 s / 53 MB | **2.1 s / 69 MB** | |

两个版本的结果逐条一致：组件、版本、置信度和未识别目录都相同。另外 6 棵本地树（铜锁、GmSSL 伪装示例、Zephyr HAL、OpenHarmony 片段等）也逐条比对过，结果同样一致。

## 规则数与耗时

社区规则库会持续增长，所以规则多了以后扫描不能线性变慢。测法是把已加载的规则复制若干份，并给每份的哈希加盐，使副本不会命中任何真实代码。扫描对象是一棵带种子的合成 SDK：1,152 个文件，59 个组件，其中有嵌套组件，也有完全相同的副本。单进程，无缓存：

| 规则数 | 0.5 | 0.6 |
| --- | --- | --- |
| 27 | 21.3 s / 167 MB | **3.2 s / 64 MB** |
| 108 | 27.1 s / 190 MB | **3.8 s / 87 MB** |
| 432 | 56.8 s / 281 MB | **6.8 s / 181 MB** |

0.6 中，规则从 27 条增加到 432 条，增加的时间主要花在跨规则的代码切分和预筛上。真正对每个目录执行完整匹配的规则，从 0.5 的"每条都跑"变成了"只跑可能命中的"。在这棵树上，16 倍规则时一共只跑了 16 次匹配，跳过了 26,864 次。

## 漏洞比对：全量 NVD

`gangmu vuln` 要能直接读一份完整的 NVD 本地镜像（约 33 万条记录，按年份分文件）。测试 SBOM 来自 ESP-IDF v5.4.2，4 核：

| 镜像格式 | 0.5 | 0.6 |
| --- | --- | --- |
| NVD 2.0 JSON（解压后 3.0 GB） | 200.8 s / 3,902 MB | **8.9 s / 25 MB**（工作进程各约 100 MB） |
| fkie-cad 镜像（`.json.xz`，106 MB） | 读不了，0 条 | **14.1 s / 48 MB** |

两种格式得到的 38 条结果与 0.5 读解压版时完全一致。0.6 一条一条地流式解码，只要记录里没有出现 SBOM 中任何一个 CPE 产品或 purl，就直接丢掉，不建对象；年份文件由多个进程并行读取。

## 做了什么

| 改动 | 解决的问题 |
| --- | --- |
| 以文件为单位分析，按内容哈希只分析一次 | 嵌套组件（例如 `openthread` 里套着 `mbedtls`）以及 glob 不同的规则，以前会把同一个文件分词好几遍 |
| 整次扫描只遍历一次目录树，按前缀切片 | 每条规则、每个候选目录都要重新遍历和匹配 glob，路径处理占了可观的时间 |
| 每个文件只保留最小的 256 个指纹 | 目录草图是并集里最小的 k 个值，这些值一定也在各自文件的最小 k 个里，所以结果**完全精确**，内存却有上限 |
| 增量缓存（SQLite，按内容哈希和分析代码的摘要做键） | 改一个文件只重新分析这一个文件；分词器或提取器的代码一改，旧缓存自动失效，不需要人记得去改版本号 |
| 规则预筛：函数、草图、锚点文件、文件集哈希都对不上的规则直接跳过 | 以前每个目录都要跑一遍全部规则的完整匹配；预筛对排序好的哈希表做二分查找，不另外占内存 |
| 函数签名的派生集合按签名缓存 | 版本区间推断以前每个目录都要重建一遍各版本的集合 |
| 一个进程池覆盖整次扫描，一次性批量预取 | 以前每个目录各起一个进程池，小组件低于并行阈值时只能串行 |
| 分词改用 `findall`，k-gram 循环内联，窗口最小值改用 C 层的 `min` | 不装 numpy 的纯 Python 路径也更快，输出逐值不变 |
| 可选 numpy 向量路径（`pip install gangmu-sbom[fast]`） | 滚动哈希和 splitmix 用 uint64 向量运算，回绕算术与 Python 的 mod 2⁶⁴ 完全一致，测试会逐值比对两条路径 |

numpy 只在需要时才导入。默认安装不带 numpy，内存不会因此增加；装了 `[fast]` 以后，扫描很小的树时进程内存会多出约 10 MB，这是导入 numpy 本身的开销。

## 复现

```bash
# 合成 SDK：冷扫、热扫，以及 1x/4x/16x 规则数
gangmu perf --rules rules --scale 1,4,16

# 真实 SDK
git clone --depth 1 --branch v5.4.2 --recurse-submodules --shallow-submodules \
    https://github.com/espressif/esp-idf.git
gangmu perf esp-idf --rules rules --jobs 4
```

`gangmu perf` 的每次扫描都在单独的进程里运行，所以峰值内存只算这次扫描本身。输出里的 `units` 是扫描耗时除以一个固定的单核校准负载的耗时，因此笔记本和 CI 机器上测出的数字可以互相比较。

## CI 回归检查

工具仓库的每个 PR 都会用固定版本的规则库（`.github/workflows/ci.yml` 里的 `GANGMU_RULES_REF`）运行下面的检查；规则库仓库的每个 PR 也会用自己的基线运行同样的检查，新规则不能让扫描变慢：

```bash
gangmu perf --rules .gangmu-rules/rules --rules tests/fixtures/rules \
       --embed tests/fixtures/upstream/tinynet --scale 1,4,16 \
       --check benchmarks/perf-baseline.json
```

| 检查项 | 标准 |
| --- | --- |
| 识别结果 | 与基线完全相同 |
| 分词文件数、哈希文件数、实际匹配次数 | 不得超过基线。这些计数与机器无关，翻倍的重复劳动一定会被发现 |
| 扫描耗时（校准单位） | 不超过基线的 1.6 倍。只有耗时超标时会重测一次，以排除 CI 机器被占用的干扰 |
| 峰值内存 | 不超过基线的 1.35 倍 |

新能力让检查失败时，先优化再合并。改动让扫描变快了，就在同一个 PR 里更新 `benchmarks/perf-baseline.json`，并在 PR 描述里写明前后数字。

---

## Performance (in English)

ESP-IDF v5.4.2 with submodules has 10,767 sources and 266 candidate directories. On a 4-core machine it now scans in 11.0 s single-process (0.5: 72.5 s), 5.5 s with 4 workers (0.5: 35.8 s), and 2.1 s on a warm rescan (0.5: 10.2 s). Peak memory falls from 366 MB to 123 MB. Every finding is identical.

On a seeded synthetic SDK, going from 27 to 432 rules costs 3.2 s → 6.8 s (0.5: 21.3 s → 56.8 s). That is possible because rules that share no function, sketch value, anchor file or file set with a directory are never evaluated.

The main changes:
* per-file analysis keyed by content hash, with one walk and one pool per scan;
* per-file bottom-k sketches, which give exactly the same directory sketch;
* an incremental SQLite cache, keyed by content and by a digest of the analysing code;
* the rule prefilter;
* `gangmu vuln` streams a full NVD mirror (plain or `.json.xz`) and keeps only records naming the SBOM's products: 200.8 s / 3.9 GB → 8.9 s / 25 MB;
* an optional numpy path that is checked value for value against the pure-Python one.

`gangmu perf` reproduces these numbers. In CI, `--check benchmarks/perf-baseline.json` fails a pull request in any of these cases:
* its findings change;
* its work counters grow;
* its time grows past 1.6× the baseline, in calibration units;
* its peak memory grows past 1.35× the baseline.
