# 性能

[English](#performance-in-english)

纲目要放进每一次固件构建的 CI，扫描一棵完整 SDK 就不能是"去喝杯咖啡"的事。这一页记录性能基线、复现方法和 CI 里的回归检查。所有数字都可以用仓库里的工具重新测出来。

## 整棵 SDK：ESP-IDF v5.4.2

测试对象是 ESP-IDF v5.4.2，带全部子模块，共 10,767 个 `.c`/`.h` 文件。2026-10-30 用 `main` 和免费规则库 gangmu-rules 2026.10.29（1027 条规则）测得；4 核，Python 3.13，装了 numpy，没装 Capstone，没有提供构建信息（这是最慢的情形）。扫描得到 343 个候选目录和 20 条识别结果。同一时段这台机器的校准耗时约 0.063 s（CI 的 runner 在 0.033 到 0.060 s 之间）；这台机器的速度会波动，数字只能在同一时段、同一台机器上比较。

| 设置 | 耗时 | 峰值内存 |
| --- | --- | --- |
| 单进程，无缓存 | 72.9 s | 794 MB |
| 单进程，热缓存（再扫一遍） | 40.0 s | 751 MB |
| 4 进程，冷缓存 | 57.5 s | 784 MB |
| 4 进程，热缓存 | 37.5 s | 751 MB |

单进程、热缓存下，关掉各个附加步骤各省多少：

| 设置（单进程，热缓存） | 耗时 |
| --- | --- |
| 默认 | 40.0 s |
| `--no-binaries`（不清点预编译库和固件镜像） | 34.5 s |
| `--no-unknown`（不报告没有规则认得的外来代码） | 35.7 s |
| `--no-loose`（不认平铺在目录里的组件） | 37.1 s |
| 三个都关 | 32.3 s |

* ESP-IDF 树里有 183 个预编译文件要清点，这一步约 5.5 s。
* 热缓存下 4 进程只比单进程快一点（37.5 s 与 40.0 s）：分词已经缓存，剩下的是逐个目录的规则匹配，它不并行。4 进程主要在冷扫时省下分词的时间。
* 三个都关以后剩下的 32 s 几乎全是规则匹配本身：1027 条规则、343 个候选目录。

## 规则数与耗时

社区规则库会持续增长，所以规则多了以后扫描不能线性变慢。测法是把已加载的规则复制若干份，并给每份的哈希加盐，使副本不会命中任何真实代码。扫描对象是一棵带种子的合成 SDK：1,152 个文件，59 个组件，其中有嵌套组件，也有完全相同的副本。

免费规则库 1027 条加 1 条测试夹具为 1 倍，单进程，无缓存，装了 numpy，同一台 4 核机器（校准 0.063 s）：

| 规则数 | 耗时 / 峰值内存 |
| --- | --- |
| 1,028（1 倍） | 11.2 s / 601 MB |
| 4,112（4 倍） | 23.4 s / 919 MB |
| 16,448（16 倍） | 81.6 s / 2,530 MB |

规则多了 16 倍，耗时约 7.3 倍。1 倍时热缓存重扫 7.6 s。规则预筛让绝大多数规则根本不执行：1 倍时实际匹配 11 次，跳过 61,669 次；16 倍时匹配 161 次，跳过 986,719 次。内存随规则数近似线性增长，主要是规则自己的函数签名，以及「哪条规则记录了哪个函数」的索引（每个函数 6 字节）。CI 里的基线见 `benchmarks/perf-baseline.json`。

## 漏洞比对：全量 NVD

`gangmu vuln` 要能直接读一份完整的 NVD 本地镜像（按年份分文件，2002 到 2026 共 27 个 NVD 2.0 JSON 文件，解压后 2.7 GB）。2026-10-30 测得：测试 SBOM 是上面 ESP-IDF v5.4.2 那次扫描输出的 CycloneDX（203 个组件），4 核：

| 镜像格式 | 耗时 / 峰值内存 |
| --- | --- |
| NVD 2.0 JSON（解压后） | **9.3 到 9.6 s / 60 MB**（两次） |

峰值内存是主进程的。两次运行都找到 92 条与这些组件相关的记录。做法：一条一条地流式解码，只要记录里没有出现 SBOM 中任何一个 CPE 产品或 purl，就直接丢掉，不建对象；年份文件由多个进程并行读取。fkie-cad 镜像（`.json.xz`）也能读，这次没有测。

## 做了什么

扫描为什么能这么快，以及规则多了以后为什么不线性变慢：

| 改动 | 解决的问题 |
| --- | --- |
| 以文件为单位分析，按内容哈希只分析一次 | 嵌套组件（例如 `openthread` 里套着 `mbedtls`）以及 glob 不同的规则，以前会把同一个文件分词好几遍 |
| 整次扫描只遍历一次目录树，按前缀切片 | 每条规则、每个候选目录都要重新遍历和匹配 glob，路径处理占了可观的时间 |
| 每个文件只保留最小的 256 个指纹 | 目录草图是并集里最小的 k 个值，这些值一定也在各自文件的最小 k 个里，所以结果**完全精确**，内存却有上限 |
| 增量缓存（SQLite，按内容哈希和分析代码的摘要做键） | 改一个文件只重新分析这一个文件；分词器或提取器的代码一改，旧缓存自动失效，不需要人记得去改版本号 |
| 规则预筛：函数、草图、锚点文件、文件集哈希都对不上的规则直接跳过 | 以前每个目录都要跑一遍全部规则的完整匹配；预筛对排序好的哈希表做二分查找，不另外占内存 |
| 版本打分直接数各版本的位图，不为每个版本建集合；签名按已排序的哈希二分查找；整签名集合放进有总量上限的缓存 | 规则多了以后，每条规则每个版本一个集合的开销会压过扫描本身 |
| 所有规则记录的函数合成一份按哈希排序的索引，每个文件查一次；每个目录先用这份上界排除不可能命中的规则 | 不用对每个目录、每条规则各做一次不相交测试 |
| 一个进程池覆盖整次扫描，一次性批量预取 | 以前每个目录各起一个进程池，小组件低于并行阈值时只能串行 |
| 分词改用 `findall`，k-gram 循环内联，窗口最小值改用 C 层的 `min` | 不装 numpy 的纯 Python 路径也更快，输出逐值不变 |
| 可选 numpy 向量路径（`pip install gangmu-sbom[fast]`） | 滚动哈希和 splitmix 用 uint64 向量运算，回绕算术与 Python 的 mod 2⁶⁴ 完全一致，测试会逐值比对两条路径 |
| 目录草图由各文件已排序的最小指纹归并得到，不求并集 | 扫描根目录这样的大目录，并集要几百 MB；归并只需要几百个值 |
| 函数签名文件整表解码（`struct.iter_unpack`、`array.frombytes`），规则间重复哈希和有序性检查改在 C 层比较 | 加载规则库、做代码切分是每次扫描的固定开销，热扫描时尤其明显 |

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

`gangmu perf` 的每次扫描都在单独的进程里运行，所以峰值内存只算这次扫描本身。输出里的 `units` 是扫描耗时除以一个固定的单核校准负载的耗时，因此笔记本和 CI 机器上测出的数字可以互相比较。校准取 9 轮的中位数，并在整套扫描之前和之后各测一次、取平均（两次的比值记在输出 JSON 的 `calibration_drift`），这样一轮侥幸的快或慢不会定下单位。

**但单位并不和机器无关。** CI 的 runner 不是同一种机器：校准耗时约 0.033、0.045、0.060 s 各有，而一次扫描里有约 0.5 到 0.6 秒的固定开销不随 CPU 变快，所以同样的代码在快的 runner 上以校准单位算要高 20% 到 30%。基线必须落在这个范围里。`benchmarks/perf-baseline.json` 因此是从多次 CI 运行的 `perf.json` 制品重录的（用 `benchmarks/rebaseline.py`）：耗时和内存取中位数，工作计数取最大值。当前这版取自 2026-10-30 的 7 次 CI 运行（规则库 2026.10.29，加测试夹具共 1028 条规则；其中一次落在校准约 0.031 s 的快 runner 上），各次对它在 0.96 到 1.23 倍之间，1.23 倍的就是那次快 runner。规则库或合成树变了之后，要重录一次。

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

**Whole SDK, ESP-IDF v5.4.2** (with submodules, 10,767 `.c`/`.h` files). Measured on 2026-10-30 with `main` and the free rule base gangmu-rules 2026.10.29 (1027 rules); 4 cores, Python 3.13, numpy installed, no Capstone, no build facts (the slowest case). The scan sees 343 candidate directories and reports 20 findings. This machine's calibration was about 0.063 s at the time (CI runners: 0.033 to 0.060 s); its speed varies, so compare numbers only from one machine and one sitting.

| Setting | Time | Peak memory |
| --- | --- | --- |
| 1 process, no cache | 72.9 s | 794 MB |
| 1 process, warm cache | 40.0 s | 751 MB |
| 4 processes, cold cache | 57.5 s | 784 MB |
| 4 processes, warm cache | 37.5 s | 751 MB |

Single process, warm cache, with each extra step switched off:

| Setting | Time |
| --- | --- |
| default | 40.0 s |
| `--no-binaries` | 34.5 s |
| `--no-unknown` | 35.7 s |
| `--no-loose` | 37.1 s |
| all three off | 32.3 s |

* The tree has 183 prebuilt files to inventory; that step takes about 5.5 s.
* With a warm cache, 4 processes are only a little faster than 1 (37.5 s against 40.0 s): tokenising is cached, and what remains is rule matching directory by directory, which does not run in parallel. Extra processes mainly save tokenising time on a cold scan.
* With all three off, the 32 s left are rule matching itself: 1027 rules over 343 candidate directories.

**Rule count** (seeded synthetic SDK, 1,152 files, single process, no cache, numpy installed, same machine, calibration 0.063 s; the 1027 free rules plus one test fixture are 1x):

| Rules | Time / peak memory |
| --- | --- |
| 1,028 (1x) | 11.2 s / 601 MB |
| 4,112 (4x) | 23.4 s / 919 MB |
| 16,448 (16x) | 81.6 s / 2,530 MB |

16 times the rules cost about 7.3 times the time; the warm rescan at 1x is 7.6 s. Rules that share no function, sketch value, anchor file or file set with a directory are never evaluated: 11 full matches and 61,669 skipped at 1x, 161 and 986,719 at 16x. Memory grows about linearly with the rules: their own function signatures, and the index of which rule records which function (6 bytes a function).

**Vulnerability matching against a full NVD mirror** (27 NVD 2.0 JSON year files, 2002 to 2026, 2.7 GB unpacked; measured on 2026-10-30 with the CycloneDX SBOM of the ESP-IDF scan above, 203 components, 4 cores): 9.3 to 9.6 s and 60 MB peak in the main process over two runs, 92 matching records. `gangmu vuln` streams the mirror, plain or `.json.xz` (the fkie-cad mirror, not measured here), and keeps only records naming the SBOM's products.

How it is fast, and why more rules do not cost proportionally more:
* per-file analysis keyed by content hash, with one walk and one pool per scan;
* per-file bottom-k sketches, which give exactly the same directory sketch, merged from the files' sorted bottoms rather than a union;
* an incremental SQLite cache, keyed by content and by a digest of the analysing code;
* the rule prefilter: every function the rules record in one index sorted by hash, so a file is looked up once and each directory first rules out what cannot fire;
* versions scored from the signatures' bitmaps, signatures searched by bisection, and whole-signature sets in a cache bounded by their total size;
* function-signature sidecars decoded table at once;
* an optional numpy path that is checked value for value against the pure-Python one.

`gangmu perf` reproduces these numbers. In CI, `--check benchmarks/perf-baseline.json` fails a pull request in any of these cases:
* its findings change;
* its work counters grow;
* its time grows past 1.6× the baseline, in calibration units (the calibration is the median of nine rounds, measured before and after the scans and averaged). The units are not machine-independent, though: CI runners differ (calibration about 0.033, 0.045 or 0.060 s) and a scan has a fixed cost of about half a second that does not shrink with the CPU, so the same code reads 20 to 30% dearer on the fast runners. `benchmarks/perf-baseline.json` is therefore re-recorded from the `perf.json` artifacts of several CI runs (`benchmarks/rebaseline.py`: median time and memory, largest work counters); the current one is from 7 runs on 2026-10-30 (rule base 2026.10.29, 1028 rules with the test fixtures; one of them on a fast runner, calibration about 0.031 s), which read 0.96x to 1.23x against it, the 1.23x being that fast runner. Re-record it when the rule base or the synthetic tree changes;
* its peak memory grows past 1.35× the baseline.
