# 从 Windows 可执行文件和语言工具链里提取 SBOM

客户可能只交来一个 `.exe` 或 `.dll`，没有源码，也没有构建。这份文档说明纲目现在能从这样的文件里读出什么、
每一类证据能证明什么、不能证明什么，以及这些结论是怎么验证的。结论先说：

- **能读：** PE 结构（导入表、导出表、版本资源、调试路径）、Go 和 Rust 工具链有意写进文件的依赖清单、
  .NET 程序集的元数据，以及旁边的 `*.deps.json`。
- **不能读：** 一个没有任何这类信息的静态链接 C/C++ 程序。这时只有版本横幅、字符串和函数指纹，和
  [BINARY-VALIDATION.md](BINARY-VALIDATION.md) 里的结论一样，证据弱、版本常常只能给区间。
- **所有输出都标明证据类型和可信度。** 读出来的依赖清单是“构建当时解析到的版本”，不是“这个文件没被改过”的证明。

## 各类证据

| 来源 | 文件 | 读到什么 | 能否给版本 | 可信度 | 它不能证明什么 |
|---|---|---|---|---|---|
| Go 构建信息（`debug/buildinfo`） | `.exe`、`.dll`、ELF | Go 版本，每个依赖模块的路径、版本、校验和，`replace` | 能，精确 | 0.90 | 构建之后被改过的代码；`replace` 指向的代码不是列出的版本，会标成已修改 |
| `cargo auditable` 清单 | `.exe`、`.dll`、ELF | 每个 crate 的名字、版本、来源 | 能，精确 | 0.90 | 只有用 `cargo auditable` 构建的程序才有；构建期依赖不会进最终文件，已排除 |
| `*.deps.json` | 与程序同目录 | .NET SDK 解析到的 NuGet 包和捆绑的运行时 | 能，精确 | 0.85 | 它是**独立文件**，可能过期，也可能与实际带的 DLL 不一致 |
| 版本资源（`VS_VERSIONINFO`） | PE | `ProductName`、`ProductVersion` 等 | 能 | 0.70 / 0.60 | 作者自己写的文字，可能过期或被包装程序沿用；不能证明没被改过 |
| 版本横幅（`libcurl/8.4.0`） | 任何文件 | 库内置的版本字符串 | 能 | 0.70 / 0.60 | 库在文件里，但不是“未修改的上游” |
| 导出符号 | DLL | 库的导出 API | 不能 | 0.65 | 每个版本的 API 几乎一样，说不出版本 |
| 导入表 | PE | 依赖哪些 DLL | 不能 | 0.50（“可能”） | **库本身不在这个文件里**，DLL 名也不说明装的是哪个版本 |
| .NET `AssemblyRef` | 托管 PE | 引用了哪些程序集及其**程序集版本** | 不能 | 0.50（“可能”） | 程序集版本不是包版本（Newtonsoft.Json 13.0.3 的程序集版本是 13.0.0.0） |
| 独立的托管 DLL | 托管 DLL | 名字加 `ProductVersion` | 能 | 0.50（“可能”） | 不能证明它是以这个名字发布的 NuGet 包，需要人确认 |

可信度低于 0.60 的条目进“可能”一栏（CycloneDX 里是 `gangmu:possibleComponent`），不进正式组件清单。

## 研究：别人是怎么做的

下面的论文只读了检索结果里的摘要性描述，没有逐篇精读原文；引用的数字都标明出处。

**学术上，二进制第三方库检测整体并不准。**
- FSE 2026 的一项大规模实证研究在含 38,228 个测试用例、1,873 个库的基准上评测了 11 个 C/C++ 二进制库检测工具，
  平均召回率低于 60%，精确率约 75%，原因是编译会丢掉大部分源码特征。
  见 [Understanding the Limitations of C/C++ Binary Third-Party Library Detection Tools](https://conf.researchr.org/details/fse-2026/fse-2026-research-papers/2/Understanding-the-Limitations-of-C-C-Binary-Third-Party-Library-Detection-Tool-An-)。
- 方法大多是“目标二进制的特征集合对比库的特征集合”：LibDB 用函数级特征识别库版本
  （[arXiv 2204.10232](https://arxiv.org/pdf/2204.10232)）；LibAM 在函数调用图上比较相邻函数组成的“区域”，
  以减轻优化级别和架构的影响（[arXiv 2305.04026](https://arxiv.org/pdf/2305.04026)）；BinCoFer 对特征库做三阶段提纯
  （[arXiv 2504.19551](https://arxiv.org/pdf/2504.19551)）；B2SFinder 在字符串之外加入整数常量、条件常量和常量数组，
  并按编译命令分组；OSSPolice 按目录布局给目录打分，有论文指出它误报多、作者没有提供可复现的材料；
  CENTRIS（[ICSE 2021](https://prl.korea.ac.kr/papers/icse21.pdf)）处理修改过的、嵌套的开源复用。
  这些方法都需要一个预先建好的特征库，纲目的字符串、函数指纹（见 BINARY-VALIDATION.md）走的是同一条路。
- 固件上的比较：UniBOM 在 258 个提取出的 Linux 固件镜像上比较了 Syft、Trivy 和微软 sbom-tool，只有两个工具能分析
  提取出的文件系统（[arXiv 2511.22359](https://arxiv.org/pdf/2511.22359)）。没有找到把 Syft、cve-bin-tool、EMBA、FACT
  放在固件上直接比准确率的研究。

**工程上，最可靠的是读工具链自己写下的清单，其次才是猜。**
- Syft 的二进制识别靠文件名匹配加正则取版本，维护者自己说这种字节模式的做法脆弱，不给依赖信息；
  同时它也读构建期元数据，如 ELF 注释、Go 模块信息和版本资源
  （[Anchore 博客](https://anchore.com/blog/improve-open-source-sbom-tool-syft-with-binary-detection/)、
  [社区讨论](https://anchorecommunity.discourse.group/t/for-scan-c-binary-how-to-recognize-the-package-which-the-binary-come-from/433/2)）。
- cve-bin-tool 对每个产品写 `VERSION_PATTERNS`（[检查器文档](https://cve-bin-tool.readthedocs.io/en/stable/CHECKERS.html)），
  它的[用户手册](https://cve-bin-tool.readthedocs.io/en/v3.2/MANUAL.html)说明它分不出补丁回移（backport）：
  只提供字符串、版本、CVE 之间的映射。
- Go 链接器把版本和模块清单放进可执行文件，格式在标准库源码里
  （[`debug/buildinfo`](https://go.dev/src/debug/buildinfo/buildinfo.go)）：魔数 `\xff Go buildinf:`、16 字节对齐、
  32 字节头；Go 1.18 起字符串内联、带变长长度前缀，模块文本前后各有 16 字节哨兵。
- `cargo auditable` 把依赖树的 JSON 压缩后写进名为 `.dep-v0` 的段，约 4 KB，数据里没有时间戳也不含路径，
  `cargo audit`、Trivy、Grype、Syft 都能读（[文档](https://docs.rs/cargo-auditable/latest/cargo_auditable/)）。
  它的 JSON 字段在文档页没有列出，是用真实构建核对的，见下。
- .NET 的程序集版本和 NuGet 包版本是两回事，运行时只看程序集版本
  （[微软的版本指南](https://learn.microsoft.com/sk-sk/dotnet/standard/library-guidance/versioning)）。
  我用真实 NuGet 包验证了这一点，见下。

## 设计取舍

1. **按证据强度分层，不混在一起。** 工具链写下的清单 0.90，旁路文件 0.85，作者写的版本资源 0.70，导入和引用 0.50。
   每条的说明文字各写各的，因为意思不同。
2. **内嵌、依赖、自身身份是三件事，分开写。** 以前“库在这个二进制里”的说法对导出符号成立，对导入表是错的：
   一个 exe 导入 `libcurl-4.dll`，只说明运行时需要 curl，curl 本身是另一个文件。CycloneDX 里因此分成
   `gangmu:embeddedLibrary`（静态编进文件：横幅、Go 模块、Rust crate）、`gangmu:importedLibrary`（DLL 导入、.NET 程序集引用）、
   `gangmu:declaredDependency`（`deps.json` 列出的包，是旁边的独立 DLL）和 `gangmu:identifiedAs`（托管 DLL 自己说自己是什么）；
   SPDX 的备注同样分开。这个区分是用真实的工业库测试时发现的：`BACnet.dll` 一度被写成“内嵌了 BACnet 4.0.0”。
3. **不为程序自己的程序集生成 NuGet purl。** 公司内部的 `Acme.Core.dll` 在 nuget.org 上不存在，给它一个 purl
   会被漏洞库当成公开包去匹配，还有依赖混淆的风险。只有独立的托管 DLL 且带语义化 `ProductVersion` 时，才作为 0.50 的“可能”候选，
   写明需要人确认；`.exe` 一律当作产品，不当作包。
4. **Go 的 `replace` 标成已修改。** `replace` 意味着编进去的代码不是列出的那个版本，`vendor_patched` 为真，
   说明里写出 `go.mod replace directive`。
5. **只读结构明确的格式，读不懂就说读不懂。** Go 1.18 以前的旧布局（指向镜像内地址的指针）需要地址映射，没读；
   被截断的构建信息返回 `has_modules=false`，不会被当成“没有依赖”。
6. **全部有界、不执行任何东西。** 表遍历有上限，zlib 解压有上限（防解压炸弹），所有偏移先对照文件大小。

## 怎么验证的

不能把真实的二进制提交进仓库（体积和许可），所以测试用三种办法：按规范逐字节拼出来的合成 PE（`tests/pebuild.py`，
构造器不调用解析器，避免用被测代码生成测试数据）、有工具链就现场交叉编译并和官方工具对照、有真实文件就跑真实文件。
下面是**我在开发时手工跑过**的真实样本（样本本身不在仓库里）：

| 对象 | 对照什么 | 结果 |
|---|---|---|
| Go 1.24.7 构建的 Windows exe、Linux ELF、加 `-s -w` 去符号的 exe，带 `uuid v1.6.0`、`x/text v0.21.0` | `go version -m` | 依赖、校验和、主包路径、工具链版本逐项一致。测试里的现场对照还抓到一个差异：本地 `replace` 的行带 `(devel)` 占位，已修 |
| `cargo auditable` 0.7.7 构建的 Rust ELF，带 `itoa`、`smallvec` | 文档页没有的 JSON 字段 | 确认字段是 `name`、`version`、`source`、`dependencies`、`root`，运行时依赖不写 `kind`，根包 `source` 为 `local` |
| pip 26.2.1 自带的 6 个 MSVC 启动器（x86、x86-64、ARM64） | 解析结果自洽 | 机器、位数、导入、版本资源、PDB 路径都读对。`t64-arm.exe` 的版本资源 `InternalName` 写的是 `w32.exe`，说明**这些字段是作者写的，会错**，所以只用 `ProductName` 配合已知库表，不用文件名 |
| PyYAML 6.0.3 的 `win_amd64` `.pyd`（真实 DLL） | 导入、导出 | 导入 `python311.dll` 等，导出 `PyInit__yaml` |
| `Python.Runtime.dll` 3.2.1、`ClrLoader.dll` | 程序集名、版本、与 Win32 版本资源对照 | 程序集版本 `3.2.1.0` 与 pythonnet 3.2.1 一致 |
| NuGet 上的 Newtonsoft.Json 13.0.3（705 KB）、Microsoft.Extensions.Logging 8.0.0、Serilog 3.1.1 | 各包的 `.nuspec` 声明的依赖 | 大程序集（表行数多、索引变宽）解析正确；Logging 的引用与 `.nuspec` 吻合（`Bcl.AsyncInterfaces` 声明了但没有被直接引用，是类型转发的正常现象）。同时证实：程序集版本不是包版本（Newtonsoft.Json 的程序集版本 13.0.0.0，包 13.0.3；Serilog 2.0.0.0 对 3.1.1），而 `ProductVersion` 带着包版本和 `+提交号` |

另外对 .NET 元数据做了变异检验：故意把三种索引宽度（编码索引、普通表索引、字符串堆）各改错一次，
对应的测试都会失败。

仓库里的测试：`tests/test_pe.py`、`tests/test_binmeta.py`、`tests/test_dotnet.py`。有 Go 工具链和 `cargo-auditable`
时，会现场构建并与官方工具对照；有 pip 自带启动器时，用真实 PE 跑。

## 在真实工业通信库上的实测

想直接拿 GitHub 上工业设备的 exe 和固件来测，但这个环境里 GitHub 的发布页和 API 对未挂载的仓库返回 403，
只开放匿名的 `git clone`。克隆了 `libplctag`、`OpenModScan`、OpenEVSE 的 ESP32 固件仓库、`OpenPLC_Editor`、
`4diac-forte` 五个仓库，按文件头在源码树里找二进制：**一个也没有**（只有两个 `.docx`），因为这些项目的 exe、dll、固件
都在 Releases 里。所以改用同一批开源项目发布到 PyPI 和 NuGet 的真实产物，下面是结果（`gangmu scan`，规则库 gangmu-rules 2026.10.11）：

| 样本（来源） | 读到什么 | 没读到什么 |
|---|---|---|
| `snap7.dll`（python-snap7 2.1.0，Siemens S7 通信库，MSVC 2013） | 导入 `kernel32/winmm/ws2_32`，链接器 12.0 | **没识别出它是 Snap7**：没有版本资源，没有横幅，规则库里也没有它 |
| `pysoem.cp311-win_amd64.pyd`（pysoem 1.1.13，静态链接了 SOEM EtherCAT 主站） | 导入 `python311.dll`、CRT，链接器 14.44 | **没识别出里面的 SOEM** |
| `BACnet.dll` 4.0.0 | 名字、版本、PDB 路径（确定性构建的 `/_/obj/...`）、引用 `Microsoft.Extensions.Logging.Abstractions` | |
| `EasyModbus.dll` 5.6.0 | 名字、版本；PDB 路径 `W:\Projekte\...\obj\Debug\EasyModbus.pdb` | 说明发布的是 Debug 构建，还带出了开发者的目录 |
| `NModbus.dll` 3.0.83、`S7.Net.dll`（S7netplus 0.20.0） | 名字、版本、CI 构建机上的 PDB 路径 | |
| `Opc.Ua.Core.dll` 2.0.1（OPC Foundation 官方 OPC UA 栈） | 名字、版本、已签名、10 到 13 个第三方程序集引用 | 每个引用只有程序集版本，没有包版本 |
| `libplctag.NativeImport.dll` 1.0.41（Allen-Bradley PLC 通信库的 .NET 包装） | 名字、版本；**切出了里面嵌的 10 个原生库**（4 个 Linux ELF、2 个 macOS Mach-O、4 个 Windows PE，见下一节），各自的架构、工具链、导出符号 | 切出的 10 个原生库**都认出是 libplctag**（按 `plc_tag_*` 导出符号，不给版本；ELF、Mach-O 的 SONAME 写明 2.6 系列）；外层 .NET 包装本身不会被报成含有它 |

这组结果的结论要诚实地读：**.NET 库（自带元数据）识别得很好；静态链接的 C/C++ 库（snap7、SOEM）一个都没认出来**，
和上面“没有任何横幅的静态 C/C++ 程序仍然认不出”一致。要认出它们，得往规则库里加条目（Snap7 的导出 API 名单、SOEM 的字符串或函数指纹），
这不是改解析器能解决的。样本是 8 个开源项目，不是工业设备厂商的私有程序，不能代表 PLC、HMI 厂商的 exe。

## 嵌在别的文件里的原生二进制

一个文件可以把完整的可执行文件或库当数据带着：.NET 程序集把各平台的原生库当托管资源，安装包后面附着载荷，固件里嵌着 ELF。
只扫外层文件的字节能读到横幅，却说不出它属于哪个二进制，符号表、导入表、版本资源、依赖清单这些结构化读取也都无法在不是从偏移 0 开始的
文件上运行。`carve.py` 按文件头把它们找出来、算出各自的大小，每一个当作独立的条目，用和外层文件完全相同的流程分析。

- **严格校验，不凭魔数。** `MZ` 和 `\x7fELF` 在普通代码和数据里到处都是，所以候选必须有自洽的头部：PE 要有 `e_lfanew` 指到
  `PE\0\0`、合法的机器类型、节表；ELF 要有合法的类别、字节序、类型（可执行或共享对象，**不要** `.o`）、能解析的程序头和节头；Mach-O
  只认小端，要有合法的文件类型和段命令。大小来自格式自己的表：ELF 取程序头、节头和节头表的最大末端，PE 取节表的最大末端再加 Authenticode 证书，
  Mach-O 取各段的文件末端加代码签名。小于 2 KB 的、末端超出文件的，一律不切。
- **各归各的。** 切出的区间在读外层文件时被抹掉，所以横幅和工具链字符串记在它真正所在的二进制上。以前 `libplctag.NativeImport.dll` 的
  `toolchain` 显示 `Ubuntu 11.4.0`，那其实是里面嵌的 `.so` 的编译器，不是这个 .NET DLL 的。
- **子文件是 SBOM 里独立的条目。** 路径是 `外层!资源名`（.NET 资源有作者起的名字，如 `...runtime.linux_x64.libplctag.so`）或 `外层#0x偏移`，
  带 `gangmu:containedIn`、`gangmu:offsetInContainer`、`gangmu:architecture`；外层带 `gangmu:embeddedBinaries`；SPDX 里是外层文件“包含”子文件，
  不是产品直接包含。
- **有界。** 只切最外层的，里面再嵌的在分析这一层时找；最多往里两层，之后不再切，最深那层按整个文件读；一个文件最多 64 个；候选魔数的搜索有上限
  （64 MB 的随机数据或全是 `MZ` 的数据，切分各要 0.15 到 0.24 秒）。静态库（`.a`、`.lib`）不切，它们的成员就是 ELF 目标文件，不是交付的库。

验证：`libplctag.NativeImport.dll` 的托管资源表记录了每个嵌入资源的名字、偏移和大小，可以当标准答案。切出的 10 个与它**偏移和大小逐个一致**，
没有多切，其中 `MZ` 的假阳性命中（如偏移 2311216）都被结构校验挡掉了。另外：一个真实的系统 ELF 按字节原样切出；pip 自带的 MSVC 启动器
按字节原样切出；六处变异（ELF 节头表大小、PE 证书、Mach-O 签名、接受 `.o`、不跳过偏移 0、不抹掉子文件）各自被预期的测试抓住。

**这次切分的一个意外发现：** 该包的 `osx_x64` 资源和 `osx_ARM64` 资源是**逐字节相同**的同一个文件，`cputype` 是 `0x100000c`（ARM64），
也就是说 Intel Mac 那个位置放的是 arm64 的库。这是 libplctag.NativeImport 1.0.41 这个包本身的内容，我没有向上游反馈。

## 没做的，和没验证的

- **切分的范围：** 只认 ELF、PE 和小端 Mach-O；胖 Mach-O 不认（它的魔数同时是 Java 类文件的魔数）；被压缩或加密的内嵌载荷不展开（`.NET` 资源里存的若是 gzip，要解压才看得到里面的库）；最多往里两层。
- **认出来靠导出符号，不靠字符串。** 子二进制走和别的文件同一套识别。`libplctag` 的原生库按 34 个 `plc_tag_*` 导出符号识别（至少 24 个，在 10 个切出的库里全部命中），ELF 和 Mach-O 的 SONAME（`libplctag.so.2.6`）写进证据说明里，但它只是 2.6 系列，不当作版本；字符串 `2.6.0` 没有可靠的旁证，也不用。**.NET 程序集不参与导出符号匹配**：它的元数据里有同样的 `plc_tag_*` 名字，那是 P/Invoke 声明，表示它要调用库，不表示库在里面。只在这一个版本（1.0.41 里的 2.6.0）上验证过，别的 libplctag 版本没有样本，没有验证。
- **Rust 在 Windows 上的 `.dep-v0`**：段名在 PE 里的读取只用合成文件测过。我没能构建真实的 Windows Rust 程序
  （本机没有 MinGW 链接器，`rust-lld` 的 gnu 风格需要 nightly），ELF 上是真实验证过的。
- **Go 1.18 以前的旧布局**、被混淆（garble 等）或剥掉构建信息的 Go 程序：读不出，也不会猜。
- **加壳和安装包**：UPX、NSIS、Inno Setup、MSI、Electron 的 `app.asar`、PyInstaller、Delphi、Java 启动器，都没有处理。
  .NET 单文件发布和 NativeAOT 的元数据位置也没有验证。
- **只读 `AssemblyRef` 和 `Assembly` 两张表**，没有读自定义特性，所以拿不到 `AssemblyInformationalVersion`，
  只能借 Win32 版本资源里的 `ProductVersion`。
- **UTF-16 编码的版本横幅**没有匹配；库的版本横幅匹配的仍然是单字节字符串。
- **签名只看有没有**，不验证证书，也不读签名人。
- **PE 和 Mach-O 上的函数级指纹**只验证过很窄的范围：函数恢复和指纹生成（`rules binary-prints`、`binary-eval`）已支持 PE（x86、x64、ARM、Thumb、ARM64，含 Windows CE 的 ARM）和 Mach-O，真实样本只有 lz4.exe、zstd.exe 和 zstandard 的 wheel（见 BINARY-VALIDATION.md）；`gangmu scan` 对 `.exe`、`.dll` 的函数级比对只在某条规则带有这种 CPU 的参考指纹时才做（和 ELF 库一样；.NET 程序集没有原生代码，不做），免费库里有 x86-64 指纹的有 zlib、littlefs、Mbed TLS、Lua、zstd、bzip2、libdeflate、expat、libpng、Brotli、yyjson 和 PCRE2（见 BINARY-VALIDATION.md 末节：mingw 编的 Mbed TLS 2.28.8 的 DLL 被识别为 `2.28.0~2.28.8`），其余库的 PE 还不能被函数级识别；`binary-functions` 仍然只读 ELF 和裸镜像。
  字符串常量比对对任何文件的字节都会跑，但我没有在真实 PE 上验证它的准确率。
- **没有验证的想法：** Rust 程序的 panic 信息可能带着 `registry/src/.../crate-版本/` 路径，能补充没有 `cargo auditable` 的程序；
  我在一个小样本里没找到这类字符串，所以没做。
- **这是一次开发期的实测，样本很少**，不是识别率的统计结论。静态链接的 C/C++ 程序里不带横幅的库，仍然认不出。
