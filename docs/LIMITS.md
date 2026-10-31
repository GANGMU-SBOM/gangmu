# 能力边界

坦白列出来，因为缺口就是路线图：

- **Linux 发行版的库只有部分能认出来。** 版本横幅只覆盖少数库，发行版常把横幅剥掉；`.note.package` 只在发行版写了它时有用。clang 编译的固件、真实厂商固件这一轮没有在当前版本上重测（见 [BINARY-VALIDATION.md](BINARY-VALIDATION.md)「这一轮没有测的」）。高熵的原始镜像只给出提示，不会替你解密或解包。
- **二进制分析有限，不是完整的反汇编或反编译。** 没有源码也没有构建，构建事实无从下手；对 `.a`、`.lib`、`.so`、
  `.elf`、`.axf`、`.bin`、`.exe`、`.dll` 做清单（路径、SHA-256、大小）、解开 HEX、S-record、UF2、U-Boot uImage 和 gzip/xz/bzip2/zlib/zip 封装、读版本横幅和导出符号（ELF 会解析符号表并标注是否已剥离），作为较低置信度的补充证据。
  装了可选依赖 Capstone（`pip install 'gangmu-sbom[disasm]'`）后，还能从 ELF 和带 Cortex-M 向量表的 `.bin` 里恢复函数边界（`gangmu binary-functions`，支持 Thumb、ARM、AArch64、RISC-V、MIPS32（小端、大端；MIPS16e、microMIPS 不支持）、x86；Xtensa（ESP32 经典款、ESP8266）因为 Capstone 没有解码器，用自带的最小实现 `xtensa.py` 处理：只认 `entry` 指令找函数起点、只还原 `l32r` 取到的字面量，不是完整反汇编，且只在一个 xtensa-esp32-elf-gcc 版本上验证过）。另外：规则可以用 `identity.binary_banners` 自带版本横幅；读 ELF 的 `.note.package`（发行版打包元数据）和 GNU build-id；共享库文件名里的数字就是发行版（`libz.so.1.3.1`）且与 SONAME 一致时给出较低置信度的版本；原始 Cortex-M 镜像的向量表可以不在偏移 0，MCUboot 头也认（`--offset`）。PE（x86、x64、ARM、Thumb、ARM64，含 Windows CE 的 ARM）和 Mach-O（x86、x86-64、ARM64）的函数恢复与指纹生成（`rules binary-prints`、`binary-eval`）也已支持，`gangmu scan` 对 `.exe`、`.dll` 也只在某条规则带有这种 CPU 的参考指纹时才做函数级比对，免费库里 x86-64 的指纹有 12 条：zlib、littlefs、Mbed TLS，以及 Lua、zstd、bzip2、libdeflate、expat、libpng、Brotli、yyjson、PCRE2（Thumb 只有前三条，RISC-V 有 littlefs 和 Mbed TLS），别的库的 x86 和 PE 还认不出。在此之上还有逐函数指纹（`gangmu rules binary-prints`，规则里的 `identity.binary_functions`；生成命令会先用作者提供的、同一版本的多个构建互相验证，没通过就不写文件，规则里必须带验证结果）：每个函数引用的字符串和用到的显著常量，从机器码里还原。自己交叉编译的基准（Cortex-M3、rv32imac、AArch64、Xtensa 四种架构，14 个库、各自的发布版、4 个优化级别，不带 `assert()`，`gangmu binary-eval` 可复现）见 [docs/BINARY-VALIDATION.md](BINARY-VALIDATION.md)：同一种架构时召回率 72% 到 81%、精确率 95% 到 100%，认出的镜像里版本正确或区间含真值 97% 到 100%，但能唯一定到一个版本的只有 37% 到 47%；参考指纹和镜像不是同一种 CPU 时只比字符串、只报库，召回率降到 36% 到 55%；有指纹的函数太少的小库（inih、heatshrink、cJSON）认不出来。几个库共有的函数（lz4 和 zstd 都带着 xxHash）不算任何一个库的证据，但 Cortex-M3 上仍有 0.3% 的负对照命中，来自很小的、只有常量的指纹。自测通过不代表真实固件上同样准：真实固件的配置（配置宏、是否带 assert）和参考构建不同时，匹配上的函数会明显变少、版本区间更宽。 Windows 的 `.exe`、`.dll` 另外读 PE 的导入表、导出表和版本资源，Go 和 Rust（`cargo auditable`）工具链写进文件的依赖清单，.NET 的程序集引用和旁边的 `*.deps.json`；这些证据的可信度、没做的部分和验证方法见 [docs/BINARY-SBOM.md](BINARY-SBOM.md)。静态链接、没有任何横幅的 C/C++ 程序仍然认不出。
  这是有意的取舍：识别结果只是较低置信度的补充证据；对剥离过符号的 MCU 镜像，这种办法能恢复名字、偶尔恢复版本，却填不满 CRA 要求的字段。
- **链接 map 只验证过手写样例。** `--link-map` 支持 GNU ld、lld、IAR ilink（`MODULE SUMMARY`）、Arm armlink（`Image component sizes`、`Removing Unused input sections`）和 TI armlnk/lnk2000（`SECTION ALLOCATION MAP`）。IAR ilink（STM32F030 的 IAR 8.20 工程，17 个目标文件与 12 个库成员）、Arm armlink（Keil 5.06 的 STM32F103 工程，16 个目标文件与 81 个库成员）和 TI 的解析都对照过公开的真实工程 map，数量与 map 里独立统计的完全一致，但这些文件不能随仓库发布，测试里用的是手写样例；其中 armlink 对照真实 map 时发现并修了两处（带 `*` 标记的行、没有加载地址的零初始化行读不到；库成员被当成目标文件）。TI 的那份是公开的 CC26x2 工程 map（`TI ARM Linker v20.2.3`，38 个目标文件与库成员全部对上），但该文件许可证禁止再分发，所以测试里用的仍是手写样例。IAR 与 TI 都不打印被丢弃的模块，所以工程里编译了、map 里没出现的源文件会被判为未链接。
- **评测规模有限。** 实测覆盖 lwIP、FreeRTOS、RT-Thread、国密与 OpenSSL 系列、Mbed TLS、FatFs、
  littlefs、LVGL、libcoap、TinyCrypt、TencentOS-tiny、nghttp2 等十几个组件族，共约一百多棵真实上游树
  和国产 SDK 里的几十份副本（见 [docs/BENCHMARK.md](BENCHMARK.md)）；
  CENTRIS 的评测集是 10,241 个项目。方法是对的，规模还不是。
- **规则还少。** 引擎和导入器能承载上千条，数据还没到。全志 Tina Linux 的 SDK（RTOS SDK 已覆盖）
  不在 Zephyr 上游，需要单独导入。
- **递归导入对两种清单都可用，但 west 只支持常用的 `import` 写法。** `gangmu rules import --recursive`
  对 `.gitmodules` 会沿着子模块里的子模块导入；对 west 清单（`--manifest west`）会跟随项目和 `manifest: self:` 里的
  `import:`（`true`、文件/目录路径、带 `name/path-allowlist`、`name/path-blocklist`、`path-prefix` 的映射及其列表），
  深度上限 4 层，按项目名和 (url, 提交) 防环。`import-flags`、通过 west 扩展命令的导入不支持。
- **`gangmu vuln` 本身不联网。** 很多固件团队在内网开发，一份必须联网才能出的报告，
  在工厂内网里出不来，在漏洞披露后的 24 小时里也出不来。联网的一步单独做成
  `gangmu vuln-fetch`：在有网的机器上跑，把目录带进内网即可。
- **编译器包装器只能拦截按名字查找的编译器。** Makefile 里写死绝对路径（`CC=/opt/gcc/bin/gcc`）会绕过 PATH 上的 shim；
  Windows 下 shim 是由 pip 自带的 distlib 启动器生成的 `gcc.exe`（CI 已在 windows-latest 上验证：MinGW gcc 下 `cmd /c`、`mingw32-make` 的简单配方均可记录，MSVC `cl.exe` 的 `/c`、`/Fo` 也可记录，交叉编译器 `arm-none-eabi-gcc`（Chocolatey 的 gcc-arm-embedded）经 `cmd /c` 与 `mingw32-make` 均可记录，clang 同样可以）；找不到启动器时退回 `.cmd`，只有经 `cmd.exe` 启动编译器才可见。MSYS/Git `sh` 里的构建未验证。
  此时 `gangmu wrap` 会提示“nothing was recorded”，请改用 `--compiler` 指定构建实际使用的名字，或用 `--project`。
