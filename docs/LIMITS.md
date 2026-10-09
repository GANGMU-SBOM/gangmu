# 能力边界

坦白列出来，因为缺口就是路线图：

- **不做深度二进制分析。** 没有源码也没有构建，指纹比对和构建事实都无从下手；对 `.a`、`.lib`、`.so`、
  `.elf`、`.axf`、`.bin` 只做清单（路径、SHA-256、大小）、解开 HEX、S-record、UF2 和 gzip/xz/bzip2/zlib/zip 封装、读版本横幅和导出符号（ELF 会解析符号表并标注是否已剥离），作为较低置信度的补充证据。
  装了可选依赖 Capstone（`pip install 'gangmu-sbom[disasm]'`）后，还能从 ELF 和带 Cortex-M 向量表的 `.bin` 里恢复函数边界（`gangmu binary-functions`，支持 Thumb、ARM、AArch64、RISC-V、x86；Xtensa（ESP32 经典款、ESP8266）因为 Capstone 没有解码器，用自带的最小实现 `xtensa.py` 处理：只认 `entry` 指令找函数起点、只还原 `l32r` 取到的字面量，不是完整反汇编，且只在一个 xtensa-esp32-elf-gcc 版本上验证过）。在此之上还有逐函数指纹（`gangmu rules binary-prints`，规则里的 `identity.binary_functions`；生成命令会先用作者提供的、同一版本的多个构建互相验证，没通过就不写文件，规则里必须带验证结果）：每个函数引用的字符串和用到的显著常量，从机器码里还原。自己交叉编译的基准（Cortex-M3、rv32imac、AArch64、Xtensa 四种架构，各 7 个库、20 个版本、4 个优化级别，不带 `assert()`，`gangmu binary-eval` 可复现）见 [docs/BINARY-VALIDATION.md](BINARY-VALIDATION.md)：参考库只含库自己的代码；用**同一种架构**编译时比全部特征，指纹文件里记录了架构，用别的架构的镜像去匹配时只比字符串（Cortex-M3 的参考库对其他三种架构的镜像：57 到 60 个答案、0 个错误，其余大多认不出；旧版本生成的指纹文件没有这条记录，仍按全部特征比，需要重新生成）；负对照每组 1920 对 0 次误报；给出答案的里错误率约 2% 到 6%（Cortex-M3 7/189，rv32imac 12/188，AArch64 4/199，Xtensa 3/192），多数答案是 `低~高` 区间；有指纹的函数太少的小库（inih、heatshrink、cJSON）认不出来。**真实固件上更差：** 用 Zephyr 3.7、4.0、4.1（Cortex-M7，Zephyr 自己的构建）测过，库的身份 6/6 认对，但版本只能给出很宽的区间（Mbed TLS 约 `2.16.12~3.6.2`，littlefs 约 `2.6.1~2.9.3`），不在指纹覆盖范围内的版本会被报成最接近的那个；固件配置和参考构建不同（配置宏、是否带 assert）会让匹配的函数明显变少。自测通过不代表真实固件上同样准，见 BINARY-VALIDATION.md 的“真实固件”各节。
  这是有意的取舍：对剥离过符号的 MCU 镜像，这种办法能恢复名字、偶尔恢复版本，却填不满 CRA 要求的字段。
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
