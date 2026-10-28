# 更新记录

这里记录各版本新增的能力和当时的评测结果，按版本倒序。当前能力总览见 [README](../README.md)，各家国产生态的覆盖见 [CHINA.md](CHINA.md)。

## 未发布
* **只拷了 `src/` 内容的副本，标记文件也能找到它。** 规则的标记文件写在 `src/` 下（`src/core/init.c`）时，扫描现在也按去掉 `src/` 的路径找候选目录，所以改了名的扁平副本（`net/stack/core/init.c`）也会被检查。有了这一条，`generic/lwip` 带上自己的标记文件后，`generic/lwip-flat` 就多余了：在 lwIP 2.0.3、2.1.3、2.2.0 的扁平副本（目录名为 `lwip` 或任意名字）和完整上游树上，去掉 `lwip-flat` 后的结果与原来逐项相同（规则库同步删除该规则）。
* **只带了一部分的副本，不再让被捆绑的库失去自己的代码。** 分割原来只认"整份捆绑"：B 某个版本至少 80% 在 A 里。freetype、libgit2 只带 zlib 的 inflate，arm-trusted-firmware 只带 zlib 的一部分，zlib-ng 与 zlib 共有 16 个函数；这些项目不算捆绑 zlib，于是只要一个函数也在它们手里，就对谁都不算自有代码，zlib 最新版本 222 个函数只剩 86 个。现在，如果某个项目整份捆绑了 B（tcl、sudo、clamav 带着完整的 zlib），而另一个持有者与 B 共有的部分只占它自己的一小部分（不超过 10%），这个持有者也算借用。只有部分副本、没有任何整份副本时仍不算数，因为那可能是两个项目各自带着的第三个库。在免费规则库上，22 个库拿回了自有代码、没有一个减少：zlib 86→215/222、bzip2 71→141/141、xxHash 148→204/204、lmdb 227→286/286、expat 104→132/132、Lua 1049→1177/1178、PCRE2 349→442/581、LevelDB 38→98/99、mdns 17→60/60、CMSIS-5 Core 84→137/455。用 16 个上游项目的源码树对比扫描结果，只有三处变化，都是真实副本：LÖVE 里的 xxHash 现在能认出（0.82），OP-TEE 的 `core/lib/zlib` 现在能认出（zlib 1.2.12，0.77），OpenColorIO 里的 xxHash 从 0.80 升到 0.88。CI 的性能检查通过。

## 0.13.9
* **只拷了 `src/` 内容的副本也能认出。** 很多规则的 include 都在一个目录下（`src/**/*.c`），而厂商常常只把这个目录里的东西拷进来：aws-c-common 的 `source/external/libcbor` 就是 libcbor 的 `src/`。规则的 glob 在这样的目录里一个文件也选不到，于是函数层、锚点都看不到它：这份 libcbor 副本原来完全认不出（连宽松文件匹配也不行，因为它同样按 glob 选文件）。现在，当规则的 include 都在同一个目录 P 下、这里没有 P、按原 glob 选不到任何函数时，函数层改用去掉 P/ 的 glob，锚点也按去掉 P/ 的路径找；证据里写明"a flattened copy"。这份 libcbor 现在认成 0.13.0（0.95，锚点和 254/254 个函数）。免费规则库里有 33 条规则的 include 都在一个目录下（14 条在 `src/`）。原样的上游目录结构结果不变；CI 的性能检查通过。
* **`gangmu rules bundled`：哪些规则带着别的规则的库。** 只读签名，列出每一对"A 的签名里有 B 某个版本的几乎全部函数"，并标明分割的结果：`kept`（副本只占 A 的一小部分，代码仍算 B 的）、`lineage`（双方互相包含，是分叉或拆分出来的库，谁都不算是对的）、`lost`（副本占 A 太大，B 因此失去自己的代码）。`lost` 要在宿主规则里修：`--rule A --tree 上游目录` 用除 A 之外的规则扫描 A 的上游目录，列出副本所在的目录，给出相对于规则根目录的 `identity.exclude`，再用相同的 `--exclude` 重建签名。在免费规则库上它列出 17 个 `lost`（dropbear 里的 libtomcrypt、picotool 里的 littlefs、aws-c-common 里的 libcbor、valkey 里的 jemalloc、swupdate 里的 mongoose、TinyUF2 里的 CMSIS 等）和 2 对 `lineage`（Mbed TLS 与 Mbed Crypto、OpenSSL 与 Tongsuo）。
* **被很多项目自带的库，保留自己的代码。** 以前的分割规则是：一个函数只要出现在一条以上规则里，就对谁都不算自有代码。于是一个被别的项目拷贝过的库会失去自己的身份：免费规则库里有 60 条规则的最新版本只剩不到一半的函数算自有代码，18 条不到十分之一，zlib、CMSIS-5 Core、lmdb 一个都不剩，expat、bzip2、ArduinoJson、libyaml 不到 10%。这样的库只能靠锚点文件识别，被改过的副本就无法按代码认出：改名 10% 的 expat 副本只靠版本头文件认出（0.75），也没被标为修改。现在，如果签名显示一条规则捆绑了另一条（B 的某个版本至少 80% 在 A 里，该版本至少 40 个函数且不小于 B 最大版本的一半，而这部分不到 A 的 10%），共有的函数只算 A 借用，仍是 B 自己的。上面那个改名的 expat 副本现在按函数认出（0.88）并标为修改；34 个库现在能在自带它们的项目里被认出（CPython 里的 expat、OP-TEE 里的 qcbor、TinyUF2 里的 FatFs、PJSIP 里的 libsrtp 等）。分叉（OpenSSL 与 Tongsuo）、从另一个库拆出来的库（Mbed TLS 与 Mbed Crypto）以及很多规则共有的代码仍然谁都不算：原版的 Mbed TLS、GmSSL 树照旧识别。zlib 仍未恢复，因为 zlib-ng 与它共有核心代码，需要在同源规则之间做裁决。在完整的免费规则库上，每次扫描的分割多花约 2 秒；CI 的性能检查通过。
* **部分副本和衍生版两条路径不再计入借用的代码。** 它们原来计入签名里的全部函数，包括分割标为别的规则的那些，于是一个被捆绑库的原版副本，可能被当成自带它的项目的部分副本：删掉一半文件的 zlib 副本被报成 libgit2 1.9.5~1.9.7，原版 zlib 带着 tcl、sudo、VeraCrypt 三个备选。在整个免费规则库上，有 16 个原版库可能被这样认领，现在为 0。

## 0.13.8
* **改过名的副本，版本现在也从改过名的代码里推。** 厂商改了符号名时，原来已经用标识符抽象后的函数体来认组件，但版本仍从精确函数体推，而这种函数体剩下不多：版本区间变宽，甚至指向错误的版本。现在版本也从抽象函数体推（每个版本的抽象哈希原本就在签名里）。Mbed TLS 3.6.2 去掉版本头文件、改名 25% 后，函数证据从 3.6.0~3.6.7（一致度 0.13，投给 3.6.1）变成 3.6.1~3.6.3（一致度 0.88），与原版树相同；lwIP 2.1.3 的 12 个变异样本里，给出单一版本的从 6 个变成 12 个。在原版的 lwIP 和 Mbed TLS 上结果与之前相同。
* **原版副本不再被说成"改过名"。** 以前只要抽象函数体的覆盖率高于精确函数体，哪怕只高一点点，就改用抽象的结果。两个度量的分母不同（只差名字的函数体会合并成同一个抽象哈希），所以原版的部分副本可能高出 0.001，结果被写成"精确函数体没有匹配上，这里的符号被改过名"（在用 `lwip-flat` 规则扫描上游 lwIP 2.1.3 的 `src/` 时发现）。现在要高出至少 0.05 才改用。
* **`gangmu eval --mutate`：改名这一步不再改 C 关键字。** 原来会挑任何六个字母以上的小写单词，`return`、`struct`、`static`、`sizeof`、`switch`、`unsigned` 也被改名，这会让代码失效，也会改变抽象哈希（抽象哈希保留关键字）。这让基准低估了抗改名能力：lwIP 2.1.3 上"改名 50%"原来是 0.191、认不出，"厂商式"组合是 0.120、认不出且版本错；现在分别是 0.650 和 0.614，都认出、版本正确（都是 9/9）。BENCHMARK.md 里 GmSSL 2.5.4 和 3.2.0 的"厂商式"那两行（0.092、0.123，"认不出"）现在是 0.732、0.825，都认出。`eval` 现在也按引擎的方式推版本。BENCHMARK.md 和 README 里的数字已重测。

* **`vuln-fetch --sbom FILE --build-patches PATCHES.json`：为 SBOM 匹配到的公告批量生成补丁记录。** 抓取完成后，对 SBOM 匹配到的每条公告，如果它的 OSV 记录写明了修复（带 `fixed` 提交的 `GIT` 范围），就从修复提交生成一条记录（改动了哪些函数，修复前后各取哈希，和 `patch-build` 相同），存给 `vuln --patches` 用。记录以 CVE 编号为键，每生成一条就存盘，下次接着上次的进度做：文件里已有的记录，以及无法记录的公告（修复没改任何 C 函数、改动大到属于重构、仓库连不上；原因记在文件里）都不会再试。`--patch-limit N`（默认 25）限制单次运行的条数，`--patch-refresh` 重新生成；刷新失败时保留原有记录。只用数据库明确写出的修复，不用从引用链接里找到的提交网址。需要 `git` 并读取上游仓库，所以属于联网步骤；单次 `git` 调用超过 300 秒现在只算该公告失败，不会拖住整批。

## 0.13.7
* **`vuln --source`：补丁记录里修复改过的函数就是漏洞函数。** 以前可达性分析要靠 `--symbols`，或从公告文字里猜函数名。公告有补丁记录时（`--patches`，或已安装规则包的 `patches/`），改用修复改动或删除的函数（修复新增的函数没有漏洞版本，不算），结果的依据标为 `patch record`。优先级：`--symbols`、补丁记录、公告文字。记录里的函数在树里找不到时给 `unknown` 而不是 `absent`，因为可能是裁剪过的副本或厂商改了名；只有构建配置把它编译掉时才仍判 `absent`。
* **`gangmu vuln --source --link-map FILE --elf FILE`：漏洞函数不只在源码里，还要看它在不在镜像里。** 用 `-ffunction-sections --gc-sections` 构建时，GNU ld 的 map 会逐个列出 `.text.函数名` 段是被保留还是被丢弃（含来自哪个目标文件）；链接后的 ELF 符号表则列出镜像里有的函数。漏洞函数被链接器丢弃、且没有同名副本被保留（两个静态函数重名时按目标文件区分），无论调用图怎么说，都报 `discarded`，`--reachability-vex` 会把它写成 `not_affected` / `code_not_present`；在镜像里找到的函数保留源码结论并标 `image: linked`。符号表里没有只算提示（编译器可能内联了它）。看不到的：内联进被保留代码里的副本，以及没开函数分段的构建（map 里没有信息，得 `unknown`）。目前只读 GNU ld 的 map。VEX 带 `gangmu:reachabilityImage` 属性。
* **`gangmu cbom` 跟随构建配置，并忽略注释。** 注释里的名字（`//#define MBEDTLS_DES_C`、`/* uses RC4 */`）、`#undef` 之后的名字、Kconfig 的 `# CONFIG_X is not set` 行和 `CONFIG_X=n`，不再被算作构建里的算法；字符串字面量（`"AES-128-GCM"`）仍然算。新增 `--config`、`--define/-D`、`--assume-undefined-off`（与 `vuln --source` 相同；树里的 `sdkconfig` / `sdkconfig.h` 不用指定就会找到），配置排除的 `#if` 分支不读；配合 `--compile-db` 时每个文件按自己的 `-D`/`-U` 判断。行号不变，没读的行数写在备注里。认不出的宏照旧保留分支。
* **`gangmu cbom --link-map FILE --elf FILE`：CBOM 也用函数级链接证据。** 算法名只出现在被链接器丢弃的函数里（`-ffunction-sections` 构建的 GNU ld map）时，标为 `not-linked`，不进计数资产和依赖列表，和文件级构建事实一致；出现在镜像里有的函数中则为 `linked`。只有 map 里明确的丢弃才算数：ELF 符号表里找不到不够，因为编译器可能内联了它。表、宏等不在任何函数里的名字和头文件里的名字不受影响。只给 `--link-map` 不给 `--compile-db` 时，它现在只用于这项判断，不再生成把每个文件都标成未链接的空构建事实。

## 0.13.6
* **CBOM 内置算法表认得硬件安全芯片、厂商 HAL、TPM、SSH 协商名和 Linux 内核的密码接口。** Microchip cryptoauthlib（`atcab_sign`、`atcab_ecdh`、`atcab_sha`、`atcab_aes_cbc_*`、`atcab_hmac`）、Infineon OPTIGA Trust M（`optiga_crypt_ecdsa_*`、`optiga_crypt_rsa_*`、`optiga_crypt_hmac*`、`optiga_crypt_hkdf*`）、STM32 HAL（`HAL_HMAC*`、`CRYP_DES_*`/`CRYP_TDES_*`）、Zephyr 加密接口（`CRYPTO_CIPHER_ALGO_AES`、`CRYPTO_HASH_ALGO_SHA*`）、ESP-IDF 硬件驱动（`esp_ecdsa_*`、`esp_hmac_*`、`esp_ds_*`、`esp_sha256_*`、`esp_sha512_*`）、TPM 2.0 的算法标识（`TPM_ALG_RSA`、`TPM2_ALG_ECDSA`、`TPM_ALG_SHA256` 等，含 ML-KEM/ML-DSA）、SSH 协商字符串（`ssh-rsa`、`ecdsa-sha2-nistp256`、`ssh-ed25519`、`curve25519-sha256`、`diffie-hellman-group14-sha256`、`aes128-ctr`、`hmac-sha2-256`、`chacha20-poly1305@openssh.com`，剥掉符号的二进制里仍能读到）和 Linux 内核（`aes_expandkey`、`arc4_setkey`、`sha256_update`、`hmac_sha256_key`）。对 cryptoauthlib、OPTIGA、STM32 HAL、Zephyr、ESP-IDF、wolfTPM、libtpms、tpm2-tss、dropbear、libssh2 和 Linux 的 `crypto/` 做了新旧对比，新命中的都是真实的接口名、常量或协商字符串。规则库 gangmu-cbom-rules 的种子文件同步重新导出。
* **`vuln-fetch --all`：存盘批量可调、停止时有提示（#131）。**
  * 新增 `--save-batch N`（默认 2000）：攒够 N 条才重写一次年份分片。每次存盘要重写它涉及的每个分片，而 NVD 返回的记录散落在所有年份里，所以全量库上一次存盘就是把整个库读出、解析、再压缩一遍，耗时只取决于库有多大，和这一批多少条无关；批量越大，存盘次数越少。每条记录在内存里约占 15 KB（在真实 NVD 页面上量的：500 条 7.7 MB），2 万条约 300 MB。默认值没变。
  * Ctrl+C 或出错退出时，如果还有没存的记录，不加 `-v` 也会提示“正在保存已取到的 N 条记录，大库上可能要几分钟，请不要强制结束”；保存完后提示重跑同一条命令即可继续，并以退出码 130 结束，不再打印 Python 的 traceback。`-v` 时，每次存盘的日志行带上耗时。

## 0.13.5
* **CBOM 内置算法表认得更多库的函数名和 TLS 密码套件名。** 原来 AES、SHA、HMAC、RSA 等只认 Mbed TLS、wolfSSL、OpenSSL 的写法，现在补上 BearSSL（`br_aes_*`、`br_sha256_*`、`br_rsa_*`、`br_ecdsa_*`、`br_hmac_drbg_*`）、TinyCrypt（`tc_aes128_*`、`tc_sha256_*`、`tc_hmac_*`、`tc_ctr_prng_*`）、LibTomCrypt（`rijndael_*`、`rsa_make_key`、`ecc_sign_hash`、`sha256_init`）、libsodium（`crypto_hash_sha256`、`crypto_auth_hmacsha256`、`crypto_kdf_hkdf_*`）、Monocypher（`crypto_x25519`、`crypto_ed25519_*`、`crypto_chacha20_*`、`crypto_sha512`）和 OpenSSL 的 `EVP_aes_*_cbc`、`EVP_sha256` 等。liboqs 里小写的 `OQS_SIG_alg_slh_dsa_*`、`OQS_SIG_STFL_alg_xmss_*`、`OQS_LMS_ID_*` 也算进 SLH-DSA 和 LMS/XMSS。TLS 密码套件名（`TLS_ECDHE_RSA_WITH_…`，含 mbedTLS 的 `MBEDTLS_TLS_…`、BearSSL 的 `BR_TLS_…` 和 OpenSSL 风格的 `ECDHE-RSA-…`）按它带的密钥交换和认证算法计入 RSA、ECDSA、ECDH、DH，含 RC4、3DES 的套件计入对应的弱算法。对 BearSSL、Mbed TLS、OpenSSL、wolfSSL 和 hostap 的源码做了新旧对比，新命中的都是真实的接口名或套件名。规则库 gangmu-cbom-rules 的种子文件同步重新导出。

## 0.13.4
* **NVD 年份分片改用 xz 级别 3 写盘（原来是默认的 6）。** 压缩一个大分片从 10.5 s 降到 1.0 s，文件大约大三分之一（5000 条记录的模拟下载：每页都写盘、级别 6 要 45.8 s，攒批后 7.9 s，再加上级别 3 是 2.1 s；分片总大小 0.29 MB → 0.38 MB）。读取不受影响，已有的分片照常可读，下次重写时才换成新级别。
* **`vuln-fetch --all` 的全量下载：进度、批量写盘、重试选项（#124、#125、#119）。**
  * 每页取完打印位置和总数：`200 record(s) fetched, next index 105200, total 413013`；写盘时再打一行 `2000 record(s) saved, next index 105200`。
  * 以前每取一页（小页时 200 条）就把涉及的每个年份分片整片重写，压缩一个大分片要十几秒：往一个 1.4 万条记录的分片里合并 200 条要 12 s，合并 2000 条也是 12.5 s，与批量大小几乎无关。现在攒够 2000 条再合并写盘（5000 条、每页 200 条的模拟下载：44.9 s → 7.9 s）。续传用的位置只在写盘成功之后才前进，出错或 Ctrl+C 之前先把已取到的存下来，所以不会丢，也不会跳过。
  * 新增 `--page-size N`（1 到 2000）和 `--retries N`（默认 5；0 表示一直重试到成功，用 Ctrl+C 结束）；`-v` 时每次重试都打印原因和等待时间。网络类错误的退避上限从 60 s 降到 16 s（限流仍按服务器给的时间或最多 60 s）。
* **预编译库和固件镜像的清点快了约 5 倍（ESP-IDF v5.4.2 的 183 个文件，17.7 s → 3.6 s），输出逐项不变。** 一个 32 KB 的分区表镜像被当成 Cortex-M 固件，在 64 个偏移上各做一次基址搜索，单这一个文件就要 8.8 s：基址评分改为一次统计所有候选，同一张镜像的布局结果也不再重复计算。版本横幅的正则先用字节查找排除不含对应字面量的文件，API 符号集合改为一次切分后查表。整树扫描：单进程冷扫 60.5 s → 50.1 s，热缓存 31.6 s → 17.5 s（峰值内存多约 17 到 28 MB）。数据见 PERFORMANCE.md，那一页同时改为当前版本的测量（原来还是 0.5/0.6 的数字）。

## 0.13.3
* **修复：`vuln-fetch` 下载到一半遇到 `IncompleteRead` 直接崩溃（#118）。** 响应体被中途截断时抛出的是 `http.client.IncompleteRead`，它不是 `OSError`，`http_json` 没有捕获，于是不重试、直接带着 traceback 退出；截断的内容解析 JSON 失败（`ValueError`）也一样。现在这两种情况都按网络错误重试，重试用完后给出一条清楚的错误信息。
* **`vuln-fetch` 的单页大小在传输失败时自动减半（#119）。** NVD 一页 2000 条有几兆字节，国内的网络上常常传到一大半被截断，重试同样大小的页也一直失败。现在一页重试用完仍然是传输失败（截断、读超时、连接被重置、响应不是 JSON）时，页大小减半重新请求，最小 100 条，并记进 `.gangmu-fetch.state` 的 `nvd_page`，下次运行直接用这个大小，不用再失败一遍。网络好的时候仍是 2000 条一页。

## 0.13.2
* **`vuln-fetch --all` 的全量下载中断后可以接着下。** 以前全量下载要跑完才写 `.gangmu-fetch.state`，中途断了（网络、被限流）再跑一遍就从第 0 条重新下，已经落盘的分片也白费。现在每下完一页就记下位置和开始时间，再次运行同一条命令会从上次的位置（退回一页，防止 NVD 期间新增的记录让分页错位）继续；全量下完后，增量水位线取的是**开始时间**，下载期间改动过的记录由下一次增量补上。报错信息里也会提示重新运行同一条命令。

## 0.13.1
* **Mbed TLS 的 x86-64 指纹补上 TLS 和 X.509 层**（`libs.yaml` 的 `mbedtls-full`；规则在 gangmu-rules 2026.10.20）。原来只含加密库的 225 个函数，现在 1586 个，自检 22 个跨构建镜像全部 exact；Ubuntu 的 `libmbedtls.so` 由认不出变成 exact 2.28.8，mingw 编的整个 2.28.8 由 `2.28.0~2.28.8` 变成 exact。`libmbedx509.so` 仍认不出（只占参考的一小部分，低于覆盖率下限）。数据见 BINARY-VALIDATION。
* **修复：x86-64 共享库（`.so`）里的立即数被当成地址丢掉。** 共享库链接在地址 0，小于映像大小的数都落在映像里，`fprint` 把它们当指针，函数里的状态号、魔数这类常量就提不出来（zlib 的 `inflate` 在 Ubuntu 的构建里 36 个常量只留 2 个，参考有 37 个）。位置无关的映像里立即数现在算数字。**效果**（同一批 x86-64 指纹，Ubuntu 24.04 的库）：`libz.so.1.3` 由认不出变成 `1.2.11~1.3.2`（88%，真值 1.3）；PCRE2 的区间由 `10.35~10.44` 收窄到 `10.42~10.43`（真值 10.42）；覆盖率 Brotli 17%→42%、bzip2 79%→100%、libpng 76%→85%、zstd 24%→37%、expat 39%→45%。只改 x86-64，固定地址的映像不变。
* **新增：`build_corpus.py --target x86-64`**（原生 GCC，只含库自己的代码）。免费库里的 zlib、littlefs、Mbed TLS，以及 Lua、zstd、bzip2、libdeflate、expat、libpng、Brotli、yyjson、PCRE2 因此有了 x86-64 的函数指纹（gangmu-rules 2026.10.19，后九个在 2026.10.20），x86-64 的 ELF 库和 Windows 的 PE 能做函数级识别：Ubuntu 的 `libmbedcrypto.so.2.28.8`（抹掉横幅）报 `2.28.0~3.3.0`，mingw 编的 2.28.8 DLL 报 `2.28.0~2.28.8`。zlib 在 x86-64 上函数特征少，Ubuntu 的 libz 认不出。数据见 BINARY-VALIDATION。

## 0.13.0
* **新增：认出平铺在自研目录里的组件。** 厂商常把库的几个文件直接丢进自己的目录（`app/lwprintf.c` 挨着 `app/main.c`），按目录识别认不出来：这种目录不是候选，而且里面大部分函数不属于这个库。现在扫描会对还没解释的源文件逐个比函数，某个文件的函数至少 80% 在某条规则的签名里，就归给这条规则；同一目录里归给同一条规则的文件，用目录的同一套判据定身份和版本。文件名对得上组件名时，部分拷贝的门槛从 40 个函数降到 8 个，对不上时仍是 40 个；同一批文件只归一条规则，文件名对得上的优先。已认出的目录里，不属于该组件的文件会放出来再查；如果组件在一个平铺目录里只占不到一半的函数，这条结论就收窄到它自己的文件。只是弱相似（possible）的目录，让位给在其中找到的组件文件；组件在其所在目录的兄弟目录里还有文件时（lwmem 的 `src/system` 挨着 `src/lwmem`），算同一份拷贝，记在原结论的证据里，不重复报。结论多了 `files` 字段，CycloneDX 写进 `evidence.occurrences`，许可证只从这些文件读。`--no-loose` 关闭。**验证：** GangmuAI 的 120 个生成工程、9 条生成规则：拷贝认出 73/73（之前 57/73），其中平铺 14/14（之前 0/14），qpc 6/6（之前 5/6），版本 67 个精确、6 个区间、0 个错，已有规则的结论 0 个被挤掉。这一轮发现的 17 处重复（同一库的 `src/system` 移植文件被当成第二份）已按上述「兄弟目录」规则修掉，在受影响的工程上复查过；修复后的全量重跑还没做。
* **新增：报告没有规则认得的外来代码。** 把 GangmuAI 的发现模块移植进 `gangmu scan`。判据包括自带许可证文件、清单、子模块、版权人、函数前缀、版本宏、是否引用工程头文件，在已认出的组件之外找目录和平铺的文件组，各给名字和版本提示。结果进 JSON 的 `unknown`、表格的 UNKNOWN 段和 CycloneDX 元数据属性 `gangmu:unknownThirdParty`，不进 SBOM。已认出的文件只读前 4 KB 来取版权人，所以 139 MB 的 LVGL 工程上多花约 1.7 秒（8%）。原模块在 GangmuAI 留出组件评测上找到 167 个拷贝中的 160 个（只看许可证、清单、子模块是 97 个），误报 1 个。`--no-unknown` 关闭。
* **新增：从一份上游项目清单生成通用规则草稿。** `gangmu rules import 清单.json --manifest candidates --out rules/generic`。清单（JSON）只提供仓库地址（可选子目录、许可、备注），例如由公开 registry 索引找出的、被许多包转发的库。gangmu 自己列出该仓库的发行 tag（去掉预发布），用最新发行版生成指纹，用最近 `--limit` 个发行版（默认 12）生成 `.fnsig`，`upstream.source.ref` 钉在最新 tag 上，所以 `gangmu rules verify` 能逐位复现。规则描述的是整个仓库（含移植层、示例应用），厂商很少整份拷贝，所以标 `functions.subset`；清单里标了 `bundles` 的条目（大量代码也出现在其他无关包里）不标，免得认领那些包的拷贝。不猜 CPE：`cpe_status` 写 `unverified`，`review.todo` 要求合并前查。**验证：** 用 GangmuAI 的 registry 索引导出的 9 个库（lwrb、lwjson、lwmem、lwprintf、lwshell、tinyexpr、nanoprintf、agile_modbus、qpc）生成规则，扫描 120 个生成的固件工程：独立目录里的拷贝认出 57/59，版本 52 个精确、5 个区间、0 个错；平铺在自研目录里的 0/14（按目录识别的老限制）；新规则 0 误报，已有规则的结论 0 个被挤掉。另用排名前 40 的候选生成规则：40 条全过 `rules lint`，抽 5 条 `rules verify` 全部逐位复现，同样 120 个工程上 0 误报；一份 LVGL 9.2.0 拷贝上，捆绑了 LVGL 的 inkplate-lvgl-library 规则在标 `bundles` 之前会认领 LVGL 自带的 lodepng、lz4、qrcode 目录，之后不再认领。**局限：** 生成的规则都没有 CPE，必须人工补；版本标签照抄上游 tag，tag 命名怪异的项目（`05`、`131.2.0`）需要人看。
* `rules import` 的 `--vendor`、`--sdk` 改为只在 gitmodules 和 west 时必填。
* **新增：`gangmu scan` 对 `.exe`、`.dll` 也做函数级比对**，条件与 ELF 库相同：某条规则带有这种 CPU 的参考指纹才做，否则不花这份时间；.NET 程序集（没有原生代码）不做。目前免费库里的指纹只有 Thumb 和 RISC-V，所以实际上还没有 PE 能被函数级识别，要等规则带上 x86/x64 的指纹。
* **文档：** README.en 的快速上手补上 `vuln-coverage`、`binary-functions`；中文命令表补上 `vuln-coverage`。
* **修复：AArch64 的常量不再被拆成两半。** GCC 常把无关指令排在 `mov` 和 `movk` 之间（`mov x2, #0x3800; mov w3, #0xf; movk x2, #0x4002, lsl #16`），半成品常量在遇到第一条无关指令时就被当作两个孤立的半字（0x3800 和 0x4002）记下，而不是 0x40023800。现在寄存器里的值一直保留到该寄存器被 `movk` 以外的指令读写或控制流离开为止（#101）。
* **新增：`gangmu vuln --format json` 带出国内漏洞库的结果。** 此前只有文本输出有：与匹配同一 CVE 的 CNNVD/CNVD 条目（中文标题和国内等级）、没有 CVE 号但产品文字点名了组件的候选（不是匹配，不给状态，由人判断）、国内与国际等级不一致的条目，现在放在 JSON 的 `cn` 字段里（#103）。

## 0.12.0
* **新增：规则可以自带版本横幅。** `identity.binary_banners` 是一组正则（第一个捕获组为版本），用来在编译后的镜像里读库自己打印的文字，不用等引擎内置。加载规则时就检查：不超过 160 个字符、有且至少一个捕获组、至少 4 个字面字符、不允许无界通配符（`.*`、`\S+`、`[^x]+`）和嵌套重复，因为这个正则会跑过树里每个二进制的每个字节。引擎内置的横幅优先。需要 gangmu 0.12.0。
* **新增：共享库的文件名里带发行版时，据此给出版本。** `libz.so.1.3.1`、`liblzma.so.5.4.5`、`libzstd`、`liblz4`、`libxml2` 的文件名数字就是发行版，且必须与库自己的 SONAME 一致、必须是库而不是程序、必须没有横幅给出版本才采用；置信度低于横幅（版本 0.55）。libtool 编号的库（`libexpat.so.1.8.10` 不是 expat 2.4.x）不在其中。
* **新增：记录 GNU build-id。** 二进制清单（JSON 的 `build_id`）里多了这个字段，它指明这一个具体构建，可以拿去查调试信息服务器或厂商记录；它本身不说明发行版。
* **改进：CI 现在安装 `arm-none-eabi-gcc`（Python 3.13 一行）。** 真实编译 Cortex-M 代码的 `tests/test_thumb_firmware.py` 之前在 CI 里因没有编译器被跳过，一次合并因此改坏了它而没被发现，现已修好并由 CI 守住。
* **验证：clang 编译的固件，库仍能被 gcc 编译的参考指纹识别，版本区间更宽。** 见 BINARY-VALIDATION：zlib、Mbed TLS 12 个 clang 构建全部识别出库；littlefs 0/6 识别不出。
* **新增：解开 U-Boot legacy uImage。** 头部（魔数、长度、类型、压缩方式）自洽才认；负载为不压缩、gzip、bzip2 或 LZMA（LZMA 没有魔数，之前扫描找不到）时解开再读横幅，可以出现在镜像中的任意偏移。LZO、LZ4、zstd 仍没有解码器，这类镜像按高熵 `.bin` 提示。
* **提速：函数指纹提取约快 1.5–2 倍，结果逐位相同。** 边界扫描改用 Capstone 的轻量解码（只读地址、长度、助记符和操作数文本），x86 上文本里没有数字和 RIP 的指令不再做操作数解码。6 个 Ubuntu 库和 1 个 Thumb 固件的特征集与改前完全一致。
* **修复：Thumb 函数起点不再被 `.rodata` 里的数据冒充。** 重复出现的、碰巧像地址的数据字（zlib 的固定哈夫曼表）曾被「被引用两次」的规则当成函数指针，把 `adler32_z` 切成 26 个假函数。现在只有在代码自己的字面量池里重复出现的指针才算「被引用两次」。clang 编译的 Cortex-M3 zlib 上，函数边界精确率由 0.60–0.65 升到约 0.98，召回不变（0.98）。
* **改进：Linux 用户态二进制也进清单。** 带版本号的共享库（`libz.so.1.3`）和没有扩展名的 ELF 程序（按魔数和 `e_type` 判断，核心转储与 `.o` 排除）现在会被检查；新增 expat、Lua、libjpeg-turbo、busybox 横幅，zlib 横幅同时认 `deflate`/`inflate` 版权串。Ubuntu 24.04 的 13 个库从 0 个识别提高到 4 个。
* **新增：读 `.note.package`（FDO 打包元数据）。** 发行版把包名、版本、架构写进 ELF 时，直接生成带发行版的 `pkg:deb`/`rpm`/`apk` purl，说明版本带发行版的回移补丁，不拼上游 CPE。
* **改进：ELF 的 ARM/Thumb 模式按构建属性判断**（`.ARM.attributes`），无入口点的 Cortex-M ELF 不再被当成 ARM 解码。
* **改进：原始镜像的向量表可以不在偏移 0。** 识别 MCUboot 头、对齐的包装偏移，只有应用没有引导区时用字符串指针打分推断基址；新增 `gangmu binary-functions --offset`。证据不足时仍然报 unknown。
* **新增：高熵 `.bin` 镜像的提示。** 读不出内容的镜像（加密或压缩方式未知）会在扫描输出里说明，而不是静默当成空。
* **改进：库的函数级比对只在规则带有该 CPU 指纹时才做**，避免对无关库白白反汇编。
## 0.11.0
* **扫描提速，结果不变。** 规则预筛先用各文件保存的最小指纹做一次廉价的不相交判断，只在可能相交时才算精确的目录草图；函数签名文件整表解码；规则库切分时的重复和有序检查改在 C 层完成。仓库自带的合成 SDK 基准上，冷扫描约快 22%、热扫描约快 19%（规则 16 倍时约 8%），识别结果和各项计数完全相同。
* **修复：只给出主次版本号的版本头不再覆盖锚点给出的发布版。** littlefs 的 `lfs.h` 只定义 `LFS_VERSION 0x00020009`（2.9），文件与 2.9.1 锚点一致的 2.9.1 源码树被报成规则没有记录的「2.9」，评测判错（littlefs 2.9.1、2.11.3）。现在探针值是锚点发布版的前缀（`2.9.1` 的 `2.9`）时保留锚点的答案；探针指向另一个未记录的发布版时仍然以探针为准（#72）。
* **改进：二进制版本答案落在指纹所含的最新发布版时，加提示「镜像可能是更新、指纹没有覆盖的版本」。** 指纹里没有的更新版本会被归到最近的区间，区间不含真值（RISC-V 的 mbedtls 3.6.5 镜像报 `3.6.0~3.6.2`，littlefs 2.10.2 和 2.11.0 报 `2.0.4~2.9.3`）。引擎无法判断是否有更新版，所以只提示、不改答案；对应源码侧的「可能更新」提示（#70）。
* **改进：镜像和指纹不是同一种 CPU 时，只报库，版本给规则覆盖的整个区间。** 以前跨架构只比较字符串并给出单一版本；用 Cortex-M 的 Mbed TLS 指纹扫 RISC-V 镜像时，2.28.2 被报成 3.1.0（可信度 0.60），是错的。现在这种情况下版本写成该规则的「最早~最晚」，证据里说明没有收窄和为什么；规则只有一个版本、或有同架构指纹时不受影响。代价是跨架构的结果更宽，要收窄需要该架构自己的指纹。
* **改进：ARM64 的 Windows PE（Windows on ARM）按 `.pdata` 取函数边界。** 以前只靠扫描；现在读 ARM64 的异常表（压缩格式的长度，或 `.xdata` 记录里的长度），和 x64 一样给出精确起止，扫描补齐表里没有的。真实样本 `zstandard` 0.25.0 的 `win_arm64` wheel：表里 803 个函数，只用扫描只找到其中 345 个；识别结果仍是 zstd v1.5.7（对 Linux aarch64 参考，改前改后相同，命中 35/126 对 36/126），所以提高的是边界，不是识别率。只有这一个样本。
* **新增：函数指纹也认 Mach-O（macOS / iOS 的可执行文件和 dylib）。** 以前遇到 Mach-O 只有字节扫描。现在读节、入口、符号表和 `LC_FUNCTION_STARTS`（链接器写入的函数起点列表，剥了符号也在，边界精确），支持 x86、x86-64、ARM64，fat 通用文件默认取 arm64 再 x86_64；32 位 ARM 和大端明确报「不支持」。模块：`macho.py`。**验证（见 docs/BINARY-VALIDATION.md「Mach-O」）：** 用 PyPI 上 `zstandard` 的 macOS wheel（里面静态链接 zstd，版本由二进制里的版本字符串确认）对 gcc 编译的 zstd 参考，8 个组合里 8 个区间含真实版本，6 个最佳答案精确，其余 2 个差 2 到 3 个版本。**范围：** 只有 zstd 一个库；覆盖率 0.16 到 0.29；含 xxHash 的程序仍会和 lz4 的指纹互相命中（用 `--negative`）；Swift/Objective-C、dyld 缓存没测。
* **新增：一条规则可以带多个架构的二进制函数指纹。** `identity.binary_functions` 以前只能写一份 `.fnprint`，而指纹是为某个 CPU 编出来的（编译器在不同 CPU 上会推导出不同的常量），其他架构只能靠字符串比较，所以一个库在 Thumb 上编的指纹认不出 AArch64 的镜像。现在可以写成列表，每个架构一份；扫描时先用与镜像 CPU 相同架构的那份，认不出再试其余的，同一个库只报一次；`gangmu rules lint` 拒绝同一个架构写两份。单个映射的写法不变。**验证：** 用 zlib 7 个版本（1.2.8 到 1.3.2）分别为 Thumb（gcc 13.2.1，Cortex-M3）和 AArch64 编出的指纹组成一条规则，把镜像里的版本字符串抹掉后扫描：Thumb 镜像给出 `1.2.11~1.3.2`，AArch64 镜像给出 `1.2.11~1.3.1`（真值 1.2.13，都在区间内）；只有 Thumb 一份时 AArch64 镜像认不出；RISC-V 镜像两种情况下都认不出（没有该架构的指纹）。**局限：** 只测了 zlib 一个库、两个架构；这个 AArch64 指纹只用 2 个负对照镜像过的自测，所以没有放进 gangmu-rules。
* **改进：MIPS 的真实固件测试，修了两个读不出的问题。** 用 OpenWrt 官方大端 mips_24kc 包测：libmbedcrypto 2.28.10（gcc 编译的位置无关共享库）用 clang 编译的 mbedtls 参考识别为 `v2.28.0~v2.28.8`（96 个指纹函数命中 61 个），没有错报，真实版本在参考之外、最近的参考在区间内。修了：(1) 节表被剥掉的 ELF（OpenWrt 的做法）以前读不出函数，现在由程序头的 `PT_LOAD` 段合成节，并读 `DT_PLTGOT` 得到 MIPS 的 `$gp`；(2) 链接在地址 0 的共享库，以前地址为 0 的可加载节被当成未放置而丢掉。(3) MIPS16e/microMIPS 的 ELF（OpenWrt 的 liblz4、zlib、libbz2、libpcre2 都是）以前按 MIPS32 解码成噪声，现在明确报「不支持」。**范围：** 只有一个库一个版本；其余 OpenWrt 库是 MIPS16e，没法测。
* **新增：函数指纹支持 MIPS32 的 ELF（小端和大端）。** 路由器、摄像头、网关固件常用 MIPS（Realtek、MediaTek、Atheros、Broadcom 等），以前 `.elf` 的机器类型是 MIPS 时直接报「没有解码器」。现在能恢复函数边界（`jal` 调用目标、`addiu $sp,$sp,-N` 序言、`jr $ra` 返回，分支延迟槽里的指令仍属于原函数），并还原 `lui`+`addiu`/`ori` 拼出的常量和字符串地址；位置无关代码（`-fPIC`，用户态程序常见）按 `$gp` = `_gp_disp + $t9` 的写法取 GOT 项里的地址，`_gp_disp` 本身不当作常量（它随布局变化）。验证见 docs/BINARY-VALIDATION.md「MIPS32」一节：用 clang+lld 交叉编译 lz4、littlefs、heatshrink，各 4 个优化级别，小端和大端各一组；错答案 1 到 2 个（都是识别 `-O0` 镜像时），负对照 0 误报。**范围很窄：** 没有真实 MIPS 固件的测试；库只有 3 个、heatshrink 太小认不出；MIPS64 和 microMIPS 不支持；用 clang 而不是固件常用的 gcc 编译。`benchmarks/binary/build_corpus.py` 新增 `--target mipsel` 和 `--target mips`。
* **新增：生成函数指纹时，自动剔除和其他程序共享的函数（`gangmu rules binary-prints --negative`）。** lz4 和 zstd 都自带 xxHash，所以用 lz4 的指纹去扫 zstd.exe（或反过来）会命中 7 到 11 个函数、覆盖率 0.15 到 0.33，把一个只带 xxHash 的程序报成这个库。现在 `--negative` 给出的镜像（ELF 或 PE）里已经含有的参考函数，会从指纹和自测里去掉，数量记进 sidecar 的 `shared_dropped`；如果被剔除的超过参考函数的一半，说明这个负对照其实就是这个库本身，不剔除，照旧按误报判失败。**验证：** 用 lz4 和 zstd 各三个优化级别的 x86-64 参考，负对照是单独编译的 xxhash.c（`-Os`、`-O2`），不是被测的两个 exe：6 个组合里，对方 exe 上的命中全部消失（6 个原来都命中），自己 exe 上给出的版本答案不变（覆盖率下降 0.01 到 0.11，因为分母少了共享函数）。局限：只有 lz4/zstd/xxHash 这一对；负对照必须由规则作者提供，不给就没有这个效果；已经发布的指纹要重新生成才会生效。
* **新增：逐函数指纹现在也认 Windows 的 PE（`.exe`/`.dll`），包括 Windows CE。** 以前函数指纹只读 ELF 和带向量表的 Cortex-M `.bin`，PE 即使是 x86/x64 也只有导入表和版本资源。现在读出映像基址、入口、节属性和 x64 异常表：x64 用异常表（`.pdata`）里每个函数的精确起止，其余（叶子函数、x86）用扫描补全；支持 x86、x64、ARM、Thumb（含 Windows RT 的 ARMNT）、ARM64。Windows CE 靠子系统 9 识别，ARM 的 CE 映像按其 20 字节、绝对地址的异常表取函数边界；SH-3/SH-4、MIPS、PowerPC 的 CE 映像没有解码器，结果里明确写「不支持」，不猜。模块：`pe.py`、`disasm.recover_pe`、`fprint.memory_from_pe`。**验证范围很窄：** 真实二进制只测了官方发布的 `lz4.exe` 1.9.4 和 `zstd.exe` 1.5.5（x64，均为 MinGW 构建），参考库用 Linux gcc 的 ELF 编译；WinCE 和 x86 PE 只有合成的单元测试，没有真实样本。结果、以及 lz4 和 zstd 因共享 xxHash 代码而互相命中的现象，见 docs/BINARY-VALIDATION.md「Windows PE」一节。
* **改进：二进制版本评分改为按「矛盾证据」计，错误明显减少。** 以前用「该版本解释了多少匹配」的占比，且一条只有 2 个特征的指纹偶然命中会被当成一条完整的反证；现在每条匹配上而该版本不含的指纹记一次矛盾，权重按特征数（4 个及以上为 1，2 个为 1/3），相差不超过 2 的版本报成区间。在自己交叉编译的语料上（7 个库、20 个版本、4 个优化级别）错误数：Cortex-M3 7 → 1，AArch64 4 → 2，Cortex-M3 参考去识别 AArch64 镜像 7 → 0；负对照仍 0/1920。代价是 Cortex-M3 上唯一识别的少了 17 个（52 → 35），AArch64 上多了 13 个（34 → 47）；间隔 2 是对照三个语料选的（三者错误都不超过 2 的最小间隔），相邻取值的完整对照见 `docs/BINARY-VALIDATION.md`。没有用真实固件复测。旧评分仍可用 `gangmu binary-eval --tie-share 0.85`。
* **新增：可达性读取 `compile_commands.json`（`gangmu vuln --source DIR --compile-db FILE`）。** 数据库里没有列出的 `.c/.cpp` 文件没有被编译，只在其中定义的漏洞函数判为「不存在」；列出的文件按各自的 `-D`/`-U` 求值 `#if`（以前只有全局的 `--config`/`-D`）。数据库没有任何一条能对上 `--source` 下的文件时（例如在另一台机器上生成、路径布局不同）忽略并提示，而不是把整棵树当成没编译；同一棵树换了路径前缀仍按相对路径对上。没有 `-D` 的宏仍是「未知」，因为头文件可能定义它，保留分支。
* **新增：读取 Arduino 库的 `library.properties` 和 ESP-IDF 组件管理器的 `dependencies.lock`。** Arduino 库（名称、版本、URL、作者作供应商；PlatformIO 工程里的库仍由 PlatformIO 读取器负责，这里跳过）；`dependencies.lock` 里锁定的每个注册表组件及其精确版本，并读出 ESP-IDF 本身的发布版本（`idf`），`managed_components/` 下有源码的指向该目录，只锁定未下载的不带目录。注册表组件的版本是注册表包的版本，包的是上游库而不等于上游发布，所以不当作上游版本。不联网。模块：`declared_deps.py`。
* **改进：规则 YAML 在 PyYAML 带 libyaml 时走 C 解析器。** 从未建索引的规则目录（git checkout 的 `--rules`、开发者和 CI）每次加载都要解析全部 YAML，纯 Python 解析器占了加载时间的大头。PyPI 的 PyYAML wheel 自带 libyaml，`CSafeLoader` 与 `SafeLoader` 对同一份输入产出相同对象（测试对已安装的 98 条规则逐个比较）；没有 libyaml 时（如部分系统包）自动退回原解析器。在带 libyaml 的 PyYAML 6.0.3 上解析 98 个规则文件从 0.47 s 降到 0.047 s；本机的系统 PyYAML 没有 libyaml，所以这里量不到端到端扫描的变化，没有声称整体提速数字。已建索引的 wheel 安装不受影响。模块：`core/yamlfast.py`。
* **新增：函数级可达性现在看得到条件编译，被配置编译掉的函数判为「不存在」。** 以前 `#if 0`、`#ifdef CONFIG_X`、`#if !defined(MBEDTLS_X)` 的各个分支一律算进调用图，一个在当前配置下根本没编进固件的漏洞函数会被判成「已定义」甚至「可达」。现在 `gangmu vuln --source` 会按构建配置求值这些条件（三值逻辑：只有条件在已知的配置下确定为假才丢掉分支，任何未知的宏、`__has_include`、函数式宏调用都保留分支），只在一个函数只存在于被排除的分支里时报 `absent`（"源码里有，但构建配置把它编译掉了"），加 `--reachability-vex` 即写成 `not_affected / code_not_present`。配置来源：`--config`（Kconfig 的 `sdkconfig`/`.config`，或 C 头文件如 `mbedtls_config.h`、`sdkconfig.h`；不写则自动找 `sdkconfig`/`.config` 与 `sdkconfig.h`/`autoconf.h`）、`-D NAME[=值]`、`--assume-undefined-off`（没有任何配置提到的宏当作未定义，适合已用 `--config` 指定了产品配置头文件的库）。树里别处的 `#define` 不当作事实：一棵树常带多套备选配置（Mbed TLS 的 `configs/config-*.h`），只有被 `--config` 点名的头文件里的无条件 `#define` 才算数，其他地方定义或 `#undef` 的名字一律视为未知。在 Mbed TLS 3.6.2 的真实源码上核对：默认 `mbedtls_config.h` 下被编译掉的是可重启 ECP、LMS 签名、内存缓冲分配器、实验性的 `mbedtls_mpi_mod_*`，与默认配置一致；AES/GCM/RSA/SSL 握手等启用的函数都在。模块：`ifdef.py`。
* **新增：版本探针可以只给出主次版本来收窄函数给出的区间，并能读十六进制和可选后缀。** 联盛德 SDK 的 littlefs 头文件写 `LFS_VERSION 0x0002000a`（2.10），函数只能给出 `2.10.2~2.11.1`，现在探针读到 2.10，区间收窄为 2.10.2；函数已经给出更精确的版本时，探针不再把它覆盖成主次版本。探针模式名以 `hex_` 开头表示按十六进制读成十进制，以 `dash_` 开头表示非空时加 `-` 前缀（Zephyr 的 `EXTRAVERSION = rc2` 现在读成 `4.5.0-rc2`，此前丢了后缀）。规则侧另给 libcoap 加了 `ChangeLog` 探针（联盛德的 libcoap 源码里没有版本宏，现在是 4.3.4）。
* **修复：版本定义（如 `build_info.h`）写的发布版本若不在规则记录之内，则优先于锚点版本。** 锚点只证明文件与某个发布一致，下一个发布可能原样带着它们：Zephyr 的 Mbed TLS 头文件写 4.1.1，规则只记录 4.1.0，此前报为 4.1.0。规则已记录的版本不受影响（三个 Mbed TLS 标签没有升头文件版本，锚点仍然优先）。
* **修复：组件被识别在 `src` 目录、版本头文件在它旁边时，探针现在会到上一级找。** WinnerMicro SDK 的 LVGL 在 `lvgl/src`（其中的 `lvgl.h` 没有版本宏），真正的 `lvgl.h` 在上一级，此前只能报 `8.3.11~8.4.0`；FreeRTOS 的头文件在 `freertos/include`，报 `10.4.0~10.4.2`。现在分别是 8.4.0 和 10.4.1，与各自头文件一致。仅对名为 `src`、`source`、`lib`、`library` 的目录生效，且上一级内的文件名必须唯一。
* **新增：最接近的是规则记录的最老（或最新）版本、且该版本大量函数缺失或被改时，标注"可能更老（更新）"。** ESP8266 RTOS SDK 里的 libsodium 实际是 1.0.12（`port_include/sodium/version.h` 写着 `1.0.12-idf`），规则只记录 1.0.17 起，于是它被报成 1.0.17 且没有任何提示，而旧版本的漏洞要多得多。现在当最佳匹配是最老（最新）的记录版本、且它至少 25% 的函数缺失或被改时，证据里会写明"这棵树可能比规则记录的任何版本都更老（更新）"，终端表格的备注也改为 `vendor-modified (or older than known releases)`。版本号本身不改。在 pico-sdk、ESP-IDF、STM32CubeG4、Bouffalo SDK、ESP8266 RTOS SDK 的真实扫描里只触发这一处，没有误报。根本的修法是规则补记更老的发布版（这里是 libsodium 1.0.12 到 1.0.16），属于 gangmu-rules。
* **文档：与当前 CLI 和规则库对齐。** 免费规则库的数量改为实际的 98 条（53 条带 CPE、45 条没有），`gangmu rules index` 的加载耗时按 98 条重测；README 补全 `binary-eval`、`binary-functions`、`cbom --fail-on legacy`、`aibom` 的选项，英文 README 补上 `merge` 与 `license-check`；仓库一节写明商业版内容在私有仓库（gangmu-rules-pro、gangmu-policy-pro、gangmu-enterprise），EDITIONS 增补合并与许可证分诊、更多声明读取器；llms.txt、docs/index.md 补全相关仓库；说明示例产物由 0.6.x 生成。
* **修正：版本头文件放在带命名空间的子目录里时探针读不到，弱匹配也因此没被认定。** FreeRTOS 规则读 `include/task.h`，ESP-IDF 的分叉把它放在 `include/freertos/task.h`，固定路径找不到，所以 ESP-IDF 自带的 FreeRTOS 10.5.1 只剩"可能"（0.52，且只有函数给出的区间 `10.5.0~10.5.1`，不进 SBOM）。现在按文件名在向下四层内找，只在恰好一个候选时采信（探针的正则要求文件里定义了该组件自己的版本宏，所以名字相同的无关文件读不出东西）。另外：只是弱相似、又定义了该组件版本宏的目录，身份置信度提到 0.75（原先停在 0.50 的"需人工复核"）；锚点文件命中但整体不像的那条保护规则不受影响。ESP-IDF 的 `components` 扫描里 FreeRTOS 分叉从"可能"变为 `10.5.1`（0.77），其余结果不变；gangmu-bench 25 行不变（21 确切、4 区间、0 错误）。
* **修正：厂商多包了一层目录时，版本探针和锚点文件也能找到。** 规则记录的路径是 `src/include/lwip/init.h`，BTstack 自带的 lwIP 放在 `lwip/core/src/include/lwip/init.h`，原先按固定路径找不到，只能靠函数推断，结果把头文件明写 2.2.0 的开发版报成 `2.1.0~2.1.3`（比实际更老，会让只在 2.2.0 才修复的漏洞被当成仍然存在）。现在固定路径找不到时，往下找一到两层，且只在恰好有一个候选时采信，两个候选不猜。在 Raspberry Pi pico-sdk（5 个子模块，逐个对照头文件）的真实扫描中发现；其余 mbedtls 3.6.6、TinyUSB 0.18.0、lwIP 2.2.1 都与头文件一致。
* **修正：STM32 HAL 驱动的版本读成了次新的一条，现在优先读源文件里的版本宏。** STM32WB 的 `Release_Notes.html` 把最新一条写成小写的 `v1.3.0`，之前的正则只认大写 `V`，于是报成下面一条的 1.2.0（偏旧）。现在不区分大小写，并取最高的一条而不是第一条；另外读 `Src/stm32*xx_hal.c` 里的 `__STM32xx_HAL_VERSION_MAIN/SUB1/SUB2/RC`（宏在源文件里，不在头文件里，之前的说明写错了），有宏就以宏为准，候选版带 `-rcN`。F4 的宏与发布说明一致（1.8.5）；H7、G0 的源文件已没有这些宏，仍读发布说明。在 pico-sdk 里 BTstack 自带的 STM32WB HAL 上发现。
* **CI：新增 mypy 类型检查。** 之前 `src` 下有 96 个类型错误，全部清掉，CI 增加 `types` 任务（`mypy`，版本固定，配置在 `pyproject.toml` 的 `[tool.mypy]`）。多数是 Optional 没收窄、同一变量在不同分支被赋了不同类型；顺手发现两处会在边界条件下抛 `AttributeError` 的写法（`patchtest` 的 `workdir` 为空串、gitmodules 导入的“无固定提交”分支传了不是 `VendoredProject` 的对象），一并改正。行为不变，测试全过。
* **新增：`gangmu license-check SBOM` 对 CycloneDX 里的许可证做分诊。** 组件分为宽松、弱 copyleft（LGPL、MPL、EPL、CDDL）、强 copyleft（GPL）、网络 copyleft（AGPL）和未知（`OR` 表达式按最宽松的选择归类；`WITH` 例外会标出但不采信）。列出 copyleft 组件、按 FSF 许可证列表不能合成一个作品的组合（Apache-2.0 与 GPL-2.0-only、GPL-2.0-only 与 GPL-3.0-only、带广告条款的许可证以及 CDDL、EPL-1.0 与 GPL）、没有许可证的组件和预编译二进制。组合只报"可能"，因为 SBOM 不说两个组件是怎么合在一起的。`--fail-on copyleft|incompatible|unlicensed`、`--format json`。在 21 个真实发布树的扫描结果上跑过：列出 SOEM（GPL-2.0-only）与 Mbed TLS、CANopenNode（Apache-2.0）的组合，以及 11 个预编译 `.lib`/`.a`/`.bin`。是给人看的分诊，不是法律结论。
* **修正：几个版本都原样带着的锚点文件，不再只认第一个版本。** 规则库记录每个版本某个锚点文件的哈希，open62541 的 1.4.3 与 1.4.4 里 `ua_server.c` 逐字节相同；引擎取第一个匹配的版本，于是 1.4.4 的树被按锚点置信度（0.98）报成确切的 1.4.3，尽管它的 `CMakeLists.txt` 写的是 1.4.4。现在多个版本共用同一个哈希时，由版本探针或函数签名在其中选；两者都没有就报区间（`1.4.3~1.4.4`，来源 `anchor-shared`，置信度 0.88）。这是在 gangmu-bench 上新增 12 个用例（11 个确切）时发现的，同一用例现在报 1.4.4。凡是锚点覆盖补丁版本且文件没变的规则都受影响。
* **新增：读取已解开的根文件系统里的包数据库。** `var/lib/dpkg/status`（只算已安装的）、opkg 的 `var/lib/opkg/status` 或 `usr/lib/opkg/status`（Yocto 的 `-r0` 修订号去掉得到上游版本，git 快照不给版本）、Alpine 的 `lib/apk/db/installed`。已对照本构建容器自己的 dpkg 数据库验证：读出 827 个包，与 `dpkg-query` 的数目一致。dpkg 和 apk 的版本带发行版自己的修订号并回移修复，所以按原样报告，不当上游版本，也不套上游 CPE。不解镜像，需要指向已解开的目录。模块：`declared_rootfs.py`。
* **新增：`gangmu merge` 合并多份 CycloneDX 文档。** 一个产品的 SBOM 常来自多个工具（Yocto 构建、供应商、Conan、本工具的源码扫描）。purl 相同、否则名称加版本相同的算同一个组件；第一份文档已有的字段保留，后面的只补空缺（并加 `gangmu:alsoIn` 属性）；同一组件版本不同时两条都保留并报告为分歧；`bom-ref` 冲突自动改名，依赖图跟着改；漏洞（VEX）按 id 合并，分析状态不一致时取更谨慎的；`--fail-on-disagreement` 在出现任一类冲突时返回 1。合并结果通过 CycloneDX 1.6 schema 校验。只支持 CycloneDX JSON，不读 SPDX，组件内嵌的子组件原样带过去但不去重。
* **新增：读取 STM32Cube 包和 CMSIS-Pack 自己声明的版本。** CMSIS 设备头里的 `__STM32xx_CMSIS_VERSION_*` 宏（没有就取旁边 `Release_Notes.html` 的最新一条）、ST HAL 驱动 `Release_Notes.html` 的最新一条（现行 HAL 头文件不带版本宏）、CMSIS-Pack `*.pdsc` 的 vendor、name 和最新 `<release>`。已对照 ST 官方仓库的 F1、F4、G0、H7 的 HAL 与 CMSIS 设备树验证；不声称 CPE。模块：`declared_packs.py`。
* **新增：读取 CMake、vcpkg、Meson、Cargo 里声明的依赖。** `FetchContent_Declare`、`ExternalProject_Add` 和 CPM 的 `CPMAddPackage`（发布 tag 或带版本号的压缩包名算版本；分支、提交哈希、`${变量}` 只报名称不报版本）；`vcpkg.json`（`overrides` 钉住的才算版本，`version>=` 是下限不当版本报，`host` 依赖不算）；`subprojects/*.wrap`；`Cargo.lock` 里的 `*-sys` crate（绑定或内含 C 库的那些，crate 版本不冒充 C 库版本）。不联网。模块：`declared_deps.py`。

## 0.10.0

* **修正：`performance` 检查的基线改为在 CI 机器上重录。** 主线上有一次 `performance` 失败，热扫描是基线的 1.61 倍，刚过 1.6 倍的上限。原因不是校准抖动：CI 的 runner 有快慢几类（校准耗时约 0.033、0.045、0.060 s），一次扫描里约 0.5 到 0.6 秒的固定开销不随 CPU 变快，所以同样的代码在快的 runner 上以校准单位算要高 20% 到 30%，而旧基线是在开发机上录的，落在这个范围之外。现在基线取自 11 次 CI 运行的中位数（工作计数取最大值），这 11 次对新基线最差是 1.32 倍；另取更早几天的 6 次运行做对照，全部通过。旧基线的内存也过松（规则数 82 对现在的 90，x16 的峰值 609.6 MB 对 CI 上约 224 MB，内存涨到 2.7 倍才会报警），现在 1.35 倍的阈值才真正起作用。重录用 `benchmarks/rebaseline.py`。阈值（1.6 倍、1.35 倍）没有改。上一条里“校准取 9 轮中位数、前后各测一次”的改动仍在，它让校准更稳，但并没有解决这个失败（此前我把原因归到“取最快一轮的侥幸”，那是错的：在 0.045 s 这类机器上新方法同样测出 0.045 s）。
* **改进：`performance` 检查的校准取 9 轮中位数，并在整套扫描前后各测一次取平均**（两次的比值记为 `calibration_drift`），以前取 3 轮里最快的一轮。在一台静止的机器上，单次调用的波动从约 28% 降到约 9%。它让校准更稳，但不是偶发失败的原因（见上一条）。
* **新增：认出 libplctag。** 按 `plc_tag_*` 导出符号识别 libplctag 的原生库（不给版本，SONAME 的 2.6 系列写在证据说明里）；`libplctag.NativeImport.dll` 里切出的 10 个原生库全部认出。.NET 程序集不参与导出符号匹配，它元数据里的同名符号只是 P/Invoke 声明，不会被报成“内含 libplctag”。
* **新增：拆出嵌在别的文件里的原生二进制。** 按文件头找出嵌在文件中的 ELF、PE 和 Mach-O（.NET 程序集里按平台打包的原生库、附着载荷的安装包、嵌了 ELF 的固件），按各自格式的表算出大小，每个当作独立的条目、用同样的流程分析；横幅和工具链记在它真正所在的二进制上，外层文件不再背着嵌入库的工具链。SBOM 里是独立组件，带 `gangmu:containedIn`、`gangmu:offsetInContainer`、`gangmu:architecture`，SPDX 里由外层文件“包含”；.NET 资源里的库用作者起的资源名命名。在 `libplctag.NativeImport.dll` 上切出的 10 个与它的托管资源表逐个一致。不切静态库（`.a`、`.lib`）和 `.o`，最多往里两层。切出来不等于认出来：库本身是哪个库仍要靠规则。见 [BINARY-SBOM.md](BINARY-SBOM.md)。
* **新增：从 Windows 的 `.exe`、`.dll` 里提取 SBOM。** 读 PE 的导入表、导出表、版本资源和 PDB 路径；Go（`debug/buildinfo`）和 Rust（`cargo auditable`）写进文件的依赖清单按精确版本进 SBOM，purl 为 `pkg:golang`、`pkg:cargo`，Go 的 `replace` 标为已修改；.NET 读程序集引用，并读旁边的 `*.deps.json` 得到 NuGet 包的精确版本。各类证据的可信度不同：工具链清单 0.90、`deps.json` 0.85、版本资源 0.70、导入表和 .NET 引用 0.50（进“可能”一栏）。**导入只说明运行时依赖，不再被写成“内嵌”**（SBOM 里分开写成 `gangmu:embeddedLibrary`、`gangmu:importedLibrary`、`gangmu:declaredDependency`（`deps.json`）和 `gangmu:identifiedAs`（托管 DLL 自己的身份））。不为程序自己的程序集生成 NuGet purl。在真实 Go、Rust、MSVC 和 NuGet 样本上验证过，Go 与 `go version -m` 逐项一致；加壳、安装包、静态链接且无横幅的程序仍然认不出。证据、研究依据和没做的部分见 [BINARY-SBOM.md](BINARY-SBOM.md)。
* **修正：ESP-IDF 的 `managed_components/` 不再被跳过。** 组件管理器从注册表下载的依赖都放在这里，也都编进固件；以前发现阶段按目录名跳过它，即使编译数据库表明编译了，SBOM 里也没有这些组件。
* **修正：OSV 记录的 CVSS 评级。** 真实 OSV 记录的 `severity[].score` 是向量字符串，以前原样写进 CycloneDX 评级的 `severity`（只允许等级名），VEX 不符合 bom-1.6 schema，分数为空（按 0 分排序），MIIT 和 CRA 报告里的“危害程度”显示成向量。现在 v3 向量按规范公式算出基础分；v4 向量保留原文、等级取 GHSA 的 `database_specific.severity`；向量和方法写进评级各自的字段。NVD 只有 `cvssMetricV40` 时也读出分数和等级。
* **修正：同一漏洞不再重复计数。** NVD 的 CVE 和以它为别名的 GHSA 记录，或同一记录经 CPE 和 PURL 两个通道命中同一组件，以前是两条结果，`--fail-on`、CycloneDX 和 CSAF 都算两次。现在每个漏洞和组件只留一条，取更严重的状态，另一条记录的编号进 `aliases`。`vuln coverage` 仍按通道统计。
* **修正：`git describe` 形式的版本不再被判为“不受影响”。** `0.2-265-gad902ca` 以前把哈希里的数字当成版本号，对“0.2.1 修复”得出不受影响；在 0.2 之后 265 个提交，不一定包含 0.2.1 的修复。现在只在它的标签能决定时排序，否则交人工判断（in_triage）。
* **修正：`vuln-fetch --product ... --since` 早于 120 天时不再被悄悄截成最近 119 天**，按 API 允许的窗口分段拉取。
* **修正：读不出的 NVD 年度分片不再导致整年记录丢失。** 以前当作空分片，一次增量拉取就用本次的几条记录覆盖它。现在移到 `*.unreadable` 并警告，同时清除增量水位，下一次（不带 `--since`）重新全量下载。
* **可复现输出：设置 `SOURCE_DATE_EPOCH` 时，同样的输入生成逐字节相同的文档。** 时间取该值，文档编号（CycloneDX `serialNumber`、SPDX 命名空间、OpenVEX `@id`）由内容生成（uuid5），适用于 SBOM、VEX、CBOM、AIBOM 和证据包清单；不设置时行为不变。
* **修正：`gangmu binary-eval` 的特征缓存改用 JSON（`.features.json`）。** 以前从语料目录读取并反序列化 `.features.pickle`，语料来自他人时等于执行对方的代码；旧的 pickle 文件不再读取。
* **修正：带转义冒号的 CPE（如 `acme\:labs`）。** 以前有六处按每个冒号拆分，厂商、产品、版本整体错位：匹配用的产品键、公告 CPE 的固定版本、规则校验（会拒绝合法名称）、覆盖率统计、`sbom.yml` 读取和版本拼接。现在统一按规范拆分，拼入的版本会转义。
* **各个目录遍历共用一组“永不是固件内容”的目录**（`.git`、`node_modules`、`__pycache__`、`.venv`、`venv`），各自只追加与用途相关的目录；许可证和声明的遍历现在也跳过 Python 虚拟环境。指纹计算（dirprint）不变，以免规则库失效。
* **内部：`cli.py` 按命令组拆到 `gangmu/commands/`，行为不变。** 移走的名字仍可从 `gangmu.cli` 导入，插件不用改；新增测试逐个生成 35 个子命令的 `--help`。
* **CI：** gangmu-rules 固定到具体提交（v2026.10.11）；新增 `ruff check src tests`（只查未用和未定义的名字），并清理了已有的问题。

## 0.9.0

* **新命令 `gangmu policy check`：把 CBOM、AIBOM 对照写成数据的策略，给出每条检查的状态和期限。** 策略放在 `kind` 为 `policy` 的规则包的 `policies/*.yaml`：按算法 key 或量子状态选 CBOM 资产，按缺许可证或训练数据选 AIBOM 模型，带 `deprecated-after` / `disallowed-after` 日期；结果为 `ok`、`due`、`deprecated`、`fail`，可按 `--as-of` 判断，`--fail-on` 作 CI 闸门，输出表格、Markdown 或 JSON。不下法律结论，也不看密钥长度。见 [策略检查指南](guides/policy.md)。
* **`gangmu aibom --rules`：模型格式和推理库的识别表可以用规则包扩充。** 规则包 `kind` 为 `aibom`，目录里放 `formats/*.yaml` 和 `runtimes/*.yaml`；同名 `key` 替换内置项，新 `key` 新增；已安装的 aibom 包自动读取。种子规则在 [gangmu-aibom-rules](https://github.com/GANGMU-SBOM/gangmu-aibom-rules)，是内置表的原样导出。
* **`gangmu aibom` 支持声明文件，补训练数据、许可证、用途和评测。** 目录根的 `gangmu-aibom.yaml`（或 `--declarations FILE`）按路径通配符或 SHA-256 对应到模型，并进 CycloneDX 的许可证、数据集、`modelCard.considerations` 和评测；对不上的条目保留为“仅声明”组件；内容标为人工声明，不核对。`--require-declarations` 在有模型缺许可证或训练数据时退出 1。见 [AIBOM 指南](guides/aibom.md#声明文件)。
* **新命令 `gangmu aibom`：AI 物料清单最小版（CycloneDX 1.6）。** 列出目录里的机器学习模型（按文件签名或扩展名：TFLite、GGUF、ExecuTorch、ONNX、safetensors、PyTorch 等，带 SHA-256，GGUF 读出架构；编进 C 数组的 TFLite 模型也认）和推理运行时（TFLite Micro、CMSIS-NN、Edge Impulse、ONNX Runtime、llama.cpp 等）。PyTorch pickle 格式附“加载可能执行代码”的提示。不读训练数据和许可证，不看构建事实。见 [AIBOM 指南](guides/aibom.md)。
* **`gangmu cbom --format readiness`：后量子迁移摘要（Markdown）。** 把清单按“必须迁移、现在就换、已是后量子、对称”分组，给出 NIST 的替代方案；证据弱的和被构建事实排除的分开列。见 [CBOM 指南](guides/cbom-post-quantum.md)。
* **`gangmu cbom --libraries`：从认出的库和版本推出算法。** 先跑 SBOM 扫描，再按 CBOM 规则包 `libraries/*.yaml` 的能力表，把该版本源码提供的算法加进清单，证据类型 `library`、可信度最高 0.6（提供不等于调用）。版本认不出或不在任何版本段内时在提示里列出，不猜。见 [CBOM 指南](guides/cbom-post-quantum.md)。
* **内部拆出 `gangmu.core`，为后续的 CBOM、AIBOM 共用做准备，行为不变。** 插件入口点、规则包与清单、证据类型（`Technique`、`Evidence`）、路径匹配、固件容器解包和签名搬进 `gangmu/core/`；原来的导入路径（`gangmu.plugins`、`gangmu.signing`、`gangmu.globbing`、`gangmu.unpack`、`gangmu.rules.packs`）保留为同一模块的别名，外部插件不用改。`tests/test_architecture.py` 检查 core 不依赖任何引擎模块。
* **`gangmu cbom` 的算法表可以由规则包补充或覆盖。** 规则包写 `"kind": "cbom"`，算法放在 `algorithms/*.yaml`，用 `--rules DIR` 指定，或安装后自动读取；同名 `key` 替换内置项，新 `key` 新增。见 [CBOM 指南](guides/cbom-post-quantum.md)。
* **修正内置 CBOM 的三处误报：** `mbedtls_sha384_*` 不再被算成 SHA-3，`MBEDTLS_ECP_DP_CURVE448` 不再被算成 Ed25519；SM2 同时认 OpenSSL 3 的 `ossl_sm2_*` 命名。
* **规则包清单可以写 `kind`。** 不写等于 `sbom`（组件指纹，和以前一样）；写了别的值（例如 `cbom`）的包，SBOM 扫描会跳过而不是当成组件规则去解析。用 `--rules` 或 `GANGMU_RULES` 明确指定的目录不受影响。

## 0.8.0

* **函数级二进制识别支持更多架构，并加了真实固件验证。** 指纹现在记录它是为哪种架构编的；参考库和镜像架构不同时只比较字符串字面量（常量会随编译器而变，曾是所有错误版本的来源）。Cortex-M3 的参考库去认 rv32imac、AArch64、ESP32（Xtensa）镜像：给出答案的 0 个错、负对照 0 次误报，但许多库认不出来。旧版 `.fnprint` 仍可读，需要重新生成才有架构记录。
* **支持 Xtensa（ESP32、ESP8266）。** Capstone 没有 Xtensa 解码器，所以自带最小实现：只认 `entry` 指令找函数起点、只还原 `l32r` 取到的字面量，不是完整反汇编，只在一个 `xtensa-esp32-elf-gcc` 版本上验证过。
* **版本打分改为“被匹配的函数里有多少属于该版本”。** 固件通常只链进库的一部分（`--gc-sections`），原来的 Jaccard 总偏向函数少的旧版本。5 个语料上错误数持平或下降（Cortex-M3：14 降到 6，只留 25% 函数时），负对照仍 0 次误报；代价是镜像含整个库时更常给出区间而不是唯一版本。覆盖率低于 50% 的结果会注明“只是已指纹化版本中最接近的”。
* **真实固件（Zephyr 4.1，Cortex-M7）上的结果不如自测好，已写进 [BINARY-VALIDATION.md](BINARY-VALIDATION.md)。** littlefs 认出库但版本报错（真实版本不在指纹覆盖范围内）；Mbed TLS 现在给出包含真值的区间，但很宽。Zephyr 的配置会让匹配数明显变少。自测“全对”不能外推到别的配置、分支或未覆盖的版本。
* **链接 map：** 新增 TI armlnk、修正 Arm armlink 的解析，用公开的真实 map 验证。
* **规则库：** littlefs、mbedtls 带函数指纹（`identity.binary_functions`）。需要 `requires_gangmu >= 0.8.0`。
* **试过没成的（已写明，没有合并）：** 用调用关系佐证命中、用函数在镜像里的位置聚集度、放宽阈值，都没有净收益。

## 0.7.0

* **新命令 `gangmu cbom`：固件密码物料清单（CycloneDX 1.6 CBOM）。** 读源码、配置文件、预编译库和固件镜像里的算法名（AES、RSA、ECDSA、ECDH、SM2/3/4、SHA 系列、ML-KEM 等），
  每个算法写成 `cryptographic-asset` 组件，带文件和行号证据、置信度和量子风险（`gangmu:quantumStatus`）。给了编译数据库或链接 map 时只统计真正编译、链接的源文件
  （头文件只算声明，未编译的源文件记为 `not-linked`）；没有时每项标 `unverified`，并在输出里说明这是“树里有什么”而不是“固件里有什么”。AES 带密钥长度和模式。
  `--fail-on quantum-vulnerable|legacy` 可在 CI 里失败。输出用官方 CycloneDX 1.6 schema 在测试里校验（schema 放在 `tests/fixtures/schemas/`）。
  局限：按名字识别，不识别手写算法，不判断密钥长度和协议；用 Mbed TLS 的 PSA 接口名只识别部分。见 [CBOM 指南](guides/cbom-post-quantum.md)。
* **表格里的 `vendor-modified` 改为 `vendor-modified (or newer than known releases)`。** 用 ST 官方 STM32CubeF1 实测：子模块锁定的 HAL 提交比 v1.1.10 标签多改了 26 个文件，
  被标 `vendor-modified`；同一个 v1.1.10 标签的纯净副本不会被标。标记本身没错（树与已记录的发布版不一致），但容易被读成“客户改过”，所以说明另一种常见原因：比已记录版本更新的上游提交。仅改终端表格文字，SBOM 与 VEX 输出不变。
* **有链接 map 时，不属于本次构建的固件镜像不再算“已出货”。** 整库扫描 STM32CubeF1 时，示例工程的 `.bin`、音频文件 `audio.bin` 等 5 个镜像曾以 `required` 进 SBOM，
  而链接 map 只列链接输入，从不列镜像，所以此前没法判断。现在给了链接 map 时，只有与 map 同名的镜像（`fw.map` 对 `fw.elf`、`fw.bin`，即这次构建自己的产物）
  算已链接，其余记为未链接，CycloneDX 里 `scope` 为 `excluded`（和未链接的预编译库一致）。没有链接 map 时行为不变（未知）。
  核对：同一个 STM32CubeF1 整库扫描，`required` 只剩 HAL 和 lwIP 两项，10 个预编译文件全部 `excluded`。
* **新输出格式：SPDX 3.0.1、OpenVEX 0.2.0、CSAF 2.0（csaf_vex）。** `gangmu scan --format spdx3` 写 SPDX 3.0.1 JSON-LD（Software 配置：
  供应商是独立的 Agent、组件哈希进 `verifiedUsing`、许可证是元素并用关系挂接）；`gangmu vuln --format openvex|csaf` 把同一份分析写成 OpenVEX 或 CSAF。
  三种格式都用官方 JSON schema 在测试里校验（schema 放在 `tests/fixtures/schemas/`）。SPDX 2.3 仍是 `--format spdx`，默认输出不变。
  OpenVEX 和 CSAF 要求声明者，所以必须传 `--publisher`（CSAF 还要 `--publisher-url`），工具不替人编一个；
  CSAF 文档状态是 `draft`，`affected` 的补救措施写 `none_available`（工具只知道版本命中，不知道修复版本）。
  同一条公告被 CPE 和 PURL 两条通道同时命中时只写一条语句，取需要处理最多的状态。
* **组件维护状态与停止支持日期。** FDA 上市前网络安全指南要求 SBOM 里每个组件写明厂商维护支持级别和停止支持日期。
  来源有两个：规则里的 `upstream.support` 块，或 `gangmu scan --support FILE`（JSON / YAML）；文件里的条目优先。
  没有人声明的组件写 `unknown`，不留空，也不猜。CycloneDX 写成 `gangmu:supportStatus` / `gangmu:endOfSupport` 属性，
  SPDX 2.3 写 `validUntilDate`，SPDX 3 写 `supportLevel` 和 `validUntilTime`。状态取值：`maintained`、`limited`（只修安全问题）、
  `no_longer_maintained`、`abandoned`、`unknown`。
* **用真实固件（Zephyr、FreeRTOS、ESP-IDF）跑出的四个问题，已修。**
  1. `gangmu vuln` 对“在树里但没链接进镜像”的组件仍写 `exploitable`。现在读 SBOM 的 `gangmu:linkedIntoImage=false`（或扫描结果），降为 `in_triage` 并写明原因；
     确认后加 `--unlinked-vex` 记为 `not_affected` / `code_not_present`。这些组件在 CycloneDX 里 `scope` 为 `excluded`，SPDX 里有一行说明。
  2. 单体仓库里别的板子的预编译库被当成组件。有链接图时，没被链接图点名的预编译库标 `excluded` 并在扫描结果里给出数量。
  3. 厂商规则在它自己写的路径之外命中时（ESP-IDF 的 FatFs 被 Zephyr 的规则认出），不再把规则里的厂商写成供应商，也不沿用该厂商的 fork 说明。
  4. 规则新增可选字段 `upstream.advisory_scope: subsystem`，给 Zephyr 这类 OS/SDK 树用：公告每条只涉及一个子系统，版本区间命中只写 `in_triage`，不写 `exploitable`。
     免费规则库补上 Zephyr 内核规则（gangmu-rules#7）后，Zephyr 4.1.0 能被识别，它的 189 条版本命中因此不会被误报为可利用。
* **GitLab CI 与 Jenkins 模板**（`examples/ci/`），GitHub Action 新增 `spdx3` 格式和 `support` 输入。模板没有在真实的 GitLab 或 Jenkins 上运行过，
  只验证了 YAML 语法和参数拼装。
* **用真实工程（ST 官方 STM32CubeF1 的 LwIP 示例）验证后修了四个问题。**
  1. IAR（`.ewp`）和 Eclipse/CCS 工程用相对路径传给 `--project` 时，源文件路径被拼了两次，结果是 0 个组件，
     却仍打印“已构建 61 个源文件”。现在先转成绝对路径；工程里列出的源文件全部不存在时直接报错，部分不存在时给出提示。
  2. `--project` 直接传 `.cproject` 文件会报“不支持 .cproject”（点文件没有后缀）。现在可以。
  3. `gangmu wrap` 默认只拦截 cc、gcc、g++、clang、clang++，`arm-none-eabi-gcc` 这类交叉编译器记录 0 步，
     之后 `scan` 还会把所有组件标成“未链接”。现在默认同时拦截 PATH 上所有 `<triple>-gcc`、`-g++`、`-clang`；
     编译数据库里没有任何属于被扫描目录的源文件时，`scan` 报错退出。
  4. GNU ld 的 map 里，开了 `--gc-sections` 后整个目标文件被丢光，但仍出现在 `LOAD` 行，被算作“已链接”。
     现在只有在映像段里实际贡献了字节的目标文件才算已链接；LTO 或 map 里看不到贡献时仍保守地全部保留。
     在该示例里 62 个目标文件有 20 个被判为已被链接器丢掉。

* **`--link-map` 读 IAR ilink、Arm armlink 和 lld 的 map，并能与 IAR、Keil、CCS 工程配合。** 以前链接 map 只认 GNU ld，
  IDE 工程又不记录目标文件路径，所以这几类工程拿不到“编译了但被链接器丢掉”的信息。现在格式自动识别，
  IDE 工程按“源文件名 + .o / .obj”生成目标文件名，与 map 里的 `init.c.obj`、`init.o` 按主干名对齐。
  版式按厂商文档手写测试，尚未用真实工程验证，见 [LIMITS.md](LIMITS.md)。

## 0.6.2

* **GitHub Action 与 pre-commit 钩子。** 根目录 `action.yml`（`uses: GANGMU-SBOM/gangmu@v0`）在 CI 里生成 SBOM；
  `.pre-commit-hooks.yaml` 提供 `gangmu-scan` 钩子。
* **文档。** 按任务组织的指南（ESP-IDF、Zephyr、RT-Thread / OpenHarmony、国密库、魔改组件识别、CRA 与工信部报送）、
  与同类工具的对比页、`examples/output/` 示例产物、FAQ 的 FAQPage 结构化数据。
* 发布工作流只在 `vX.Y.Z` 形式的 tag 上触发，滚动 tag `v0` 不再触发 PyPI 发布。


准确率与噪声。用真实上游版本按 SDK 的摆法摆好再扫（lwIP、Mbed TLS、libcoap、littlefs、FreeRTOS-Kernel、nanopb、
miniz、TinyCrypt、cJSON、wolfSSL、LVGL、RT-Thread，共 12 个真实上游版本，放进两个模拟 SDK）。修复前：第一个 SDK 里
9 份未改动的上游副本有 7 份被标成 `vendor-modified`；nanopb 被报了三次（其中两个是它自己 `examples/` 里的幻影）；
第二个 SDK 丢了 RT-Thread 内核，FatFs 也报在错的目录上。

* **`vendor-modified` 现在只表示"已记录的代码缺失或被改动"。** 以前只要出现签名没见过的函数就触发，而在未改动的
  目录里这指的是签名没覆盖的头文件、移植层和宏（lwIP 2,092 个里有 136 个，FreeRTOS 1,743 个里有 1,487 个），
  `multi_version` 也会被未改动的 lwIP 触发。`vendor_patched` 会进入漏洞匹配的 `is_fork`，所以每个误标都会把真实
  通告降成待研判。现在：9 份未改动副本 0 份被标；改动 3 个 lwIP 函数则被标出，证据里带着个数。只"新增"代码的副本不会被标：
  新增并不改变有漏洞的代码是否还在。
* **已识别组件内部 example / test 目录里的清单不再当作组件。** 即 nanopb 的 `examples/conan_dependency`（多出一个
  0.4.6 的 nanopb）和 `examples/platformio`（再多一个没版本的）。项目自己的 `examples/` 目录照常读取，扫描会说明忽略了几条。
* **组件归到真正存放它的目录。** 函数包含度在每一层祖先目录都会触发，"每目录一个胜者"曾让它把父目录从真正的
  内核手里抢走（RT-Thread 输给了它自己里面的 FatFs）。现在子目录说了同样的话，就丢掉祖先的那条；更弱的嵌套匹配、
  或根目录精确版本对内层区间，都不会顶掉根目录。

* **补丁存在性检测。** `gangmu patch-build CVE` 记录一条公告的修复提交改动了哪些函数（提交号从 OSV 记录读，或用 `--repo`
  和 `--fix` 指定），`gangmu vuln --source ROOT --patches FILE` 看代码而不是看版本：有修复后的函数体就 `resolved`，
  仍是修复前的函数体就确认为 `exploitable`，被厂商改过的留给人判断。魔改的 fork 只报告它所基于的版本号，
  过去每条之后才修复的公告都会让它永远停在 `in_triage`，现在不会了。见 [ALGORITHMS.md](ALGORITHMS.md#patch-presence)。
* **补丁存在性的近似匹配。** 厂商改过的函数以前只能报 `modified`，没有下文。现在记录里还保存修复新增和删去的
  token 窗口，改过的副本可以被报成 `likely_fixed` 或 `likely_vulnerable`，并附上依据的比例。
  只有加 `--patch-near-vex` 才会改 VEX 状态。在 cJSON 的历史上（112 个安全修复 × 49 个发布版）
  它在 1,166 条精确结论之外又给出 853 条正确结论，没有一条错误。
  没有用到识别上：在一个真实 fork 里，98.9% 的函数本来就精确匹配。
* **补丁记录随规则包一起发布。** `gangmu vuln --source ROOT` 会读取已安装规则包里的 `patches/*.json`，社区包的记录
  不用手动指定就生效（`--no-pack-patches` 关闭，`--rules DIR` 指向别的规则目录）。`gangmu patch-verify` 按记录里写明的
  上游提交重新生成并比对；`patch-build --first-parent` 用来记录以 pull request 合入的修复。
  同时修了验证真实记录时发现的两个问题：同一函数有多个修复提交，以及相邻提交的拉取把修复提交留在浅克隆边界上。
* **SBOM 记录每个组件是由哪个规则包识别的。** CycloneDX 组件新增属性 `gangmu:rulePack` 与 `gangmu:rulePackVersion`
  （规则包 `rulebase.json` 里的 `name` 与 `version`；没有清单时用入口点名或目录名，且不带版本），SPDX 的组件备注里写
  “from rule pack …”，`gangmu scan --format json` 的每个发现多出 `rule_pack`、`rule_pack_version`。同一条规则被后加载的包
  覆盖时，记的是后者。来自构建声明或二进制字符串、不经规则识别的组件不带这两个字段。这样团队能看出一份 SBOM 里有多少
  组件是靠哪个规则包识别的，也是商业规则包“价值报告”的数据来源。

## 0.6.1

在干净环境里从 PyPI 验证 0.6.0 时发现并修复的问题。

* **`gangmu init DIR` 在 `DIR` 不存在时不再崩溃。** 现在会自动创建目录；目标写不进去时只打印一行错误，不再抛
  Python traceback。
* **测试输入不再被当作固件。** 名为 `test`、`tests`、`testdata`、`test_data`、`fuzz`、`fixtures` 的目录之下的
  `.bin`、`.elf`、`.axf` 文件（比如 lwIP 的 `test/fuzz/inputs/*.bin`，其实是模糊测试的数据包）不再被列为预编译镜像，
  也就不会出现在 SBOM 里，或者变成 `gangmu vuln` 无法查询的组件。`.a`、`.lib`、`.so` 在任何目录里都照常列出。

## 0.6

### 快：整棵 SDK 十秒级，规则再多也不线性变慢

纲目要放进每一次固件构建的 CI，扫描一棵完整 SDK 就不能是"去喝杯咖啡"的事。4 核机器，ESP-IDF v5.4.2 带全部子模块：

| 设置 | 0.5 | 0.6 |
| --- | --- | --- |
| 单进程，无缓存 | 72.5 s / 366 MB | **11.0 s / 123 MB** |
| 4 进程，冷缓存 | 35.8 s | **5.5 s** |
| 4 进程，再扫一遍 | 10.2 s | **2.1 s** |

两个版本识别结果逐条一致，另外 6 棵本地树也逐条比对过。做法是：每个文件按内容哈希只分析一次；用精确的分文件 bottom-k 草图，结果与原算法完全相同；SQLite 增量缓存，键里带分析代码的摘要，代码一改缓存自动失效；规则预筛，把不可能命中的规则直接跳过。

性能也进了 CI。`gangmu perf --check benchmarks/perf-baseline.json` 会把识别结果、分词次数、匹配次数、耗时（校准单位）和峰值内存与基线比较，有任何一项退步，PR 就不能合并。详见 [docs/PERFORMANCE.md](PERFORMANCE.md)。

### FreeRTOS 与 RT-Thread：厂商把内核挪到哪里都能找到

国产芯片 SDK 几乎都带一份 RTOS 内核，但常常改了目录名（`freertos_riscv`、`bl702_freertos`），不带 LICENSE，有时还藏在三层深的示例目录里。0.6 的规则改用"标志文件"来定位：`tasks.c` + `queue.c` + `list.c` 同时出现，就是 FreeRTOS；`src/thread.c` + `src/ipc.c` + `include/rtthread.h` 同时出现，就是 RT-Thread。找到目录后，再用函数签名判断版本。FreeRTOS 的签名覆盖 28 个发布版，RT-Thread 覆盖 27 个。

测试对象是博流、沁恒、联盛德、乐鑫共 7 个 SDK 里的 14 份内核副本，**14/14 全部找到**。报告的版本要么正好是厂商头文件里写的那个，要么是一个包含它的区间，区间里的几个发布版内核代码相同。这 14 份在 0.5 里一份都找不到。加上这两条规则后，扫描耗时的变化在测量噪声以内。

### Mbed TLS、FatFs、littlefs：不再只认 Zephyr 和 ESP-IDF 的目录

这三个库原有的规则只认 Zephyr（`modules/crypto/mbedtls`）和 ESP-IDF（`components/mbedtls/mbedtls`）的布局。国产 SDK 里它们却到处都是，而且这是漏洞所在：博流、联盛德、乐鑫 ESP8266 的 SDK 里，Mbed TLS 的 CVE 远多于厂商自己的 HAL。现在各有一条通用规则，用标志文件定位，不管目录叫什么：

* `generic/mbedtls`：63 个发布版，2.1.18 到 4.2.0（2.16.x、2.17 到 2.28.x、3.x 逐版齐全）；
* `generic/fatfs`：R0.10a 到 R0.16 共 20 个发布版；
* `generic/littlefs`：1.7.2 和 2.0.0 到 2.11.3 共 38 个发布版。

在 5 套 SDK 里找到的 12 份副本（Mbed TLS 6 份，FatFs 4 份，littlefs 2 份）**全部识别，版本全部正确或是包含正确版本的区间**。另外用 34 棵真实上游发布版目录（改名、删掉版本头文件、改动源文件三种方式）测试，34 棵都识别为正确的组件，28 棵版本精确，6 棵是包含正确版本的区间，0 棵错误。详见 [docs/BENCHMARK.md](BENCHMARK.md#1d-third-party-libraries-inside-chinese-vendor-sdks)。

后续又加入 LVGL（54 个发布版，6.0 到 9.6.0）、libcoap（13 个）和 TinyCrypt（7 个）。其中 LVGL、libcoap、TinyCrypt 的 CPE 状态是"未核实"：写规则时 NVD 不可达，没有猜测。5 套 SDK 里的 7 份副本全部识别，另用 25 棵真实发布版目录测试，25 棵都识别为正确的组件，21 棵版本精确，4 棵是包含正确版本的区间，0 棵错误。

这一步暴露并修复了两个问题：同一目录被通用规则和 Zephyr/ESP 规则同时认出时，原来按规则的"具体程度"裁决，于是一份原版 Mbed TLS 4.1.1 被报成"Zephyr 的 4.1.0，已改动"，原版 littlefs 2.11.3 被报成 `git-e9a8638fc228`（这种版本号无法和 CVE 的版本范围比较）。现在证据种类多的一方、版本可比较的一方优先，厂商规则在自己的路径上仍然胜出。另外版本比较此前忽略末尾字母，`1.1.1k` 与 `1.1.1n` 比较为相等（在 1.1.1n 修复的 CVE，因此被判为不影响 1.1.1k），FatFs 的标签 `R0.14b` 被当成 beta；两处都已修正并加了测试。

### CPE 从 NVD 证据里来，全量 NVD 直接读

`gangmu rules cpe-evidence --nvd DIR` 逐条检查 CVE：只要它的参考链接指向某条规则的上游仓库或官网，这条 CVE 配置里写的 vendor:product 就算作证据。工具按证据多少排序，交给人工确认。这次查出的结果：

- FreeRTOS、RT-Thread、OpenThread、FatFs 有了 CPE；
- cJSON 有 13 条 CVE 登记在 `davegamble:cjson` 下，原规则只写了 `cjson_project:cjson`，以前全部漏掉；
- 每个新 CPE 都在规则里用 `cpe_evidence` 列出所依据的 CVE。

`gangmu vuln` 现在能直接读完整的 NVD 镜像，包括压缩的 `.json.xz`，同一份 SBOM 从 200.8 s、3.9 GB 降到 8.9 s、25 MB。在 8 个 SDK 上，漏洞比对结果从 133 条增加到 243 条。沁恒的 3 个 SDK 和 ESP8266 SDK 以前是 0 条，现在各有 12 到 17 条。

### OpenHarmony：部件和依赖关系，直接读 `bundle.json`

OpenHarmony 的每个部件都带一份 `bundle.json`，里面写着部件名、子系统、版本、许可证，以及它依赖哪些部件和第三方库。这是源码树里唯一记录"谁用了谁"的地方，而一个 CVE 出来后，大家最先问的就是这个问题。纲目现在会读取它：

- OpenHarmony 自身的部件作为组件列入 SBOM；
- 第三方目录在 `README.OpenSource` 给出的上游身份之外，再加上部件名；
- 依赖关系写进 CycloneDX 的 `dependencies` 和 SPDX 的 `DEPENDS_ON`；
- 声明了、但在树里找不到的依赖，会在组件属性里列出，不会悄悄丢掉。

在海思 Hi3861 轻量系统的整机代码上测试（官方清单 `default_mini.xml` 的 43 个仓库，18 万个文件），识别出的组件从 15 个增加到 45 个，依赖边从 0 条增加到 89 条，扫描耗时不变（28.9 s）。现在能直接看出 Mbed TLS 被 device_auth、huks、dsoftbus、init 等 6 个部件用到。

## 0.4–0.5

### RT-Thread 与 OpenHarmony：有包管理器，就直接读声明

声明式信息比任何相似度都准。国产生态在这一点上反而比国际生态更好做，
因为声明就躺在源码树里：

| 生态 | 读什么 | 声明的是 |
| --- | --- | --- |
| RT-Thread | `.config` 中的 `CONFIG_PKG_USING_*` / `_PATH` / `_VER`，以及 `packages/pkgs.json` | **软件包**的版本 |
| OpenHarmony | 各第三方目录下的 `README.OpenSource`；0.6 起还读各部件的 `bundle.json` | **上游**名称、版本、许可证、地址；部件名与依赖关系 |
| Yocto / OpenEmbedded | 构建产物 `tmp*/deploy/licenses/*/license.manifest`（没有就读 `images/*/*.manifest`；都没有，才读 `local.conf` / 镜像配方里 `IMAGE_INSTALL` 选中的 `.bb`） | **上游**名称、版本、许可证；`_git.bb` 这类跟踪分支的配方没有发布版本，只报名称 |
| PlatformIO | `.pio/libdeps/*/*/library.json`（已下载，版本确切，目录也会照常做指纹识别）；其次是 `platformio.ini` 的 `lib_deps` | **上游**名称与版本；`^1.2` 这类版本范围不当作版本，只报名称 |
| Conan | `conan.lock`（确切版本），其次 `conanfile.txt` 的 `[requires]`、`conanfile.py` 的 `requires` / `self.requires()`；`tool_requires` 不算（跑在构建机上，不在固件里） | **上游**名称与版本；`[>=3.0 <4]` 这类范围不当作版本 |
| Bazel | `MODULE.bazel` 的 `bazel_dep`（去掉 `.bcr.N` 得到上游版本），以及 `WORKSPACE` 的 `http_archive` / `git_repository`（版本取自 `strip_prefix`、URL 或 tag）；开发依赖和 `rules_*` 工具链模块不算 | **上游**名称与版本；读不出版本的只报名称 |

两者的差别直接影响 CVE 匹配，所以处理方式不同：

- OpenHarmony 声明的是上游版本，规则库里的 CPE 可以直接套用；
- RT-Thread 的 `v1.0.2` 是软件包自己的标签，**绝不拼进上游 CPE**。gangmu 会照常对该目录做指纹识别，
  由规则库给出里面真正的上游版本，软件包声明作为证据附上；
- `.config` 里选了但还没下载的包，会作为提示列出，而不是悄悄消失。

```
$ gangmu scan rt-thread-bsp/ --format table
CONF  COMPONENT  VERSION  SRC    DIRECTORY              NOTES
----  ---------  -------  -----  ---------------------  -----
0.75  cJSON      1.7.17   probe  packages/cJSON-v1.0.2

note: rt-thread: package webclient v2.2.0 is selected in .config but not downloaded
```

声明与代码不一致时（比如 `README.OpenSource` 写 1.4.0、锚点文件证明是 1.4.2），
以代码为准，并把分歧写进证据交给人工判断。用 `--no-declared` 可以关闭这一层。

### 国密库识别

商用密码合规审查必查，国际 SBOM 工具完全不认识这些组件。

| 组件 | 覆盖版本 | 识别方式 |
| --- | --- | --- |
| GmSSL 3.x | 3.0.0、3.1.0、3.1.1、3.2.0 | 逐版本锚点 + 四版本函数签名 + 版本探针 |
| GmSSL 2.x（独立规则 `generic/gmssl-2`） | 2.0.0–2.5.4，共 20 个版本 | 逐版本锚点 + 20 版本函数签名 + 版本探针；上游没有 2.x 标签，固定到提交 |
| 铜锁 Tongsuo（含 BabaSSL 时期） | 8.1.3、8.2.0、8.2.1、8.3.0–8.3.3、8.4.0、8.5.0 | 逐版本锚点 + 九版本函数签名 + 版本探针 |
| OpenSSL | 1.1.0–1.1.0l、1.1.1–1.1.1w 全部版本，及 3.0–3.6 各线最新补丁版 | 逐版本锚点 + 44 版本函数签名 + 版本探针 |

铜锁是 OpenSSL 3.0 的分支，两者共享上万个函数。同时加载两条规则时，共享的函数
对谁都不算身份证据（CENTRIS 的代码分割），各自只靠自己独有的代码被认出来。

这里抓到过一个真问题：分割原本只做在精确哈希层，抗重命名的抽象层漏掉了。结果一棵
原版 OpenSSL 3.0.22 通过共享代码以 0.90 的身份置信度「也像铜锁」，反过来也一样。
0.5 把分割同时做到抽象层之后，每棵树只匹配自己的规则。

### 国产芯片 HAL

用已有的 west 导入器，从 Zephyr 4.4 的锁定提交直接生成，全部能从上游逐字节复现：

博流智能 BL60x/BL70x、沁恒 CH32（ch32fun）、思澈科技 SiFli、泰凌微 TLSR9、瑞昱 Ameba/Bee，
加上此前的兆易 GD32。

### Zephyr 模块自带的安全声明

Zephyr 模块可以在 `zephyr/module.yml` 的 `security.external-references` 里声明 CPE 和 PURL，
Mbed TLS、nanopb、hostap、TF-M 都这样做了。gangmu 现在把它当作厂商清单读取，扫描和规则导入都用得上。

据此重新导入后，纠正了一条旧规则的错误判断：Zephyr 的 `modules/crypto/mbedtls` 不是一层构建胶水，
而是 Mbed TLS 4.1.0 本体，现在带着正确的 CPE 与 PURL。同时新增了 hostap（wpa_supplicant / hostapd），
它是 Zephyr Wi-Fi 的基础，也是漏洞高发组件。
