# Limits

No deep binary analysis: prebuilt libraries and firmware images (`.a`, `.lib`, `.so`, `.elf`, `.axf`, `.bin`, `.exe`, `.dll`) are only inventoried and read for version banners and exported symbols. Windows `.exe` and `.dll` files are also read for the PE import and export tables and version resource, the dependency lists the Go and Rust (`cargo auditable`) toolchains write into the file, .NET assembly references and the `*.deps.json` beside a program; see [BINARY-SBOM.md](BINARY-SBOM.md) for what each proves, what is not done and how it was checked. A statically linked C/C++ program with no banner is still not recognised. Benchmarks now span a dozen-odd component families (about a hundred real upstream trees and several dozen copies inside Chinese vendor SDKs, see docs/BENCHMARK.md), not a corpus of thousands.
Rule coverage is still small; Allwinner Tina Linux SDKs (the RTOS SDKs are covered) are not
in Zephyr and need their own import. Recursive import
(`gangmu rules import --recursive`) covers `.gitmodules` SDKs and west manifests; for west it
follows the common `import:` forms (true, file/directory paths, allow/block lists, `path-prefix`,
and lists of these) to depth 4, but not `import-flags` or imports via west extension commands.
`gangmu vuln` itself never touches the network; `gangmu vuln-fetch` is the
separate online step that fills its directory (`--sbom` for just the products an
SBOM can match, `--all` for the whole NVD, incremental afterwards). The compiler
wrapper works on POSIX and Windows, but it only intercepts compilers the build finds
by name on `PATH`: `make` with an absolute `CC=/opt/gcc/bin/gcc` bypasses it. On
Windows the shim is a real `gcc.exe` built from pip's vendored distlib launcher, so
`cmd /c` and plain `mingw32-make` recipes are recorded, and so is MSVC `cl.exe`
(`/c`, `/Fo`); a cross compiler, `arm-none-eabi-gcc`, works too (all verified in CI on
windows-latest with MinGW gcc, clang, MSVC and the Arm GNU toolchain from Chocolatey). Without that launcher it falls back to a `.cmd` file
that only `cmd.exe` finds, and builds run under MSYS/Git `sh` are not verified.
`gangmu wrap` warns when nothing was recorded; use `--project` then.

Linux distribution libraries are only partly identified: version banners cover few libraries (4 of 13 on Ubuntu 24.04) and distributions often strip them; `.note.package` helps only where the distribution wrote it. On clang-built Thumb firmware function-boundary recall and precision are both about 0.98 (a tail-called leaf, `crc32_z`, is missed), and a controlled comparison against gcc-built references (docs/BINARY-VALIDATION.md) found the library in clang builds of zlib and Mbed TLS (26-33% coverage) but not littlefs, with a release range rather than a single release. High-entropy raw images get a note; the scan does not decrypt or unpack them.
