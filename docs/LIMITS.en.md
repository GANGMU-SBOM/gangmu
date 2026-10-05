# Limits

No deep binary analysis: prebuilt libraries and firmware images (`.a`, `.lib`, `.so`, `.elf`, `.axf`, `.bin`) are only inventoried and read for version banners and exported symbols. Benchmarks now span a dozen-odd component families (about a hundred real upstream trees and several dozen copies inside Chinese vendor SDKs, see docs/BENCHMARK.md), not a corpus of thousands.
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
