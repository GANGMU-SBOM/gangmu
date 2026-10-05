"""The compiler shim.

These run a real build with the system compiler, because the whole point of the
wrapper is that it observes what actually happened rather than what a project
file claims.
"""

import json
import os
import shutil
from pathlib import Path

import pytest

from gangmu.build.wrap import wrap_build

HAVE_CC = shutil.which("cc") or shutil.which("gcc")
# These tests drive a POSIX `make` that runs recipes through `sh`. On Windows
# that combination bypasses .cmd shims (see wrap.py), so the Windows path is
# covered by the Windows-only tests below and by the wrap-windows CI job.
HAVE_MAKE = shutil.which("make") if os.name != "nt" else None


def _project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int a(void){return 1;}\n")
    (tmp_path / "src" / "b.c").write_text("int b(void){return 2;}\n")
    (tmp_path / "src" / "never.c").write_text("int never(void){return 3;}\n")
    (tmp_path / "Makefile").write_text(
        "CC ?= cc\n"
        "all: build/a.o build/b.o\n"
        "build/%.o: src/%.c\n"
        "\t@mkdir -p build\n"
        "\t$(CC) -c $< -o $@\n"
    )
    return tmp_path


def test_only_the_files_the_build_compiled_are_recorded(tmp_path):
    if not (HAVE_CC and HAVE_MAKE):
        pytest.skip("needs cc and make")
    root = _project(tmp_path)
    out = root / "compile_commands.json"
    result = wrap_build(["make"], ["cc", "gcc"], out, workdir=root)
    assert result.returncode == 0
    files = {Path(e["file"]).name for e in json.loads(out.read_text())}
    assert files == {"a.c", "b.c"}
    assert "never.c" not in files          # exists on disk, never compiled


def test_the_object_path_is_captured_for_the_link_map_join(tmp_path):
    if not (HAVE_CC and HAVE_MAKE):
        pytest.skip("needs cc and make")
    root = _project(tmp_path)
    out = root / "cc.json"
    wrap_build(["make"], ["cc", "gcc"], out, workdir=root)
    entries = json.loads(out.read_text())
    assert all(e.get("output", "").endswith(".o") for e in entries)


def test_the_build_itself_is_unchanged(tmp_path):
    if not (HAVE_CC and HAVE_MAKE):
        pytest.skip("needs cc and make")
    root = _project(tmp_path)
    wrap_build(["make"], ["cc", "gcc"], root / "cc.json", workdir=root)
    assert (root / "build" / "a.o").is_file()
    assert (root / "build" / "b.o").is_file()


def test_a_failing_build_returns_its_own_exit_code(tmp_path):
    if not (HAVE_CC and HAVE_MAKE):
        pytest.skip("needs cc and make")
    root = _project(tmp_path)
    (root / "src" / "a.c").write_text("this is not C\n")
    result = wrap_build(["make"], ["cc", "gcc"], root / "cc.json", workdir=root)
    assert result.returncode != 0


def test_shimming_a_compiler_that_is_not_installed_is_refused(tmp_path):
    with pytest.raises(RuntimeError, match="nothing to shim"):
        wrap_build(["true"], ["definitely-not-a-compiler-xyz"],
                   tmp_path / "out.json")


def test_link_steps_are_not_mistaken_for_compiles(tmp_path):
    if not HAVE_CC:
        pytest.skip("needs cc")
    (tmp_path / "m.c").write_text("int main(void){return 0;}\n")
    out = tmp_path / "cc.json"
    # No -c: this is a compile-and-link in one step, and the shim must not
    # record it as a translation unit with a known object file.
    wrap_build(["cc", "m.c", "-o", "m"], ["cc"], out, workdir=tmp_path)
    assert json.loads(out.read_text()) == []


# -- shared log format and the Windows shim, testable without Windows ---------

import subprocess
import sys

from gangmu.build import shim
from gangmu.build.wrap import _parse_log, _write_shim

ON_WINDOWS = os.name == "nt"


def test_response_files_follow_gcc_quoting():
    text = 'a "b c" \'d e\' f\\ g\r\n-DX="1 2"\r\n\r\n'
    assert shim.split_response_text(text) == ["a", "b c", "d e", "f g", "-DX=1 2"]
    assert shim.split_response_text("") == []
    assert shim.split_response_text('""') == [""]


def test_response_files_are_expanded_recursively_and_relative_to_cwd(tmp_path):
    (tmp_path / "inner.rsp").write_text("-O2 y.c\n")
    (tmp_path / "outer.rsp").write_bytes(b"\xef\xbb\xbf-c @inner.rsp\r\n-o x.o")
    args = shim.expand_response_files(["@outer.rsp", "@missing.rsp"], str(tmp_path))
    assert args == ["-c", "-O2", "y.c", "-o", "x.o", "@missing.rsp"]


def test_response_file_cycles_terminate(tmp_path):
    (tmp_path / "loop.rsp").write_text("@loop.rsp -c")
    args = shim.expand_response_files(["@loop.rsp"], str(tmp_path))
    assert "-c" in args and len(args) < 100


def test_shim_record_is_what_the_parser_reads(tmp_path):
    log = tmp_path / "log"
    shim.log_invocation(str(log), "/work dir", ["-c", "my file.c", "-o", "o.o"])
    entries = _parse_log(log)
    assert entries == [{"directory": "/work dir", "file": "my file.c",
                        "arguments": ["-c", "my file.c", "-o", "o.o"],
                        "output": "o.o"}]


def test_parser_tolerates_crlf_translated_logs(tmp_path):
    log = tmp_path / "log"
    log.write_bytes(shim.build_record("/w", ["-c", "a.c"]).replace(b"\n", b"\r\n"))
    assert [e["file"] for e in _parse_log(log)] == ["a.c"]


def test_python_shim_logs_expands_and_returns_the_exit_code(tmp_path):
    (tmp_path / "args.rsp").write_text("-c a.c\r\n")
    log = tmp_path / "log"
    env = dict(os.environ, GANGMU_WRAP_LOG=str(log))
    # The "compiler" is the Python interpreter itself, so @args.rsp is passed on
    # to it unexpanded while the log gets the expanded form.
    proc = subprocess.run(
        [sys.executable, "-m", "gangmu.build.shim", sys.executable,
         "-c", "import sys; sys.exit(7)", "@args.rsp"],
        cwd=tmp_path, env=env)
    assert proc.returncode == 7
    entries = _parse_log(log)
    assert [e["file"] for e in entries] == ["a.c"]
    assert entries[0]["directory"] == str(tmp_path)


def test_python_shim_reports_a_missing_compiler(tmp_path, capsys):
    assert shim.main([str(tmp_path / "no-such-compiler"), "-c", "a.c"]) == 127


def test_exe_shim_has_launcher_shebang_and_a_runnable_zip(tmp_path):
    import zipfile
    blob = shim.build_exe_shim(b"MZ-stub", r"C:\Program Files\Python\python.exe",
                               r"C:\mingw\bin\gcc.exe")
    assert blob.startswith(b'MZ-stub#!"C:\\Program Files\\Python\\python.exe"\r\n')
    path = tmp_path / "gcc.exe"
    path.write_bytes(blob)
    with zipfile.ZipFile(path) as zf:      # a zip with a prefix, as distlib makes
        main_py = zf.read("__main__.py").decode()
    assert "from gangmu.build.shim import main" in main_py
    assert r"'C:\\mingw\\bin\\gcc.exe'" in main_py
    compile(main_py, "__main__.py", "exec")


def test_windows_prefers_an_exe_shim_and_falls_back_to_cmd(tmp_path):
    exe = _write_shim(tmp_path, "gcc.exe", "gcc.exe", windows=True, use_exe=b"MZ")
    assert exe.name == "gcc.exe" and exe.read_bytes().startswith(b"MZ#!")
    sub = tmp_path / "nolauncher"
    sub.mkdir()
    import gangmu.build.wrap as wrap_mod
    orig = wrap_mod.shim.find_launcher
    wrap_mod.shim.find_launcher = lambda: None
    try:
        cmd = _write_shim(sub, "gcc", "gcc.exe", windows=True)
    finally:
        wrap_mod.shim.find_launcher = orig
    assert cmd.name == "gcc.cmd"


def test_windows_shim_file_shape(tmp_path):
    import gangmu.build.wrap as wrap_mod
    orig = wrap_mod.shim.find_launcher
    wrap_mod.shim.find_launcher = lambda: None
    try:
        path = _write_shim(tmp_path, "gcc.exe", r"C:\mingw\bin\gcc.exe",
                           windows=True)
    finally:
        wrap_mod.shim.find_launcher = orig
    assert path.name == "gcc.cmd"
    data = path.read_bytes()
    assert b"-m gangmu.build.shim" in data and b"%*" in data
    assert r'"C:\mingw\bin\gcc.exe"'.encode() in data
    assert data.count(b"\r\n") == data.count(b"\n")     # CRLF throughout


@pytest.mark.skipif(not ON_WINDOWS, reason="Windows only")
def test_windows_wrap_records_a_cmd_launched_compile(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("needs gcc")
    (tmp_path / "my dir").mkdir()
    (tmp_path / "my dir" / "a b.c").write_text("int a(void){return 1;}\n")
    (tmp_path / "x.rsp").write_text('-c "my dir/a b.c" -o a.o\r\n')
    out = tmp_path / "cc.json"
    result = wrap_build(["cmd", "/c", "gcc @x.rsp"], ["gcc"], out, workdir=tmp_path)
    assert result.returncode == 0
    assert (tmp_path / "a.o").is_file()
    entries = json.loads(out.read_text())
    assert [Path(e["file"]).name for e in entries] == ["a b.c"]
    assert entries[0]["output"] == "a.o"


@pytest.mark.skipif(not ON_WINDOWS, reason="Windows only")
def test_windows_failing_compile_keeps_its_exit_code(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("needs gcc")
    (tmp_path / "bad.c").write_text("this is not C\n")
    result = wrap_build(["cmd", "/c", "gcc -c bad.c -o bad.o"], ["gcc"],
                        tmp_path / "cc.json", workdir=tmp_path)
    assert result.returncode != 0


@pytest.mark.skipif(not ON_WINDOWS, reason="Windows only")
def test_windows_exe_shim_is_found_by_a_direct_createprocess(tmp_path):
    if not shutil.which("gcc") or shim.find_launcher() is None:
        pytest.skip("needs gcc and pip's launcher")
    (tmp_path / "d.c").write_text("int d(void){return 4;}\n")
    out = tmp_path / "cc.json"
    # No cmd.exe in between: this is what make does for a plain recipe line.
    result = wrap_build(["gcc", "-c", "d.c", "-o", "d.o"], ["gcc"], out,
                        workdir=tmp_path)
    assert result.returncode == 0
    assert [Path(e["file"]).name for e in json.loads(out.read_text())] == ["d.c"]


def test_msvc_compile_flags_and_object_paths_are_understood(tmp_path):
    log = tmp_path / "log"
    for args in (["/nologo", "/c", r"src\a.c", "/Foa.obj"],
                 ["/nologo", "/c", "src/b.cpp", "/Fo:out/b.obj"],
                 ["/nologo", "/c", "c.c", "/Foobj" + "\\"],
                 ["/nologo", "x.c", "/Fex.exe"]):          # compile and link
        log.write_bytes(log.read_bytes() if log.exists() else b"")
        with open(log, "ab") as fh:
            fh.write(shim.build_record("C:/w", args))
    entries = _parse_log(log)
    assert [(Path(e["file"].replace("\\", "/")).name, e["output"]) for e in entries] == [
        ("a.c", "a.obj"), ("b.cpp", "out/b.obj"), ("c.c", "obj\\c.obj")]


def test_msvc_response_files_keep_backslashes_but_gcc_ones_do_not():
    text = r'/c "C:\my dir\a.c" /Fo:C:\out\a.obj'
    assert shim.split_response_text(text, msvc=True) == [
        "/c", r"C:\my dir\a.c", r"/Fo:C:\out\a.obj"]
    assert shim.split_response_text(r"C:\out") == ["C:out"]       # GCC rules
