"""A compiler wrapper, for builds that produce no compile database.

Plain Makefiles are still how a large share of embedded firmware is built, and
they record nothing. The trick is older than this project: put a shim earlier on
``PATH`` than the real compiler, have it log its own invocation and then exec the
real thing. The build is unchanged -- same compiler, same flags, same output --
but afterwards we know exactly which translation units were compiled.

This is better evidence than a project file, because it observes the build that
actually ran rather than the build the project file describes. Conditional
compilation, generated sources and a dirty tree all come out right.

On POSIX the shim is a ``/bin/sh`` script. On Windows it is a real ``<name>.exe``
(a distlib console launcher, the kind pip makes for ``console_scripts``, carrying a
zipped ``__main__`` that calls ``gangmu.build.shim``), so ``CreateProcess`` and
``make``'s direct exec find it. If pip's launcher stub is not available it falls
back to a ``<name>.cmd`` that runs ``python -m gangmu.build.shim``, which only
``cmd.exe`` finds. Either way the shim writes the same log record (``@file``
response files expanded) and then runs the real compiler; both feed ``_parse_log``.

Limits, on every platform: a PATH shim only sees compilers the build looks up by
name. A build that calls the compiler by absolute path (a Makefile with
``CC=/opt/gcc/bin/gcc``) bypasses it. On Windows, in the ``.cmd`` fallback, a
compiler spawned without ``cmd.exe`` (GNU make's plain recipe lines) bypasses it
too. When nothing is recorded, ``gangmu wrap`` says so; use ``--project`` then.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import shim  # noqa: E402

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".s", ".S", ".sx", ".asm"}

_SHIM = """#!/bin/sh
# gangmu compiler shim: log the invocation, then run the real compiler.
{{
  printf '%s\\0' "$PWD"
  for arg in "$@"; do printf '%s\\0' "$arg"; done
  printf '\\n'
}} >> "$GANGMU_WRAP_LOG" 2>/dev/null
exec "{real}" "$@"
"""


_CMD_SHIM = (
    "@echo off\r\n"
    "rem gangmu compiler shim: log the invocation, then run the real compiler.\r\n"
    '"{python}" -m gangmu.build.shim "{real}" %*\r\n'
    "exit /b %ERRORLEVEL%\r\n"
)


@dataclass
class WrapResult:
    returncode: int
    invocations: int
    compile_entries: List[dict]
    log: Path


def _write_shim(bindir: Path, name: str, real: str,
                windows: Optional[bool] = None,
                use_exe: Optional[bytes] = None) -> Path:
    if windows is None:
        windows = os.name == "nt"
    if windows:
        stem = name[:-4] if name.lower().endswith(".exe") else name
        launcher = shim.find_launcher() if use_exe is None else use_exe
        if launcher:
            path = bindir / (stem + ".exe")
            path.write_bytes(shim.build_exe_shim(launcher, sys.executable, real))
            return path
        path = bindir / (stem + ".cmd")
        path.write_bytes(_CMD_SHIM.format(python=sys.executable,
                                          real=real).encode("utf-8"))
        return path
    path = bindir / name
    path.write_text(_SHIM.format(real=real))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _output_option(args: Sequence[str]) -> Optional[str]:
    """The object path a compile asked for: GCC ``-o x`` or MSVC ``/Fo[:]x``."""
    for i, arg in enumerate(args):
        if arg == "-o" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("-o") and len(arg) > 2:
            return arg[2:]
        if arg[:3] in ("/Fo", "-Fo") and len(arg) > 3:
            return arg[3:].lstrip(":")
    return None


def _object_for(output: str, source: str) -> str:
    """``/Fo`` may name a directory, in which case the object is <dir><stem>.obj."""
    if output.endswith(("/", "\\")):
        return output + Path(source.replace("\\", "/")).stem + ".obj"
    return output


def _parse_log(log: Path) -> List[dict]:
    entries: List[dict] = []
    try:
        raw = log.read_bytes()
    except OSError:
        return entries
    for record in raw.split(b"\n"):
        if record.endswith(b"\r"):
            record = record[:-1]    # a log that went through CRLF translation
        if not record:
            continue
        parts = [p.decode("utf-8", "replace") for p in record.split(b"\0") if p]
        if len(parts) < 2:
            continue
        cwd, args = parts[0], parts[1:]
        if "-c" not in args and "/c" not in args:
            continue            # a link or a preprocess-only run, not a compile
        sources = [a for a in args[1:]
                   if not a.startswith("-") and Path(a).suffix in SOURCE_SUFFIXES]
        if not sources:
            continue
        output = _output_option(args)
        for source in sources:
            entry = {"directory": cwd, "file": source, "arguments": args}
            if output:
                entry["output"] = _object_for(output, source)
            entries.append(entry)
    return entries


def wrap_build(command: Sequence[str], compilers: Sequence[str],
               out: Path, workdir: Optional[Path] = None,
               env: Optional[Dict[str, str]] = None) -> WrapResult:
    """Run *command* with shims for *compilers* on PATH; write a compile db."""
    tmp = Path(tempfile.mkdtemp(prefix="gangmu-wrap-"))
    bindir = tmp / "bin"
    bindir.mkdir()
    log = tmp / "invocations.log"
    log.touch()

    base_env = dict(env or os.environ)
    missing: List[str] = []
    for name in compilers:
        real = shutil.which(name, path=base_env.get("PATH", os.defpath))
        if not real:
            missing.append(name)
            continue
        _write_shim(bindir, Path(name).name, real)
    if missing and len(missing) == len(compilers):
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(
            f"none of {list(compilers)} is on PATH, so there is nothing to shim")

    base_env["PATH"] = f"{bindir}{os.pathsep}{base_env.get('PATH', os.defpath)}"
    base_env["GANGMU_WRAP_LOG"] = str(log)
    if os.name == "nt":
        # The shim runs `python -m gangmu.build.shim`; make that importable even
        # when gangmu is run from a source tree rather than installed.
        pkg_root = str(Path(__file__).resolve().parents[2])
        base_env["PYTHONPATH"] = os.pathsep.join(
            p for p in (pkg_root, base_env.get("PYTHONPATH", "")) if p)

    argv = list(command)
    if os.name == "nt" and not any(sep in argv[0] for sep in "\\/"):
        # CreateProcess searches the *parent's* PATH, not env=, so a bare
        # `gcc` would skip the shim directory. POSIX execvpe uses env's PATH.
        argv[0] = shutil.which(argv[0], path=base_env["PATH"]) or argv[0]
    proc = subprocess.run(argv, cwd=str(workdir) if workdir else None,
                          env=base_env)
    entries = _parse_log(log)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    kept = log.parent / "invocations.log"
    return WrapResult(returncode=proc.returncode, invocations=len(entries),
                      compile_entries=entries, log=kept)
