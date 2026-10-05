"""The Windows half of the compiler wrapper.

On Windows the ``PATH`` shim is a ``<name>.cmd`` file that calls
``python -m gangmu.build.shim <real-compiler> <args...>``. This module appends
the invocation to ``$GANGMU_WRAP_LOG`` in exactly the record format the POSIX
``/bin/sh`` shim writes (``cwd NUL arg NUL ... NUL LF``), then runs the real
compiler and returns its exit code, so ``wrap._parse_log`` reads both alike.

It is plain Python with no Windows-only calls, so it is unit-tested on Linux.
"""

from __future__ import annotations

import io
import os
import platform
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import List, Optional, Sequence

_MAX_RESPONSE_DEPTH = 8


def split_response_text(text: str, msvc: bool = False) -> List[str]:
    """Split a response file the way GCC (libiberty ``buildargv``) does.

    Whitespace separates arguments; single or double quotes group; a backslash
    escapes the next character. Any line ending, CRLF included, is whitespace.
    With *msvc*, as for ``cl.exe``: only double quotes group and a backslash is
    an ordinary character, so Windows paths survive.
    """
    args: List[str] = []
    cur: List[str] = []
    have = False
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and not msvc:
            i += 1
            cur.append(text[i])
            have = True
        elif quote:
            if ch == quote:
                quote = ""
            else:
                cur.append(ch)
        elif ch in ('"' if msvc else "'\""):
            quote = ch
            have = True
        elif ch.isspace():
            if have:
                args.append("".join(cur))
                cur, have = [], False
        else:
            cur.append(ch)
            have = True
        i += 1
    if have:
        args.append("".join(cur))
    return args


def expand_response_files(args: Sequence[str], cwd: str, msvc: bool = False,
                          _depth: int = 0) -> List[str]:
    """Replace ``@file`` arguments by the arguments the file holds.

    An ``@`` argument whose file cannot be read is kept verbatim, as GCC does.
    """
    out: List[str] = []
    for arg in args:
        if arg.startswith("@") and len(arg) > 1 and _depth < _MAX_RESPONSE_DEPTH:
            path = Path(arg[1:])
            if not path.is_absolute():
                path = Path(cwd) / path
            try:
                text = path.read_bytes().decode("utf-8-sig", "replace")
            except OSError:
                out.append(arg)
                continue
            out.extend(expand_response_files(split_response_text(text, msvc), cwd,
                                             msvc, _depth + 1))
        else:
            out.append(arg)
    return out


def build_record(cwd: str, args: Sequence[str]) -> bytes:
    """One log record, byte-identical to what the POSIX shim emits."""
    return b"".join(a.encode("utf-8", "surrogateescape") + b"\0"
                    for a in (cwd, *args)) + b"\n"


def log_invocation(log: Optional[str], cwd: str, args: Sequence[str],
                   msvc: bool = False) -> None:
    if not log:
        return
    try:
        record = build_record(cwd, expand_response_files(args, cwd, msvc))
        with open(log, "ab") as fh:
            fh.write(record)
    except OSError:
        pass            # never let logging break the build being observed


def build_exe_shim(launcher: bytes, python: str, real: str) -> bytes:
    """A console ``.exe`` that runs this module's ``main`` for *real*.

    Same layout pip uses for ``console_scripts``: a distlib launcher stub, then a
    ``#!`` line naming the interpreter, then a zip holding ``__main__.py``. Being
    a real executable, it is found by ``CreateProcess`` and by ``make``'s direct
    exec, which a ``.cmd`` shim is not.
    """
    main_py = ("import sys\n"
               "from gangmu.build.shim import main\n"
               f"sys.exit(main([{real!r}] + sys.argv[1:]))\n")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("__main__.py", main_py)
    shebang = b'#!"' + python.encode("utf-8") + b'"\r\n'
    return launcher + shebang + buf.getvalue()


def find_launcher() -> Optional[bytes]:
    """The console launcher stub vendored by pip (distlib), or None."""
    import importlib.util
    try:
        spec = importlib.util.find_spec("pip")
    except (ImportError, ValueError):
        return None
    if not spec or not spec.origin:
        return None
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        name = "t64-arm.exe"
    elif sys.maxsize > 2 ** 32:
        name = "t64.exe"
    else:
        name = "t32.exe"
    path = Path(spec.origin).parent / "_vendor" / "distlib" / name
    try:
        return path.read_bytes()
    except OSError:
        return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m gangmu.build.shim <real-compiler> [args...]",
              file=sys.stderr)
        return 2
    real, args = argv[0], argv[1:]
    msvc = Path(real).stem.lower() == "cl"
    log_invocation(os.environ.get("GANGMU_WRAP_LOG"), os.getcwd(), args, msvc)
    try:
        return subprocess.call([real, *args])
    except OSError as exc:
        print(f"gangmu shim: cannot run {real}: {exc}", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main())
