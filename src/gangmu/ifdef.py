"""Which lines of a C file does the build actually compile?

``#if 0``, ``#ifdef CONFIG_FEATURE`` and ``#if !defined(MBEDTLS_X)`` decide
whether a function exists in the firmware at all. A source tree holds every
branch; the reachability pass would otherwise treat a function that is compiled
out as defined and, through the over-approximate call graph, as reachable.

The evaluation is three-valued and errs toward keeping code. A condition is
false only when every name in it is known and the result is definitely false;
anything unknown (a macro from the toolchain, ``__has_include``, a
function-like macro call) keeps the branch. So blanking a region means the
configuration we were given says it is not compiled, never "we could not tell".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

_DIRECTIVE = re.compile(rb"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif|define|undef)\b(.*)$")
_COMMENT = re.compile(rb"/\*.*?\*/|//.*$", re.S)
_TOKEN = re.compile(r"\s*(?:(0[xX][0-9A-Fa-f]+|\d+)[uUlL]*|([A-Za-z_]\w*)|"
                    r"(&&|\|\||==|!=|<=|>=|<<|>>|[-+*/%()!<>~&|^?:,]))")

Value = Optional[int]            # None: not known


@dataclass
class Macros:
    """What is known about each macro name.

    ``value`` maps a name to its integer value, or to ``None`` when it is
    defined but not to a number we can read. ``undefined`` lists names the
    configuration says are off.
    """
    value: Dict[str, Value] = field(default_factory=dict)
    undefined: Set[str] = field(default_factory=set)
    assume_undefined: bool = False      # a name nobody defines is off
    alias: Dict[str, str] = field(default_factory=dict)   # `#define A B`
    maybe: Set[str] = field(default_factory=set)   # defined under some #if: unknown

    def defined(self, name: str) -> Optional[bool]:
        if name in self.undefined:
            return False
        if name in self.value:
            return True
        if name in self.maybe:
            return None
        return False if self.assume_undefined else None

    def number(self, name: str, _depth: int = 0) -> Value:
        if name in self.undefined:
            return 0
        if name in self.value:
            v = self.value[name]
            if v is None and name in self.alias and _depth < 8:
                return self.number(self.alias[name], _depth + 1)
            return v
        if name in self.maybe:
            return None
        return 0 if self.assume_undefined else None

    def define(self, name: str, text: str = "1") -> None:
        self.undefined.discard(name)
        self.value[name] = _literal(text)

    def add_kconfig(self, values: Dict[str, str]) -> None:
        for name, raw in values.items():
            symbol = "CONFIG_" + name
            if raw in ("n", ""):
                self.value.pop(symbol, None)
                self.undefined.add(symbol)
            elif raw in ("y", "m"):
                self.define(symbol, "1")
            else:
                self.define(symbol, raw)

    def derive(self, args: Sequence[str]) -> "Macros":
        """A copy with a compile command's ``-D``/``-U`` flags applied, or
        ``self`` when the command has none."""
        flags = tuple(a for a in args if a[:2] in ("-D", "-U")) \
            + tuple(a for prev, a in zip(args, args[1:]) if prev in ("-D", "-U"))
        if not flags:
            return self
        out = Macros(dict(self.value), set(self.undefined), self.assume_undefined,
                     dict(self.alias), set(self.maybe))
        out.add_flags(args)
        return out

    def add_flags(self, args: Iterable[str]) -> None:
        """``-DNAME``, ``-DNAME=VALUE``, ``-D NAME`` and ``-UNAME`` from a compile command."""
        it = iter(args)
        for arg in it:
            if arg in ("-D", "-U"):
                arg = arg + next(it, "")
            if arg.startswith("-D") and len(arg) > 2:
                name, _, text = arg[2:].partition("=")
                self.define(name, text if "=" in arg else "1")
            elif arg.startswith("-U") and len(arg) > 2:
                self.value.pop(arg[2:], None)
                self.undefined.add(arg[2:])


def _literal(text: str) -> Value:
    text = text.strip().rstrip("uUlL")
    try:
        return int(text, 0)
    except ValueError:
        return None


# ---------------------------------------------------------- expression value

class _Unknown(Exception):
    pass


def _lex(expr: str) -> List[str]:
    out: List[str] = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise _Unknown
        out.append(m.group(1) or m.group(2) or m.group(3))
        pos = m.end()
    return out


class _Parser:
    """Recursive descent over the usual C operators; ``None`` is "unknown"."""

    def __init__(self, toks: Sequence[str], macros: Macros):
        self.toks = list(toks)
        self.i = 0
        self.m = macros

    def peek(self) -> str:
        return self.toks[self.i] if self.i < len(self.toks) else ""

    def eat(self) -> str:
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self) -> Value:
        v = self.ternary()
        if self.i != len(self.toks):
            raise _Unknown
        return v

    def ternary(self) -> Value:
        cond = self.or_()
        if self.peek() == "?":
            self.eat()
            a = self.ternary()
            if self.eat() != ":":
                raise _Unknown from None
            b = self.ternary()
            if cond is None:
                return a if a == b else None
            return a if cond else b
        return cond

    def or_(self) -> Value:
        v = self.and_()
        while self.peek() == "||":
            self.eat()
            w = self.and_()
            if v is not None and v != 0 or w is not None and w != 0:
                v = 1
            elif v is None or w is None:
                v = None
            else:
                v = 0
        return v

    def and_(self) -> Value:
        v = self.cmp()
        while self.peek() == "&&":
            self.eat()
            w = self.cmp()
            if v == 0 or w == 0:
                v = 0
            elif v is None or w is None:
                v = None
            else:
                v = 1
        return v

    def cmp(self) -> Value:
        v = self.add()
        while self.peek() in ("==", "!=", "<", ">", "<=", ">="):
            op = self.eat()
            w = self.add()
            if v is None or w is None:
                v = None
                continue
            v = int({"==": v == w, "!=": v != w, "<": v < w, ">": v > w,
                     "<=": v <= w, ">=": v >= w}[op])
        return v

    def add(self) -> Value:
        v = self.unary()
        while self.peek() in ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"):
            op = self.eat()
            w = self.unary()
            if v is None or w is None:
                v = None
                continue
            try:
                v = {"+": lambda: v + w, "-": lambda: v - w, "*": lambda: v * w,
                     "/": lambda: v // w, "%": lambda: v % w, "&": lambda: v & w,
                     "|": lambda: v | w, "^": lambda: v ^ w,
                     "<<": lambda: v << w, ">>": lambda: v >> w}[op]()
            except (ZeroDivisionError, ValueError):
                raise _Unknown from None
        return v

    def unary(self) -> Value:
        tok = self.eat()
        if tok == "!":
            v = self.unary()
            return None if v is None else int(not v)
        if tok == "-":
            v = self.unary()
            return None if v is None else -v
        if tok == "~":
            v = self.unary()
            return None if v is None else ~v
        if tok == "(":
            v = self.ternary()
            if self.eat() != ")":
                raise _Unknown from None
            return v
        if not tok:
            raise _Unknown
        if tok[0].isdigit():
            return int(tok.rstrip("uUlL") or "0", 0)
        if tok == "defined":
            paren = self.peek() == "("
            if paren:
                self.eat()
            name = self.eat()
            if paren and self.eat() != ")":
                raise _Unknown from None
            d = self.m.defined(name)
            return None if d is None else int(d)
        if tok in ("IS_ENABLED", "IS_BUILTIN", "IS_MODULE") and self.peek() == "(":
            self.eat()
            name = self.eat()
            if self.eat() != ")":
                raise _Unknown from None
            v = self.m.number(name)
            return None if v is None else int(v == 1)
        if self.peek() == "(":                       # a function-like macro call
            raise _Unknown
        return self.m.number(tok)


def evaluate(expr: str, macros: Macros) -> Value:
    """Value of an ``#if`` expression, or None when it cannot be decided."""
    try:
        return _Parser(_lex(expr), macros).parse()
    except (_Unknown, IndexError, RecursionError):
        return None


# ---------------------------------------------------------------- the filter

@dataclass
class _Frame:
    taken: bool = False       # an earlier branch is definitely compiled
    unknown: bool = False     # an earlier branch may or may not be
    off: bool = False         # the current branch is definitely not compiled


def _directives(data: bytes) -> Iterable[Tuple[int, bytes, bytes]]:
    """(line index, keyword, argument) for each directive, joining continuations
    and skipping lines inside block comments."""
    lines = data.split(b"\n")
    in_comment = False
    i = 0
    while i < len(lines):
        line = lines[i]
        start = i
        was_comment = in_comment
        in_comment = _comment_state(line, in_comment)
        if not was_comment:
            m = _DIRECTIVE.match(line)
            if m:
                arg = m.group(2)
                while arg.rstrip().endswith(b"\\") and i + 1 < len(lines):
                    arg = arg.rstrip()[:-1] + b" " + lines[i + 1]
                    i += 1
                    in_comment = _comment_state(lines[i], in_comment)
                yield start, m.group(1), arg
                if i != start:
                    yield i, b"", b""            # marks the last continued line
        i += 1


def _comment_state(line: bytes, inside: bool) -> bool:
    pos = 0
    while True:
        if inside:
            end = line.find(b"*/", pos)
            if end < 0:
                return True
            inside, pos = False, end + 2
        else:
            start = line.find(b"/*", pos)
            slash = line.find(b"//", pos)
            if slash >= 0 and (start < 0 or slash < start):
                return False
            if start < 0:
                return False
            inside, pos = True, start + 2


def _strip(arg: bytes) -> str:
    return _COMMENT.sub(b" ", arg).decode("utf-8", "replace").strip()


def inactive_lines(data: bytes, macros: Macros) -> Set[int]:
    """Indices of the lines whose branch the configuration rules out."""
    out: Set[int] = set()
    stack: List[_Frame] = []
    off_depth = 0              # frames currently definitely off
    last = -1
    for idx, kw, arg in _directives(data):
        if not kw:
            continue
        if off_depth:
            out.update(range(last + 1, idx))
        last = idx
        if kw in (b"if", b"ifdef", b"ifndef"):
            frame = _Frame()
            val: Value = _condition(kw, arg, macros)
            frame.off = val == 0
            frame.taken = bool(val)
            frame.unknown = val is None
            stack.append(frame)
            off_depth += frame.off
        elif kw in (b"elif", b"else") and stack:
            frame = stack[-1]
            off_depth -= frame.off
            if kw == b"else":
                val = 1
            else:
                val = _condition(b"if", arg, macros)
            if frame.taken:
                frame.off = True
            elif val == 0:
                frame.off = True
            elif val is None or frame.unknown:
                frame.off = False
                frame.unknown = True
            else:
                frame.off = False
                frame.taken = True
            off_depth += frame.off
        elif kw == b"endif" and stack:
            off_depth -= stack.pop().off
        if off_depth:
            out.add(idx)           # the directive line itself of a dead branch
    if off_depth:
        out.update(range(last + 1, data.count(b"\n") + 1))
    return out


def _condition(kw: bytes, arg: bytes, macros: Macros) -> Value:
    text = _strip(arg)
    if kw in (b"ifdef", b"ifndef"):
        name = text.split()[0] if text.split() else ""
        d = macros.defined(name)
        if d is None:
            return None
        return int(d) if kw == b"ifdef" else int(not d)
    return evaluate(text, macros)


def strip_inactive(data: bytes, macros: Macros) -> Tuple[bytes, int]:
    """``data`` with the lines of dead branches blanked (line numbers kept),
    and how many lines that was."""
    if b"#" not in data:
        return data, 0
    dead = inactive_lines(data, macros)
    if not dead:
        return data, 0
    lines = data.split(b"\n")
    for i in dead:
        if i < len(lines):
            lines[i] = b""
    return b"\n".join(lines), len(dead)


# -------------------------------------------------- defines found in the tree

_SKIP = {".git", ".svn", "node_modules", "__pycache__"}
_HDR = (".h", ".hpp", ".hh", ".inc", ".c", ".cc", ".cpp")
# Generated headers that state the build's configuration; found without being named.
GENERATED_CONFIG = ("sdkconfig.h", "autoconf.h")


def find_config_headers(root: Path) -> List[Path]:
    """Generated configuration headers (sdkconfig.h, autoconf.h) under ``root``."""
    out: List[Path] = []
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            entries = sorted(cur.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in _SKIP:
                    stack.append(p)
            elif p.name in GENERATED_CONFIG:
                out.append(p)
    return out


def collect_tree_defines(root: Path, macros: Macros, authoritative: Sequence[Path] = (),
                         max_file: int = 2_000_000) -> int:
    """Learn macros from the tree.

    A tree holds several alternative configurations (Mbed TLS ships a dozen
    ``configs/config-*.h`` beside its default), so a ``#define`` somewhere in it
    does not mean the build has it. Only the ``authoritative`` headers, the ones
    the build is known to use, make a name defined: their unconditional
    ``#define NAME [value]`` lines, outside an include guard. A name defined or
    ``#undef``-ed anywhere else in the tree is recorded as unknown, so a branch
    that depends on it is kept. Returns the number of names made defined.
    """
    want = {Path(p).resolve() for p in authoritative}
    seen: Dict[str, Value] = {}
    alias: Dict[str, str] = {}
    clash: Set[str] = set()
    undef: Set[str] = set()
    unsure: Set[str] = set()
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            entries = sorted(cur.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in _SKIP:
                    stack.append(p)
            elif p.suffix in _HDR or p.resolve() in want:
                try:
                    if p.stat().st_size > max_file:
                        continue
                    data = p.read_bytes()
                except OSError:
                    continue
                is_config = p.resolve() in want
                depth = 0
                guard = 0          # an include guard wraps the file: not a condition
                first = True
                for _idx, kw, arg in _directives(data):
                    if first and kw:
                        first = False
                        if kw == b"ifndef":
                            guard = 1
                    if kw in (b"if", b"ifdef", b"ifndef"):
                        depth += 1
                    elif kw == b"endif":
                        depth = max(0, depth - 1)
                    elif kw == b"undef":
                        words = _strip(arg).split()
                        undef.add(words[0] if words else "")
                    elif kw == b"define":
                        text = _strip(arg)
                        m = re.match(r"([A-Za-z_]\w*)(\(?)\s*(.*)$", text)
                        if not m:
                            continue
                        if not is_config or depth > guard:
                            unsure.add(m.group(1))
                            continue
                        name = m.group(1)
                        val = None if m.group(2) else _literal(m.group(3) or "1")
                        target = m.group(3).strip()
                        if val is None and re.fullmatch(r"[A-Za-z_]\w*", target):
                            if alias.setdefault(name, target) != target:
                                clash.add(name)
                        if name in seen and seen[name] != val:
                            clash.add(name)
                        seen.setdefault(name, val)
    for name in unsure | undef:
        if name and name not in seen and name not in macros.value \
                and name not in macros.undefined:
            macros.maybe.add(name)
    n = 0
    for name, val in seen.items():
        if name in macros.value or name in macros.undefined or name in undef:
            continue
        macros.value[name] = None if name in clash else val
        if name in alias and name not in clash:
            macros.alias[name] = alias[name]
        n += 1
    for name in undef:
        if name and name not in macros.undefined:
            macros.value.pop(name, None)
            macros.maybe.add(name)
    return n
