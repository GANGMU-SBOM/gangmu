"""Kconfig answers: which options the build was configured with.

A source tree holds everything the SDK ships; the build compiles only what the
configuration turns on.  Without a compile database that difference is
invisible, and the SBOM lists components that never reach the firmware.  Both
ESP-IDF (``sdkconfig``) and Zephyr (``build/zephyr/.config``) write the answer
in the same ``CONFIG_NAME=value`` form, so one reader serves both.

A rule names the options that switch its component on (``component.config_symbols``).
The conclusion drawn is deliberately one-sided: a component is dropped only when
the configuration *says* an option is off.  An option the file never mentions
may simply not exist in this SDK release, and a missing component is the worse
error for a compliance document than an extra one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# Relative to the scan root, most specific first.
CANDIDATES: Tuple[str, ...] = (
    "build/zephyr/.config",      # Zephyr, west build / cmake
    "build/sdkconfig",          # ESP-IDF with an out-of-tree configuration
    "sdkconfig",                # ESP-IDF
    ".config",                  # RT-Thread Env, Kbuild
)

_SET = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*?)\s*$")
_NOT_SET = re.compile(r"^#\s*CONFIG_([A-Za-z0-9_]+) is not set\s*$")


@dataclass
class KconfigValues:
    path: str = ""
    values: Dict[str, str] = field(default_factory=dict)

    def state(self, symbol: str) -> Optional[bool]:
        """True = on, False = explicitly off, None = this file does not know it."""
        symbol = symbol[len("CONFIG_"):] if symbol.startswith("CONFIG_") else symbol
        if symbol not in self.values:
            return None
        return self.values[symbol] in ("y", "m")

    def __len__(self) -> int:
        return len(self.values)


def parse_kconfig(text: str, path: str = "") -> KconfigValues:
    out = KconfigValues(path=path)
    for line in text.splitlines():
        line = line.strip()
        match = _SET.match(line)
        if match:
            out.values[match.group(1)] = match.group(2).strip().strip('"')
            continue
        match = _NOT_SET.match(line)
        if match:
            out.values[match.group(1)] = "n"
    return out


def read_kconfig(path: Path) -> KconfigValues:
    return parse_kconfig(Path(path).read_text(encoding="utf-8", errors="replace"),
                         str(path))


def find_kconfig(root: Path) -> Optional[Path]:
    for rel in CANDIDATES:
        candidate = Path(root) / rel
        if candidate.is_file():
            return candidate
    return None


def disabled_by(symbols: Sequence[str], config: KconfigValues) -> Optional[List[str]]:
    """The symbols that keep a component out of the build, or None if it is in.

    ``symbols`` are alternatives: any one being on enables the component.  The
    component is out only when every symbol the configuration knows is off, and
    at least one is known.
    """
    states = [(s, config.state(s)) for s in symbols]
    known = [(s, st) for s, st in states if st is not None]
    if not known or any(st for _, st in known):
        return None
    if len(known) < len(states):         # an alternative this file cannot judge
        return None
    return [s for s, _ in known]
