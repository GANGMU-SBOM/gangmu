"""``yaml.safe_load`` through libyaml when PyYAML was built with it.

Parsing a pack's YAML is the largest cost of loading its rules, and PyYAML's
pure-Python loader is about ten times slower than the C one that PyPI wheels
ship. The two build identical objects for the same safe subset (checked on every
rule of gangmu-rules), so the C loader is used whenever it exists.
"""

from __future__ import annotations

from typing import Any

import yaml

_LOADER: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def safe_load(stream: Any) -> Any:
    return yaml.load(stream, Loader=_LOADER)  # noqa: S506 -- a safe loader
