"""Moved to :mod:`gangmu.core.packs`. This alias keeps the old import path working."""
import sys as _sys

from ..core import packs as _moved

_sys.modules[__name__] = _moved
