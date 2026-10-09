"""Moved to :mod:`gangmu.core.unpack`. This alias keeps the old import path working."""
import sys as _sys

from .core import unpack as _moved

_sys.modules[__name__] = _moved
