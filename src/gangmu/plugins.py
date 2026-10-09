"""Moved to :mod:`gangmu.core.plugins`. This alias keeps the old import path working."""
import sys as _sys

from .core import plugins as _moved

_sys.modules[__name__] = _moved
