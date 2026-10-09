"""Moved to :mod:`gangmu.core.globbing`. This alias keeps the old import path working."""
import sys as _sys

from .core import globbing as _moved

_sys.modules[__name__] = _moved
