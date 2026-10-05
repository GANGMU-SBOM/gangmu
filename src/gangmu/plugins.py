"""Entry-point plug-ins.

Two groups are read:

* ``gangmu.rule_packs`` -- installed rule bases (see :mod:`gangmu.rules.packs`).
* ``gangmu.commands``   -- extra ``gangmu`` subcommands. The entry point names a
  callable taking the CLI's subparsers object; it adds its parser and sets
  ``func`` like a built-in command does::

      def register(subparsers):
          p = subparsers.add_parser("hello", help="...")
          p.set_defaults(func=lambda args: 0)

A plug-in that fails to load prints a warning and is skipped: an add-on must
never be able to take the open-source commands down with it.
"""

from __future__ import annotations

import sys
from typing import List

COMMAND_GROUP = "gangmu.commands"


def entry_points(group: str) -> List:
    from importlib.metadata import entry_points as _all
    eps = _all()
    if hasattr(eps, "select"):
        return list(eps.select(group=group))
    return list(eps.get(group, []))         # Python 3.9


def register_commands(subparsers) -> None:
    for ep in entry_points(COMMAND_GROUP):
        try:
            ep.load()(subparsers)
        except Exception as exc:
            print(f"warning: gangmu plug-in '{ep.name}' could not be loaded: {exc}",
                  file=sys.stderr)
