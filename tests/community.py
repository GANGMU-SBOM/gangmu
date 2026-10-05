"""Where the tests find the community rule base.

The rules live in their own repository and distribution (``gangmu-rules``).
Tests that check the tool against the real rules use, in order: the first
directory in ``GANGMU_RULES``, or the installed ``gangmu_rules`` package. With
neither, those tests are skipped -- unless ``GANGMU_REQUIRE_RULES`` is set, as
it is in CI, where a missing rule base is an error rather than a quiet skip.
"""

import os
from pathlib import Path
from typing import Optional

import pytest


def _find() -> Optional[Path]:
    env = os.environ.get("GANGMU_RULES")
    if env:
        return Path(env.split(os.pathsep)[0])
    try:
        import gangmu_rules
    except ImportError:
        return None
    return Path(gangmu_rules.path())


REPO_RULES = _find()
if REPO_RULES is None and os.environ.get("GANGMU_REQUIRE_RULES"):
    raise RuntimeError("GANGMU_REQUIRE_RULES is set but no rule base was found: "
                       "pip install gangmu-rules, or set GANGMU_RULES")

needs_rules = pytest.mark.skipif(
    REPO_RULES is None,
    reason="community rule base not installed (pip install gangmu-rules)")
