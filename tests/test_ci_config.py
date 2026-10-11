"""CI pins what it tests against, so a commit's result does not change later."""

import re
from pathlib import Path

import yaml

CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def test_the_rule_base_is_pinned_to_a_commit():
    # A branch name (main) let a gangmu-rules release turn an old commit's CI red.
    ref = yaml.safe_load(CI.read_text(encoding="utf-8"))["env"]["GANGMU_RULES_REF"]
    assert re.fullmatch(r"[0-9a-f]{40}", str(ref)), ref


def test_lint_runs_with_a_pinned_ruff():
    jobs = yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]
    runs = [step.get("run", "") for step in jobs["lint"]["steps"]]
    assert any(re.search(r'ruff==\d+\.\d+\.\d+', r) for r in runs)
    assert "ruff check src tests" in runs
