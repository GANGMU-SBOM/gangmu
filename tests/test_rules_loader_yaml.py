"""The libyaml loader builds the same objects as PyYAML's pure-Python one."""

import os
from pathlib import Path

import yaml

from gangmu.core.yamlfast import safe_load


def test_matches_the_python_loader_on_every_installed_rule():
    import gangmu_rules
    # An editable install of gangmu-rules has no data/ beside the package; CI points
    # GANGMU_RULES at the checkout's rules/ instead.
    roots = [Path(gangmu_rules.__file__).parent]
    if os.environ.get("GANGMU_RULES"):
        roots.append(Path(os.environ["GANGMU_RULES"]))
    texts = [p.read_text(encoding="utf-8") for r in roots for p in r.rglob("*.y*ml")]
    assert texts
    for text in texts:
        assert safe_load(text) == yaml.safe_load(text)


def test_errors_are_still_yaml_errors():
    import pytest
    with pytest.raises(yaml.YAMLError):
        safe_load("a: [unclosed")
