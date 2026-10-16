"""The libyaml loader builds the same objects as PyYAML's pure-Python one."""

from pathlib import Path

import yaml

from gangmu.core.yamlfast import safe_load


def test_matches_the_python_loader_on_every_installed_rule():
    import gangmu_rules
    root = Path(gangmu_rules.__file__).parent
    texts = [p.read_text(encoding="utf-8") for p in root.rglob("*.y*ml")]
    assert texts
    for text in texts:
        assert safe_load(text) == yaml.safe_load(text)


def test_errors_are_still_yaml_errors():
    import pytest
    with pytest.raises(yaml.YAMLError):
        safe_load("a: [unclosed")
