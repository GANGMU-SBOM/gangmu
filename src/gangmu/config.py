"""Project configuration.

Most of what CRA asks for is not in the source tree. Which member states the
product is placed on the market in, who the manufacturer is, when the support
period ends, where the coordinated-disclosure policy lives -- a tool cannot
derive any of that, and a team should not retype it on every command line.

So it lives in one file at the project root, written once, and every command
reads it: the SBOM's metadata, the CRA self-check and the incident-report
drafts all come from the same declaration. When a field is missing the tool
says which obligation it blocks, rather than silently producing a document with
a hole in it.

``gangmu.yaml`` is the canonical form. ``gangmu.toml`` is read too on Python
3.11+, because a lot of teams keep project config in TOML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

CONFIG_NAMES = ("gangmu.yaml", "gangmu.yml", "gangmu.toml")

TEMPLATE = """\
# gangmu project configuration. Everything here is a fact only your team knows;
# the tool derives the rest. Fields marked REQUIRED block a CRA obligation when
# left empty -- `gangmu cra-check` will tell you which.

product:
  name: ""                 # REQUIRED. As placed on the market, not the repo name.
  version: ""              # REQUIRED. The released firmware version.
  description: ""
  # Annex III class, if any: "default", "important-i", "important-ii", "critical".
  # Decides the conformity assessment route; "default" means self-assessment.
  class: default

manufacturer:
  name: ""                 # REQUIRED for any Article 14 notification.
  contact: ""              # REQUIRED. Article 13: a single point of contact.
  # Annex I Part II(6): a contact address for reporting vulnerabilities found in
  # the product. Often a security.txt URL or a dedicated mailbox.
  vulnerability_contact: ""
  # Annex I Part II(5): the coordinated vulnerability disclosure policy.
  cvd_policy_url: ""

market:
  # Article 14(1): a notification names the member states the product is
  # available in. ISO 3166-1 alpha-2, or ["EU"] for the whole union.
  member_states: []
  placed_on_market: ""     # ISO date; starts the support-period clock.

support:
  # Article 13(8): at least five years, unless the expected lifetime is shorter.
  period_ends: ""          # ISO date.
  security_update_channel: ""   # how updates reach devices in the field

reporting:
  # Article 14 notifications go through the ENISA Single Reporting Platform.
  # The platform has no API at its first release, so these are what the drafts
  # are pre-filled with; a human still pastes them in.
  csirt: ""                # the coordinating CSIRT you registered with
  assigned_representative: ""   # the person holding the EU Login account

build:
  # Defaults for `gangmu scan`, so CI and a developer's laptop agree.
  root: "."
  compile_db: ""
  link_map: ""
  project: ""
  rules: ""

china:
  # 《网络产品安全漏洞管理规定》（工信部等 2021 年第 28 号令）第七条：
  # 网络产品提供者发现漏洞后 2 日内向工业和信息化部网络安全威胁和漏洞信息
  # 共享平台（cstis.cn）报送。触发条件比 CRA 更宽：不以被积极利用为前提。
  in_china_market: true    # 产品是否在中国境内提供
  model: ""                # 产品型号；报送要求产品名称、型号、版本三项
  contact: ""              # 报送联系人及联系方式
  exports_to_eu: false     # 同时出口欧盟时，工具会提示双重报送义务的冲突点

retention:
  # Article 13(14): technical documentation is kept for ten years after the
  # product is placed on the market, or for the support period if longer.
  years: 10
"""


@dataclass
class Config:
    path: Optional[Path] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def section(self, name: str) -> Dict[str, Any]:
        value = self.raw.get(name)
        return value if isinstance(value, dict) else {}

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        if node in ("", [], {}, None):
            return default
        return node

    @property
    def product_name(self) -> Optional[str]:
        return self.get("product.name")

    @property
    def product_version(self) -> Optional[str]:
        return self.get("product.version")


def find_config(start: Optional[Path] = None) -> Optional[Path]:
    here = Path(start or Path.cwd()).resolve()
    for directory in [here, *here.parents]:
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load_config(path: Optional[Path] = None) -> Config:
    found = Path(path) if path else find_config()
    if found is None:
        return Config()
    text = found.read_text(encoding="utf-8")
    if found.suffix == ".toml":
        try:
            import tomllib
        except ModuleNotFoundError:          # Python 3.9 / 3.10
            raise RuntimeError(
                f"{found.name} needs Python 3.11 or newer to read TOML; "
                f"rename it to gangmu.yaml or upgrade Python")
        return Config(path=found, raw=tomllib.loads(text))
    return Config(path=found, raw=yaml.safe_load(text) or {})


def write_template(path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE, encoding="utf-8")
    return path
