"""《网络产品安全漏洞管理规定》报送草稿。

为什么必须单独做
----------------
对出口欧盟的中国厂商，CRA 不是唯一的报送义务，而且不是最宽的那个。
工信部、网信办、公安部 2021 年第 28 号令《网络产品安全漏洞管理规定》
自 2021 年 9 月 1 日施行，第七条要求网络产品提供者**发现漏洞后 2 日内**
向工业和信息化部网络安全威胁和漏洞信息共享平台报送。

与 CRA 第 14 条的差别是实质性的：

* **范围更宽。** CRA 报送的是"被积极利用的"漏洞；本规定报送的是"发现"的
  漏洞，不以被利用为前提。
* **时限不同。** CRA 是 24 小时预警 / 72 小时通报；本规定是 2 日内。
* **字段不同。** 本规定要求产品名称、型号、版本，漏洞的技术特点、危害程度
  和影响范围。

一个只做 CRA 的工具会让中国厂商漏掉本土那条，而本土那条触发得更频繁。

一个工具不该替人下的法律结论
----------------------------
第九条第（七）项规定，不得将未公开的网络产品安全漏洞信息向网络产品提供者
之外的境外组织或者个人提供。条文**未设例外**。而 CRA 第 14 条要求向 ENISA
与成员国 CSIRT 报送尚未公开的漏洞。

这两条之间是否构成冲突、如何处理，是法务判断，不是工具判断。工具能做的、
也应该做的，是在生成欧盟报送草稿时把这件事摆到桌面上，而不是让团队在
24 小时倒计时的第 20 小时才第一次想到它。
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import Config

MIIT_STAGES = ("report", "update")

_PLATFORM = "工业和信息化部网络安全威胁和漏洞信息共享平台（cstis.cn）"

CONFLICT_NOTICE = """\
⚠ 双重报送义务提示（需法务确认，工具不下结论）

《网络产品安全漏洞管理规定》（工信部、网信办、公安部 2021 年第 28 号令）
第九条第（七）项：不得将未公开的网络产品安全漏洞信息，向网络产品提供者
之外的境外组织或者个人提供。该条未设例外情形。

欧盟 CRA 第 14 条：制造商应在知悉被积极利用的漏洞后 24 小时内向 ENISA 与
相关成员国 CSIRT 预警，72 小时内正式通报。被报送的漏洞在此时通常尚未公开。

如果贵司产品同时在中国境内提供并出口欧盟，这两项义务可能在同一事件上同时
触发。工具不判断是否构成冲突，也不建议任何一种处理方式——这需要法务在报送
发生之前给出意见，而不是在倒计时里临时决定。

建议在《网络产品安全漏洞管理规定》报送与 CRA 报送之间，预先确定：
  1. 两边各自的触发条件与时限（本规定 2 日内；CRA 24 小时 / 72 小时）
  2. 境外报送的内部审批路径与留痕方式
  3. 漏洞信息公开的时点与顺序
"""


@dataclass
class MiitField:
    label: str
    value: str
    required: bool = True
    source: str = ""

    @property
    def filled(self) -> bool:
        return bool(self.value.strip())


@dataclass
class MiitDraft:
    stage: str
    deadline: str
    fields: List[MiitField] = field(default_factory=list)
    notices: List[str] = field(default_factory=list)

    @property
    def missing(self) -> List[MiitField]:
        return [f for f in self.fields if f.required and not f.filled]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "regime": "cn-miit",
            "stage": self.stage,
            "deadline": self.deadline,
            "platform": _PLATFORM,
            "fields": [{"label": f.label, "value": f.value, "required": f.required,
                        "source": f.source} for f in self.fields],
            "missing": [f.label for f in self.missing],
            "notices": self.notices,
        }

    def to_markdown(self) -> str:
        lines = [
            "# 网络产品安全漏洞报送草稿",
            "",
            "依据：《网络产品安全漏洞管理规定》第七条",
            f"**时限：{self.deadline}**",
            f"**报送平台：{_PLATFORM}**",
            "",
            "| 字段 | 内容 | 来源 |",
            "| --- | --- | --- |",
        ]
        for f in self.fields:
            value = f.value.replace("\n", "<br>") if f.filled else (
                "**— 缺失 —**" if f.required else "_（选填，未提供）_")
            lines.append(f"| {f.label} | {value} | {f.source} |")
        if self.missing:
            lines += ["", "## 提交前需要补齐", ""]
            lines += [f"- **{f.label}** — {f.source}" for f in self.missing]
        for notice in self.notices:
            lines += ["", "---", "", notice]
        return "\n".join(lines)


def _component_for(vex: Optional[dict], advisory_id: str) -> Dict[str, str]:
    if not vex:
        return {}
    for vuln in vex.get("vulnerabilities") or []:
        if vuln.get("id") != advisory_id:
            continue
        refs = {a.get("ref") for a in vuln.get("affects") or []}
        for component in vex.get("components") or []:
            if component.get("bom-ref") in refs:
                return {
                    "name": component.get("name", ""),
                    "version": component.get("version", ""),
                    "description": vuln.get("description", ""),
                    "severity": ((vuln.get("ratings") or [{}])[0]).get("severity", ""),
                    "detail": (vuln.get("analysis") or {}).get("detail", ""),
                }
        return {"name": "", "version": "",
                "description": vuln.get("description", ""),
                "severity": ((vuln.get("ratings") or [{}])[0]).get("severity", ""),
                "detail": (vuln.get("analysis") or {}).get("detail", "")}
    return {}


_SEVERITY_CN = {"critical": "严重", "high": "高危", "medium": "中危",
                "low": "低危", "none": "无", "unknown": "未评估"}


def draft_miit_report(config: Config, advisory_id: str,
                      vex: Optional[dict] = None,
                      found_at: Optional[str] = None,
                      impact: str = "",
                      scope: str = "",
                      measures: str = "",
                      stage: str = "report") -> MiitDraft:
    if stage not in MIIT_STAGES:
        raise ValueError(f"stage 必须是 {MIIT_STAGES} 之一")

    component = _component_for(vex, advisory_id)
    found = found_at or _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    deadline = "自发现之日起 2 日内" if stage == "report" else "情况变化后及时补充"

    def cfg(key: str, label: str, why: str, required: bool = True) -> MiitField:
        value = config.get(key)
        return MiitField(label=label, value=str(value) if value else "",
                         required=required,
                         source=f"gangmu.yaml：{key}" if value
                         else f"请填写 {key} —— {why}")

    severity = component.get("severity", "")
    draft = MiitDraft(stage=stage, deadline=deadline)
    draft.fields = [
        cfg("manufacturer.name", "产品提供者名称", "报送主体"),
        cfg("product.name", "产品名称", "第七条要求载明产品名称"),
        MiitField("产品型号",
                  str(config.get("china.model") or config.get("product.name") or ""),
                  source="gangmu.yaml：china.model"
                  if config.get("china.model") else
                  "未单独填写 china.model，已回退到产品名称"),
        cfg("product.version", "产品版本", "第七条要求载明版本"),
        MiitField("漏洞编号", advisory_id, required=False,
                  source="命令行参数"),
        MiitField("发现时间", found,
                  source="命令行参数 --found-at" if found_at
                  else "默认取当前时间，请改为实际发现时间"),
        MiitField("漏洞的技术特点",
                  component.get("description", "") or impact,
                  source="取自 VEX 中的漏洞描述" if component.get("description")
                  else "请填写技术特点"),
        MiitField("受影响的开源组件及版本",
                  (f"{component.get('name','')} {component.get('version','')}".strip()
                   or ""),
                  required=False,
                  source="取自 SBOM —— 这是本工具相对手工填报的主要价值"),
        MiitField("危害程度",
                  _SEVERITY_CN.get(severity.lower(), severity) if severity else impact,
                  source="取自 VEX 评级" if severity else "请评估危害程度"),
        MiitField("影响范围", scope,
                  source="命令行参数 --scope" if scope
                  else "请填写受影响的产品范围、批次或装机量"),
        MiitField("已采取的措施", measures, required=False,
                  source="命令行参数 --measures"),
        cfg("china.contact", "联系人及联系方式", "平台报送需要联系人",
            required=False),
    ]

    if component.get("detail"):
        draft.notices.append(f"VEX 判定说明：{component['detail']}")
    if config.get("china.exports_to_eu") or config.get("market.member_states"):
        draft.notices.append(CONFLICT_NOTICE)
    return draft


def check_dual_regime(config: Config) -> List[str]:
    """两套义务同时适用时，把差异摆出来。"""
    notes: List[str] = []
    in_cn = bool(config.get("china.in_china_market", True))
    in_eu = bool(config.get("market.member_states"))
    if in_cn and in_eu:
        notes.append(
            "产品同时在中国境内提供并在欧盟市场投放：《网络产品安全漏洞管理"
            "规定》第七条（发现后 2 日内报工信部平台）与 CRA 第 14 条"
            "（24 小时预警 / 72 小时通报 ENISA）可能在同一事件上同时触发。")
        notes.append(
            "两者触发条件不同：本规定报送"
            "“发现的漏洞”，不以被积极利用为前提；CRA 报送"
            "“被积极利用的漏洞”。前者触发更频繁。")
        notes.append(CONFLICT_NOTICE)
    elif in_eu:
        notes.append("仅标注了欧盟市场。若产品同时在中国境内提供，"
                     "请设置 china.in_china_market 并复核本土报送义务。")
    return notes
