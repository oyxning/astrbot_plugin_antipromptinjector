import re
from collections.abc import Mapping
from math import isfinite
from typing import Any, Dict, List, Optional


class PersonaProfile:
    def __init__(
        self,
        name: str,
        description: str,
        speech_style_markers: Optional[List[str]] = None,
        allowed_behaviors: Optional[List[str]] = None,
        forbidden_patterns: Optional[List[Dict[str, Any]]] = None,
        references: Optional[List[str]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self.speech_style_markers = speech_style_markers or []
        self.allowed_behaviors = allowed_behaviors or []
        self.forbidden_patterns = forbidden_patterns or []
        self.references = references or []


class PersonaMatcher:
    """
    Persona consistency checker and scorer.

    - Computes a 0–100 compatibility score of a user request against persona constraints
    - Produces a structured conflict report with references and suggested compliant phrasing
    - Advisory only: results do not feed technical risk, blocking, or punishment.
    """

    def __init__(self, sensitivity: float = 0.7) -> None:
        self.sensitivity = self._sensitivity(sensitivity)
        self._profiles: Dict[str, PersonaProfile] = {}
        self._register_default_profiles()

    def _register_default_profiles(self) -> None:
        # 示例人设：丰川祥子大小姐
        # 典型行为准则：
        # - 言语优雅克制，不做幼稚或拟声类行为（如“喵喵喵”）
        # - 保持淑女风范，避免粗俗/低幼/恶俗调侃
        # - 拒绝违背身份设定的过度亲昵或角色崩坏请求
        forbidden = [
            {
                "name": "幼稚拟声行为",
                "pattern": r"喵喵喵|喵{2,}|mew|にゃ[ー~]*",
                "severity": 3,
                "rule": "保持淑女风范，避免幼稚拟声行为",
                "suggestion": "可改为端庄回应或用温婉措辞表达情绪。",
            },
            {
                "name": "粗俗调侃",
                "pattern": r"(土味情话|骚话|下流|低幼|幼稚|粗俗)",
                "severity": 2,
                "rule": "用语需克制优雅，避免粗俗或低幼表达",
                "suggestion": "改用礼貌且含蓄的措辞，保持角色气质。",
            },
            {
                "name": "角色设定破坏",
                "pattern": r"(装可爱|卖萌|撒娇|嗲嗲|扮演猫娘)",
                "severity": 2,
                "rule": "避免违背“大小姐”设定的过度亲昵与卖萌行为",
                "suggestion": "以端庄方式表达，或婉拒该类请求。",
            },
        ]

        profile = PersonaProfile(
            name="丰川祥子大小姐",
            description=(
                "端庄优雅的大小姐人设。措辞克制，不搞幼稚或拟声，"
                "维持礼仪与气质，不做粗俗或卖萌行为。"
            ),
            speech_style_markers=["端庄", "优雅", "克制", "礼貌"],
            allowed_behaviors=["礼貌交流", "理性讨论", "得体回应"],
            forbidden_patterns=forbidden,
            references=[
                "人设准则 #1：保持淑女风范与礼仪",
                "人设准则 #2：用语克制优雅，避免低幼表达",
                "人设准则 #3：避免破坏既有人设设定的行为",
            ],
        )
        self._profiles[profile.name] = profile

    def list_profiles(self) -> List[str]:
        return list(self._profiles.keys())

    def get_profile(self, persona_name: Optional[str]) -> Optional[PersonaProfile]:
        return self._profiles.get(persona_name) if persona_name else None

    def analyze(
        self,
        prompt: str,
        system_prompt: str = "",
        persona_name: Optional[str] = None,
        *,
        config: Mapping | None = None,
    ) -> Dict[str, Any]:
        # A name mentioned in free-form system text does not select a policy.
        config = config or {}
        enabled = config.get("persona_enabled", True) is not False
        profile = self.get_profile(persona_name) if enabled else None
        if profile is None:
            return {
                "status": "not_applicable" if enabled else "disabled",
                "persona_name": None,
                "compatibility_score": None,
                "action_level": "none",
                "reason": "未选择适用的人设规则" if enabled else "已关闭人设建议",
                "conflicts": [],
                "references": [],
                "suggestions": [],
            }

        score = 100
        conflicts: List[Dict[str, Any]] = []
        sensitivity = self._sensitivity(config.get("persona_sensitivity", self.sensitivity))

        text = (prompt or "")[:16_384].lower()
        # 基于禁则库的正则匹配
        for item in profile.forbidden_patterns:
            pattern = item.get("pattern", "")
            try:
                match = re.search(pattern, text, re.I) if pattern else None
                if match:
                    severity = int(item.get("severity", 1))
                    penalty = self._penalty_by_severity(severity)
                    penalty = int(penalty * sensitivity)
                    score = max(0, score - penalty)
                    conflicts.append(
                        {
                            "name": item.get("name", "违规行为"),
                            "rule": item.get("rule", "行为违反人设准则"),
                            "severity": severity,
                            "snippet": match[0],
                            "suggestion": item.get("suggestion", "请改为符合人设的表达。"),
                        }
                    )
            except re.error:
                # 忽略无效正则
                continue

        return {
            "status": "advisory",
            "persona_name": profile.name,
            "compatibility_score": int(score),
            "action_level": "suggest" if conflicts else "none",
            "reason": "人设建议，不影响安全判断" if conflicts else "未命中人设建议",
            "conflicts": conflicts,
            "references": list(profile.references),
            "suggestions": [c.get("suggestion") for c in conflicts if c.get("suggestion")],
        }

    @staticmethod
    def _sensitivity(value: float) -> float:
        try:
            value = float(value)
        except (TypeError, ValueError, OverflowError):
            return 0.7
        return max(0.1, min(1.0, value)) if isfinite(value) else 0.7

    @staticmethod
    def _penalty_by_severity(sev: int) -> int:
        # 1:10, 2:25, 3:50 作为基准罚分
        if sev >= 3:
            return 50
        if sev == 2:
            return 25
        return 10
