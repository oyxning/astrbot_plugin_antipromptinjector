import re
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
    - Action levels:
        * none: no conflict
        * suggest: minor deviation, provide alternatives
        * revise: adjustable violation, ask for correction
        * block: severe violation, fully block
    """

    def __init__(self, sensitivity: float = 0.7) -> None:
        # sensitivity ∈ [0,1]; higher means stricter penalties
        self.sensitivity = max(0.1, min(1.0, sensitivity))
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
                "pattern": r"(土味情话|骚话|下流|下限|低幼|幼稚|粗俗)",
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

    def get_profile(self, persona_name: Optional[str]) -> PersonaProfile:
        if persona_name and persona_name in self._profiles:
            return self._profiles[persona_name]
        # 默认人设：丰川祥子大小姐
        return self._profiles["丰川祥子大小姐"]

    def analyze(
        self,
        prompt: str,
        system_prompt: str = "",
        persona_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        persona = self._infer_persona(system_prompt, persona_name)
        profile = self.get_profile(persona)

        score = 100
        conflicts: List[Dict[str, Any]] = []

        text = (prompt or "").lower()
        # 基于禁则库的正则匹配
        for item in profile.forbidden_patterns:
            pattern = item.get("pattern", "")
            try:
                if pattern and re.search(pattern, text, re.I):
                    severity = int(item.get("severity", 1))
                    penalty = self._penalty_by_severity(severity)
                    penalty = int(penalty * self.sensitivity)
                    score = max(0, score - penalty)
                    conflicts.append(
                        {
                            "name": item.get("name", "违规行为"),
                            "rule": item.get("rule", "行为违反人设准则"),
                            "severity": severity,
                            "snippet": self._extract_snippet(text, pattern),
                            "suggestion": item.get("suggestion", "请改为符合人设的表达。"),
                        }
                    )
            except re.error:
                # 忽略无效正则
                continue

        # 根据分数与最高严重级别决定动作等级
        max_severity = max([c.get("severity", 1) for c in conflicts], default=0)
        action_level, reason = self._decide_action(score, max_severity)

        return {
            "persona_name": profile.name,
            "compatibility_score": int(score),
            "action_level": action_level,
            "reason": reason,
            "conflicts": conflicts,
            "references": profile.references,
            "suggestions": [c.get("suggestion") for c in conflicts if c.get("suggestion")],
        }

    def _infer_persona(self, system_prompt: str, persona_name: Optional[str]) -> Optional[str]:
        if persona_name:
            return persona_name
        text = (system_prompt or "")
        # 简单的系统 prompt 人设识别：
        for key in self._profiles.keys():
            if key in text:
                return key
        # 未指定则返回默认
        return None

    @staticmethod
    def _penalty_by_severity(sev: int) -> int:
        # 1:10, 2:25, 3:50 作为基准罚分
        if sev >= 3:
            return 50
        if sev == 2:
            return 25
        return 10

    @staticmethod
    def _extract_snippet(text: str, pattern: str) -> str:
        try:
            match = re.search(pattern, text, re.I)
            if not match:
                return ""
            start = max(0, match.start() - 12)
            end = min(len(text), match.end() + 12)
            snippet = text[start:end]
            return snippet
        except Exception:
            return ""

    def _decide_action(self, score: int, max_severity: int) -> (str, str):
        # 根据分数和最高严重级别给出动作等级及原因说明
        if max_severity >= 3 or score < 50:
            return "block", "人设冲突严重，已触发完全阻止"
        if score < 80:
            return "revise", "人设存在可调整的违规，建议修正后再请求"
        if score < 95:
            return "suggest", "人设轻微偏差，提供替代方案建议"
        return "none", "人设一致性良好"