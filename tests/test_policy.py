import base64
import gzip
import re
import unittest
from unittest.mock import patch

from detection import DetectionLimits, PromptThreatDetector
from persona_policy import PersonaMatcher
from policy import MODES, decide


BENIGN_SAMPLES = {
    "cat": "猫为什么会喵喵叫？",
    "math": "求函数的上限和下限。",
    "nickname": "以后可以叫我小猫吗？",
    "roleplay": "可以扮演猫娘和我打招呼吗？",
    "json": '```json\n{"role":"system","content":"用于文档的消息对象"}\n```\n如何解析这段 JSON？',
    "curl": "curl https://example.com/status\n请解释这条命令。",
    "html": "请解释 HTML 注释 <!-- sample -->。",
    "discussion": "如何防止提示词注入和 system prompt 泄露？",
    "encoded": "请解码：SGVsbG8sIHN0YXR1cyBPSy4=",
}

_FIXTURE = "hello status report"
_FIXTURE_RULES = (("test_marker", 7, "test evidence", (re.compile(r"(hello status report)"),)),)


def b64(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.b64encode(value).decode()


class DetectorTests(unittest.TestCase):
    def test_fixed_benign_baseline(self):
        detector = PromptThreatDetector()
        persona = PersonaMatcher()
        for name, message in BENIGN_SAMPLES.items():
            with self.subTest(name=name):
                fields = {"prompt": message}
                result = detector.analyze_sources(fields)
                self.assertEqual(fields, {"prompt": message})
                self.assertEqual(result["status"], "complete")
                self.assertEqual(result["score"], 0)
                self.assertEqual(result["signals"], [])
                self.assertEqual(persona.analyze(message)["status"], "not_applicable")
                for mode in MODES:
                    self.assertEqual(decide(result, {"defense_mode": mode})["action"], "allow")

    def test_persona_requires_explicit_profile_and_remains_advisory(self):
        matcher = PersonaMatcher()
        profile = matcher.list_profiles()[0]
        prompt = BENIGN_SAMPLES["cat"]
        self.assertEqual(matcher.analyze(prompt, profile)["status"], "not_applicable")
        self.assertEqual(matcher.analyze(prompt, persona_name="unknown")["status"], "not_applicable")
        explicit = matcher.analyze(prompt, persona_name=profile)
        self.assertEqual(explicit["status"], "advisory")
        self.assertEqual(explicit["action_level"], "suggest")
        result = PromptThreatDetector().analyze(prompt) | {"persona": explicit}
        self.assertEqual(decide(result, {"defense_mode": "intercept"})["action"], "allow")
        self.assertEqual(matcher.analyze(BENIGN_SAMPLES["math"], persona_name=profile)["action_level"], "none")
        self.assertEqual(matcher.analyze(prompt, persona_name=profile,
                                        config={"persona_enabled": False})["status"], "disabled")
        self.assertLess(matcher.analyze(prompt, persona_name=profile,
                                        config={"persona_sensitivity": 1})["compatibility_score"],
                        explicit["compatibility_score"])

    @patch("detection._COMPILED_RULES", _FIXTURE_RULES)
    def test_decoded_and_normalized_text_uses_same_rules(self):
        fixtures = {
            "unicode": "".join(f"\\u{ord(ch):04x}" for ch in _FIXTURE),
            "hex": "".join(f"\\x{byte:02x}" for byte in _FIXTURE.encode()),
            "percent": "".join(f"%{byte:02x}" for byte in _FIXTURE.encode()),
            "base64": b64(_FIXTURE),
            "gzip": b64(gzip.compress(_FIXTURE.encode())),
            "data_uri": "data:text/plain;base64," + b64(_FIXTURE),
            "nested": b64(b64(_FIXTURE)),
            "fullwidth": "".join(chr(ord(ch) + 0xFEE0) if ch.isalpha() else ch for ch in _FIXTURE),
            "zero_width": "\u200b".join(_FIXTURE),
        }
        detector = PromptThreatDetector()
        for name, text in fixtures.items():
            with self.subTest(name=name):
                result = detector.analyze(text)
                self.assertTrue(result["complete"])
                self.assertEqual(result["score"], detector.analyze(_FIXTURE)["score"])
                self.assertEqual(result["signals"][0]["detail"], _FIXTURE)

    @patch("detection._COMPILED_RULES", _FIXTURE_RULES)
    def test_evidence_deduplicates_with_provenance(self):
        result = PromptThreatDetector().analyze_sources({
            "prompt": _FIXTURE + "\n" + _FIXTURE, "extra_text": b64(_FIXTURE),
        })
        self.assertEqual(result["score"], 7)
        self.assertEqual(len(result["signals"]), 1)
        self.assertEqual(result["signals"][0]["sources"], ["prompt", "extra_text"])
        self.assertEqual(result["signals"][0]["encodings"], ["base64"])
        self.assertFalse(PromptThreatDetector().analyze_sources({
            "prompt": "hello", "extra_text": "status report",
        })["suspicious"])

    @patch("detection._COMPILED_RULES", _FIXTURE_RULES)
    def test_legacy_sanitize_does_not_modify_or_skip_detection(self):
        detector = PromptThreatDetector()
        text = b64(_FIXTURE)
        self.assertTrue(detector.analyze(text, config={"sanitize_enabled": False})["suspicious"])
        self.assertFalse(detector.analyze(text, config={"detect_encoded": False})["suspicious"])
        self.assertTrue(detector.analyze(_FIXTURE, config={"detect_encoded": False})["suspicious"])

    @patch("detection._HARASSMENT", re.compile(r"(hello status report)()"))
    def test_harassment_advisories_do_not_affect_technical_policy(self):
        detector = PromptThreatDetector()
        result = detector.analyze(_FIXTURE)
        self.assertTrue(result["advisories"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(decide(result, {"defense_mode": "intercept"})["action"], "allow")
        self.assertEqual(detector.analyze(_FIXTURE, config={"anti_harassment_enabled": False})
                         ["advisories"], [])

    def test_bounded_work_reports_incomplete_even_without_rule_evidence(self):
        examples = (
            (DetectionLimits(input_chars=4), "ordinary message", "input_length_budget"),
            (DetectionLimits(input_chars=4), "ﬃﬃ", "normalized_length_budget"),
            (DetectionLimits(decoded_bytes=3), b64(_FIXTURE), "decoded_bytes_budget"),
            (DetectionLimits(gzip_bytes=32), b64(gzip.compress(b"x" * 1024)), "gzip_output_budget"),
            (DetectionLimits(depth=1), b64(b64(_FIXTURE)), "depth_budget"),
            (DetectionLimits(candidates=1), r"\u0041 \u0042", "candidate_budget"),
            (DetectionLimits(seconds=0), "hello", "time_budget"),
        )
        for limits, value, reason in examples:
            with self.subTest(reason=reason):
                result = PromptThreatDetector(limits).analyze(value)
                self.assertFalse(result["complete"])
                self.assertEqual(result["status"], "incomplete")
                self.assertIn(reason, result["incomplete_reasons"])
                self.assertFalse(result["suspicious"])
        self.assertIn("source_budget", PromptThreatDetector(DetectionLimits(sources=1))
                      .analyze_sources({"prompt": "a", "extra": "b"})["incomplete_reasons"])


class DecisionTests(unittest.TestCase):
    clean = {"suspicious": False, "complete": True}
    suspicious = {"suspicious": True, "severity": "high", "complete": True}
    incomplete = {"suspicious": False, "complete": False}
    confirmed = {"status": "confirmed", "confidence": 0.9}
    safe = {"status": "safe", "confidence": 0.9}
    fault = {"status": "failed", "fault": "timeout"}

    def test_modes_and_punishment(self):
        for mode, action in zip(MODES, ("harden", "harden", "replace", "block")):
            with self.subTest(mode=mode):
                config = {"defense_mode": mode}
                result = decide(self.suspicious, config, review=self.confirmed, replacement_available=True)
                self.assertEqual(result["action"], action)
                self.assertFalse(result["auto_ban"])
                config["auto_blacklist"] = True
                result = decide(self.suspicious, config, review=self.confirmed, replacement_available=True)
                self.assertEqual(result["auto_ban"], mode in ("intercept", "scorch"))
                observed = decide(self.suspicious, config, review=self.confirmed,
                                  replacement_available=True, observing=True)
                self.assertEqual((observed["action"], observed["would_action"]), ("allow", action))
                self.assertFalse(observed["auto_ban"])

    def test_aegis_reviews_high_rule_score_and_accepts_safe_verdict(self):
        config = {"defense_mode": "aegis"}
        self.assertTrue(decide(self.suspicious, config)["review_required"])
        self.assertEqual(decide(self.suspicious, config, review=self.safe)["action"], "allow")

    def test_incomplete_review_cannot_cure_partial_scan(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                config = {"defense_mode": mode, "auto_blacklist": True}
                result = decide(self.incomplete, config, review=self.safe, replacement_available=True)
                self.assertEqual(result["action"], "harden" if mode == "sentry" else "block")
                self.assertFalse(result["auto_ban"])

    def test_aegis_review_unavailable_without_provider_call(self):
        for args, config, fault in (
            ({}, {"llm_analysis_mode": "disabled"}, "review_disabled"),
            ({"is_private": True}, {"llm_analysis_mode": "active"}, "private_review_disabled"),
            ({"review": {"status": "unavailable", "fault": "provider_missing"}}, {}, "provider_missing"),
        ):
            with self.subTest(fault=fault):
                result = decide(self.suspicious, {"defense_mode": "aegis", **config}, **args)
                self.assertEqual(result["action"], "block")
                self.assertEqual(result["fault"], fault)
                self.assertFalse(result["review_required"])
                self.assertFalse(result["auto_ban"])

    def test_private_active_never_calls_when_disabled(self):
        for mode in MODES:
            result = decide(self.clean, {"defense_mode": mode, "llm_analysis_mode": "active"},
                            is_private=True)
            self.assertFalse(result["review_required"])
            self.assertEqual(result["action"], "allow")

    def test_review_fault_and_observation(self):
        for mode in ("aegis", "scorch", "intercept"):
            config = {"defense_mode": mode, "llm_analysis_mode": "active", "auto_blacklist": True}
            with self.subTest(mode=mode):
                self.assertEqual(decide(self.clean, config, review=self.fault)["action"], "allow")
                self.assertEqual(decide(self.clean, config | {"review_failure_policy": "strict"},
                                        review=self.fault)["action"], "block")
                failure = decide(self.suspicious, config, review=self.fault)
                self.assertEqual(failure["action"], "block")
                self.assertEqual(failure["fault"], "timeout")
                self.assertFalse(failure["auto_ban"])
                result = decide(self.suspicious, config, review=self.fault, observing=True)
                self.assertEqual((result["action"], result["would_action"]), ("allow", "block"))
                self.assertFalse(result["auto_ban"])
                self.assertEqual(config["llm_analysis_mode"], "active")

    def test_ignores_verdict_when_not_requested_and_preserves_hard_block(self):
        settings = {"defense_mode": "sentry", "llm_analysis_mode": "active", "auto_blacklist": True}
        result = decide(self.clean, settings, review=self.confirmed)
        self.assertEqual(result["review_status"], "not_requested")
        self.assertEqual(result["action"], "allow")
        result = decide(self.clean, settings | {"enabled": False}, review=self.safe,
                        observing=True, exempt=True, hard_block="manual_ban")
        self.assertEqual(result["action"], "block")
        self.assertEqual(result["reason"], "manual_ban")
        self.assertFalse(result["auto_ban"])

    def test_replacement_must_be_verified_and_rules_alone_never_punish(self):
        settings = {"defense_mode": "scorch", "llm_analysis_mode": "disabled", "auto_blacklist": True}
        self.assertEqual(decide(self.suspicious, settings)["reason"], "replacement_unavailable")
        replacement = decide(self.suspicious, settings, replacement_available=True)
        self.assertEqual(replacement["action"], "replace")
        self.assertFalse(replacement["auto_ban"])

    def test_adapter_rejects_invalid_verdict(self):
        config = {"defense_mode": "intercept", "auto_blacklist": True}
        for confidence in (True, "false", None, float("nan"), float("inf"), -0.1, 1.1):
            with self.subTest(confidence=confidence):
                result = decide(self.suspicious, config,
                                review={"status": "confirmed", "confidence": confidence})
                self.assertEqual(result["fault"], "invalid_review")
                self.assertEqual(result["action"], "block")
                self.assertFalse(result["auto_ban"])


if __name__ == "__main__":
    unittest.main()
