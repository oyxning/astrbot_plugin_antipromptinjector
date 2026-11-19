import unittest
from types import SimpleNamespace
from unittest.mock import patch

from request_input import MAX_EXTRA_PARTS, InputBlock, inspect_input, isolate


class Plain:
    def __init__(self, text):
        self.text = text


class TextPart:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class ImagePart:
    pass


def event(text, *components):
    return SimpleNamespace(
        message_str=text,
        message_obj=SimpleNamespace(message=list(components) or [Plain(text)]),
    )


def request(prompt, **overrides):
    fields = dict(
        prompt=prompt, session_id="session", image_urls=[], audio_urls=[],
        extra_user_content_parts=[], func_tool=None, contexts=[], system_prompt="",
        conversation=None, tool_calls_result=None, model=None,
    )
    return SimpleNamespace(**(fields | overrides))


class Opaque:
    def __bool__(self):
        raise AssertionError("Must not inspect opaque host objects")

    def __repr__(self):
        raise AssertionError("Must not serialize opaque host objects")


class RequestInputTests(unittest.TestCase):
    def setUp(self):
        host_types = patch(
            "request_input._host_text_types", return_value=(Plain, TextPart, (ImagePart,)),
        )
        host_types.start()
        self.addCleanup(host_types.stop)

    def test_exact_plain_message_is_attributable(self):
        text = "How are upper and lower limits defined?"
        incoming = event(text, Plain("How are "), Plain("upper and lower limits defined?"))
        result = inspect_input(incoming, request(text))
        self.assertEqual(result.blocks, (InputBlock("prompt", text, True),))
        self.assertEqual(result.incomplete_reasons, ())
        self.assertTrue(result.attributable)
        self.assertEqual(result.review_text, text)

    def test_mismatched_or_nonplain_event_prompt_not_exported(self):
        text = "Hi"
        for incoming, prompt in (
            (event(text), "Added prefix: Hi"),
            (event(text, Plain(text), Opaque()), text),
            (event(text, Plain("Not the same text")), text),
            (None, text),
        ):
            with self.subTest(prompt=prompt):
                result = inspect_input(incoming, request(prompt))
                self.assertEqual(result.blocks, (InputBlock("prompt", prompt, False),))
                self.assertEqual(result.incomplete_reasons, ())
                self.assertIn("unverified_prompt_source", result.attribution_reasons)
                self.assertEqual(result.review_unavailable_reason, "unverified_text_source")
                self.assertFalse(result.attributable)
                self.assertIsNone(result.review_text)

    def test_mixed_parts_local_only_regardless_of_their_text(self):
        text = "Current message"
        req = request(text, extra_user_content_parts=[
            TextPart("retrieval"), {"type": "text", "text": "host reminder", "_no_save": True},
            {"type": "text", "text": text},
        ])
        before = req.extra_user_content_parts[:]
        result = inspect_input(event(text), req)
        self.assertEqual(result.blocks, (
            InputBlock("prompt", text, True),
            InputBlock("extra_user_content_parts", "retrieval", False, 0),
            InputBlock("extra_user_content_parts", "host reminder", False, 1),
            InputBlock("extra_user_content_parts", text, False, 2),
        ))
        self.assertEqual(result.incomplete_reasons, ())
        self.assertIn("mixed_extra_source", result.attribution_reasons)
        self.assertFalse(result.attributable)
        self.assertIsNone(result.review_text)
        self.assertEqual(result.review_unavailable_reason, "unverified_text_source")
        self.assertEqual(result.prompt_review_text, text)
        for actual, original in zip(req.extra_user_content_parts, before, strict=True):
            self.assertIs(actual, original)

    def test_media_tools_history_and_system_are_not_traversed_or_exported(self):
        text = "Current message"
        result = inspect_input(event(text), request(
            text, contexts=[{"content": "private history"}], system_prompt="private system",
            image_urls=["original.jpeg"], audio_urls=["original.wav"], func_tool=Opaque(),
            tool_calls_result=Opaque(), conversation=Opaque(),
            extra_user_content_parts=[
                {"type": "image_url", "image_url": Opaque()},
                {"type": "audio_url", "audio_url": Opaque()},
                ImagePart(),
                Opaque(),
            ],
        ))
        self.assertEqual(result.blocks, (InputBlock("prompt", text, True),))
        self.assertEqual(result.review_text, text)
        self.assertFalse(result.attributable)
        self.assertEqual(result.incomplete_reasons, ())
        self.assertEqual(set(result.uncovered_fields), {
            "contexts", "system_prompt", "image_urls", "audio_urls",
            "func_tool", "tool_calls_result", "conversation",
            "extra_user_content_parts", "extra_user_content_parts.media",
        })

    def test_event_components_remain_uncovered_even_without_request_media(self):
        result = inspect_input(event("hi", Plain("hi"), ImagePart()), request("hi"))
        self.assertIn("event.message_obj.message", result.uncovered_fields)
        self.assertEqual(result.incomplete_reasons, ())
        self.assertIsNone(result.review_text)

    def test_disabling_extra_scan_leaves_other_budget_and_coverage_intact(self):
        text = "hello"
        result = inspect_input(event(text), request(
            text, extra_user_content_parts=[TextPart("too big to scan")] * (MAX_EXTRA_PARTS + 1),
        ), max_chars=len(text), scan_extra_text=False)
        self.assertEqual(result.blocks, (InputBlock("prompt", text, True),))
        self.assertEqual(result.incomplete_reasons, ())
        self.assertIn("extra_user_content_parts", result.uncovered_fields)
        self.assertFalse(result.attributable)
        self.assertEqual(result.review_text, text)

    def test_character_and_candidate_budgets_do_not_truncate(self):
        text = "Current"
        result = inspect_input(event(text), request(
            text, extra_user_content_parts=[TextPart("short")] * (MAX_EXTRA_PARTS + 1),
        ), max_chars=12)
        self.assertEqual([block.text for block in result.blocks], ["Current", "short"])
        self.assertIn("part_budget", result.incomplete_reasons)
        self.assertIn("text_budget", result.incomplete_reasons)
        self.assertEqual(result.review_unavailable_reason, "incomplete_text")
        self.assertFalse(result.attributable)
        oversized = inspect_input(event(text), request(text), max_chars=len(text) - 1)
        self.assertEqual(oversized.blocks, ())
        self.assertIsNone(oversized.review_text)
        self.assertEqual(oversized.incomplete_reasons, ("text_budget",))

    def test_unknown_fields_and_unsupported_shapes_are_explicit(self):
        text = "Current message"
        result = inspect_input(event(text), request(text, unsurveyed=Opaque()))
        self.assertIn("unknown_request_fields", result.uncovered_fields)
        self.assertEqual(result.incomplete_reasons, ())
        self.assertFalse(result.attributable)
        result = inspect_input(event(text), request(
            5, extra_user_content_parts=[{"type": "text", "text": [], "_no_save": False}],
        ))
        self.assertEqual(result.blocks, ())
        self.assertEqual(set(result.incomplete_reasons), {"invalid_prompt", "invalid_extra_text"})
        result = inspect_input(event(text), request(text, extra_user_content_parts=None))
        self.assertIn("extra_user_content_parts", result.uncovered_fields)
        self.assertEqual(result.incomplete_reasons, ())

    def test_block_fallback_has_no_event_or_request_side_effects(self):
        text = "Current message"
        incoming = event(text)
        for req in (
            request(text),
            request(text, image_urls=["original.jpeg"], func_tool=Opaque()),
            request(text, unknown=Opaque()),
            Opaque(),
        ):
            saved_req = vars(req).copy()
            saved_event = vars(incoming).copy()
            self.assertIs(isolate(incoming, req), False)
            self.assertEqual(vars(req), saved_req)
            self.assertEqual(vars(incoming), saved_event)
            self.assertEqual(incoming.message_obj.message[0].text, text)


if __name__ == "__main__":
    unittest.main()
