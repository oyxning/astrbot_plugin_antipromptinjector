import asyncio
import unittest
from types import SimpleNamespace

from review import MAX_INPUT_CHARS, SYSTEM_PROMPT, ReviewService, parse_review_response


SAFE = '{"is_injection":false,"confidence":0.95,"reason":"Not an injection."}'


class FakeProvider:
    def __init__(self, provider_id="chat", provider_type="chat_completion"):
        self.metadata = SimpleNamespace(
            id=provider_id, provider_type=SimpleNamespace(value=provider_type)
        )
        self.calls = []
        self.response = SimpleNamespace(role="assistant", completion_text=SAFE)
        self.started = asyncio.Event()
        self.wait = None
        self.error = None

    def meta(self):
        return self.metadata

    def get_model(self):
        return "default-model"

    async def text_chat(self, **kwargs):
        self.calls.append(kwargs)
        self.started.set()
        if self.wait is not None:
            await self.wait.wait()
        if self.error:
            raise self.error
        return self.response


class FakeContext:
    def __init__(self, provider):
        self.default_provider = provider
        self.explicit_providers = {}
        self.id_lookups = []
        self.session_lookups = []

    def get_provider_by_id(self, provider_id):
        self.id_lookups.append(provider_id)
        return self.explicit_providers.get(provider_id)

    async def get_using_provider_async(self, umo):
        self.session_lookups.append(umo)
        return self.default_provider


def event(group_id="group"):
    return SimpleNamespace(
        unified_msg_origin="test:GroupMessage:session" if group_id else "test:FriendMessage:pm",
        get_group_id=lambda: group_id,
    )


class ParseTests(unittest.TestCase):
    def test_only_boolean_controls_verdict(self):
        self.assertEqual(parse_review_response(SAFE), (False, 0.95, "Not an injection."))
        self.assertEqual(
            parse_review_response('{"is_injection":true,"confidence":1,"reason":"  test\\n text  "}'),
            (True, 1.0, "test text"),
        )

    def test_malformed_responses(self):
        for text in (
            None,
            "",
            "This is not an injection; true is a JSON literal.",
            SAFE + " extra",
            f"```json\n{SAFE}\n```",
            "[]",
            '{"is_injection":false,"confidence":0.95}',
            SAFE.replace("false", '"false"'),
            SAFE.replace("false", "0"),
            SAFE.replace("0.95", '"0.95"'),
            SAFE.replace("0.95", "true"),
            SAFE.replace("0.95", "NaN"),
            SAFE.replace("0.95", "Infinity"),
            SAFE.replace("0.95", "1e9999"),
            SAFE.replace("0.95", "1.00000000000000001"),
            SAFE.replace("0.95", "-0.01"),
            SAFE.replace("Not an injection.", ""),
            SAFE.replace("Not an injection.", r"\ud800"),
            SAFE.replace('"reason":', '"reason":"other","reason":'),
            " " * 4097 + SAFE,
        ):
            with self.subTest(text=str(text)[:120]), self.assertRaises(ValueError):
                parse_review_response(text)


class ReviewTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.provider = FakeProvider()
        self.context = FakeContext(self.provider)
        self.service = ReviewService(self.context)
        self.event = event()

    async def test_session_route_is_one_tool_free_call(self):
        text = "What are the limits of this sequence?"
        result = await self.service.review(
            self.event, text, {"llm_analysis_mode": "active"}
        )
        self.assertEqual(result.status, "safe")
        self.assertEqual(result.provider_id, "chat")
        self.assertEqual((result.model, result.model_source), ("default-model", "provider_default"))
        self.assertEqual(self.context.session_lookups, [self.event.unified_msg_origin])
        self.assertEqual(self.context.id_lookups, [])
        self.assertEqual(
            self.provider.calls,
            [dict(
                prompt=text, system_prompt=SYSTEM_PROMPT, func_tool=None,
                model=None, request_max_retries=1,
            )],
        )

    async def test_explicit_route_and_actual_response_model(self):
        explicit = FakeProvider("review")
        self.context.explicit_providers["review"] = explicit
        explicit.response.raw_completion = SimpleNamespace(model="served-version")
        result = await self.service.review(
            None, "A sentence.",
            {"review_provider": " review ", "review_model": " alias "}, required=True,
        )
        self.assertEqual(result.status, "safe")
        self.assertEqual(result.provider_id, "review")
        self.assertEqual((result.model, result.model_source), ("served-version", "response"))
        self.assertEqual(explicit.calls[0]["model"], "alias")
        self.assertEqual(self.context.id_lookups, ["review"])
        self.assertEqual(self.context.session_lookups, [])
        self.assertEqual(self.provider.calls, [])

    async def test_invalid_explicit_route_never_falls_back(self):
        self.context.explicit_providers["tts"] = FakeProvider("tts", "text_to_speech")
        for provider_id in ("missing", "tts"):
            result = await self.service.review(
                self.event, "A sentence.", {"review_provider": provider_id}, required=True,
            )
            self.assertEqual((result.status, result.error), ("failed", "provider_unavailable"))
            self.assertEqual(result.provider_id, provider_id)
        self.assertEqual(self.context.session_lookups, [])
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.context.explicit_providers["tts"].calls, [])

    async def test_private_disabled_is_zero_lookup_and_call_even_if_active(self):
        for required in (False, True):
            result = await self.service.review(
                event(""), "A sentence.", {"llm_analysis_mode": "active"}, required=required,
            )
            self.assertEqual(result.error, "private_chat_disabled")
            self.assertEqual(result.status, "failed" if required else "skipped")
        self.assertEqual(self.context.session_lookups, [])
        self.assertEqual(self.provider.calls, [])

    async def test_private_enabled_passes_private_session_origin(self):
        private = event("")
        result = await self.service.review(
            private, "A sentence.",
            {"llm_analysis_mode": "active", "llm_analysis_private_chat_enabled": True},
        )
        self.assertEqual(result.status, "safe")
        self.assertEqual(self.context.session_lookups, [private.unified_msg_origin])

    async def test_mode_gates_do_not_mutate_config(self):
        for config, required, status, error in (
            ({}, False, "skipped", None),
            ({"llm_analysis_mode": "disabled"}, False, "skipped", "disabled"),
            ({"llm_analysis_mode": "disabled"}, True, "failed", "disabled"),
            ({"llm_analysis_mode": "standby"}, True, "safe", None),
        ):
            before = config.copy()
            result = await self.service.review(self.event, "A sentence.", config, required=required)
            self.assertEqual((result.status, result.error), (status, error))
            self.assertEqual(config, before)
        self.assertEqual(len(self.provider.calls), 1)

    async def test_missing_session_and_provider(self):
        simulated = await self.service.review(None, "trial", {}, required=True)
        self.assertEqual(simulated.error, "session_required")
        self.assertEqual(self.context.session_lookups, [])
        self.context.default_provider = None
        result = await self.service.review(self.event, "A sentence.", {}, required=True)
        self.assertEqual((result.status, result.error), ("failed", "provider_unavailable"))
        self.assertEqual(self.provider.calls, [])

    async def test_input_and_config_budgets_before_provider_lookup(self):
        excess = await self.service.review(
            self.event, "x" * (MAX_INPUT_CHARS + 1), {}, required=True,
        )
        self.assertEqual(excess.error, "input_budget")
        for config in (
            {"review_max_concurrency": 17},
            {"review_max_concurrency": True},
            {"review_timeout_seconds": float("nan")},
            {"review_timeout_seconds": 61},
            {"review_max_chars": 255},
            {"review_max_chars": 8193},
            {"review_max_chars": 4096.0},
        ):
            result = await self.service.review(self.event, "A sentence.", config, required=True)
            self.assertEqual(result.error, "invalid_config")
        self.assertEqual(self.context.session_lookups, [])
        self.assertEqual(self.provider.calls, [])

    async def test_review_character_budget_uses_config_and_default(self):
        for config, limit in (
            ({}, 4096), ({"review_max_chars": 256}, 256), ({"review_max_chars": 8192}, 8192),
        ):
            with self.subTest(limit=limit):
                text = "x" * limit
                over = await self.service.review(self.event, text + "x", config, required=True)
                self.assertEqual(over.error, "input_budget")
                exact = await self.service.review(self.event, text, config, required=True)
                self.assertEqual(exact.status, "safe")
                self.assertEqual(self.provider.calls[-1]["prompt"], text)
        self.assertEqual(len(self.provider.calls), 3)

    async def test_failures_have_no_verdict_and_do_not_retry(self):
        self.provider.response.completion_text = SAFE.replace("false", '"false"')
        result = await self.service.review(self.event, "A sentence.", {}, required=True)
        self.assertEqual((result.status, result.error, result.confidence), (
            "failed", "invalid_response", None,
        ))
        self.assertEqual(len(self.provider.calls), 1)
        self.provider.error = ConnectionError("private provider details")
        result = await self.service.review(self.event, "A sentence.", {}, required=True)
        self.assertEqual((result.status, result.error, result.reason), (
            "failed", "provider_error", "",
        ))
        self.assertEqual(len(self.provider.calls), 2)

    async def test_timeout_releases_slot(self):
        self.provider.wait = asyncio.Event()
        config = {"review_timeout_seconds": 0.1, "review_max_concurrency": 1}
        result = await self.service.review(self.event, "First request", config, required=True)
        self.assertEqual((result.status, result.error), ("failed", "timeout"))
        self.provider.wait.set()
        result = await self.service.review(self.event, "Second request", config, required=True)
        self.assertEqual(result.status, "safe")
        self.assertEqual(len(self.provider.calls), 2)

    async def test_concurrency_limit_and_cancellation_release_slot(self):
        config = {"review_max_concurrency": 1}
        self.provider.wait = asyncio.Event()
        first = asyncio.create_task(
            self.service.review(self.event, "Pending", config, required=True)
        )
        try:
            await asyncio.wait_for(self.provider.started.wait(), timeout=1)
            busy = await self.service.review(self.event, "Concurrent", config, required=True)
            self.assertEqual((busy.status, busy.error), ("failed", "busy"))
        finally:
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
        self.provider.wait.set()
        final = await self.service.review(self.event, "Sequential", config, required=True)
        self.assertEqual(final.status, "safe")
        self.assertEqual([call["prompt"] for call in self.provider.calls], ["Pending", "Sequential"])


if __name__ == "__main__":
    unittest.main()
