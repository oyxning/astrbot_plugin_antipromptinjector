"""Exercise main's request hook with real v4.29.4 DTOs and an offline provider."""

import asyncio
import importlib
import json
import os
import re
import sys
import tempfile
import uuid
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


PLUGIN = Path(__file__).resolve().parents[1]
PACKAGE = "_antipromptinjector_runtime_test"
NORMAL = "Please count the letters in hello."
MARKER = "hello status report"
EXTRA_MARKER = "outside fixture text"
REVIEW_REASON = "The fixture has a supported verdict."


@pytest.fixture(scope="module")
def runtime_modules():
    source = os.environ.get("ASTRBOT_HOST_SOURCE")
    if not source:
        pytest.skip("Set ASTRBOT_HOST_SOURCE to the local v4.29.4 source checkout")
    assert sys.dont_write_bytecode, "Start Python with -B"
    source = Path(source).resolve(strict=True)
    with tempfile.TemporaryDirectory(dir=PLUGIN.parent, prefix="plugin-runtime-") as directory:
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("ASTRBOT_ROOT", directory)
            patch.setenv("ASTRBOT_RELOAD", "0")
            patch.chdir(directory)
            patch.syspath_prepend(str(source))

            import astrbot
            from astrbot.api import AstrBotConfig
            from astrbot.api.provider import ProviderRequest
            from astrbot.core.message.components import Plain
            from astrbot.core.platform.astr_message_event import AstrMessageEvent
            from astrbot.core.platform.astrbot_message import AstrBotMessage, MessageMember
            from astrbot.core.platform.message_type import MessageType
            from astrbot.core.platform.platform_metadata import PlatformMetadata
            from astrbot.core.provider.entities import LLMResponse
            from astrbot.core.star.star import star_map, star_registry
            from astrbot.core.star.star_handler import star_handlers_registry

            assert astrbot.__version__ == "4.29.4"
            assert Path(astrbot.__file__).resolve().is_relative_to(source)

            # Import the workspace copy without copying files into the host's plugin store.
            package = ModuleType(PACKAGE)
            package.__path__ = [str(PLUGIN)]
            patch.setitem(sys.modules, PACKAGE, package)
            try:
                main = importlib.import_module(f"{PACKAGE}.main")
                yield SimpleNamespace(
                    main=main, directory=Path(directory), config=AstrBotConfig,
                    request=ProviderRequest, response=LLMResponse, plain=Plain,
                    event=AstrMessageEvent, message=AstrBotMessage, member=MessageMember,
                    message_type=MessageType, platform=PlatformMetadata,
                )
            finally:
                name = f"{PACKAGE}.main"
                for handler in star_handlers_registry.get_handlers_by_module_name(name):
                    star_handlers_registry.remove(handler)
                metadata = star_map.pop(name, None)
                if metadata in star_registry:
                    star_registry.remove(metadata)
                for module in tuple(sys.modules):
                    if module.startswith(f"{PACKAGE}."):
                        sys.modules.pop(module)


@pytest.fixture
def runtime(runtime_modules, monkeypatch):
    host = runtime_modules
    root = host.directory / uuid.uuid4().hex[:10]
    root.mkdir()
    config = host.config(
        config_path=str(root / "plugin_config.json"),
        schema=json.loads((PLUGIN / "_conf_schema.json").read_text(encoding="utf-8")),
    )
    provider = SimpleNamespace(
        meta=lambda: SimpleNamespace(id="fixture-provider", provider_type=SimpleNamespace(value="chat_completion")),
        get_model=lambda: "fixture-default",
        text_chat=AsyncMock(),
    )
    context = SimpleNamespace(
        get_provider_by_id=Mock(return_value=provider),
        get_using_provider_async=AsyncMock(return_value=provider),
        registered_web_apis=[],
    )
    # This suite invokes plugin methods directly and does not need a Dashboard transport.
    monkeypatch.setattr(host.main, "register_web_api", Mock())
    monkeypatch.setattr(host.main.StarTools, "get_data_dir", lambda _: root / "state")
    instance = host.main.AntiPromptInjector(context, config)
    detection = importlib.import_module(f"{PACKAGE}.detection")
    monkeypatch.setattr(detection, "_COMPILED_RULES", (
        ("prompt_fixture", 7, "fixture match", (re.compile(f"({MARKER})"),)),
        ("extra_fixture", 7, "fixture match", (re.compile(f"({EXTRA_MARKER})"),)),
    ))

    def settings(**patch):
        view = instance.web_settings()
        assert instance.web_apply_settings(patch, view["revision"])["status"] == "applied"

    def verdict(injection):
        return host.response(
            role="assistant",
            completion_text=json.dumps({
                "is_injection": injection, "confidence": 0.95, "reason": REVIEW_REASON,
            }),
            raw_completion=SimpleNamespace(model="fixture-actual"),
        )

    def turn(text=NORMAL, *, group=True, admin=False, extra=None):
        message = host.message()
        message.type = host.message_type.GROUP_MESSAGE if group else host.message_type.FRIEND_MESSAGE
        message.message = [host.plain(text=text)]
        message.message_str = text
        message.sender = host.member(user_id="fixture-user", nickname="Fixture")
        message.self_id = "fixture-bot"
        if group:
            message.group_id = "fixture-group"
        event = host.event(
            text, message, host.platform(name="fixture", description="Fixture", id="fixture-instance"),
            "fixture-session",
        )
        if admin:
            event.role = "admin"
        event.send = AsyncMock()
        req = host.request(prompt=text, system_prompt="Trusted fixture.", session_id="fixture-session")
        if extra is not None:
            req.extra_user_content_parts = [{"type": "text", "text": extra}]
        return event, req

    return SimpleNamespace(
        instance=instance, provider=provider, context=context, settings=settings, verdict=verdict,
        turn=turn, hook=instance.intercept_llm_request, records=instance.web_list_records,
        identity=host.main.identity_from_event, main=host.main,
        config_file=Path(config.config_path), state_file=root / "state" / "antipromptinjector-state.json",
    )


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("explicit", [True, False])
async def test_gentle_refusal_follows_persona_not_original_request(runtime, explicit):
    runtime.settings(defense_mode="intercept", llm_analysis_mode="disabled", gentle_refusal=True,
                     refusal_provider="fixture-provider" if explicit else "",
                     refusal_model="independent-model" if explicit else "")
    event, req = runtime.turn(MARKER)
    req.model = "session-model"
    persona = AsyncMock(return_value=("fixture", {"prompt": "安静温和。"}, None, False))
    runtime.context.persona_manager = SimpleNamespace(resolve_selected_persona=persona)
    answer = "这件事我帮不上忙呀。"

    async def generate(**kwargs):
        assert event.is_stopped()
        return SimpleNamespace(role="assistant", is_chunk=False, completion_text=answer,
                               tools_call_name=[], tools_call_args=[], tools_call_ids=[])

    runtime.provider.text_chat.side_effect = generate
    await runtime.hook(event, req)
    assert event.is_stopped()
    assert event.send.await_args.args[0].get_plain_text() == answer
    args = runtime.provider.text_chat.await_args.kwargs
    assert args["system_prompt"] == "安静温和。"
    assert MARKER not in str(args) and req.system_prompt not in str(args)
    assert args["contexts"] == [] and args["func_tool"] is None
    assert args["model"] == ("independent-model" if explicit else "session-model")
    if explicit:
        runtime.context.get_using_provider_async.assert_not_awaited()
    else:
        runtime.context.get_using_provider_async.assert_awaited_once_with(event.unified_msg_origin)


@pytest.mark.parametrize("case", ["missing", "timeout", "invalid", "paragraph", "disabled", "blacklist", "observe", "harden", "review_fault"])
async def test_refusal_fallback_and_non_triggers(runtime, case):
    runtime.settings(defense_mode="sentry" if case == "harden" else "aegis" if case == "review_fault" else "intercept",
                     llm_analysis_mode="disabled", gentle_refusal=case != "disabled",
                     refusal_provider="fixture-provider")
    event, req = runtime.turn(MARKER)
    runtime.context.persona_manager = SimpleNamespace(resolve_selected_persona=AsyncMock(return_value=(None, None, None, False)))
    if case == "blacklist":
        runtime.instance.state.put_entry("blacklist", runtime.identity(event))
    if case == "observe":
        runtime.instance.web_set_observation(3)
    if case == "missing":
        runtime.context.get_provider_by_id.return_value = None
    if case == "timeout":
        runtime.provider.text_chat.side_effect = TimeoutError()
    if case == "invalid":
        runtime.provider.text_chat.return_value = SimpleNamespace(role="error")
    if case == "paragraph":
        runtime.provider.text_chat.return_value = SimpleNamespace(role="assistant", is_chunk=False,
            tools_call_name=[], tools_call_args=[], tools_call_ids=[], completion_text="对不起。换个话题吧。")
    await runtime.hook(event, req)
    assert event.is_stopped() == (case not in ("observe", "harden"))
    if event.is_stopped():
        assert event.send.await_args.args[0].get_plain_text() == (runtime.main.RETRY if case == "review_fault" else runtime.main.DENIED)
    assert runtime.provider.text_chat.await_count == int(case in ("timeout", "invalid", "paragraph"))
    runtime.context.get_using_provider_async.assert_not_awaited()


@pytest.mark.parametrize("text,stopped", [(NORMAL, False), (MARKER, True)], ids=["ordinary", "required-review"])
async def test_private_review_disabled_makes_zero_provider_calls(runtime, text, stopped):
    runtime.settings(defense_mode="aegis", llm_analysis_mode="active",
                     llm_analysis_private_chat_enabled=False)
    event, req = runtime.turn(text, group=False)
    assert event.get_group_id() == ""
    await runtime.hook(event, req)
    assert event.is_stopped() is stopped
    assert (req.prompt, req.system_prompt) == (text, "Trusted fixture.")
    runtime.context.get_using_provider_async.assert_not_awaited()
    runtime.context.get_provider_by_id.assert_not_called()
    runtime.provider.text_chat.assert_not_awaited()
    assert runtime.records()[0]["review_status"] == ("unavailable" if stopped else "not_requested")
    assert runtime.instance.state.stats()["ban"] == 0


async def test_manual_restriction_wins_over_admin_whitelist_observation_and_disabled(runtime):
    runtime.settings(enabled=False, llm_analysis_mode="active")
    runtime.instance.web_set_observation(5)
    event, req = runtime.turn(admin=True)
    identity = runtime.identity(event)
    runtime.instance.state.put_entry("whitelist", identity)
    runtime.instance.state.put_entry("blacklist", identity)
    await runtime.hook(event, req)
    assert event.is_stopped()
    event.send.assert_awaited_once()
    runtime.provider.text_chat.assert_not_awaited()
    record = runtime.records()[0]
    assert (record["action"], record["decision_reason"], record["observed"], record["banned"]) == (
        "block", "blacklist", False, False,
    )


@pytest.mark.parametrize("provider_failure", [False, True], ids=["confirmed", "provider-failure"])
async def test_observation_records_would_block_without_mutation_or_punishment(runtime, provider_failure):
    runtime.settings(defense_mode="intercept", auto_blacklist=True)
    runtime.instance.web_set_observation(5)
    if provider_failure:
        runtime.provider.text_chat.side_effect = OSError("fixture")
    else:
        runtime.provider.text_chat.return_value = runtime.verdict(True)
    event, req = runtime.turn(MARKER)
    await runtime.hook(event, req)
    assert not event.is_stopped()
    event.send.assert_not_awaited()
    assert (req.prompt, req.system_prompt) == (MARKER, "Trusted fixture.")
    assert runtime.instance.state.list_entries() == []
    assert runtime.instance.state.settings["defense_mode"] == "intercept"
    record = runtime.records()[0]
    assert (record["observed"], record["action"], record["intended_action"], record["banned"]) == (
        True, "allow", "block", False,
    )
    assert record["review_failed"] is provider_failure


async def test_valid_review_replay_replaces_rule_verdict_and_preserves_correlation(runtime):
    runtime.settings(defense_mode="aegis", auto_blacklist=True)
    runtime.provider.text_chat.side_effect = [runtime.verdict(False), runtime.verdict(True)]
    first, first_req = runtime.turn(MARKER)
    second, second_req = runtime.turn(MARKER)
    assert first.unified_msg_origin == second.unified_msg_origin
    await runtime.hook(first, first_req)
    await runtime.hook(second, second_req)
    assert not first.is_stopped() and not second.is_stopped()
    assert first_req.system_prompt == "Trusted fixture."
    assert second_req.system_prompt == "Trusted fixture.\n" + runtime.main.NOTICE
    assert runtime.instance.state.list_entries() == []
    assert runtime.context.get_using_provider_async.await_count == 2
    assert all(call.args == (first.unified_msg_origin,)
               for call in runtime.context.get_using_provider_async.await_args_list)
    for call in runtime.provider.text_chat.await_args_list:
        assert call.kwargs["prompt"] == MARKER
        assert call.kwargs["func_tool"] is None
    confirmed, safe = runtime.records()
    assert (safe["action"], safe["review_status"]) == ("allow", "safe")
    assert (confirmed["action"], confirmed["review_status"]) == ("harden", "confirmed")
    assert safe["request_id"] != confirmed["request_id"]
    assert (confirmed["provider"], confirmed["model"], confirmed["model_source"], confirmed["confidence"]) == (
        "fixture-provider", "fixture-actual", "response", 0.95,
    )
    assert confirmed["review_reason"] == REVIEW_REASON


async def test_same_session_concurrent_cancelled_and_failed_review_release_budget(runtime):
    runtime.settings(defense_mode="intercept", llm_analysis_mode="active", review_max_concurrency=1)
    entered = asyncio.Event()
    released = asyncio.Event()

    async def wait_for_cancel(**kwargs):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            released.set()

    runtime.provider.text_chat.side_effect = wait_for_cancel
    first, first_req = runtime.turn(NORMAL)
    task = asyncio.create_task(runtime.hook(first, first_req))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        concurrent, concurrent_req = runtime.turn(MARKER)
        assert first.unified_msg_origin == concurrent.unified_msg_origin
        await asyncio.wait_for(runtime.hook(concurrent, concurrent_req), 2)
        assert concurrent.is_stopped() and not first.is_stopped()
        assert runtime.records()[0]["fault"] == "busy"
        assert runtime.provider.text_chat.await_count == 1
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
    assert released.is_set()
    assert first.is_stopped()
    assert len(runtime.records()) == 1
    first.send.assert_not_awaited()

    runtime.provider.text_chat.side_effect = [OSError("fixture"), runtime.verdict(False)]
    failed, failed_req = runtime.turn(NORMAL)
    await runtime.hook(failed, failed_req)
    assert not failed.is_stopped()
    assert runtime.records()[0]["fault"] == "provider_error"
    last, last_req = runtime.turn(MARKER)
    await runtime.hook(last, last_req)
    assert not last.is_stopped()
    assert runtime.records()[0]["review_status"] == "safe"
    assert runtime.provider.text_chat.await_count == 3
    assert runtime.instance.state.list_entries() == []


async def test_rule_and_paid_trials_leave_config_records_lists_and_observation_unchanged(runtime):
    runtime.settings(defense_mode="intercept", auto_blacklist=True, review_provider="fixture-provider")
    event, req = runtime.turn()
    await runtime.hook(event, req)
    runtime.instance.state.put_entry("whitelist", runtime.identity(event))
    runtime.instance.web_set_observation(5)
    before = (runtime.instance.web_settings(), runtime.records(),
              runtime.instance.web_list_entries(), runtime.instance.web_overview())
    disk_before = (runtime.config_file.read_bytes(), runtime.state_file.read_bytes())
    dry = await runtime.instance.web_preview(MARKER)
    assert dry["suspicious"] and not dry["provider"]
    runtime.provider.text_chat.assert_not_awaited()
    runtime.provider.text_chat.return_value = runtime.verdict(True)
    paid = await runtime.instance.web_preview(MARKER, use_llm=True)
    assert (paid["action"], paid["intended_action"], paid["review_status"]) == (
        "allow", "block", "confirmed",
    )
    runtime.provider.text_chat.assert_awaited_once()
    assert before == (runtime.instance.web_settings(), runtime.records(),
                      runtime.instance.web_list_entries(), runtime.instance.web_overview())
    assert disk_before == (runtime.config_file.read_bytes(), runtime.state_file.read_bytes())


async def test_manual_ban_added_mid_review_wins_over_safe_verdict(runtime):
    runtime.settings(defense_mode="aegis", auto_blacklist=True)
    event, req = runtime.turn(MARKER)

    async def safe_after_manual_ban(**kwargs):
        await asyncio.sleep(0)
        runtime.instance.state.put_entry("blacklist", runtime.identity(event))
        runtime.instance.web_set_observation(5)
        return runtime.verdict(False)

    runtime.provider.text_chat.side_effect = safe_after_manual_ban
    await runtime.hook(event, req)
    assert event.is_stopped()
    assert req.system_prompt == "Trusted fixture."
    record = runtime.records()[0]
    assert (record["action"], record["decision_reason"], record["observed"], record["banned"]) == (
        "block", "blacklist", False, False,
    )


async def test_mixed_input_is_not_sent_to_review_or_attributed_to_sender(runtime):
    runtime.settings(defense_mode="aegis", auto_blacklist=True)
    event, req = runtime.turn(NORMAL, extra=EXTRA_MARKER)
    await runtime.hook(event, req)
    assert event.is_stopped()
    assert req.prompt == NORMAL
    assert req.extra_user_content_parts == [{"type": "text", "text": EXTRA_MARKER}]
    runtime.provider.text_chat.assert_not_awaited()
    assert runtime.instance.state.list_entries() == []
    record = runtime.records()[0]
    assert record["source"] == "extra_user_content_parts"
    assert record["fault"] == "source_not_reviewable" and not record["banned"]
    assert not record["excerpt"] and all(not rule["evidence"] for rule in record["rules"])


async def test_prompt_hit_cannot_enable_logging_evidence_from_unverified_extra(runtime):
    runtime.settings(defense_mode="aegis", auto_blacklist=True)
    await runtime.hook(*runtime.turn(MARKER, extra=EXTRA_MARKER))
    record = runtime.records()[0]
    assert not record["banned"]
    assert any(rule["id"] == "extra_fixture" for rule in record["rules"])
    assert EXTRA_MARKER not in json.dumps(record)


async def test_benign_extra_does_not_prevent_verified_prompt_review(runtime):
    runtime.settings(defense_mode="aegis", auto_blacklist=True)
    runtime.provider.text_chat.return_value = runtime.verdict(False)
    event, req = runtime.turn(MARKER, extra="Host clock fixture.")
    await runtime.hook(event, req)
    assert not event.is_stopped()
    runtime.provider.text_chat.assert_awaited_once()
    assert runtime.provider.text_chat.await_args.kwargs["prompt"] == MARKER
    assert runtime.records()[0]["action"] == "allow"


async def test_unexpected_inspection_exception_leaves_diagnostic(runtime, monkeypatch):
    monkeypatch.setattr(runtime.main, "inspect_input", Mock(side_effect=RuntimeError("fixture")))
    event, req = runtime.turn()
    await runtime.hook(event, req)
    assert event.is_stopped()
    assert len(runtime.records()) == 1
    assert runtime.records()[0]["action"] == "block" and runtime.records()[0]["fault"]
