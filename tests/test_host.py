"""Offline directory integration against the real AstrBot 4.29.4 host."""

import ast
import asyncio
import copy
import json
import os
import shutil
import sys
import tempfile
import uuid
from functools import partial
from dataclasses import replace
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

PLUGIN = Path(__file__).resolve().parents[1]
RUN = PLUGIN.parent / "host-run"
PACKAGE = os.environ.get("ASTRBOT_HOST_PACKAGE")
SLUG = "antipromptinjector" if PACKAGE else "astrbot_plugin_antipromptinjector"
MODULE = f"data.plugins.{SLUG}.main"
TEXT = "Please count the letters in hello."


@pytest.fixture(scope="module")
def host():
    if "ASTRBOT_HOST_SOURCE" not in os.environ:
        pytest.skip("Set ASTRBOT_HOST_SOURCE to the local v4.29.4 source checkout")
    source = Path(os.environ["ASTRBOT_HOST_SOURCE"]).resolve(strict=True)
    assert (source / "astrbot" / "__init__.py").is_file()
    assert sys.dont_write_bytecode, "Start Python with -B"
    assert not any(k == "astrbot" or k.startswith("astrbot.") for k in sys.modules)
    assert RUN.resolve() == RUN, "host-run must not redirect to another directory"
    RUN.mkdir(exist_ok=True)
    mode = "package" if PACKAGE else "directory"
    root = RUN / f"{mode}-{uuid.uuid4().hex}"
    root.mkdir()
    temp = root / "tmp"
    temp.mkdir()
    with pytest.MonkeyPatch.context() as patch:
        for key, value in {
            "ASTRBOT_ROOT": str(root),
            "ASTRBOT_RELOAD": "0",
            "TEMP": str(temp),
            "TMP": str(temp),
            "TMPDIR": str(temp),
            "PIP_NO_INDEX": "1",
            "PIP_NO_CACHE_DIR": "1",
        }.items():
            patch.setenv(key, value)
        patch.setattr(tempfile, "tempdir", str(temp))
        patch.chdir(root)
        patch.syspath_prepend(str(source))
        patch.syspath_prepend(str(root))

        import astrbot

        assert astrbot.__version__ == "4.29.4"
        assert Path(astrbot.__file__).resolve().is_relative_to(source)
        yield root


def request_hooks():
    from astrbot.core.star.star_handler import EventType, star_handlers_registry

    return [
        handler
        for handler in star_handlers_registry.get_handlers_by_module_name(MODULE)
        if handler.event_type == EventType.OnLLMRequestEvent
    ]


@pytest_asyncio.fixture
async def runtime(host, monkeypatch):
    from astrbot.core import astrbot_config, db_helper, pip_installer
    from astrbot.core.star.context import Context
    from astrbot.core.star.star_manager import Metric, PluginManager

    # A missing dependency is a test failure, not permission to install it.
    monkeypatch.setattr(
        pip_installer, "install", AsyncMock(side_effect=AssertionError("offline test"))
    )
    monkeypatch.setattr(Metric, "upload", AsyncMock())
    await db_helper.initialize()
    config = copy.deepcopy(dict(astrbot_config))
    config["provider_settings"].update(
        enable=True, streaming_response=False, datetime_system_prompt=False
    )
    providers = MagicMock()
    context = Context(
        event_queue=asyncio.Queue(),
        config=astrbot_config,
        db=db_helper,
        provider_manager=providers,
        platform_manager=MagicMock(),
        conversation_manager=MagicMock(),
        message_history_manager=MagicMock(),
        persona_manager=MagicMock(),
        astrbot_config_mgr=MagicMock(get_conf=MagicMock(return_value=config)),
        knowledge_base_manager=MagicMock(),
        cron_manager=MagicMock(),
    )
    context.registered_web_apis = []
    manager = PluginManager(context, astrbot_config)
    return SimpleNamespace(manager=manager, config=config, context=context)


@pytest_asyncio.fixture
async def loaded(host, runtime, monkeypatch):
    from astrbot.core.star.context import Context

    entry = PLUGIN / "main.py"
    if not entry.is_file():
        pytest.skip("Enhanced main.py is not present")
    tree = ast.parse(entry.read_bytes(), filename=str(entry))
    hooks = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef)
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "on_llm_request"
    ]
    if hooks != ["intercept_llm_request"]:
        pytest.skip("Enhanced single-hook main.py is not active; candidate not loaded")

    listen = AsyncMock(side_effect=AssertionError("host test must not open a listener"))
    monkeypatch.setattr(asyncio, "start_server", listen)
    monkeypatch.setattr(asyncio.get_running_loop(), "create_server", listen)
    manager = runtime.manager
    context = runtime.context
    target = Path(manager.plugin_store_path) / SLUG
    assert target.resolve() == host / "data" / "plugins" / SLUG
    if not PACKAGE:
        shutil.copytree(
            PLUGIN,
            target,
            ignore=shutil.ignore_patterns(
                ".git", "tests", "docs", "__pycache__", "*.pyc", ".pytest_cache"
            ),
        )
    config_dir = Path(manager.plugin_config_path)
    assert config_dir.resolve().is_relative_to(host)
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / f"{SLUG}_config.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "llm_analysis_mode": "disabled",
                "defense_mode": "intercept",
                "auto_blacklist": False,
                "whitelist": ["unbound-fixture"],
                "webui_enabled": False,
                "custom_fixture": "preserve in backup",
            }
        ),
        encoding="utf-8",
    )
    try:
        if PACKAGE:
            archive = host / "tmp" / "candidate.zip"
            shutil.copyfile(PACKAGE, archive)
            await manager.install_plugin_from_file(str(archive))
            assert not archive.exists(), "The loader should consume only the local copy"
        else:
            success, error = await manager.load(specified_dir_name=SLUG)
            assert success, (error, manager.failed_plugin_info)
        stars = [
            star for star in Context.get_all_stars(context) if star.module_path == MODULE
        ]
        assert len(stars) == 1 and stars[0].activated and stars[0].star_cls is not None
        star = stars[0]
        assert Path(sys.modules[MODULE].__file__).resolve() == target / "main.py"
        yield SimpleNamespace(
            manager=manager, star=star, target=target, context=context
        )
    finally:
        registered = [
            star for star in Context.get_all_stars(context) if star.module_path == MODULE
        ]
        if registered:
            await manager.uninstall_plugin(registered[0].name)
        elif target.is_dir():
            assert target.resolve() == host / "data" / "plugins" / SLUG
            shutil.rmtree(target)
        listen.assert_not_awaited()


def plugin_tasks(instance):
    return [
        value
        for name, value in vars(instance).items()
        if name.endswith("_task") and isinstance(value, asyncio.Task)
    ]


def assert_bound(hook, instance):
    assert isinstance(hook.handler, partial)
    assert hook.handler.args == (instance,)
    assert hook.handler.func.__name__ == "intercept_llm_request"


@pytest.mark.asyncio
async def test_directory_load_reload_uninstall(loaded):
    from astrbot.core.star.star_handler import star_handlers_registry
    from astrbot.dashboard.api.plugins import _call_plugin_extension
    from starlette.requests import Request

    async def overview():
        req = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/api/plug/antipromptinjector/overview",
                "headers": [],
                "query_string": b"",
                "app": SimpleNamespace(
                    state=SimpleNamespace(
                        core_lifecycle=SimpleNamespace(star_context=loaded.context)
                    )
                ),
            }
        )
        return await _call_plugin_extension("antipromptinjector/overview", req, "admin")

    name = loaded.star.name
    original = loaded.star.star_cls
    assert original.state.settings["defense_mode"] == "intercept"
    config_path = Path(loaded.manager.plugin_config_path) / f"{SLUG}_config.json"
    backup = config_path.with_name(config_path.name + ".antipromptinjector-v1.bak")
    backup_bytes = backup.read_bytes()
    assert json.loads(backup_bytes)["custom_fixture"] == "preserve in backup"
    assert "webui_enabled" not in json.loads(config_path.read_text(encoding="utf-8-sig"))
    assert [row["user"] for row in original.state.list_entries("whitelist", pending=True)] == ["unbound-fixture"]
    assert original.state.remove_legacy("whitelist", "unbound-fixture")
    old_tasks = plugin_tasks(original)
    old_handlers = star_handlers_registry.get_handlers_by_module_name(MODULE)
    old_hook_names = [hook.handler_name for hook in request_hooks()]
    assert old_handlers and old_hook_names == ["intercept_llm_request"]
    assert_bound(request_hooks()[0], original)
    old_routes = list(loaded.context.registered_web_apis)
    assert old_routes
    keys = {(route, tuple(methods)) for route, _, methods, _ in old_routes}
    assert len(keys) == len(old_routes)
    assert ("/antipromptinjector/overview", ("GET",)) in keys
    assert (await overview()).status_code == 200

    success, error = await loaded.manager.reload(name)
    assert success, error
    current = loaded.context.get_registered_star(name).star_cls
    assert current is not original
    assert backup.read_bytes() == backup_bytes
    assert not current.state.list_entries("whitelist", pending=True)
    assert original._closed
    assert all(task.done() for task in old_tasks)
    assert [hook.handler_name for hook in request_hooks()] == old_hook_names
    assert_bound(request_hooks()[0], current)
    assert not set(map(id, old_handlers)) & {
        id(h) for h in star_handlers_registry.get_handlers_by_module_name(MODULE)
    }
    routes = loaded.context.registered_web_apis
    assert len(routes) == len(keys)
    assert {(route, tuple(methods)) for route, _, methods, _ in routes} == keys
    assert not {id(route[1]) for route in routes} & {id(route[1]) for route in old_routes}
    assert (await overview()).status_code == 200

    current_tasks = plugin_tasks(current)
    await loaded.manager.uninstall_plugin(name)
    assert loaded.context.get_registered_star(name) is None
    assert not star_handlers_registry.get_handlers_by_module_name(MODULE)
    assert MODULE not in sys.modules
    assert not loaded.target.exists()
    assert current._closed
    assert all(task.done() for task in current_tasks)
    assert not loaded.context.registered_web_apis
    assert (await overview())["status"] == "error"


@pytest_asyncio.fixture
async def main_request(runtime, monkeypatch):
    from astrbot.core import astr_main_agent
    from astrbot.core.agent.tool import FunctionTool, ToolSet
    from astrbot.core.message.components import Plain
    from astrbot.core.pipeline.process_stage.method.agent_sub_stages import internal
    from astrbot.core.pipeline.process_stage.stage import ProcessStage
    from astrbot.core.platform.astr_message_event import AstrMessageEvent
    from astrbot.core.platform.astrbot_message import AstrBotMessage, MessageMember
    from astrbot.core.platform.message_type import MessageType
    from astrbot.core.platform.platform_metadata import PlatformMetadata
    from astrbot.core.provider.entities import LLMResponse, ProviderRequest
    from astrbot.core.provider.provider import Provider

    provider = MagicMock(spec=Provider)
    provider.provider_config = {
        "id": "primary",
        "model": "host-test",
        "modalities": ["text", "tool_use"],
        "max_context_tokens": 4096,
    }
    provider.get_model.return_value = "host-test"
    provider.text_chat = AsyncMock(
        side_effect=[
            LLMResponse(
                role="assistant",
                tools_call_name=["host_count"],
                tools_call_args=[{}],
                tools_call_ids=["host-call"],
            ),
            LLMResponse(role="assistant", completion_text="Host control complete."),
        ]
    )
    tool_calls = []

    async def count_only(event):
        tool_calls.append(event.get_sender_id())
        return "Counted locally."

    tool = FunctionTool(
        name="host_count",
        description="Count one local invocation.",
        parameters={"type": "object", "properties": {}},
        handler=count_only,
    )

    context = runtime.context
    context.get_using_provider_async = AsyncMock(return_value=provider)
    context.get_provider_by_id = MagicMock(return_value=provider)
    context.persona_manager.resolve_selected_persona = AsyncMock(
        return_value=(None, None, None, False)
    )
    context.persona_manager.personas_v3 = []
    context.conversation_manager.get_curr_conversation_id = AsyncMock(return_value=None)
    context.get_llm_tool_manager().get_builtin_tool.side_effect = lambda cls, **kw: cls(
        **kw
    )
    monkeypatch.setattr(internal, "_record_internal_agent_stats", AsyncMock())
    monkeypatch.setattr(internal.Metric, "upload", AsyncMock())
    monkeypatch.setattr(
        astr_main_agent, "retrieve_knowledge_base", AsyncMock(return_value=None)
    )
    from astrbot.core.pipeline.process_stage.method.agent_request import (
        SessionServiceManager,
    )

    monkeypatch.setattr(
        SessionServiceManager, "should_process_llm_request", AsyncMock(return_value=True)
    )
    stage = ProcessStage()
    await stage.initialize(
        SimpleNamespace(astrbot_config=runtime.config, plugin_manager=runtime.manager)
    )

    async def process(sender):
        message = AstrBotMessage()
        message.message = [Plain(text=TEXT)]
        message.message_str = TEXT
        message.type = MessageType.FRIEND_MESSAGE
        message.sender = MessageMember(user_id=sender, nickname="Host Test")
        message.self_id = "host-bot"
        event = AstrMessageEvent(
            TEXT,
            message,
            PlatformMetadata(name="host-test", description="Local test", id="host-test"),
            sender,
        )
        event.is_at_or_wake_command = True
        event.send = AsyncMock()
        event.send_typing = AsyncMock()
        event.stop_typing = AsyncMock()
        event.trace.record = MagicMock(wraps=event.trace.record)
        event.set_extra(
            "provider_request", ProviderRequest(prompt=TEXT, func_tool=ToolSet([tool]))
        )
        async for _ in stage.process(event):
            pass
        return event

    return SimpleNamespace(
        process=process, provider=provider, tool_calls=tool_calls, response=LLMResponse
    )


async def assert_normal_turn(main_request):
    allowed = await main_request.process("host-allowed")
    assert not allowed.is_stopped()
    assert main_request.provider.text_chat.await_count == 2
    assert main_request.tool_calls == ["host-allowed"]
    return allowed


def assert_dispatched(event):
    records = [
        call.kwargs["status"]
        for call in event.trace.record.call_args_list
        if call.args == ("handler_end",)
        and call.kwargs.get("hook") == "OnLLMRequestEvent"
        and call.kwargs.get("handler") == "intercept_llm_request"
    ]
    assert records == ["success"]


@pytest.mark.asyncio
async def test_host_normal_control_without_plugin(main_request):
    assert not request_hooks()
    await assert_normal_turn(main_request)


@pytest.mark.asyncio
async def test_main_request_block_and_normal_control(loaded, main_request):
    identity = import_module(f"data.plugins.{SLUG}.state").Identity
    hooks = request_hooks()
    assert [h.handler_name for h in hooks] == ["intercept_llm_request"], (
        "Candidate not ready: no request was sent through the old hooks"
    )
    assert_bound(hooks[0], loaded.star.star_cls)
    loaded.star.star_cls.state.put_entry(
        "blacklist", identity("host-test", "host-test", "host-denied")
    )

    denied = await main_request.process("host-denied")
    assert_dispatched(denied)
    assert denied.is_stopped()
    main_request.provider.text_chat.assert_not_awaited()
    assert main_request.tool_calls == []

    allowed = await assert_normal_turn(main_request)
    assert_dispatched(allowed)


@pytest.mark.asyncio
async def test_real_priority_order_and_cancelled_review(loaded, main_request):
    from astrbot.core.star.star_handler import star_handlers_registry

    hook, = request_hooks()
    assert hook.extras_configs["priority"] == -1000

    async def witness(event, req):
        pass

    peers = [replace(hook, handler_name=name, handler_full_name=f"{MODULE}_{name}",
                     handler=witness, extras_configs={"priority": priority})
             for name, priority in (("after_check", -1001), ("before_check", 999))]

    def order(event):
        return [call.kwargs["handler"] for call in event.trace.record.call_args_list
                if call.args == ("handler_start",) and call.kwargs.get("hook") == "OnLLMRequestEvent"]

    try:
        for peer in peers:
            star_handlers_registry.append(peer)
        allowed = await assert_normal_turn(main_request)
        assert order(allowed) == ["before_check", "intercept_llm_request", "after_check"]
        main_request.provider.text_chat.reset_mock()
        main_request.tool_calls.clear()

        review = MagicMock()
        review.meta.return_value = SimpleNamespace(id="qa-review", provider_type=SimpleNamespace(value="chat_completion"))
        review.get_model.return_value = "qa-model"
        review.text_chat = AsyncMock(side_effect=asyncio.CancelledError)
        loaded.context.get_provider_by_id.side_effect = {"primary": main_request.provider, "qa-review": review}.get
        loaded.star.config.update(llm_analysis_mode="active", llm_analysis_private_chat_enabled=True,
                                  review_provider="qa-review")
        cancelled = await main_request.process("host-cancelled")
        review.text_chat.assert_awaited_once()
        assert cancelled.is_stopped()
        assert order(cancelled) == ["before_check", "intercept_llm_request"]
        main_request.provider.text_chat.assert_not_awaited()
        assert not main_request.tool_calls
    finally:
        for peer in peers:
            star_handlers_registry.remove(peer)


@pytest.mark.asyncio
@pytest.mark.parametrize("gentle", [False, True])
async def test_review_decision_uses_only_the_configured_fake_provider(loaded, main_request, gentle):
    review_provider = MagicMock()
    review_provider.meta.return_value = SimpleNamespace(
        id="host-review", provider_type=SimpleNamespace(value="chat_completion")
    )
    review_provider.get_model.return_value = "host-review-model"
    review_provider.text_chat = AsyncMock(
        side_effect=[
            main_request.response(
                role="assistant",
                completion_text=json.dumps(
                    {"is_injection": verdict, "confidence": 1, "reason": "Synthetic verdict"}
                ),
            )
            for verdict in (True, False)
        ]
    )
    refusal = MagicMock()
    refusal.meta.return_value = SimpleNamespace(id="refusal", provider_type=SimpleNamespace(value="chat_completion"))
    refusal.text_chat = AsyncMock(return_value=main_request.response(role="assistant", completion_text="抱歉，这次不方便。"))
    loaded.context.get_provider_by_id.side_effect = {
        "primary": main_request.provider, "host-review": review_provider, "refusal": refusal,
    }.get
    loaded.star.config.update(
        llm_analysis_mode="active",
        llm_analysis_private_chat_enabled=True,
        review_provider="host-review",
        gentle_refusal=gentle, refusal_provider="refusal",
    )
    denied = await main_request.process("host-review-denied")
    assert_dispatched(denied)
    assert denied.is_stopped()
    review_provider.text_chat.assert_awaited_once()
    assert review_provider.text_chat.await_args.kwargs["func_tool"] is None
    main_request.provider.text_chat.assert_not_awaited()
    assert main_request.tool_calls == []
    assert refusal.text_chat.await_count == int(gentle)
    if gentle:
        assert denied.send.await_args.args[0].get_plain_text() == "抱歉，这次不方便。"

    allowed = await assert_normal_turn(main_request)
    assert_dispatched(allowed)
    assert review_provider.text_chat.await_count == 2
    assert refusal.text_chat.await_count == int(gentle)
