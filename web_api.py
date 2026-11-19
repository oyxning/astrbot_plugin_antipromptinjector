"""Dashboard transport. The plugin owns persistence and runtime decisions."""

import asyncio
import inspect
import json
import re

from .state import BOUNDS, SCHEMA, _excerpt, _label, _valid_setting


PLUGIN_NAME = "antipromptinjector"
MAX_BODY = 64 * 1024
MAX_SAMPLE = 8192

SETTINGS = {
    key: spec for key, spec in SCHEMA.items()
    if spec["type"] in {"bool", "int", "float", "string"}
}


class InvalidRequest(ValueError):
    pass


def _object(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys():
        raise InvalidRequest("请求缺少必要字段。")
    if value.keys() - set(required) - set(optional):
        raise InvalidRequest("请求包含不支持的字段。")
    return value


def _string(value, limit, *, required=False, strip=True):
    if type(value) is not str or len(value) > limit:
        raise InvalidRequest("文本字段类型或长度不正确。")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise InvalidRequest("文本包含无效字符。")
    if "\x00" in value:
        raise InvalidRequest("文本包含无效字符。")
    if strip:
        value = value.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise InvalidRequest("字段不能包含控制字符。")
    if required and not value.strip():
        raise InvalidRequest("必填文本不能为空。")
    return value


def _integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise InvalidRequest(f"请输入 {lower} 至 {upper} 之间的整数。")
    return value


def _setting(key, value):
    if not _valid_setting(key, value):
        raise InvalidRequest(f"设置 {key} 的值无效。")
    return value


def _snapshot(value):
    revision = _string(value["revision"], 128, required=True)
    config = value["config"]
    if not isinstance(config, dict):
        raise TypeError("Invalid settings snapshot")
    return {
        "revision": revision,
        "config": {key: config[key] for key in SETTINGS if key in config},
        "apply_status": value.get("apply_status", value.get("status", "applied")),
        "fields": {
            key: {
                "type": spec["type"],
                "description": spec["description"],
                **({"options": spec["options"]} if "options" in spec else {}),
                **({"bounds": BOUNDS[key]} if key in BOUNDS else {}),
            }
            for key, spec in SETTINGS.items() if key in config
        },
    }


def _entry(body, action):
    required = ("kind", "user") if action == "remove_pending" else ("kind", "user", "platform", "instance")
    optional = () if action == "remove_pending" else ("session",)
    if action == "add":
        optional += ("reason", "duration_minutes")
    _object(body, required, optional)
    kind = body["kind"]
    if kind not in ("blacklist", "whitelist"):
        raise InvalidRequest("请选择黑名单或白名单。")
    entry = {"kind": kind, "user": _string(body["user"], 1024, required=True, strip=False)}
    if any(ord(char) < 32 or ord(char) == 127 for char in entry["user"]):
        raise InvalidRequest("用户 ID 包含控制字符。")
    if action == "remove_pending":
        return entry
    for key in ("user", "platform", "instance", "session"):
        val = entry["user"] if key == "user" else body.get(key)
        if key == "session" and val in (None, ""):
            entry[key] = None
            continue
        _string(val, 1024, required=True)
        entry[key] = val
    if "reason" in body:
        entry["reason"] = _string(body["reason"], 240)
    if "duration_minutes" in body:
        entry["duration_minutes"] = _integer(body["duration_minutes"], 0, 525600)
    return entry


def _decision(value, *, sample=False):
    fields = (
        "action", "intended_action", "source", "review_status", "elapsed_ms",
        "observed", "incomplete", "review_failed",
    )
    row = {key: value[key] for key in fields if key in value}
    for key in ("provider", "model", "fault"):
        row[key] = _label(value.get(key))
    for key in ("decision_reason", "review_reason"):
        row[key] = _excerpt(value.get(key))
    model_source = value.get("model_source")
    if model_source in ("response", "requested", "provider_default"):
        row["model_source"] = model_source
    if not sample:
        request_id = value["request_id"]
        row.update(
            time=value["time"],
            request_id=request_id if isinstance(request_id, str) and re.fullmatch(r"[0-9a-f]{24}", request_id) else "",
            banned=value.get("banned") is True, excerpt=_excerpt(value.get("excerpt")),
        )
    row["rules"] = [
        {"id": _label(rule.get("id")), "evidence": _excerpt(rule.get("evidence"))}
        for rule in value.get("rules", ())[:16] if _label(rule.get("id"))
    ]
    return row


def register_web_api(plugin):
    """Register fixed Dashboard-only endpoints on AstrBot's plugin namespace."""
    from astrbot.api.web import error_response, json_response, request
    from astrbot.core import DEMO_MODE
    from astrbot.core.workspace import API_KEY_USERNAME_PREFIX

    headers = {"Cache-Control": "no-store"}

    async def call(method, *args, **kwargs):
        value = getattr(plugin, method)(*args, **kwargs)
        return await value if inspect.isawaitable(value) else value

    async def settings():
        return _snapshot(await call("web_settings"))

    async def providers():
        choices = []
        for provider in plugin.context.get_all_providers():
            meta = provider.meta()
            if meta.provider_type.value == "chat_completion":
                choices.append({"id": _string(meta.id, 256, required=True),
                                "model": _string(provider.get_model() or "", 256)})
        return choices

    async def models(body):
        _object(body, ("provider",))
        selected = _string(body["provider"], 256, required=True)
        provider = plugin.context.get_provider_by_id(selected)
        if provider is None or provider.meta().id != selected or provider.meta().provider_type.value != "chat_completion":
            raise InvalidRequest("该对话提供商已不可用。")
        async with asyncio.timeout(6):
            names = await provider.get_models()
        if not isinstance(names, (list, tuple)):
            raise TypeError("Invalid model list")
        return sorted({s for s in names if isinstance(s, str) and s.strip() == s
                       and 0 < len(s) <= 256 and s.isprintable()})[:2000]

    async def save(body):
        _object(body, ("revision", "patch"))
        revision = _string(body["revision"], 128, required=True)
        patch = _object(body["patch"], (), SETTINGS)
        if not patch:
            raise InvalidRequest("没有需要保存的设置。")
        changes = {key: _setting(key, value) for key, value in patch.items()}
        current = await settings()
        if changes.keys() - current["config"].keys():
            raise InvalidRequest("当前版本不支持其中一项设置。")
        # The owner repeats the revision check at the storage boundary.
        if current["revision"] != revision:
            return {"status": "conflict"}
        result = await call("web_apply_settings", changes, revision)
        status = result["status"]
        if status in ("applied", "reload_required"):
            return {"status": status, **_snapshot(result)}
        if status in ("conflict", "save_failed", "apply_failed"):
            return {"status": status}
        raise TypeError("Invalid settings apply status")

    async def observe(body):
        _object(body, ("minutes",))
        await call("web_set_observation", _integer(body["minutes"], 0, 1440))
        return {"updated": True}

    async def update_entry(body):
        _object(body, ("action", "entry"))
        action = body["action"]
        if action not in ("add", "remove", "adopt", "remove_pending"):
            raise InvalidRequest("名单操作无效。")
        entry = _entry(body["entry"], action)
        result = await call("web_change_entry", action, entry)
        if result is False or (action != "add" and result is None):
            return {"updated": False}
        return {"updated": True}

    async def clear(body):
        _object(body, ("confirm",))
        if body["confirm"] is not True:
            raise InvalidRequest("需要确认清除诊断记录。")
        await call("web_clear_records")
        return {"cleared": True}

    async def preview(body, *, use_llm=False):
        _object(body, ("text", "confirm") if use_llm else ("text",), ("expected_provider_id",) if use_llm else ())
        text = _string(body["text"], MAX_SAMPLE, required=True, strip=False)
        if use_llm:
            if body["confirm"] is not True:
                raise InvalidRequest("需要确认模型调用及可能产生的费用。")
            effective = (await call("web_overview"))["effective"]
            provider = effective.get("review_provider")
            if not isinstance(provider, str) or not provider.strip():
                raise InvalidRequest("模型试算须先配置并应用复核 Provider ID。")
            if "expected_provider_id" in body and body["expected_provider_id"] != provider:
                raise InvalidRequest("复核 Provider 已变更。请刷新后重新确认。")
        return _decision(await call("web_preview", text, use_llm=use_llm), sample=True)

    async def paid_preview(body):
        return await preview(body, use_llm=True)

    def bind(handler, verb):
        async def view():
            try:
                username = request.username
            except (AttributeError, RuntimeError):
                username = None
            if not isinstance(username, str) or not username.strip():
                return error_response("请先登录 AstrBot Dashboard。", status_code=401, headers=headers)
            try:
                # A plugin-scoped OpenAPI key is not a Dashboard administrator.
                if request.plugin_name != PLUGIN_NAME or username.startswith(API_KEY_USERNAME_PREFIX):
                    return error_response("此操作仅限 AstrBot Dashboard 登录用户。", status_code=403, headers=headers)
                if DEMO_MODE:
                    return error_response("演示模式不开放安全设置中心。", status_code=403, headers=headers)
                if request.method != verb:
                    return error_response("请求方法不受支持。", status_code=405, headers=headers)
                if request.query:
                    raise InvalidRequest("此端点不接受查询参数。")
                if verb == "POST":
                    if (request.content_type or "").split(";", 1)[0].strip().lower() != "application/json":
                        return error_response("请求须使用 JSON。", status_code=415, headers=headers)
                    length = request.headers.get("content-length")
                    if length is not None and (not length.isascii() or not length.isdecimal() or len(length) > 10):
                        raise InvalidRequest("请求长度无效。")
                    if length is not None and int(length) > MAX_BODY:
                        return error_response("请求内容过长。", status_code=413, headers=headers)
                    raw = await request.body()
                    if len(raw) > MAX_BODY:
                        return error_response("请求内容过长。", status_code=413, headers=headers)
                    try:
                        data = json.loads(raw.decode("utf-8"))
                    except (ValueError, RecursionError):
                        raise InvalidRequest("请求不是有效的 JSON。") from None
                    result = await handler(data)
                else:
                    result = await handler()
                return json_response({"status": "ok", "data": result}, headers=headers)
            except InvalidRequest as exc:
                return error_response(str(exc), status_code=400, headers=headers)
            except Exception:
                # Do not serialize provider/persistence exceptions or input bodies.
                return error_response("操作失败，请查看插件状态后重试。", status_code=500, headers=headers)

        return view

    async def overview():
        value = await call("web_overview")
        effective = value["effective"]
        return {
            "effective": {
                key: effective[key] for key in (
                    "enabled", "defense_mode", "llm_analysis_mode", "review_provider",
                    "review_model", "llm_analysis_private_chat_enabled",
                )
            },
            "observation_until": value["observation_until"],
            "stats": {
                key: value["stats"][key]
                for key in ("allow", "harden", "replace", "block", "ban", "review_failure")
            },
        }

    async def entries():
        return await call("web_list_entries")

    async def records():
        return [_decision(row) for row in await call("web_list_records")]

    for path, verb, handler in (
        ("overview", "GET", overview),
        ("settings", "GET", settings),
        ("providers", "GET", providers),
        ("models", "POST", models),
        ("settings/save", "POST", save),
        ("observation", "POST", observe),
        ("entries", "GET", entries),
        ("entries/update", "POST", update_entry),
        ("records", "GET", records),
        ("records/clear", "POST", clear),
        ("preview/rules", "POST", preview),
        ("preview/review", "POST", paid_preview),
    ):
        plugin.context.register_web_api(f"/{PLUGIN_NAME}/{path}", bind(handler, verb), [verb], f"AntiPromptInjector: {path}")
