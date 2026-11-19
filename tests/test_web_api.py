import importlib
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "_antipromptinjector_web_test"


class Request:
    username = "dashboard-user"
    plugin_name = "antipromptinjector"
    content_type = "application/json; charset=utf-8"
    query = {}
    headers = {}
    raw = b""

    async def body(self):
        return self.raw


def response(data, *, status_code=200, headers=None):
    return status_code, data, headers


def error(message, *, status_code, headers):
    return response({"status": "error", "message": message}, status_code=status_code, headers=headers)


class Plugin:
    def __init__(self, state):
        self.config = dict(state.DEFAULTS)
        self.config["webui_token"] = "not-for-dashboard"
        self.routes = {}
        self.context = types.SimpleNamespace(register_web_api=self.register)
        self.rev = "1"
        self.calls = []
        self.result = "applied"
        self.entry_result = True

    def register(self, route, handler, methods, _desc):
        self.routes[(route, tuple(methods))] = handler

    def web_settings(self):
        return {"config": self.config, "revision": self.rev, "apply_status": "applied"}

    async def web_apply_settings(self, patch, revision):
        self.calls.append(("save", patch, revision))
        if self.result in {"conflict", "save_failed", "apply_failed"}:
            return {"status": self.result}
        if revision != self.rev:
            return {"status": "conflict"}
        self.config.update(patch)
        self.rev = str(int(self.rev) + 1)
        return {**self.web_settings(), "status": self.result, "apply_status": self.result}

    def web_overview(self):
        return {
            "effective": self.config,
            "observation_until": None,
            "stats": dict.fromkeys(("allow", "harden", "replace", "block", "ban", "review_failure"), 0),
        }

    def web_list_entries(self):
        return {"entries": [], "pending": [{"kind": "whitelist", "user": "42", "expires_at": None}]}

    def web_change_entry(self, action, entry):
        self.calls.append(("entries", action, entry))
        return self.entry_result

    def web_set_observation(self, minutes):
        self.calls.append(("observation", minutes))

    def web_list_records(self):
        return [{
            "action": "allow", "time": 100, "request_id": "0123456789abcdef01234567",
            "excerpt": "password: very-private", "system_prompt": "hidden",
        }]

    def web_clear_records(self):
        self.calls.append(("clear",))

    async def web_preview(self, text, *, use_llm):
        self.calls.append(("preview", text, use_llm))
        return {
            "action": "allow", "review_status": "safe" if use_llm else "not_requested",
            "provider": "example-provider" if use_llm else "",
            "model": "example-model" if use_llm else "",
            "rules": [{"id": "demo-rule", "evidence": "hello"}, {"id": "private", "evidence": "密钥：abc"}],
            "reason": "secret provider response",
            "model_source": "response" if use_llm else None,
            "decision_reason": "no_risk",
            "review_reason": "example" if use_llm else "",
        }


class WebApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        namespace = types.ModuleType(PACKAGE)
        namespace.__path__ = [str(ROOT)]
        self.request = Request()
        self.web = types.SimpleNamespace(request=self.request, json_response=response, error_response=error)
        self.core = types.SimpleNamespace(DEMO_MODE=False)
        modules = {
            PACKAGE: namespace,
            "astrbot.api.web": self.web,
            "astrbot.core": self.core,
            "astrbot.core.workspace": types.SimpleNamespace(API_KEY_USERNAME_PREFIX="api_key:"),
        }
        self.addCleanup(self.cleanup_package)
        self.enterContext(patch.dict(sys.modules, modules))
        self.api = importlib.import_module(f"{PACKAGE}.web_api")
        self.state = importlib.import_module(f"{PACKAGE}.state")
        self.plugin = Plugin(self.state)
        self.api.register_web_api(self.plugin)

    @staticmethod
    def cleanup_package():
        for key in tuple(sys.modules):
            if key == PACKAGE or key.startswith(f"{PACKAGE}."):
                del sys.modules[key]

    async def call(self, path, body=None, *, verb=None, check_cache=True):
        method = verb or ("POST" if body is not None else "GET")
        handler = self.plugin.routes[(f"/antipromptinjector/{path}", (method,))]
        self.request.method = method
        self.request.raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        code, payload, headers = await handler()
        if check_cache:
            self.assertEqual(headers.get("Cache-Control"), "no-store")
        return code, payload.get("data", payload)

    async def test_every_endpoint_rejects_anonymous_and_api_app(self):
        for (route, verbs) in self.plugin.routes:
            verb, = verbs
            path = route.removeprefix("/antipromptinjector/")
            for name, code in ((None, 401), ("", 401), (" ", 401), ("api_key:with-plugin-scope", 403)):
                with self.subTest(path=path, name=name, verb=verb):
                    self.request.username = name
                    self.assertEqual((await self.call(path, {}, verb=verb))[0], code)
        self.assertEqual(self.plugin.calls, [])

    async def test_picker_discloses_only_chat_ids_and_models(self):
        def provider(id_, kind):
            return types.SimpleNamespace(
                meta=lambda: types.SimpleNamespace(id=id_, provider_type=types.SimpleNamespace(value=kind)),
                get_model=lambda: "default", get_models=AsyncMock(return_value=["m2", "m1", "m1"]),
                provider_config={"key": "never-send"})
        chat, speech = provider("chat", "chat_completion"), provider("tts", "tts")
        self.plugin.context.get_all_providers = lambda: [chat, speech]
        self.plugin.context.get_provider_by_id = Mock(side_effect={"chat": chat, "tts": speech}.get)
        self.assertEqual(await self.call("providers"), (200, [{"id": "chat", "model": "default"}]))
        self.assertEqual(await self.call("models", {"provider": "chat"}), (200, ["m1", "m2"]))
        for id_ in ("missing", "tts"):
            self.assertEqual((await self.call("models", {"provider": id_}))[0], 400)
        speech.get_models.assert_not_awaited()

    async def test_missing_context_wrong_plugin_and_demo(self):
        self.web.request = property(lambda: None)
        self.api.register_web_api(self.plugin)
        self.assertEqual((await self.call("settings"))[0], 401)
        self.web.request = self.request
        self.api.register_web_api(self.plugin)
        self.request.plugin_name = "another-plugin"
        self.assertEqual((await self.call("settings"))[0], 403)
        self.request.plugin_name = "antipromptinjector"
        self.core.DEMO_MODE = True
        self.api.register_web_api(self.plugin)
        self.assertEqual((await self.call("records"))[0], 403)
        self.assertEqual((await self.call("preview/review", {"text": "sample", "confirm": True}))[0], 403)
        self.assertEqual(self.plugin.calls, [])

    async def test_transaction_uses_schema_and_prevents_stale_write(self):
        code, settings = await self.call("settings")
        self.assertEqual(code, 200)
        self.assertNotIn("webui_token", settings["config"])
        low, high = self.state.BOUNDS["review_timeout_seconds"]
        self.assertEqual(settings["fields"]["review_timeout_seconds"]["bounds"], (low, high))
        sensitivity = settings["fields"]["persona_sensitivity"]
        self.assertEqual(sensitivity["type"], "float")
        self.assertEqual(sensitivity["bounds"], self.state.BOUNDS["persona_sensitivity"])
        for patch_body in (
            {"review_timeout_seconds": high + 1}, {"incident_history_size": True},
            {"auto_blacklist": "false"}, {"blacklist": {}}, {"webui_token": "new"},
            {"persona_sensitivity": 1.5},
        ):
            self.assertEqual((await self.call("settings/save", {"revision": "1", "patch": patch_body}))[0], 400)
        self.assertEqual(self.plugin.calls, [])
        body = {"revision": settings["revision"], "patch": {"review_timeout_seconds": high, "persona_sensitivity": 0.45}}
        self.assertEqual((await self.call("settings/save", body))[1]["status"], "applied")
        self.assertEqual((await self.call("settings/save", body))[1]["status"], "conflict")
        self.assertEqual(len(self.plugin.calls), 1)

    async def test_storage_conflict_and_apply_failure_are_distinct(self):
        body = {"revision": "1", "patch": {"enabled": False}}
        for status in ("conflict", "save_failed", "apply_failed", "reload_required"):
            self.plugin.result = status
            code, data = await self.call("settings/save", body)
            self.assertEqual(code, 200)
            self.assertEqual(data["status"], status)

    async def test_overview_does_not_expose_config_secrets(self):
        code, data = await self.call("overview")
        self.assertEqual(code, 200)
        self.assertNotIn("webui_token", data["effective"])
        self.assertEqual(data["stats"]["review_failure"], 0)

    async def test_scoped_entries_adopt_and_remove_pending(self):
        old = {"kind": "whitelist", "user": "42"}
        scoped = {**old, "platform": "qq", "instance": "one", "session": None}
        self.assertEqual((await self.call("entries"))[1]["pending"][0]["user"], "42")
        for action, entry in (("adopt", old), ("remove_pending", scoped), ("adopt", {**scoped, "duration_minutes": 0})):
            self.assertEqual((await self.call("entries/update", {"action": action, "entry": entry}))[0], 400)
        for action, entry in (
            ("adopt", scoped), ("remove_pending", old),
            ("add", {**scoped, "duration_minutes": 30}), ("remove", scoped),
        ):
            self.assertEqual((await self.call("entries/update", {"action": action, "entry": entry}))[1], {"updated": True})
            self.assertEqual(self.plugin.calls[-1], ("entries", action, entry))
        self.plugin.entry_result = None
        self.assertEqual((await self.call("entries/update", {"action": "adopt", "entry": scoped}))[1], {"updated": False})

    async def test_preview_and_records_have_separate_narrow_surfaces(self):
        for body in ({"text": "hello"}, {"text": "hello", "confirm": "true"},
                     {"text": "hello", "confirm": True, "session": "not-used"}):
            self.assertEqual((await self.call("preview/review", body))[0], 400)
        self.assertEqual((await self.call("preview/rules", {"text": "hello", "confirm": True}))[0], 400)
        text = " sample\n"
        code, result = await self.call("preview/rules", {"text": text})
        self.assertEqual(code, 200)
        self.assertEqual(result["rules"][1]["evidence"], "")
        self.assertNotIn("reason", result)
        self.assertEqual(self.plugin.calls, [("preview", text, False)])
        self.assertEqual((await self.call("preview/review", {"text": text, "confirm": True}))[0], 400)
        self.assertEqual(self.plugin.calls, [("preview", text, False)])
        self.plugin.config["review_provider"] = "example-provider"
        self.assertEqual((await self.call("preview/review", {
            "text": text, "confirm": True, "expected_provider_id": "outdated-provider",
        }))[0], 400)
        self.assertEqual(self.plugin.calls, [("preview", text, False)])
        code, paid = await self.call("preview/review", {
            "text": text, "confirm": True, "expected_provider_id": "example-provider",
        })
        self.assertEqual(code, 200)
        self.assertEqual(paid["model"], "example-model")
        self.assertEqual(paid["model_source"], "response")
        self.assertEqual(paid["decision_reason"], "no_risk")
        self.assertEqual(paid["review_reason"], "example")
        self.assertEqual(self.plugin.calls[-1], ("preview", text, True))
        _, rows = await self.call("records")
        self.assertEqual(rows[0]["excerpt"], "")
        self.assertNotIn("system_prompt", rows[0])
        self.assertEqual(rows[0]["request_id"], "0123456789abcdef01234567")
        self.assertEqual((await self.call("records/clear", {"confirm": False}))[0], 400)
        self.assertEqual((await self.call("records/clear", {"confirm": True}))[1], {"cleared": True})
        self.assertEqual(self.plugin.calls[-1], ("clear",))

    async def test_bad_json_large_bodies_unknown_queries_and_private_errors(self):
        self.assertEqual((await self.call("preview/rules", b"{"))[0], 400)
        self.assertEqual((await self.call("preview/rules", b" " * (self.api.MAX_BODY + 1)))[0], 413)
        self.request.headers = {"content-length": str(self.api.MAX_BODY + 1)}
        self.assertEqual((await self.call("preview/rules", {"text": "sample"}))[0], 413)
        self.request.query = {"username": "anyone"}
        self.assertEqual((await self.call("settings"))[0], 400)
        self.request.query = {}
        with patch.object(self.plugin, "web_settings", side_effect=RuntimeError("private provider failure")):
            status, payload = await self.call("settings")
        self.assertEqual(status, 500)
        self.assertNotIn("private provider failure", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
