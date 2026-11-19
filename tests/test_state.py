import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "antipromptinjector_test_state", Path(__file__).resolve().parents[1] / "state.py",
)
state = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = state
spec.loader.exec_module(state)


class FakeAstrBotConfig(dict):
    def __init__(self, path):
        self.config_path = str(path)
        raw = json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
        super().__init__(state.DEFAULTS | {key: raw[key] for key in state.SCHEMA if key in raw})
        self.fail = False
        self.save_config()

    def save_config(self, values=None):
        if values is not None:
            self.update(values)
        if self.fail:
            raise OSError("simulated write error")
        Path(self.config_path).write_text(json.dumps(self), encoding="utf-8-sig")


class PluginStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "antipromptinjector_config.json"
        self.data_dir = self.root / "data"
        self.now = 1000
        self.identity = state.Identity("test", "bot-a", "42", "group-1")

    def load(self):
        self.config = FakeAstrBotConfig(self.path)
        self.store = state.PluginState(self.config, self.data_dir, clock=lambda: self.now)
        return self.store

    def save(self, **changes):
        return self.store.save_settings(changes, self.store.config_view()["revision"])

    def test_backup_precedes_schema_pruning_and_adoption_is_idempotent(self):
        old = {
            "defense_mode": "intercept", "auto_blacklist": True,
            "initial_whitelist": ["removed"], "whitelist": ["42", "42"],
            "blacklist": {"42": 1090, "43": float("inf"), "44": 900},
            "persona_sensitivity": 0.35, "custom": {"note": "fixture"},
        }
        raw = json.dumps(old).encode()
        self.path.write_bytes(raw)
        state.prepare_legacy_config(self.path)
        store = self.load()
        self.assertEqual(store.settings["defense_mode"], "intercept")
        self.assertTrue(store.settings["auto_blacklist"])
        self.assertEqual(store.settings["persona_sensitivity"], 0.35)
        self.assertNotIn("whitelist", self.config)
        self.assertEqual(state._backup_path(self.path).read_bytes(), raw)
        self.assertEqual([row["user"] for row in store.list_entries("whitelist", pending=True)], ["42"])
        self.assertFalse(store.match_list("whitelist", self.identity))
        other = state.Identity("other", "bot-b", "42", "group-2")
        self.assertEqual(store.match_list("blacklist", other)["origin"], "legacy")
        self.assertIsNone(store.match_list("whitelist", other))
        self.assertEqual(store.adopt_legacy("blacklist", self.identity)["expires_at"], 1090)
        self.assertEqual(store.match_list("blacklist", self.identity)["expires_at"], 1090)
        self.assertIsNone(store.match_list("blacklist", other))
        self.assertEqual(store.list_entries("blacklist", pending=True)[0]["expires_at"], None)
        self.assertEqual(store.list_entries("blacklist", pending=True)[1]["remaining_seconds"], 0)
        self.assertTrue(store.remove_legacy("blacklist", "43"))
        self.assertIsNone(store.match_list("blacklist", state.Identity("test", "bot-a", "43")))
        self.assertTrue(store.remove_legacy("whitelist", "42"))
        state.prepare_legacy_config(self.path)
        reloaded = self.load()
        self.assertEqual(state._backup_path(self.path).read_bytes(), raw)
        self.assertFalse(reloaded.list_entries("whitelist", pending=True))
        self.assertEqual(len(reloaded.list_entries()), 1)
        self.now = 1090
        self.assertIsNone(reloaded.match_list("blacklist", self.identity))

    def test_failed_backup_leaves_legacy_file_intact(self):
        raw = b'{"whitelist": ["42"]}'
        self.path.write_bytes(raw)
        with patch.object(state, "_atomic_write", side_effect=OSError):
            with self.assertRaises(OSError):
                state.prepare_legacy_config(self.path)
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertFalse(state._backup_path(self.path).exists())

    def test_scoped_entries_and_instance_wide_matching(self):
        store = self.load()
        self.assertFalse(store.settings["auto_blacklist"])
        store.put_entry("whitelist", self.identity)
        self.assertTrue(store.match_list("whitelist", self.identity))
        for other in (
            state.Identity("other", "bot-a", "42", "group-1"),
            state.Identity("test", "bot-b", "42", "group-1"),
            state.Identity("test", "bot-a", "43", "group-1"),
            state.Identity("test", "bot-a", "42", "group-2"),
        ):
            self.assertIsNone(store.match_list("whitelist", other))
        broad = state.Identity("test", "bot-a", "42")
        store.put_entry("blacklist", broad, reason="manual reason")
        self.assertIsNone(store.put_entry("blacklist", broad, expires_at=1050, origin="automatic"))
        self.assertEqual(store.match_list("blacklist", self.identity)["reason"], "manual reason")

    def test_revision_rejects_stale_page_and_native_change(self):
        store = self.load()
        revision = store.config_view()["revision"]
        self.assertEqual(self.save(defense_mode="scorch")["status"], "applied")
        with self.assertRaises(state.RevisionConflict):
            store.save_settings({"enabled": False}, revision)
        revision = store.config_view()["revision"]
        native = FakeAstrBotConfig(self.path)
        native.save_config({"defense_mode": "intercept"})
        self.assertEqual(store.config_view()["status"], "reload_required")
        with self.assertRaises(state.RevisionConflict):
            store.save_settings({"enabled": False}, revision)
        self.assertEqual(self.load().settings["defense_mode"], "intercept")

    def test_apply_failure_does_not_claim_runtime_changed(self):
        store = self.load()
        store.put_entry("blacklist", self.identity, expires_at=1100)
        store.set_observation(1)
        revision = store.config_view()["revision"]
        with patch.object(self.config, "save_config", side_effect=OSError):
            with self.assertRaises(state.StateError):
                store.save_settings({"defense_mode": "intercept"}, revision)
        self.assertEqual(store.config_view()["revision"], revision)
        result = store.save_settings(
            {"defense_mode": "scorch"}, revision, apply=lambda _: self.fail("simulated apply error"),
        )
        self.assertEqual(result["status"], "apply_failed")
        self.assertEqual(result["settings"]["defense_mode"], "scorch")
        self.assertEqual(store.settings["defense_mode"], "sentry")
        with self.assertRaises(ValueError):
            self.save(review_timeout_seconds=True)
        with self.assertRaises(ValueError):
            self.save(review_max_chars=8193)
        with self.assertRaises(ValueError):
            self.save(persona_sensitivity=float("nan"))
        with self.assertRaises(ValueError):
            self.save(whitelist=[])
        self.assertEqual(self.load().settings["defense_mode"], "scorch")
        self.assertEqual(self.store.match_list("blacklist", self.identity)["expires_at"], 1100)
        self.now = 1060
        self.assertIsNone(self.store.observation_until)
        self.assertEqual(self.store.settings["defense_mode"], "scorch")

    def test_invalid_native_setting_can_be_repaired(self):
        self.path.write_text('{"persona_sensitivity": NaN}', encoding="utf-8")
        store = self.load()
        self.assertEqual(store.settings["persona_sensitivity"], 0.7)
        self.assertEqual(store.config_view()["invalid_settings"], ["persona_sensitivity"])
        result = self.save(
            persona_sensitivity=1.0, review_timeout_seconds=60,
            review_max_concurrency=16, review_max_chars=8192,
        )
        self.assertEqual(result["invalid_settings"], [])
        self.assertEqual(result["effective"]["persona_sensitivity"], 1.0)

    def test_diagnostics_are_bounded_pruned_and_isolated(self):
        store = self.load()
        self.save(incident_history_size=2)
        store.put_entry("whitelist", self.identity)
        store.set_observation(1)
        store.record(request_id="not-retained", source="prompt", action="replace")
        store.record(
            request_id="request-2", source="prompt", action="block",
            review_status="failed", provider="local", model="example-model",
            elapsed_ms=1.125, fault="timeout", banned=True,
            model_source="provider_default", review_reason="cookie=fixture",
            confidence=0.25, decision_reason="review required",
            rules=[{"id": "role_marker", "evidence": "Authorization: fixture"},
                   {"id": "fixture", "evidence": "example excerpt"}],
            excerpt="https://example.invalid/cred",
        )
        store.record(
            request_id="request-3", source="host", action="allow", intended_action="harden",
            observed=True, excerpt="private system fixture",
            rules=[{"id": "host_check", "evidence": "private system fixture"}],
        )
        raw = (self.data_dir / "antipromptinjector-state.json").read_text(encoding="utf-8")
        for forbidden in ("Authorization", "example.invalid", "private system fixture", "request-2", "cookie="):
            self.assertNotIn(forbidden, raw)
        records = self.load().records()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["review_reason"], "")
        self.assertEqual(records[1]["model_source"], "provider_default")
        self.assertEqual(records[1]["confidence"], 0.25)
        self.assertEqual(records[1]["decision_reason"], "review required")
        self.assertIn("example excerpt", raw)
        self.assertEqual(self.store.stats(), {
            "allow": 1, "block": 1, "harden": 0, "replace": 0, "ban": 1, "review_failure": 1,
        })
        self.assertEqual(self.store.clear_records(), 2)
        self.assertEqual(self.store.records(), [])
        self.assertEqual(self.store.observation_until, 1060)
        self.assertIsNotNone(self.store.match_list("whitelist", self.identity))
        self.assertEqual(self.store.settings["incident_history_size"], 2)

    def test_stale_plugin_instance_cannot_overwrite_state(self):
        old = self.load()
        new = self.load()
        new.put_entry("blacklist", self.identity)
        with self.assertRaises(state.RevisionConflict):
            old.clear_records()
        self.assertIsNotNone(self.load().match_list("blacklist", self.identity))


if __name__ == "__main__":
    unittest.main()
