"""Plugin-owned configuration validation, migration, and local state."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

SCHEMA = json.loads(Path(__file__).with_name("_conf_schema.json").read_text(encoding="utf-8"))
DEFAULTS = {key: item["default"] for key, item in SCHEMA.items()}
BOUNDS = {
    "blacklist_duration": (0, 525600),
    "review_timeout_seconds": (1, 60),
    "review_max_concurrency": (1, 16),
    "review_max_chars": (256, 8192),
    "incident_history_size": (1, 5000),
    "persona_sensitivity": (0.1, 1.0),
}
LEGACY = {
    "blacklist", "whitelist", "initial_whitelist", "enable_signature_lock", "sanitize_enabled",
    "webui_enabled", "webui_host", "webui_port", "webui_token",
    "webui_password_hash", "webui_password_salt", "webui_password_alg",
    "webui_password_iters", "webui_session_timeout",
}
REDACT = re.compile(
    r"(?i)(?:https?://|[a-z]+://|[\w.+-]+@[\w.-]+\.)|\b(?:sk|pk|gh[pousr]|github_pat|xox[baprs])[-_][\w-]+"
    r"|-----BEGIN |[A-Za-z0-9_+/=-]{24,}"
    r"|(?:password|secret|token|api[-_ ]?key|authorization|credential|cookie|密码|密钥|令牌|凭据)"
)
SAFE_LABEL = re.compile(r"[A-Za-z0-9_./:@+-]{1,128}\Z")
SOURCES = {"prompt", "extra_text", "extra_user_content_parts", "host", "unknown"}
ACTIONS = {"allow", "harden", "replace", "block"}
REVIEWS = {
    "not_requested", "skipped", "not_needed", "not_run", "safe", "confirmed",
    "attack", "injection", "suspicious", "failed", "unavailable", "disabled",
}


class StateError(RuntimeError):
    pass


class RevisionConflict(StateError):
    pass


@dataclass(frozen=True)
class Identity:
    platform: str
    instance: str
    user: str
    session: str | None = None

    def __post_init__(self):
        for value in (self.platform, self.instance, self.user):
            _identity_part(value)
        if self.session is not None:
            _identity_part(self.session)

    def as_dict(self):
        return {
            "platform": self.platform, "instance": self.instance,
            "user": self.user, "session": self.session,
        }


def _identity_part(value):
    if (
        not isinstance(value, str) or not value.strip() or len(value) > 1024
        or _unsafe_characters(value)
    ):
        raise ValueError("invalid identity")


def _unsafe_characters(value):
    return any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value)


def identity_from_event(event, *, user: str | None = None, session_scope: bool = True):
    if session_scope and not event.get_session_id():
        raise ValueError("missing session ID")
    return Identity(
        event.get_platform_name(), event.get_platform_id(),
        event.get_sender_id() if user is None else user,
        event.unified_msg_origin if session_scope else None,
    )


def _json(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, allow_nan=False)


def _config_json(data):
    # Legacy files can contain Infinity or NaN, which the host JSON loader accepts.
    return json.dumps(data, sort_keys=True)


def _read(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def _atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def _backup_path(path):
    return path.with_name(f"{path.name}.antipromptinjector-v1.bak")


def prepare_legacy_config(config_path):
    """Run at plugin module import, before AstrBotConfig prunes unknown keys."""
    path = Path(config_path)
    backup = _backup_path(path)
    if backup.exists() or not path.exists():
        return
    raw = path.read_bytes()
    config = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(config, dict):
        raise StateError("legacy configuration is not an object")
    if (LEGACY & config.keys()) or (config.keys() - SCHEMA.keys()):
        if raw != path.read_bytes():
            raise RevisionConflict("legacy configuration changed before backup")
        _atomic_write(backup, raw)


def _valid_setting(key, value):
    spec = SCHEMA[key]
    kind = spec["type"]
    if kind == "bool":
        return type(value) is bool
    if kind == "int":
        low, high = BOUNDS[key]
        return type(value) is int and low <= value <= high
    if kind == "float":
        low, high = BOUNDS[key]
        return type(value) in (int, float) and low <= value <= high
    return (
        isinstance(value, str) and len(value) <= 256
        and not _unsafe_characters(value)
        and ("options" not in spec or value in spec["options"])
    )


def _active_settings(config):
    return {
        key: config[key] if key in config and _valid_setting(key, config[key]) else default
        for key, default in DEFAULTS.items()
    }


def _legacy_entries(old):
    entries = {}
    # The initial list only seeded a missing runtime list; deleted entries stay deleted.
    values = old.get("whitelist", old.get("initial_whitelist", []))
    if isinstance(values, list):
        for uid in values:
            if isinstance(uid, str) and uid.strip() and not _unsafe_characters(uid):
                entries[("whitelist", uid)] = None
    blacklist = old.get("blacklist", {})
    if isinstance(blacklist, dict):
        for uid, expires in blacklist.items():
            if not uid.strip() or _unsafe_characters(uid) or type(expires) not in (float, int):
                continue
            if expires == math.inf:
                entries[("blacklist", uid)] = None
            elif 0 < expires < math.inf:
                entries[("blacklist", uid)] = expires
    return [
        {"kind": kind, "user": uid, "expires_at": expires}
        for (kind, uid), expires in entries.items()
    ]


def _excerpt(value):
    if (
        not isinstance(value, str) or len(value) > 2048 or REDACT.search(value)
        or _unsafe_characters(" ".join(value.split()))
    ):
        return ""
    return " ".join(value.split())[:120]


def _label(value):
    if isinstance(value, str) and SAFE_LABEL.fullmatch(value) and not REDACT.search(value):
        return value
    return ""


def _list_kind(kind):
    if kind not in ("blacklist", "whitelist"):
        raise ValueError("invalid list kind")


def _expiry(value):
    if value is not None and not (type(value) in (float, int) and 0 < value < math.inf):
        raise ValueError("invalid expiry")
    return value


class PluginState:
    """Call synchronously on AstrBot's event loop, from authorized entry points."""

    def __init__(self, config, data_dir, *, clock: Callable[[], float] = time.time):
        self.config = config
        self._clock = clock
        self._config_path = Path(config.config_path)
        self._path = Path(data_dir) / "antipromptinjector-state.json"
        self._effective = self._current_settings()
        self._apply_failed = False
        if self._path.exists():
            self._data = _read(self._path)
            if self._data.get("version") != 1:
                raise StateError("unsupported plugin state version")
            if (
                not isinstance(self._data.get("entries"), list)
                or not isinstance(self._data.get("legacy"), list)
                or not isinstance(self._data.get("records"), list)
            ):
                raise StateError("invalid plugin state")
        else:
            prepare_legacy_config(self._config_path)
            backup = _backup_path(self._config_path)
            self._data = {}
            self._commit({
                "version": 1, "entries": [], "records": [], "observation_until": None,
                "legacy": _legacy_entries(_read(backup)) if backup.exists() else [],
            })

    def _current_settings(self):
        return _active_settings(self.config)

    @property
    def settings(self):
        # Normal operation reads the AstrBot-owned object, including native edits.
        return dict(self._effective if self._apply_failed else self._current_settings())

    def _config_source(self):
        disk = _read(self._config_path)
        live = dict(self.config)
        revision = hashlib.sha256(_config_json([disk, live]).encode()).hexdigest()
        return disk, live, revision

    def config_view(self):
        disk, _, revision = self._config_source()
        settings = _active_settings(disk)
        invalid = sorted(key for key in SCHEMA if key in disk and not _valid_setting(key, disk[key]))
        effective = self.settings
        status = "apply_failed" if self._apply_failed else (
            "applied" if settings == effective else "reload_required"
        )
        return {
            "settings": settings, "config": dict(settings), "revision": revision,
            "effective": effective, "status": status, "apply_status": status,
            "invalid_settings": invalid,
            "observation_until": self.observation_until,
        }

    def save_settings(self, patch, revision, *, apply=None):
        """Optional synchronous apply callback must apply atomically or raise."""
        if not isinstance(patch, dict):
            raise ValueError("expected settings object")
        for key, value in patch.items():
            if key not in SCHEMA or not _valid_setting(key, value):
                raise ValueError("invalid setting")
        disk, live, current = self._config_source()
        if revision != current or _config_json(disk) != _config_json(live):
            raise RevisionConflict("configuration changed; reload the page or plugin")
        old_effective = self.settings
        candidate = {**live, **patch}
        try:
            self.config.save_config(candidate)
        except Exception:
            self.config.clear()
            self.config.update(live)
            raise StateError("configuration save failed") from None
        try:
            saved = _read(self._config_path)
        except (OSError, ValueError):
            self._effective = old_effective
            self._apply_failed = True
            raise StateError("configuration save could not be verified") from None
        if _config_json(saved) != _config_json(candidate):
            self._effective = old_effective
            self._apply_failed = True
            raise RevisionConflict("configuration save was superseded")
        effective = self._current_settings()
        try:
            if apply is not None:
                apply(dict(effective))
        except Exception:
            self._effective = old_effective
            self._apply_failed = True
        else:
            self._effective = effective
            self._apply_failed = False
        return self.config_view()

    def _commit(self, data):
        if self._path.exists() and _read(self._path) != self._data:
            raise RevisionConflict("plugin state changed; reload the plugin")
        _atomic_write(self._path, _json(data).encode("utf-8"))
        self._data = data

    @property
    def observation_until(self):
        until = self._data["observation_until"]
        return until if until is not None and until > self._clock() else None

    def set_observation(self, minutes):
        if type(minutes) is not int or not 0 <= minutes <= 10080:
            raise ValueError("invalid observation duration")
        self._commit({
            **self._data, "observation_until": self._clock() + minutes * 60 if minutes else None,
        })
        return self.observation_until

    def list_entries(self, kind=None, *, pending=False):
        if kind is not None:
            _list_kind(kind)
        now = self._clock()
        return [
            {
                **deepcopy(row),
                "remaining_seconds": None if row["expires_at"] is None
                else max(0, math.ceil(row["expires_at"] - now)),
            }
            for row in self._data["legacy" if pending else "entries"]
            if kind is None or row["kind"] == kind
        ]

    def match_list(self, kind, identity):
        _list_kind(kind)
        now = self._clock()
        exact = identity.as_dict()
        broad = {**exact, "session": None}
        for scope in (exact, broad):
            for row in self._data["entries"]:
                if (
                    row["kind"] == kind and row["identity"] == scope
                    and (row["expires_at"] is None or row["expires_at"] > now)
                ):
                    return deepcopy(row)
        if kind == "blacklist":
            for row in self._data["legacy"]:
                if (
                    row["kind"] == kind and row["user"] == identity.user
                    and (row["expires_at"] is None or row["expires_at"] > now)
                ):
                    return {**row, "origin": "legacy", "identity": None}
        return None

    def _updated_entry(self, kind, identity, *, expires_at, reason, origin):
        _list_kind(kind)
        if origin not in ("manual", "automatic", "legacy"):
            raise ValueError("invalid list origin")
        key = identity.as_dict()
        row = {
            "kind": kind, "identity": key, "expires_at": _expiry(expires_at),
            "reason": _excerpt(reason), "origin": origin,
        }
        previous = [
            item for item in self._data["entries"]
            if item["kind"] == kind and item["identity"] == key
        ]
        if previous:
            old = previous[0]
            if origin == "legacy":
                raise RevisionConflict("scoped entry already exists")
            if origin == "automatic" and (old["expires_at"] is None or old["expires_at"] > self._clock()):
                return self._data["entries"], None
        return [
            item for item in self._data["entries"]
            if item["kind"] != kind or item["identity"] != key
        ] + [row], row

    def put_entry(self, kind, identity, *, expires_at=None, reason="", origin="manual"):
        entries, row = self._updated_entry(
            kind, identity, expires_at=expires_at, reason=reason, origin=origin,
        )
        if row is not None:
            self._commit({**self._data, "entries": entries})
        return deepcopy(row)

    def remove_entry(self, kind, identity):
        _list_kind(kind)
        key = identity.as_dict()
        entries = [
            row for row in self._data["entries"]
            if row["kind"] != kind or row["identity"] != key
        ]
        if len(entries) == len(self._data["entries"]):
            return False
        self._commit({**self._data, "entries": entries})
        return True

    def adopt_legacy(self, kind, identity):
        _list_kind(kind)
        for row in self._data["legacy"]:
            if row["kind"] == kind and row["user"] == identity.user:
                entries, adopted = self._updated_entry(
                    kind, identity, expires_at=row["expires_at"], reason="", origin="legacy",
                )
                self._commit({
                    **self._data, "entries": entries,
                    "legacy": [item for item in self._data["legacy"] if item is not row],
                })
                return deepcopy(adopted)
        return None

    def remove_legacy(self, kind, user):
        _list_kind(kind)
        legacy = [
            row for row in self._data["legacy"] if (row["kind"], row["user"]) != (kind, user)
        ]
        if len(legacy) == len(self._data["legacy"]):
            return False
        self._commit({**self._data, "legacy": legacy})
        return True

    def record(self, *, request_id, source, action, review_status="not_requested",
               provider="", model="", elapsed_ms=0, fault="", rules=(), excerpt="",
               observed=False, intended_action=None, banned=False, review_failed=False,
               incomplete=False, model_source=None, review_reason="", confidence=None,
               decision_reason=""):
        if action not in ACTIONS or (intended_action is not None and intended_action not in ACTIONS):
            raise ValueError("invalid diagnostic action")
        if review_status not in REVIEWS:
            raise ValueError("invalid review status")
        if not (type(elapsed_ms) in (int, float) and 0 <= elapsed_ms < math.inf):
            raise ValueError("invalid elapsed time")
        if confidence is not None and not (type(confidence) in (float, int) and 0 <= confidence <= 1):
            raise ValueError("invalid review confidence")
        if isinstance(request_id, str) and 0 < len(request_id) <= 256 and not _unsafe_characters(request_id):
            request_id = hashlib.sha256(request_id.encode()).hexdigest()[:24]
        else:
            raise ValueError("invalid request ID")
        row = {
            "time": self._clock(), "request_id": request_id,
            "source": source if source in SOURCES else "unknown",
            "action": action, "intended_action": intended_action,
            "review_status": review_status, "provider": _label(provider), "model": _label(model),
            "model_source": model_source if model_source in ("response", "requested", "provider_default") else None,
            "review_reason": _excerpt(review_reason), "confidence": confidence,
            "decision_reason": _excerpt(decision_reason),
            "elapsed_ms": round(elapsed_ms, 2), "fault": _label(fault),
            "observed": observed is True, "banned": banned is True,
            "review_failed": review_failed is True or review_status in {"failed", "unavailable"},
            "incomplete": incomplete is True,
            "excerpt": _excerpt(excerpt) if source in {"prompt", "extra_text", "extra_user_content_parts"} else "",
            "rules": [],
        }
        for index, item in enumerate(rules):
            if index == 16:
                break
            if isinstance(item, dict) and (rule := _label(item.get("id"))):
                row["rules"].append({
                    "id": rule,
                    "evidence": _excerpt(item.get("evidence")) if source in {
                        "prompt", "extra_text", "extra_user_content_parts",
                    } else "",
                })
        self._commit({**self._data, "records": (
            self._data["records"] + [row]
        )[-self.settings["incident_history_size"]:]})

    def records(self):
        return deepcopy(self._data["records"][-self.settings["incident_history_size"]:][::-1])

    def stats(self):
        counts = dict.fromkeys(sorted(ACTIONS) + ["ban", "review_failure"], 0)
        for row in self.records():
            counts[row["action"]] += 1
            counts["ban"] += row["banned"]
            counts["review_failure"] += row["review_failed"]
        return counts

    def clear_records(self):
        count = len(self._data["records"])
        self._commit({**self._data, "records": []})
        return count
