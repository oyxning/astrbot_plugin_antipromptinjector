"""Read-only input snapshot for AstrBot v4.29.4 request hooks."""

from dataclasses import dataclass
from typing import Literal


MAX_INPUT_CHARS = 8192
MAX_EXTRA_PARTS = 32
MAX_MESSAGE_COMPONENTS = 32
REQUEST_FIELDS = frozenset({
    "prompt", "session_id", "image_urls", "audio_urls", "extra_user_content_parts",
    "func_tool", "contexts", "system_prompt", "conversation", "tool_calls_result",
    "model",
})
UNINSPECTED_FIELDS = (
    "image_urls", "audio_urls", "contexts", "system_prompt", "func_tool",
    "tool_calls_result", "conversation",
)
MEDIA_TYPES = ("image_url", "audio_url")
Source = Literal["prompt", "extra_user_content_parts"]


@dataclass(frozen=True, slots=True)
class InputBlock:
    source: Source
    text: str
    attributable: bool
    index: int | None = None


@dataclass(frozen=True, slots=True)
class InputInspection:
    blocks: tuple[InputBlock, ...]
    incomplete_reasons: tuple[str, ...]
    uncovered_fields: tuple[str, ...]
    attribution_reasons: tuple[str, ...] = ()

    @property
    def attributable(self) -> bool:
        """Whether the whole inspected sample can be considered for attribution."""
        return (
            bool(self.blocks)
            and not self.incomplete_reasons
            and not self.attribution_reasons
            and all(block.attributable for block in self.blocks)
        )

    @property
    def prompt_review_text(self) -> str | None:
        """Verified prompt only; suitable for a proactive review with no local hits."""
        return next((block.text for block in self.blocks if block.attributable), None)

    @property
    def review_text(self) -> str | None:
        """Payload for whole-sample review; never substitute the prompt for mixed text."""
        return None if self.review_unavailable_reason else self.prompt_review_text

    @property
    def review_unavailable_reason(self) -> str | None:
        if self.incomplete_reasons:
            return "incomplete_text"
        if any(not block.attributable for block in self.blocks):
            return "unverified_text_source"
        if self.prompt_review_text is None:
            return "no_reviewable_text"
        return None


def _host_text_types():
    from astrbot.core.agent.message import AudioURLPart, ImageURLPart, TextPart
    from astrbot.core.message.components import Plain

    return Plain, TextPart, (ImageURLPart, AudioURLPart)


def _event_matches_prompt(event, prompt: str, plain_type) -> bool:
    """Exact equality avoids treating a prefix, quotation or generated text as proof."""
    if plain_type is None or type(getattr(event, "message_str", None)) is not str:
        return False
    raw = event.message_str
    if len(raw) != len(prompt) or raw != prompt:
        return False
    chain = getattr(getattr(event, "message_obj", None), "message", None)
    if type(chain) is not list or not 0 < len(chain) <= MAX_MESSAGE_COMPONENTS:
        return False
    offset = 0
    for component in chain:
        if type(component) is not plain_type:
            return False
        text = component.text
        if type(text) is not str or not prompt.startswith(text, offset):
            return False
        offset += len(text)
    return offset == len(prompt)


def _extra_text(part, text_part_type, media_part_types) -> tuple[str | None, str | None]:
    if type(part) in media_part_types:
        return None, "extra_media"
    if type(part) is dict:
        part_type = part.get("type")
        if type(part_type) is str and part_type in MEDIA_TYPES:
            return None, "extra_media"
        if (
            len(part) not in (2, 3)
            or any(key not in ("type", "text", "_no_save") for key in part)
            or type(part_type) is not str
            or part_type != "text"
            or ("_no_save" in part and type(part["_no_save"]) is not bool)
        ):
            return None, "unsupported_extra_part"
        text = part.get("text")
    elif text_part_type is not None and type(part) is text_part_type:
        fields = vars(part)
        if len(fields) != 2 or fields.get("type") != "text":
            return None, "unsupported_extra_part"
        text = fields.get("text")
    else:
        return None, "unsupported_extra_part"
    if type(text) is not str:
        return None, "invalid_extra_text"
    return text, None


def inspect_input(
    event, req, *, max_chars: int = MAX_INPUT_CHARS, scan_extra_text: bool = True,
) -> InputInspection:
    """Return bounded local text blocks and separate coverage from scan failures.

    Extra text has no reliable provenance in v4.29.4: trusted reminders, quotes,
    retrieval and plugin text can all use the same TextPart. Never export it or
    use it to attribute a violation to the sender. Use review_text for decisions
    on the combined sample; prompt_review_text is only for prompt-only review.
    Opaque fields are not traversed.
    """
    if type(max_chars) is not int or not 1 <= max_chars <= MAX_INPUT_CHARS:
        raise ValueError("Invalid inspection character budget")
    try:
        plain_type, text_part_type, media_part_types = _host_text_types()
    except ImportError:
        plain_type = text_part_type = None
        media_part_types = ()

    try:
        fields = vars(req)
    except TypeError:
        return InputInspection((), (), ("unknown_request_fields",), ("unknown_request_fields",))
    reasons: dict[str, None] = {}
    attribution: dict[str, None] = {}
    uncovered: dict[str, None] = {}
    blocks: list[InputBlock] = []
    remaining = max_chars
    if len(fields) > len(REQUEST_FIELDS) or any(field not in REQUEST_FIELDS for field in fields):
        uncovered["unknown_request_fields"] = None
        attribution["unknown_request_fields"] = None
    chain = getattr(getattr(event, "message_obj", None), "message", None)
    if event is not None and (
        type(chain) is not list
        or len(chain) > MAX_MESSAGE_COMPONENTS
        or any(type(component) is not plain_type for component in chain)
    ):
        uncovered["event.message_obj.message"] = None
        attribution["unverified_event_components"] = None
    for name in UNINSPECTED_FIELDS:
        value = fields.get(name)
        if value is None or (type(value) in (str, list, dict) and not len(value)):
            continue
        uncovered[name] = None
        if name in ("image_urls", "audio_urls", "tool_calls_result"):
            attribution["unverified_opaque_source"] = None

    def add(text: str, source: Source, index: int | None = None) -> None:
        nonlocal remaining
        if len(text) > remaining:
            reasons["text_budget"] = None
            return
        remaining -= len(text)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            reasons["invalid_text_encoding"] = None
            return
        if not text.strip():
            return
        attributable = source == "prompt" and _event_matches_prompt(event, text, plain_type)
        if not attributable:
            key = "unverified_prompt_source" if source == "prompt" else "mixed_extra_source"
            attribution[key] = None
        blocks.append(InputBlock(source, text, attributable, index))

    prompt = fields.get("prompt")
    if type(prompt) is str:
        add(prompt, "prompt")
    elif prompt is not None:
        reasons["invalid_prompt"] = None

    parts = fields.get("extra_user_content_parts", [])
    if not scan_extra_text:
        if type(parts) is not list or parts:
            uncovered["extra_user_content_parts"] = None
            attribution["uninspected_extra_parts"] = None
    elif type(parts) is not list:
        uncovered["extra_user_content_parts"] = None
        attribution["uninspected_extra_parts"] = None
    else:
        if len(parts) > MAX_EXTRA_PARTS:
            reasons["part_budget"] = None
        for index, part in enumerate(parts[:MAX_EXTRA_PARTS]):
            text, error = _extra_text(part, text_part_type, media_part_types)
            if error == "invalid_extra_text":
                reasons[error] = None
            elif error:
                key = "extra_user_content_parts.media" if error == "extra_media" else "extra_user_content_parts"
                uncovered[key] = None
                attribution["uninspected_extra_parts"] = None
            elif text is not None:
                add(text, "extra_user_content_parts", index)
    return InputInspection(tuple(blocks), tuple(reasons), tuple(uncovered), tuple(attribution))


def isolate(event, req) -> bool:
    """False requires the caller to stop the request; leaves event and req untouched.

    The v4.29.4 hook has no per-request replacement handle or final-send guarantee.
    Internal post-hook image preparation can regenerate original-path notices from
    its local cache even with empty media, before deferred runner reset. Third-party
    reset and request mapping and later plugins have no isolation contract. Neither
    clearing all known fields nor accepting an apparently plain request proves that
    downstream code cannot rehydrate from those sources or from the original event.
    """
    return False
