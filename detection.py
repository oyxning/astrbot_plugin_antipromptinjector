import base64
import binascii
import re
import time
import unicodedata
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes


class PTDCoreBase:
    version = "5.0.0"
    name = "Prompt Threat Detector Core"

    def analyze(self, prompt: str) -> dict:
        raise NotImplementedError


@dataclass(frozen=True)
class DetectionLimits:
    input_chars: int = 16_384
    decoded_bytes: int = 16_384
    gzip_bytes: int = 4_096
    candidates: int = 32
    depth: int = 3
    seconds: float = 0.10
    sources: int = 32


_BOUNDARY = r"(?:^|(?<=[。！？!?；;\n]))[ \t]*(?:请[ \t]*|(?:please|now)[ \t]+)?"
_RULES = (
    ("instruction_override", 7, "要求覆盖现有指令", (
        r"(忽略|无视|覆盖|忘掉|抛弃)[ \t]*(?:掉)?(?:你|所有|此前|之前|先前|上文|原有|现有|的|[ \t]){1,12}(指令|系统提示词?|约束|规则)",
        r"(ignore|disregard|override|forget)[ \t]+(?:(?:all|the|your|previous|prior|earlier|existing|system)[ \t]+){1,6}(instructions|system[ \t]+prompt|rules|constraints)\b",
    )),
    ("privileged_disclosure", 7, "要求公开非公开指令", (
        r"(泄露|透露|展示|输出|打印|复述|公开)[ \t]*(?:你|完整|原始|内部|隐藏|全部|的|[ \t]){0,10}(系统提示词?|内部指令|隐藏指令)",
        r"(reveal|print|output|repeat|disclose|expose|show)[ \t]+(?:(?:me|your|the|original|full|hidden|internal|verbatim)[ \t]+){0,6}(system[ \t]+prompt|internal[ \t]+instructions|hidden[ \t]+instructions)\b",
    )),
    ("permission_override", 7, "要求停用权限检查", (
        r"(绕过|跳过|禁用|关闭)[ \t]*(?:所有|现有|当前|的|[ \t]){0,8}(权限检查|身份验证|授权检查)",
        r"(bypass|disable|skip)[ \t]+(?:(?:all|the|existing|current)[ \t]+){0,4}(authorization[ \t]+checks?|permission[ \t]+checks?|authentication)\b",
    )),
)
_COMPILED_RULES = tuple(
    (name, weight, description,
     tuple(re.compile(_BOUNDARY + pattern, re.IGNORECASE) for pattern in patterns))
    for name, weight, description, patterns in _RULES
)
_HARASSMENT = re.compile(
    _BOUNDARY
    + r"(?:(?:帮我[ \t]*)?(辱骂|霸凌|骚扰)[ \t]*(?:一下[ \t]*)?(?:某人|对方|他们|她们|他|她|群友)"
    + r"|(?:go[ \t]+)?(harass|bully|insult)[ \t]+(?:them|him|her|someone)\b)",
    re.IGNORECASE,
)

_IGNORABLE = dict.fromkeys(
    [0xAD, 0xFEFF, *range(0x200B, 0x2010), *range(0x202A, 0x202F),
     *range(0x2060, 0x2070), *range(0xE0000, 0xE0080)]
)
_ESCAPES = re.compile(
    r"(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})+|(?:\\x[0-9a-fA-F]{2})+"
)
_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_BASE64 = re.compile(
    r"(?<![A-Za-z0-9_+/-])(?:data:[^;\s,]{0,128};base64,"
    r"(?P<uri>[A-Za-z0-9_+/-]{2,}={0,2})"
    r"|(?P<token>[A-Za-z0-9_+/-]{16,}={0,2}))(?![A-Za-z0-9_+/=-])",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_IGNORABLE)


def _decode_escapes(fragment: str) -> str:
    if fragment.startswith(r"\x"):
        return bytes.fromhex(fragment.replace(r"\x", "")).decode("utf-8")
    text = fragment.encode("ascii").decode("unicode_escape")
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le")


class _Scan:
    def __init__(self, limits: DetectionLimits):
        self.limits = limits
        self.deadline = time.monotonic() + limits.seconds
        self.candidates = 0
        self.decoded_bytes = 0
        self.incomplete: set[str] = set()

    def time_left(self) -> bool:
        if time.monotonic() < self.deadline:
            return True
        self.incomplete.add("time_budget")
        return False

    def take_candidate(self, depth: int) -> bool:
        if not self.time_left():
            return False
        if depth >= self.limits.depth:
            self.incomplete.add("depth_budget")
            return False
        if self.candidates >= self.limits.candidates:
            self.incomplete.add("candidate_budget")
            return False
        self.candidates += 1
        return True

    def take_bytes(self, size: int) -> bool:
        if size > self.limits.decoded_bytes - self.decoded_bytes:
            self.incomplete.add("decoded_bytes_budget")
            return False
        self.decoded_bytes += size
        return True

    def decode_base64(self, token: str) -> str:
        try:
            data = base64.b64decode(token + "=" * (-len(token) % 4), b"-_", validate=True)
            if not self.take_bytes(len(data)):
                return ""
            if data.startswith(b"\x1f\x8b"):
                limit = min(self.limits.gzip_bytes, self.limits.decoded_bytes - self.decoded_bytes)
                inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
                data = inflater.decompress(data, limit + 1)
                if len(data) > limit:
                    reason = ("gzip_output_budget" if limit == self.limits.gzip_bytes
                              else "decoded_bytes_budget")
                    self.incomplete.add(reason)
                    return ""
                if not inflater.eof or inflater.unused_data:
                    self.incomplete.add("unsupported_gzip_stream")
                    return ""
                if not self.take_bytes(len(data)):
                    return ""
            text = data.decode("utf-8")
        except zlib.error:
            self.incomplete.add("invalid_gzip")
            return ""
        except (ValueError, binascii.Error):
            return ""
        return text if all(ch.isprintable() or ch in "\t\r\n" or ord(ch) in _IGNORABLE
                           for ch in text) else ""

    def views(self, text: str, depth: int):
        # Scan decoded escape runs in their original neighborhood, never across fields.
        for regex, encoding, decoder in (
            (_ESCAPES, "escape", _decode_escapes),
            (_PERCENT, "percent", lambda value: unquote_to_bytes(value).decode("utf-8")),
        ):
            pieces = []
            end = 0
            for match in regex.finditer(text):
                if not self.take_candidate(depth):
                    break
                try:
                    decoded = decoder(match.group())
                except (UnicodeError, ValueError):
                    continue
                if not self.take_bytes(len(decoded.encode("utf-8"))):
                    break
                pieces.extend((text[end:match.start()], decoded))
                end = match.end()
            if pieces:
                decoded = "".join((*pieces, text[end:]))
                if decoded != text:
                    yield encoding, decoded
        for match in _BASE64.finditer(text):
            token = match["uri"] or match["token"]
            if len(token) % 4 == 1:
                continue
            if not self.take_candidate(depth):
                break
            decoded = self.decode_base64(token)
            if decoded:
                yield "base64", decoded


class PromptThreatDetector(PTDCoreBase):
    """Inspect bounded text copies; signals are evidence, not attack probabilities."""

    medium_threshold = 7
    high_threshold = 11

    def __init__(self, limits: DetectionLimits | None = None):
        self.limits = limits or DetectionLimits()

    def analyze(self, prompt: str, *, config: Mapping | None = None) -> dict:
        return self.analyze_sources({"prompt": prompt}, config=config)

    def analyze_sources(self, sources: Mapping[str, str], *, config: Mapping | None = None) -> dict:
        scan = _Scan(self.limits)
        evidence = {}
        advisories = {}
        visited = set()
        remaining = self.limits.input_chars
        length = 0
        checked_sources = []
        # Legacy sanitize_enabled no longer rewrites prompts or disables the base scan.
        settings = config or {}
        decode = settings.get("detect_encoded", True) is not False
        check_harassment = settings.get("anti_harassment_enabled", True) is not False

        def inspect(text: str, source: str, encodings: tuple[str, ...] = ()):
            if not scan.time_left():
                return
            text = _normalize(text)
            if len(text) > self.limits.input_chars:
                scan.incomplete.add("normalized_length_budget")
                text = text[:self.limits.input_chars]
            key = (source, text, encodings)
            if key in visited:
                return
            visited.add(key)
            for name, weight, description, patterns in _COMPILED_RULES:
                if not scan.time_left():
                    return
                for pattern in patterns:
                    match = pattern.search(text)
                    if match:
                        # Only emit the fixed rule vocabulary, never surrounding text.
                        signal = evidence.setdefault(name, {
                            "name": name, "type": "regex", "weight": weight,
                            "description": description, "detail": " … ".join(match.groups()),
                            "source": source, "sources": [], "encodings": [],
                        })
                        if source not in signal["sources"]:
                            signal["sources"].append(source)
                        for encoding in encodings:
                            if encoding not in signal["encodings"]:
                                signal["encodings"].append(encoding)
                        break
            if check_harassment and scan.time_left():
                match = _HARASSMENT.search(text)
                if match:
                    item = advisories.setdefault("harassment_request", {
                        "name": "harassment_request", "type": "advisory",
                        "description": "疑似不当表达，仅供参考",
                        "detail": match[1] or match[2], "sources": [],
                    })
                    if source not in item["sources"]:
                        item["sources"].append(source)
            if decode:
                for encoding, view in scan.views(text, len(encodings)):
                    inspect(view, source, (*encodings, encoding))

        for index, (source, value) in enumerate(sources.items()):
            if index >= self.limits.sources:
                scan.incomplete.add("source_budget")
                break
            if not scan.time_left():
                break
            if not isinstance(value, str):
                scan.incomplete.add("invalid_source")
                continue
            length += len(value)
            if len(value) > remaining:
                scan.incomplete.add("input_length_budget")
            text = value[:remaining]
            if text:
                checked_sources.append(source)
                inspect(text, source)
            remaining -= len(text)

        scan.time_left()
        signals = list(evidence.values())
        score = sum(signal["weight"] for signal in signals)
        severity = self._score_to_severity(score)
        return {
            "score": score, "severity": severity, "signals": signals,
            "advisories": list(advisories.values()),
            "suspicious": bool(signals), "complete": not scan.incomplete,
            "status": "incomplete" if scan.incomplete else "complete",
            "incomplete_reasons": sorted(scan.incomplete),
            "sources": checked_sources, "length": length,
            "regex_hit": bool(signals), "marker_hits": 0, "code_block_count": 0,
            "reason": "，".join(signal["description"] for signal in signals),
        }

    def _score_to_severity(self, score: int) -> str:
        if score >= self.high_threshold:
            return "high"
        if score >= self.medium_threshold:
            return "medium"
        return "low" if score > 0 else "none"
