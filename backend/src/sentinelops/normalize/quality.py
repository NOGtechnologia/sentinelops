"""Input limits and data quality checks (spec 5.6).

Every raw record ends in exactly one processing status. The helpers here turn
low level problems into a :class:`Malformed` result with an error code and a
position instead of raising.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sentinelops.normalize.schema import MalformedCode


@dataclass(frozen=True, slots=True)
class Limits:
    max_line_bytes: int = 64 * 1024
    max_record_bytes: int = 1024 * 1024
    max_json_depth: int = 32
    max_file_bytes: int = 512 * 1024 * 1024
    max_field_chars: int = 16 * 1024


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True, slots=True)
class Malformed:
    code: MalformedCode
    detail: str
    position: int | None = None


def decode_text(data: bytes, limits: Limits = DEFAULT_LIMITS) -> str | Malformed:
    """Strictly decode UTF-8 (a UTF-8 BOM is accepted and removed)."""
    if len(data) > limits.max_record_bytes:
        return Malformed(MalformedCode.OVERSIZED, f"record has {len(data)} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return Malformed(MalformedCode.INVALID_ENCODING, f"invalid UTF-8 at byte {exc.start}", exc.start)
    text = text.removeprefix("﻿")
    if "\x00" in text:
        return Malformed(MalformedCode.INVALID_ENCODING, "NUL character", text.index("\x00"))
    return text


def check_line(line: str, limits: Limits = DEFAULT_LIMITS) -> Malformed | None:
    size = len(line.encode("utf-8"))
    if size > limits.max_line_bytes:
        return Malformed(MalformedCode.OVERSIZED, f"line has {size} bytes (limit {limits.max_line_bytes})")
    return None


def json_depth(value: Any, limit: int) -> int:
    """Depth of a decoded JSON value; stops counting once ``limit`` is exceeded."""
    depth = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, level = stack.pop()
        if isinstance(current, dict):
            depth = max(depth, level)
            if depth > limit:
                return depth
            stack.extend((v, level + 1) for v in current.values())
        elif isinstance(current, list):
            depth = max(depth, level)
            if depth > limit:
                return depth
            stack.extend((v, level + 1) for v in current)
    return depth


def load_json(text: str, limits: Limits = DEFAULT_LIMITS) -> Any | Malformed:
    """Decode JSON, classifying failures as TRUNCATED, PARSE_ERROR or OVERSIZED."""
    try:
        value = json.loads(text)
    except RecursionError:
        return Malformed(MalformedCode.OVERSIZED, "JSON nesting too deep")
    except json.JSONDecodeError as exc:
        truncated = exc.msg.startswith("Unterminated string") or (
            exc.pos >= len(text.rstrip()) and exc.msg.startswith("Expecting")
        )
        code = MalformedCode.TRUNCATED if truncated else MalformedCode.PARSE_ERROR
        return Malformed(code, exc.msg, exc.pos)
    if json_depth(value, limits.max_json_depth) > limits.max_json_depth:
        return Malformed(MalformedCode.OVERSIZED, f"JSON deeper than {limits.max_json_depth}")
    return value


def clip(value: str, limits: Limits = DEFAULT_LIMITS) -> str:
    """Bound the size of a single field value."""
    if len(value) <= limits.max_field_chars:
        return value
    return value[: limits.max_field_chars] + "…"
