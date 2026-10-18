"""Syslog protocol (RFC 5424, section 6).

``<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP
STRUCTURED-DATA [SP MSG]`` - ``-`` is the NILVALUE. Structured data is parsed
with escape handling (``\\"``, ``\\\\``, ``\\]``) and kept in ``original``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, BinaryIO

from sentinelops.normalize.quality import Malformed
from sentinelops.normalize.schema import MalformedCode, SourceType
from sentinelops.normalize.timestamps import TimestampError, apply_skew_policy, normalize_iso
from sentinelops.parsers.base import ParseContext, ParseResult, RawRecord, iter_lines
from sentinelops.parsers.syslog_common import SyslogMessage, to_parsed
from sentinelops.parsers.syslog_rfc3164 import decode_line

NIL = "-"


def parse_structured_data(text: str) -> tuple[dict[str, dict[str, str]], str] | Malformed:
    """Parse the STRUCTURED-DATA part; returns (elements, remaining text)."""
    if text.startswith(NIL):
        return {}, text[1:]
    elements: dict[str, dict[str, str]] = {}
    i = 0
    while i < len(text) and text[i] == "[":
        end_id = i + 1
        while end_id < len(text) and text[end_id] not in " ]":
            end_id += 1
        sd_id = text[i + 1 : end_id]
        if not sd_id:
            return Malformed(MalformedCode.PARSE_ERROR, "empty SD-ID", i)
        params: dict[str, str] = {}
        j = end_id
        while j < len(text) and text[j] == " ":
            j += 1
            eq = text.find("=", j)
            if eq < 0 or eq + 1 >= len(text) or text[eq + 1] != '"':
                return Malformed(MalformedCode.PARSE_ERROR, "invalid SD-PARAM", j)
            name = text[j:eq]
            k = eq + 2
            value: list[str] = []
            while k < len(text) and text[k] != '"':
                if text[k] == "\\" and k + 1 < len(text) and text[k + 1] in '"\\]':
                    value.append(text[k + 1])
                    k += 2
                    continue
                value.append(text[k])
                k += 1
            if k >= len(text):
                return Malformed(MalformedCode.TRUNCATED, "unterminated SD-PARAM value", j)
            params[name] = "".join(value)
            j = k + 1
        if j >= len(text) or text[j] != "]":
            return Malformed(MalformedCode.TRUNCATED, "unterminated SD-ELEMENT", j)
        elements[sd_id] = params
        i = j + 1
    if not elements:
        return Malformed(MalformedCode.PARSE_ERROR, "STRUCTURED-DATA missing", 0)
    return elements, text[i:]


def parse_line(text: str, ctx: ParseContext) -> SyslogMessage | Malformed:
    if not text.startswith("<"):
        return Malformed(MalformedCode.PARSE_ERROR, "missing PRI", 0)
    close = text.find(">")
    pri_text = text[1:close] if close > 0 else ""
    if not pri_text.isdigit() or int(pri_text) > 191:
        return Malformed(MalformedCode.PARSE_ERROR, "invalid PRI", 1)
    pri = int(pri_text)
    parts = text[close + 1 :].split(" ", 6)
    if len(parts) < 7:
        return Malformed(MalformedCode.TRUNCATED, "header incomplete", len(text))
    version, timestamp, host, app, procid, msgid, rest = parts
    if version != "1":
        return Malformed(MalformedCode.PARSE_ERROR, f"unsupported version {version!r}", close + 1)
    if timestamp == NIL:
        return Malformed(MalformedCode.MISSING_TIMESTAMP, "NILVALUE timestamp", close + 3)
    try:
        time = normalize_iso(timestamp, ctx.timezone, ctx.previous_utc)
    except TimestampError as exc:
        return Malformed(MalformedCode.PARSE_ERROR, f"invalid timestamp: {exc}", close + 3)
    time = apply_skew_policy(time, ctx.reference_utc, ctx.skew)
    sd = parse_structured_data(rest)
    if isinstance(sd, Malformed):
        return sd
    elements, message = sd
    message = message.removeprefix(" ").removeprefix("﻿")
    extra: dict[str, Any] = {}
    if msgid != NIL:
        extra["syslog.msgid"] = msgid
    for sd_id, params in sorted(elements.items()):
        for name, value in sorted(params.items()):
            extra[f"syslog.sd.{sd_id}.{name}"] = value
    return SyslogMessage(
        time=time,
        original_time=timestamp,
        host=None if host == NIL else host,
        program=None if app == NIL else app,
        pid=None if procid == NIL else procid,
        message=message,
        facility=pri // 8,
        severity=pri % 8,
        extra=extra,
    )


class SyslogRfc5424Parser:
    source_type = SourceType.SYSLOG_5424.value

    def split(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        for raw in iter_lines(stream, ctx.limits):
            if raw.content.strip():
                yield raw

    def parse(self, raw: RawRecord, ctx: ParseContext) -> ParseResult:
        text = decode_line(raw, ctx)
        if isinstance(text, Malformed):
            return text
        message = parse_line(text, ctx)
        if isinstance(message, Malformed):
            return message
        return to_parsed(message, ctx.limits)
