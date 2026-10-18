"""BSD syslog (RFC 3164) and ``auth.log``/``secure`` files.

Accepted line shapes::

    <PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG      (RFC 3164 on the wire)
    Mmm dd hh:mm:ss HOST TAG[PID]: MSG           (classic auth.log/secure)
    YYYY-MM-DDThh:mm:ss.ffffff+hh:mm HOST TAG[PID]: MSG
                                                 (rsyslog RFC 3339 file format)

RFC 3164 timestamps carry neither year nor time zone: the zone comes from the
source configuration, the year is inferred (``time_quality=inferred_year``).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import BinaryIO

from sentinelops.normalize.quality import Malformed, check_line, decode_text
from sentinelops.normalize.schema import MalformedCode, SourceType
from sentinelops.normalize.timestamps import (
    NormalizedTime,
    TimestampError,
    apply_skew_policy,
    normalize_iso,
    parse_rfc3164_time,
)
from sentinelops.parsers.base import ParseContext, ParseResult, RawRecord, iter_lines
from sentinelops.parsers.syslog_common import SyslogMessage, to_parsed

_PRI = re.compile(r"^<(?P<pri>\d{1,3})>")
_BSD_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) ")
_ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})?) ")
_TAG = re.compile(r"^(?P<prog>[A-Za-z0-9_.\-/()]{1,64}?)(?:\[(?P<pid>\d{1,10})\])?: ")


def parse_pri(text: str) -> tuple[int | None, int | None, str] | Malformed:
    match = _PRI.match(text)
    if match is None:
        return None, None, text
    pri = int(match.group("pri"))
    if pri > 191:
        return Malformed(MalformedCode.PARSE_ERROR, f"PRI out of range: {pri}", 1)
    return pri // 8, pri % 8, text[match.end() :]


def split_tag(rest: str) -> tuple[str | None, str | None, str]:
    match = _TAG.match(rest)
    if match is None:
        return None, None, rest
    return match.group("prog"), match.group("pid"), rest[match.end() :]


def decode_line(raw: RawRecord, ctx: ParseContext) -> str | Malformed:
    """Size check first (clipped lines must not be reported as bad encoding)."""
    if len(raw.content) > ctx.limits.max_line_bytes:
        return Malformed(MalformedCode.OVERSIZED, f"line exceeds {ctx.limits.max_line_bytes} bytes")
    text = decode_text(raw.content, ctx.limits)
    if isinstance(text, Malformed):
        return text
    problem = check_line(text, ctx.limits)
    return problem if problem is not None else text


def parse_line(text: str, ctx: ParseContext) -> SyslogMessage | Malformed:
    pri = parse_pri(text)
    if isinstance(pri, Malformed):
        return pri
    facility, severity, rest = pri
    bsd = _BSD_TS.match(rest)
    iso = None if bsd else _ISO_TS.match(rest)
    match = bsd or iso
    if match is None:
        if _BSD_TS.match(rest + " ") or _ISO_TS.match(rest + " "):
            return Malformed(MalformedCode.TRUNCATED, "line ends after timestamp", len(text))
        return Malformed(MalformedCode.MISSING_TIMESTAMP, "no RFC 3164 or RFC 3339 timestamp", len(text) - len(rest))
    original_time = match.group("ts")
    try:
        time: NormalizedTime
        if bsd:
            time = parse_rfc3164_time(original_time, ctx.timezone, ctx.reference_utc, ctx.previous_utc)
        else:
            time = normalize_iso(original_time, ctx.timezone, ctx.previous_utc)
    except TimestampError as exc:
        return Malformed(MalformedCode.PARSE_ERROR, f"invalid timestamp: {exc}", len(text) - len(rest))
    time = apply_skew_policy(time, ctx.reference_utc, ctx.skew)
    remainder = rest[match.end() :]
    host, sep, body = remainder.partition(" ")
    if not sep or not body.strip():
        return Malformed(MalformedCode.TRUNCATED, "line ends before message", len(text))
    program, pid, message = split_tag(body)
    return SyslogMessage(
        time=time,
        original_time=original_time,
        host=host,
        program=program,
        pid=pid,
        message=message,
        facility=facility,
        severity=severity,
    )


class SyslogRfc3164Parser:
    source_type = SourceType.SYSLOG_3164.value

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
