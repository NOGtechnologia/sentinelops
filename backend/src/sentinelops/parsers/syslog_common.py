"""Shared mapping from a decoded syslog message to the canonical schema."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinelops.normalize.dedupe import syslog_fingerprint
from sentinelops.normalize.quality import Limits, clip
from sentinelops.normalize.schema import CANONICAL_FIELDS, Outcome
from sentinelops.normalize.timestamps import NormalizedTime
from sentinelops.parsers.base import ParsedEvent
from sentinelops.parsers.linux_auth import match_message

_CANONICAL = frozenset(CANONICAL_FIELDS)


@dataclass(frozen=True, slots=True)
class SyslogMessage:
    time: NormalizedTime
    original_time: str
    host: str | None
    program: str | None
    pid: str | None
    message: str
    facility: int | None = None
    severity: int | None = None
    extra: dict[str, Any] | None = None


def to_parsed(msg: SyslogMessage, limits: Limits) -> ParsedEvent:
    message = clip(msg.message, limits)
    fields: dict[str, Any] = {
        "event.kind": "event",
        "host.os.type": "linux",
        "message": message,
        "event.time_quality": msg.time.quality.value,
    }
    original: dict[str, Any] = {}
    if msg.host:
        fields["host.name"] = msg.host
    if msg.program:
        fields["event.provider"] = msg.program
        original["syslog.appname"] = msg.program
    if msg.pid:
        fields["process.pid"] = msg.pid
    if msg.facility is not None:
        original["syslog.facility"] = msg.facility
    if msg.severity is not None:
        original["syslog.severity"] = msg.severity
    if msg.extra:
        original.update(msg.extra)
    matched = match_message(msg.program, message)
    if matched is None:
        fields["event.action"] = "syslog-message"
        fields["event.outcome"] = Outcome.UNKNOWN.value
    else:
        fields["event.action"] = matched.action
        fields["event.outcome"] = matched.outcome.value
        fields["event.category"] = list(matched.category)
        fields["event.type"] = list(matched.type)
        original["linux.pattern"] = matched.pattern
        for key, value in matched.fields.items():
            (fields if key in _CANONICAL else original)[key] = value
    if msg.time.flags:
        fields["quality.flags"] = list(msg.time.flags)
    return ParsedEvent(
        fingerprint=syslog_fingerprint(msg.host, msg.time.utc, msg.program, msg.pid, msg.message),
        time=msg.time,
        original_time=msg.original_time,
        fields=fields,
        original=original,
    )
