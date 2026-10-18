"""Canonical, ECS-inspired event schema (ADR-0002).

The schema is intentionally a small subset of the Elastic Common Schema field
names. Events are immutable value objects; normalisation never mutates raw data
(CLAUDE.md rule 6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class TimeQuality(StrEnum):
    EXACT = "exact"
    ASSUMED_TIMEZONE = "assumed_timezone"
    INFERRED_YEAR = "inferred_year"
    CLOCK_SKEW_SUSPECTED = "clock_skew_suspected"


#: Precedence used when several quality findings apply to one timestamp: the
#: most severe finding wins, the others are kept as ``quality.flags``.
TIME_QUALITY_SEVERITY: dict[TimeQuality, int] = {
    TimeQuality.EXACT: 0,
    TimeQuality.ASSUMED_TIMEZONE: 1,
    TimeQuality.INFERRED_YEAR: 2,
    TimeQuality.CLOCK_SKEW_SUSPECTED: 3,
}


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class RecordStatus(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    MALFORMED = "malformed"


class Assessment(StrEnum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"


class MalformedCode(StrEnum):
    PARSE_ERROR = "PARSE_ERROR"
    MISSING_TIMESTAMP = "MISSING_TIMESTAMP"
    INVALID_ENCODING = "INVALID_ENCODING"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    TRUNCATED = "TRUNCATED"
    OVERSIZED = "OVERSIZED"


class SourceType(StrEnum):
    WINDOWS_EVTX = "windows_evtx"
    WINDOWS_XML = "windows_xml"
    WINDOWS_JSON = "windows_json"
    SYSLOG_3164 = "syslog_3164"
    SYSLOG_5424 = "syslog_5424"
    JOURNALD_JSON = "journald_json"


#: All canonical field names (ECS-style dotted names) in a stable order. The
#: order is used for serialisation and therefore for golden files and reports.
CANONICAL_FIELDS: tuple[str, ...] = (
    "event.id",
    "@timestamp",
    "event.original_time",
    "event.time_quality",
    "event.ingested",
    "event.kind",
    "event.category",
    "event.type",
    "event.action",
    "event.outcome",
    "event.code",
    "event.provider",
    "user.name",
    "user.domain",
    "user.id",
    "user.target.name",
    "user.target.domain",
    "user.target.id",
    "group.name",
    "group.id",
    "host.name",
    "host.os.type",
    "source.ip",
    "source.port",
    "source.host",
    "logon.type",
    "auth.method",
    "process.name",
    "process.pid",
    "process.command_line",
    "log.source_type",
    "log.raw_record_id",
    "message",
    "quality.flags",
)


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    """A normalised event. ``fields`` holds the canonical values, ``original``
    the source specific fields (e.g. ``winlog.event_data.*``) that are kept for
    Sigma rules written against vendor field names."""

    event_id: str
    timestamp: datetime
    fields: dict[str, Any]
    original: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        """Look up a canonical field, falling back to source specific fields."""
        if name == "@timestamp":
            return self.timestamp
        value = self.fields.get(name)
        if value is not None:
            return value
        return self.original.get(name)

    @property
    def action(self) -> str | None:
        value = self.fields.get("event.action")
        return value if isinstance(value, str) else None

    @property
    def outcome(self) -> str:
        value = self.fields.get("event.outcome")
        return value if isinstance(value, str) else Outcome.UNKNOWN.value

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON compatible dict with a stable key order."""
        out: dict[str, Any] = {}
        for name in CANONICAL_FIELDS:
            if name == "event.id":
                out[name] = self.event_id
            elif name == "@timestamp":
                out[name] = format_timestamp(self.timestamp)
            else:
                value = self.fields.get(name)
                if value is None:
                    continue
                out[name] = format_timestamp(value) if isinstance(value, datetime) else value
        if self.original:
            out["original"] = {k: self.original[k] for k in sorted(self.original)}
        return out


def format_timestamp(value: datetime) -> str:
    """ISO 8601 in UTC with microsecond precision and a trailing ``Z``."""
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
