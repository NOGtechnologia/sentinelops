"""Fingerprints, deterministic event ids and duplicate detection (spec 5.5).

Fingerprints are defined per source family so that the *same* Windows event
yields the same ``event.id`` whether it arrives as EVTX, XML or JSON export.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sentinelops.normalize.schema import format_timestamp

FINGERPRINT_VERSION = "fp1"


def stable_hash(*parts: Any, length: int = 32) -> str:
    """SHA-256 over a canonical JSON encoding of ``parts`` (hex, truncated)."""
    payload = json.dumps(parts, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=_default)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return format_timestamp(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    raise TypeError(f"not serialisable: {type(value).__name__}")


def windows_fingerprint(
    computer: str | None,
    channel: str | None,
    record_id: int | str | None,
    provider: str | None,
    time_created: datetime,
) -> tuple[Any, ...]:
    return (
        "windows",
        (computer or "").casefold(),
        (channel or "").casefold(),
        str(record_id or ""),
        (provider or "").casefold(),
        format_timestamp(time_created),
    )


def syslog_fingerprint(
    host: str | None, timestamp: datetime, program: str | None, pid: str | None, message: str
) -> tuple[Any, ...]:
    return ("syslog", (host or "").casefold(), format_timestamp(timestamp), program or "", pid or "", message)


def json_fingerprint(profile: str, record: Mapping[str, Any], key_fields: Iterable[str] | None) -> tuple[Any, ...]:
    keys = list(key_fields or [])
    if keys:
        return ("json", profile, tuple(_lookup(record, k) for k in keys))
    return ("json", profile, stable_hash(record, length=64))


def _lookup(record: Mapping[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def event_id_for(fingerprint: tuple[Any, ...]) -> str:
    return stable_hash(FINGERPRINT_VERSION, fingerprint)


def file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(slots=True)
class Deduplicator:
    """Remembers event ids seen so far and the raw record that introduced them.

    The ingest layer pre-seeds it with ids already stored, so the in-memory
    view and the database agree.
    """

    seen: dict[str, str] = field(default_factory=dict)

    def check(self, event_id: str, raw_record_id: str) -> str | None:
        """Return the original raw record id if ``event_id`` is a duplicate."""
        original = self.seen.get(event_id)
        if original is not None:
            return original
        self.seen[event_id] = raw_record_id
        return None
