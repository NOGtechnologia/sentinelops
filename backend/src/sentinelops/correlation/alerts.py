"""Alert model, entity extraction and deterministic alert ids (spec 7.1)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.identities import canonical_ip, host_key, is_internal_ip, user_key
from sentinelops.normalize.schema import CanonicalEvent, format_timestamp

#: Accounts that never identify a person and never link cases.
NON_LINKING_USERS = frozenset({"system", "local service", "network service", "anonymous logon", "-"})


@dataclass(frozen=True, slots=True, order=True)
class Entity:
    type: str  # user | host | ip
    key: str  # normalised comparison key
    display: str  # original spelling (first seen)

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type, "key": self.key, "display": self.display}


def is_machine_account(name: str) -> bool:
    return name.endswith("$")


def event_entities(event: CanonicalEvent) -> list[Entity]:
    out: list[Entity] = []
    for name in ("user.name", "user.target.name"):
        value = event.fields.get(name)
        if isinstance(value, str):
            key = user_key(value)
            if key and not is_machine_account(key) and key not in NON_LINKING_USERS:
                out.append(Entity("user", key, value))
    for name in ("host.name", "source.host"):
        value = event.fields.get(name)
        if isinstance(value, str):
            key = host_key(value)
            if key and key not in ("localhost", "-"):
                out.append(Entity("host", key, value))
    ip = event.fields.get("source.ip")
    if isinstance(ip, str):
        canonical = canonical_ip(ip)
        if canonical and not canonical.startswith("127.") and canonical != "::1":
            out.append(Entity("ip", canonical, canonical))
    return out


def merge_entities(events: Iterable[CanonicalEvent]) -> tuple[Entity, ...]:
    seen: dict[tuple[str, str], Entity] = {}
    for event in events:
        for entity in event_entities(event):
            seen.setdefault((entity.type, entity.key), entity)
    return tuple(sorted(seen.values()))


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule_id: str
    rule_version: int
    rule_hash: str
    kind: str
    title: str
    title_de: str
    level: str
    maturity: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    event_ids: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    group_key: tuple[tuple[str, str], ...]
    entities: tuple[Entity, ...]
    explanation: dict[str, Any]
    thresholds: dict[str, Any] = field(default_factory=dict)
    related_alert_ids: tuple[str, ...] = ()
    suppressed_by: str | None = None
    privilege_change: bool = False
    success_after_failures: bool = False

    @property
    def suppressed(self) -> bool:
        return self.suppressed_by is not None

    def with_suppression(self, exception_id: str) -> Alert:
        return replace(self, suppressed_by=exception_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "rule_hash": self.rule_hash,
            "kind": self.kind,
            "title": self.title,
            "title_de": self.title_de,
            "level": self.level,
            "maturity": self.maturity,
            "tactics": list(self.tactics),
            "techniques": list(self.techniques),
            "event_ids": list(self.event_ids),
            "window_start": format_timestamp(self.window_start),
            "window_end": format_timestamp(self.window_end),
            "group_key": dict(self.group_key),
            "entities": [e.to_dict() for e in self.entities],
            "explanation": self.explanation,
            "thresholds": self.thresholds,
            "related_alert_ids": list(self.related_alert_ids),
            "suppressed_by": self.suppressed_by,
        }


def alert_id(rule_id: str, version: int, anchor: Sequence[Any], window_start: datetime) -> str:
    """Deterministic id: (rule, version, correlation group or event ids, window start)."""
    return stable_hash("alert", rule_id, version, list(anchor), format_timestamp(window_start))


def sort_events(events: Iterable[CanonicalEvent]) -> list[CanonicalEvent]:
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))


def is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return not is_internal_ip(value)
    except ValueError:
        return False
