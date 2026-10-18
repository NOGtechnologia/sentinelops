"""Chronological case timeline (spec 7.4).

Contains all events of the case's alerts plus the alerts themselves, marks
trigger events, groups by entity lanes, and shows time gaps and time quality.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sentinelops.correlation.alerts import Alert, event_entities
from sentinelops.normalize.schema import CanonicalEvent, format_timestamp

DEFAULT_GAP = timedelta(minutes=30)


@dataclass(frozen=True)
class TimelineItem:
    kind: str  # event | alert | gap
    time: str
    id: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "time": self.time, "id": self.id, **self.data}


def build_timeline(
    alerts: Sequence[Alert], events_by_id: Mapping[str, CanonicalEvent], gap: timedelta = DEFAULT_GAP
) -> list[TimelineItem]:
    trigger: dict[str, list[str]] = {}
    for alert in alerts:
        for eid in alert.event_ids:
            trigger.setdefault(eid, []).append(alert.rule_id)
    events = sorted((events_by_id[eid] for eid in trigger if eid in events_by_id), key=lambda e: (e.timestamp, e.event_id))
    items: list[tuple[Any, int, str, TimelineItem]] = []
    for event in events:
        lanes = sorted({f"{e.type}:{e.key}" for e in event_entities(event)})
        items.append((event.timestamp, 1, event.event_id, TimelineItem("event", format_timestamp(event.timestamp), event.event_id, {
            "action": event.action,
            "outcome": event.outcome,
            "code": event.fields.get("event.code"),
            "user": event.fields.get("user.name"),
            "target_user": event.fields.get("user.target.name"),
            "host": event.fields.get("host.name"),
            "source_ip": event.fields.get("source.ip"),
            "time_quality": event.fields.get("event.time_quality"),
            "quality_flags": event.fields.get("quality.flags") or [],
            "rules": sorted(set(trigger[event.event_id])),
            "lanes": lanes,
        })))
    for alert in alerts:
        items.append((alert.window_end, 2, alert.alert_id, TimelineItem("alert", format_timestamp(alert.window_end), alert.alert_id, {
            "rule_id": alert.rule_id,
            "title": alert.title,
            "title_de": alert.title_de,
            "level": alert.level,
            "window_start": format_timestamp(alert.window_start),
            "event_count": len(alert.event_ids),
        })))
    items.sort(key=lambda t: (t[0], t[1], t[2]))
    out: list[TimelineItem] = []
    previous = None
    for when, _, _, item in items:
        if previous is not None and when - previous > gap:
            out.append(TimelineItem("gap", format_timestamp(previous), f"gap-{format_timestamp(previous)}",
                                    {"until": format_timestamp(when), "seconds": int((when - previous).total_seconds())}))
        out.append(item)
        previous = when
    return out
