"""Evidence package for the AI (spec 8.3).

The model receives *only* this structured package: numbered evidence items
``E1..En`` (selected normalised fields + a truncated raw line), the alerts with
their rule descriptions, the priority factors, the entities and the playbook
catalogue. Selection and numbering are deterministic; the package hash is
stored with every AI output.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sentinelops.correlation.alerts import Alert, Entity
from sentinelops.correlation.priority import PriorityResult
from sentinelops.investigation.catalog import PlaybookStep
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.schema import CanonicalEvent, format_timestamp

PROMPT_VERSION = "case-summary/1"
MAX_ITEMS = 60
MAX_RAW_CHARS = 300
MAX_FIELD_CHARS = 200
EVIDENCE_FIELDS = (
    "event.action",
    "event.outcome",
    "event.code",
    "user.name",
    "user.domain",
    "user.target.name",
    "group.name",
    "host.name",
    "source.ip",
    "source.port",
    "source.host",
    "logon.type",
    "auth.method",
    "process.name",
    "process.command_line",
    "event.time_quality",
)


@dataclass(frozen=True)
class EvidenceItem:
    ref: str  # E1, E2, ...
    event_id: str
    time: str
    fields: dict[str, Any]
    raw_excerpt: str
    alerts: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "time": self.time,
            "fields": self.fields,
            "raw_excerpt": self.raw_excerpt,
            "alerts": list(self.alerts),
        }


@dataclass(frozen=True)
class EvidencePackage:
    case_id: str
    prompt_version: str
    items: tuple[EvidenceItem, ...]
    alerts: tuple[dict[str, Any], ...]
    priority: dict[str, Any]
    entities: tuple[dict[str, str], ...]
    playbooks: tuple[dict[str, Any], ...]
    omitted_events: int
    executed_actions: tuple[dict[str, str], ...] = field(default_factory=tuple)

    @property
    def refs(self) -> dict[str, str]:
        return {i.ref: i.event_id for i in self.items}

    def ref_for_event(self) -> dict[str, str]:
        return {i.event_id: i.ref for i in self.items}

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "prompt_version": self.prompt_version,
            "evidence": [i.to_dict() for i in self.items],
            "omitted_events": self.omitted_events,
            "alerts": list(self.alerts),
            "priority": self.priority,
            "entities": list(self.entities),
            "playbook_catalog": list(self.playbooks),
            "executed_actions": list(self.executed_actions),
        }

    @property
    def package_hash(self) -> str:
        return stable_hash("evidence-package", self.to_dict(), length=64)


def _clip(value: Any, limit: int) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def select_events(alerts: Sequence[Alert], max_items: int) -> list[str]:
    """Deterministic relevance order: for every alert (most severe first) its
    first, last and every event that is the only one of its alert; then the
    remaining events round-robin over alerts."""
    levels = ("critical", "high", "medium", "low", "informational")
    ordered = sorted(alerts, key=lambda a: (levels.index(a.level), a.window_start, a.alert_id))
    chosen: dict[str, None] = {}
    for alert in ordered:
        ids = alert.event_ids
        for eid in (ids[0], ids[-1]):
            chosen.setdefault(eid)
        success = alert.explanation.get("success_event_id")
        if isinstance(success, str):
            chosen.setdefault(success)
    queues = [list(a.event_ids[1:-1]) for a in ordered]
    while len(chosen) < max_items and any(queues):
        for queue in queues:
            if queue:
                chosen.setdefault(queue.pop(0))
    return list(chosen)[:max_items]


def build_package(
    case_id: str,
    alerts: Sequence[Alert],
    events_by_id: Mapping[str, CanonicalEvent],
    priority: PriorityResult,
    entities: Sequence[Entity],
    catalog: Mapping[str, PlaybookStep],
    raw_text: Mapping[str, str] | None = None,
    executed_actions: Sequence[dict[str, str]] = (),
    max_items: int = MAX_ITEMS,
) -> EvidencePackage:
    raw_text = raw_text or {}
    all_ids = {eid for a in alerts for eid in a.event_ids if eid in events_by_id}
    selected = [eid for eid in select_events(alerts, max_items) if eid in events_by_id]
    events = sorted((events_by_id[eid] for eid in selected), key=lambda e: (e.timestamp, e.event_id))
    alerts_of: dict[str, list[str]] = {}
    for alert in alerts:
        for eid in alert.event_ids:
            alerts_of.setdefault(eid, []).append(alert.rule_id)
    items = tuple(
        EvidenceItem(
            ref=f"E{i}",
            event_id=e.event_id,
            time=format_timestamp(e.timestamp),
            fields={
                k: _clip(e.fields[k], MAX_FIELD_CHARS) for k in EVIDENCE_FIELDS if e.fields.get(k) not in (None, "")
            },
            raw_excerpt=_clip(raw_text.get(e.event_id, ""), MAX_RAW_CHARS),
            alerts=tuple(sorted(set(alerts_of.get(e.event_id, [])))),
        )
        for i, e in enumerate(events, start=1)
    )
    ref_of = {i.event_id: i.ref for i in items}
    alert_rows = tuple(
        {
            "rule_id": a.rule_id,
            "title": a.title,
            "level": a.level,
            "tactics": list(a.tactics),
            "window_start": format_timestamp(a.window_start),
            "window_end": format_timestamp(a.window_end),
            "event_count": len(a.event_ids),
            "evidence": [ref_of[e] for e in a.event_ids if e in ref_of][:10],
        }
        for a in sorted(alerts, key=lambda a: (a.window_start, a.alert_id))
    )
    priority_row = {
        "level": priority.level,
        "score": priority.score,
        "factors": [
            {
                "label": f.label_en,
                "contribution": f.contribution,
                "evidence": [ref_of[e] for e in f.evidence if e in ref_of],
            }
            for f in priority.factors
        ],
    }
    return EvidencePackage(
        case_id=case_id,
        prompt_version=PROMPT_VERSION,
        items=items,
        alerts=alert_rows,
        priority=priority_row,
        entities=tuple(e.to_dict() for e in entities),
        playbooks=tuple(
            {"id": s.id, "title": s.title_en, "is_response_action": s.action}
            for s in sorted(catalog.values(), key=lambda s: (s.priority, s.id))
        ),
        omitted_events=len(all_ids) - len(items),
        executed_actions=tuple(dict(a) for a in executed_actions),
    )
