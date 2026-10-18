"""Loading a case with everything that belongs to it, and building views
(timeline, evidence, graph, report input) from it."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection

from sentinelops.correlation.alerts import Alert, Entity, event_entities
from sentinelops.correlation.analysis import CaseAnalysis
from sentinelops.correlation.case_builder import CaseDraft
from sentinelops.correlation.priority import Factor, PriorityResult
from sentinelops.correlation.timeline import build_timeline
from sentinelops.detection.sigma_loader import RuleSet
from sentinelops.investigation.recommendations import Recommendation
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.schema import CanonicalEvent, format_timestamp
from sentinelops.reports.render import ReportInput
from sentinelops.settings import SOFTWARE_VERSION
from sentinelops.storage.models import (
    actions,
    ai_summaries,
    alerts,
    analysis_state,
    approvals,
    case_alerts,
    case_entities,
    cases,
    events,
    notes,
    priority_explanations,
    raw_records,
)


class NotFoundError(LookupError):
    pass


@dataclass
class CaseBundle:
    case: dict[str, Any]
    alerts: list[Alert]
    alert_rows: dict[str, dict[str, Any]]
    events_by_id: dict[str, CanonicalEvent]
    raw_text: dict[str, str]
    priority: PriorityResult
    entities: list[Entity]
    summaries: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    notes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def latest_summary(self) -> dict[str, Any] | None:
        return self.summaries[-1] if self.summaries else None


def _iso(value: Any) -> Any:
    return format_timestamp(value) if isinstance(value, datetime) else value


def row_dict(row: Any) -> dict[str, Any]:
    return {k: _iso(v) for k, v in dict(row).items()}


async def load_case(conn: AsyncConnection, case_id: str, *, with_raw: bool = True) -> CaseBundle:
    case_row = (await conn.execute(select(cases).where(cases.c.case_id == case_id))).mappings().first()
    if case_row is None:
        raise NotFoundError(case_id)
    alert_ids = [
        r.alert_id for r in await conn.execute(select(case_alerts.c.alert_id).where(case_alerts.c.case_id == case_id))
    ]
    alert_rows = {
        r["alert_id"]: dict(r)
        for r in (await conn.execute(select(alerts).where(alerts.c.alert_id.in_(alert_ids)))).mappings()
    }
    alert_objs = sorted(
        (Alert.from_dict(r["data"]) for r in alert_rows.values()), key=lambda a: (a.window_start, a.alert_id)
    )
    event_ids = sorted({eid for a in alert_objs for eid in a.event_ids})
    events_by_id: dict[str, CanonicalEvent] = {}
    for start in range(0, len(event_ids), 5000):
        chunk = event_ids[start : start + 5000]
        for row in await conn.execute(select(events.c.data).where(events.c.event_id.in_(chunk))):
            event = CanonicalEvent.from_dict(row[0])
            events_by_id[event.event_id] = event
    raw: dict[str, str] = {}
    if with_raw:
        for start in range(0, len(event_ids), 5000):
            chunk = event_ids[start : start + 5000]
            rows = await conn.execute(
                select(events.c.event_id, raw_records.c.content_text)
                .join(raw_records, raw_records.c.raw_record_id == events.c.raw_record_id)
                .where(events.c.event_id.in_(chunk))
            )
            raw.update({r.event_id: r.content_text for r in rows})
    prio = (
        (await conn.execute(select(priority_explanations).where(priority_explanations.c.case_id == case_id)))
        .mappings()
        .first()
    )
    factors = tuple(
        Factor(f["code"], f["contribution"], f["label_de"], f["label_en"], tuple(f["evidence"]))
        for f in (prio["factors"] if prio else [])
    )
    priority = PriorityResult(int(case_row["score"]), str(case_row["priority"]), factors)
    entity_rows = await conn.execute(
        select(case_entities)
        .where(case_entities.c.case_id == case_id)
        .order_by(case_entities.c.type, case_entities.c.key)
    )
    entity_list = [Entity(r.type, r.key, r.display) for r in entity_rows]
    summaries = [
        dict(r)
        for r in (
            await conn.execute(
                select(ai_summaries).where(ai_summaries.c.case_id == case_id).order_by(ai_summaries.c.version)
            )
        ).mappings()
    ]
    action_rows = (
        (
            await conn.execute(
                select(actions).where(actions.c.case_id == case_id).order_by(actions.c.proposed_at, actions.c.action_id)
            )
        )
        .mappings()
        .all()
    )
    approval_rows = {
        r["action_id"]: row_dict(r)
        for r in (
            await conn.execute(
                select(approvals).where(approvals.c.action_id.in_([a["action_id"] for a in action_rows]))
            )
        ).mappings()
    }
    action_list = []
    for a in action_rows:
        item = row_dict(a)
        item["approval"] = approval_rows.get(a["action_id"])
        action_list.append(item)
    note_list = [
        row_dict(r)
        for r in (
            await conn.execute(
                select(notes).where(notes.c.case_id == case_id).order_by(notes.c.created_at, notes.c.note_id)
            )
        ).mappings()
    ]
    return CaseBundle(
        row_dict(case_row),
        alert_objs,
        alert_rows,
        events_by_id,
        raw,
        priority,
        entity_list,
        summaries,
        action_list,
        note_list,
    )


def as_case_analysis(bundle: CaseBundle) -> CaseAnalysis:
    case = bundle.case
    recommendations = tuple(
        Recommendation(
            r["step_id"],
            r["action"],
            r["title_de"],
            r["title_en"],
            tuple(r["reason_rules"]),
            r["targets"],
            tuple(r["evidence"]),
        )
        for r in case["recommendations"]
    )
    draft = CaseDraft(
        case["case_id"],
        tuple(a.alert_id for a in bundle.alerts),
        bundle.alerts[0].window_start if bundle.alerts else datetime.fromisoformat(case["window_start"]),
        max((a.window_end for a in bundle.alerts), default=datetime.fromisoformat(case["window_end"])),
        tuple(bundle.entities),
        tuple(case["related_case_ids"]),
    )
    return CaseAnalysis(draft, tuple(bundle.alerts), bundle.priority, recommendations, case["title"], case["title_de"])


def timeline_items(bundle: CaseBundle) -> list[dict[str, Any]]:
    return [i.to_dict() for i in build_timeline(bundle.alerts, bundle.events_by_id)]


def evidence_view(bundle: CaseBundle, ruleset: RuleSet) -> dict[str, Any]:
    """Alert -> rule (YAML) -> matched fields -> raw lines (spec 17.2 page 5)."""
    refs = {
        eid: f"E{i}"
        for i, eid in enumerate(
            sorted(bundle.events_by_id, key=lambda e: (bundle.events_by_id[e].timestamp, e)), start=1
        )
    }
    alerts_out = []
    for alert in bundle.alerts:
        meta = ruleset.metas.get(alert.rule_id)
        row = bundle.alert_rows[alert.alert_id]
        alerts_out.append(
            {
                **alert.to_dict(),
                "false_positive": row["false_positive"],
                "false_positive_reason": row["false_positive_reason"],
                "rule": meta.to_dict() | {"yaml": meta.yaml_text} if meta else None,
                "events": [
                    {
                        "ref": refs.get(eid),
                        "event_id": eid,
                        "time": format_timestamp(bundle.events_by_id[eid].timestamp)
                        if eid in bundle.events_by_id
                        else None,
                        "fields": bundle.events_by_id[eid].to_dict() if eid in bundle.events_by_id else None,
                        "raw": bundle.raw_text.get(eid),
                    }
                    for eid in alert.event_ids[:500]
                ],
                "events_truncated": max(0, len(alert.event_ids) - 500),
            }
        )
    return {"alerts": alerts_out, "refs": refs}


def graph_view(bundle: CaseBundle, hub_keys: set[str]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: Counter[tuple[str, str]] = Counter()
    for event in bundle.events_by_id.values():
        ents = event_entities(event)
        ids = []
        for e in ents:
            node_id = f"{e.type}:{e.key}"
            nodes.setdefault(
                node_id, {"id": node_id, "type": e.type, "label": e.display, "hub": e.key in hub_keys, "events": 0}
            )
            nodes[node_id]["events"] += 1
            ids.append(node_id)
        for i, a in enumerate(sorted(set(ids))):
            for b in sorted(set(ids))[i + 1 :]:
                edges[(a, b)] += 1
    return {
        "nodes": [nodes[k] for k in sorted(nodes)],
        "edges": [{"source": a, "target": b, "weight": w} for (a, b), w in sorted(edges.items())],
    }


async def report_input(conn: AsyncConnection, bundle: CaseBundle, config_hash: str) -> ReportInput:
    state = (await conn.execute(select(analysis_state).where(analysis_state.c.id == 1))).mappings().first()
    summary = bundle.latest_summary
    record = summary["record"] if summary else None
    refs = {
        eid: f"E{i}"
        for i, eid in enumerate(
            sorted(bundle.events_by_id, key=lambda e: (bundle.events_by_id[e].timestamp, e)), start=1
        )
    }
    evidence = [
        {
            "ref": refs[eid],
            "event_id": eid,
            "time": format_timestamp(bundle.events_by_id[eid].timestamp),
            "raw": (bundle.raw_text.get(eid) or "")[:2000],
        }
        for eid in sorted(bundle.events_by_id, key=lambda e: (bundle.events_by_id[e].timestamp, e))[:200]
    ]
    events_hash = stable_hash(
        "case-events", [bundle.events_by_id[e].to_dict() for e in sorted(bundle.events_by_id)], length=64
    )
    case = {k: v for k, v in bundle.case.items() if k not in ("recommendations", "injection_findings", "updated_at")}
    case["priority"] = bundle.priority.to_dict()
    case["entities"] = [e.to_dict() for e in bundle.entities]
    alerts_out = [
        a.to_dict() | {"false_positive": bundle.alert_rows[a.alert_id]["false_positive"]} for a in bundle.alerts
    ]
    return ReportInput(
        case=case,
        alerts=alerts_out,
        timeline=timeline_items(bundle),
        evidence=evidence,
        recommendations=bundle.case["recommendations"],
        actions=bundle.actions,
        notes=bundle.notes,
        metadata={
            "software_version": SOFTWARE_VERSION,
            "events_hash": events_hash,
            "ruleset_hash": (state["ruleset_hash"] if state else None) or "",
            "config_hash": config_hash,
            "prompt_version": record.get("prompt_version") if record else "",
            "summary_version": summary["version"] if summary else 0,
        },
        ai_summary=record,
        injection_findings=bundle.case["injection_findings"],
    )
