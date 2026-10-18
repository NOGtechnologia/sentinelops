"""Analysis job: load events -> analyze() -> persist alerts, cases, priority.

The detection result is a pure function of the events, rules and config; the
job only adds state handling: closed cases are never modified, stored and
manual case assignments are pinned, and every case gets an initial summary.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import and_, delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from sentinelops.ai.evidence import build_package
from sentinelops.ai.injection import scan_events
from sentinelops.ai.providers import LLMProvider
from sentinelops.ai.service import summarize
from sentinelops.correlation.analysis import AnalysisResult, CaseAnalysis, analyze
from sentinelops.correlation.priority import RuleStats
from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.exceptions import RuleException
from sentinelops.detection.sigma_loader import RuleSet
from sentinelops.investigation.catalog import PlaybookStep
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.schema import CanonicalEvent, format_timestamp
from sentinelops.storage import audit
from sentinelops.storage.models import (
    actions,
    ai_summaries,
    alert_events,
    alerts,
    analysis_state,
    case_alerts,
    case_entities,
    cases,
    entities,
    events,
    priority_explanations,
    raw_records,
    rule_versions,
    rules,
)

CLOSED = ("resolved_true_positive", "resolved_false_positive", "resolved_benign")

#: Set-based entity upserts (constant SQL).
ENTITY_UPSERTS = (
    """
INSERT INTO entities (type, key, display, first_seen, last_seen)
SELECT 'user', user_key, min(user_name), min(ts), max(ts) FROM events
WHERE user_key IS NOT NULL GROUP BY user_key
ON CONFLICT (type, key) DO UPDATE SET
    first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(entities.last_seen, EXCLUDED.last_seen)
""",
    """
INSERT INTO entities (type, key, display, first_seen, last_seen)
SELECT 'host', host_key, min(host_name), min(ts), max(ts) FROM events
WHERE host_key IS NOT NULL GROUP BY host_key
ON CONFLICT (type, key) DO UPDATE SET
    first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(entities.last_seen, EXCLUDED.last_seen)
""",
    """
INSERT INTO entities (type, key, display, first_seen, last_seen)
SELECT 'ip', source_ip, min(source_ip), min(ts), max(ts) FROM events
WHERE source_ip IS NOT NULL GROUP BY source_ip
ON CONFLICT (type, key) DO UPDATE SET
    first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(entities.last_seen, EXCLUDED.last_seen)
""",
)


@dataclass(frozen=True)
class AnalysisContext:
    ruleset: RuleSet
    config: DetectionConfig
    exceptions: list[RuleException]
    catalog: dict[str, PlaybookStep]
    tz: ZoneInfo
    provider: LLMProvider | None = None
    pseudonymize: bool = True
    window_days: int = 30


def active_ruleset(ruleset: RuleSet, inactive: set[str]) -> RuleSet:
    """Drop deactivated alerting rules (helpers stay; they never alert)."""
    if not inactive:
        return ruleset
    base = {k: v for k, v in ruleset.base_rules.items() if v.meta is None or v.meta.rule_id not in inactive}
    return RuleSet(
        base_rules=base,
        correlations=[c for c in ruleset.correlations if c.meta.rule_id not in inactive],
        sequences=[s for s in ruleset.sequences if s.meta.rule_id not in inactive],
        baselines=[b for b in ruleset.baselines if b.meta.rule_id not in inactive],
        pipeline_hash=ruleset.pipeline_hash,
        ruleset_hash=stable_hash(ruleset.ruleset_hash, sorted(inactive), length=64),
        metas={k: v for k, v in ruleset.metas.items() if k not in inactive},
    )


async def load_events(conn: AsyncConnection, since: datetime) -> list[CanonicalEvent]:
    rows = await conn.execute(select(events.c.data).where(events.c.ts >= since))
    return [CanonicalEvent.from_dict(r[0]) for r in rows]


async def raw_text_for(conn: AsyncConnection, event_ids: list[str]) -> dict[str, str]:
    if not event_ids:
        return {}
    rows = await conn.execute(
        select(events.c.event_id, raw_records.c.content_text)
        .join(raw_records, raw_records.c.raw_record_id == events.c.raw_record_id)
        .where(events.c.event_id.in_(event_ids))
    )
    return {r.event_id: r.content_text for r in rows}


async def _rule_stats(conn: AsyncConnection) -> dict[str, RuleStats]:
    rows = await conn.execute(select(cases.c.status, cases.c.rule_ids).where(cases.c.status.in_(CLOSED)))
    resolved: dict[str, int] = defaultdict(int)
    false_pos: dict[str, int] = defaultdict(int)
    for row in rows:
        for rule_id in row.rule_ids or []:
            resolved[rule_id] += 1
            if row.status == "resolved_false_positive":
                false_pos[rule_id] += 1
    return {r: RuleStats(resolved[r], false_pos[r]) for r in resolved}


async def sync_rules(conn: AsyncConnection, ruleset: RuleSet, now: datetime) -> set[str]:
    """Register rule versions; return the ids of deactivated rules."""
    for meta in ruleset.metas.values():
        await conn.execute(
            pg_insert(rules)
            .values(
                rule_id=meta.rule_id,
                current_version=meta.version,
                current_hash=meta.content_hash,
                title=meta.title,
                title_de=meta.title_de,
                level=meta.level,
                maturity=meta.maturity,
                source=meta.source,
                kind=meta.kind,
                active=True,
                updated_at=now,
            )
            .on_conflict_do_update(
                index_elements=["rule_id"],
                set_={
                    "current_version": meta.version,
                    "current_hash": meta.content_hash,
                    "title": meta.title,
                    "title_de": meta.title_de,
                    "level": meta.level,
                    "maturity": meta.maturity,
                    "updated_at": now,
                },
            )
        )
        await conn.execute(
            pg_insert(rule_versions)
            .values(
                rule_id=meta.rule_id,
                version=meta.version,
                content_hash=meta.content_hash,
                yaml_text=meta.yaml_text,
                meta=meta.to_dict(),
                created_at=now,
            )
            .on_conflict_do_nothing()
        )
    rows = await conn.execute(select(rules.c.rule_id).where(rules.c.active.is_(False)))
    return {r.rule_id for r in rows}


async def run_analysis(
    engine: AsyncEngine, ctx: AnalysisContext, now: datetime, actor: str = "system"
) -> dict[str, Any]:
    async with engine.begin() as conn:
        inactive = await sync_rules(conn, ctx.ruleset, now)
        since = now - timedelta(days=ctx.window_days)
        loaded = await load_events(conn, since)
        pinned_rows = await conn.execute(select(case_alerts.c.alert_id, case_alerts.c.case_id))
        pinned = {r.alert_id: r.case_id for r in pinned_rows}
        closed = {r.case_id for r in await conn.execute(select(cases.c.case_id).where(cases.c.status.in_(CLOSED)))}
        stats = await _rule_stats(conn)
    ruleset = active_ruleset(ctx.ruleset, inactive)
    result = await asyncio.to_thread(
        analyze, loaded, ruleset, ctx.config, ctx.exceptions, ctx.catalog, now, ctx.tz, pinned, frozenset(closed), stats
    )
    async with engine.begin() as conn:
        summary = await persist(conn, result, ctx, now, closed)
        await conn.execute(
            update(analysis_state)
            .where(analysis_state.c.id == 1)
            .values(
                last_run_at=now,
                ruleset_hash=ruleset.ruleset_hash,
                config_hash=ctx.config.config_hash(),
                learning_users=result.detection.learning_users,
                hubs=[{"key": h.key, "type": h.type, "reason": h.reason} for h in result.hubs],
                events_hash=stable_hash("events", sorted(result.events_by_id), length=64),
            )
        )
        await audit.append(conn, actor, "analysis.completed", "analysis", "1", {"events": len(loaded), **summary}, now)
    return {"events": len(loaded), **summary}


async def persist(
    conn: AsyncConnection, result: AnalysisResult, ctx: AnalysisContext, now: datetime, closed: set[str]
) -> dict[str, int]:
    all_alerts = result.detection.alerts
    for alert in all_alerts:
        data = alert.to_dict()
        await conn.execute(
            pg_insert(alerts)
            .values(
                alert_id=alert.alert_id,
                rule_id=alert.rule_id,
                rule_version=alert.rule_version,
                rule_hash=alert.rule_hash,
                kind=alert.kind,
                level=alert.level,
                maturity=alert.maturity,
                title=alert.title,
                title_de=alert.title_de,
                window_start=alert.window_start,
                window_end=alert.window_end,
                event_count=len(alert.event_ids),
                data=data,
                suppressed_by=alert.suppressed_by,
                created_at=now,
            )
            .on_conflict_do_update(
                index_elements=["alert_id"],
                set_={
                    "window_end": alert.window_end,
                    "event_count": len(alert.event_ids),
                    "data": data,
                    "suppressed_by": alert.suppressed_by,
                },
            )
        )
        rows = [
            {"alert_id": alert.alert_id, "event_id": eid, "ts": result.events_by_id[eid].timestamp}
            for eid in alert.event_ids
            if eid in result.events_by_id
        ]
        for start in range(0, len(rows), 5000):
            await conn.execute(pg_insert(alert_events).values(rows[start : start + 5000]).on_conflict_do_nothing())

    suspicious = sorted(result.detection.suspicious_event_ids())
    await conn.execute(update(events).where(events.c.assessment == "suspicious").values(assessment="normal"))
    for start in range(0, len(suspicious), 5000):
        chunk = suspicious[start : start + 5000]
        await conn.execute(update(events).where(events.c.event_id.in_(chunk)).values(assessment="suspicious"))

    created = 0
    for case in result.cases:
        if case.case_id in closed:
            continue
        created += await _persist_case(conn, case, result, ctx, now)
    await _refresh_entities(conn, result, ctx)
    return {
        "alerts": len(all_alerts),
        "active_alerts": len(result.detection.active_alerts),
        "cases": len(result.cases),
        "new_cases": created,
    }


async def _persist_case(
    conn: AsyncConnection, case: CaseAnalysis, result: AnalysisResult, ctx: AnalysisContext, now: datetime
) -> int:
    draft = case.draft
    rule_ids = sorted({a.rule_id for a in case.alerts})
    tactics = sorted({t for a in case.alerts for t in a.tactics})
    case_event_ids = sorted({eid for a in case.alerts for eid in a.event_ids})
    raw = await raw_text_for(conn, case_event_ids[:2000])
    findings = scan_events([result.events_by_id[e] for e in case_event_ids if e in result.events_by_id], raw)
    existing = (await conn.execute(select(cases.c.case_id).where(cases.c.case_id == draft.case_id))).scalar()
    values = {
        "title": case.title,
        "title_de": case.title_de,
        "priority": case.priority.level,
        "score": case.priority.score,
        "window_start": draft.window_start,
        "window_end": draft.window_end,
        "related_case_ids": list(draft.related_case_ids),
        "tactics": tactics,
        "rule_ids": rule_ids,
        "recommendations": [r.to_dict() for r in case.recommendations],
        "injection_findings": [f.to_dict() for f in findings],
        "updated_at": now,
    }
    if existing is None:
        await conn.execute(pg_insert(cases).values(case_id=draft.case_id, status="new", created_at=now, **values))
        await audit.append(
            conn,
            "system",
            "case.created",
            "case",
            draft.case_id,
            {"priority": case.priority.level, "alerts": list(draft.alert_ids)},
            now,
        )
    else:
        await conn.execute(update(cases).where(cases.c.case_id == draft.case_id).values(**values))
    for alert_id in draft.alert_ids:
        await conn.execute(
            pg_insert(case_alerts)
            .values(alert_id=alert_id, case_id=draft.case_id, manual=False)
            .on_conflict_do_nothing()
        )
    await conn.execute(delete(case_entities).where(case_entities.c.case_id == draft.case_id))
    if draft.entities:
        await conn.execute(
            pg_insert(case_entities)
            .values(
                [{"case_id": draft.case_id, "type": e.type, "key": e.key, "display": e.display} for e in draft.entities]
            )
            .on_conflict_do_nothing()
        )
    await conn.execute(
        pg_insert(priority_explanations)
        .values(
            case_id=draft.case_id,
            score=case.priority.score,
            level=case.priority.level,
            factors=[f.to_dict() for f in case.priority.factors],
            computed_at=now,
        )
        .on_conflict_do_update(
            index_elements=["case_id"],
            set_={
                "score": case.priority.score,
                "level": case.priority.level,
                "factors": [f.to_dict() for f in case.priority.factors],
                "computed_at": now,
            },
        )
    )
    has_summary = (
        await conn.execute(
            select(func.count()).select_from(ai_summaries).where(ai_summaries.c.case_id == draft.case_id)
        )
    ).scalar()
    if not has_summary:
        await store_summary(conn, case, result.events_by_id, raw, findings, ctx, now, version=1)
    return 1 if existing is None else 0


async def store_summary(
    conn: AsyncConnection,
    case: CaseAnalysis,
    events_by_id: dict[str, CanonicalEvent],
    raw: dict[str, str],
    findings: list[Any],
    ctx: AnalysisContext,
    now: datetime,
    version: int,
    provider: LLMProvider | None = None,
    actor: str = "system",
) -> dict[str, Any]:
    executed = await _executed_actions(conn, case.case_id)
    package = build_package(
        case.case_id, case.alerts, events_by_id, case.priority, case.draft.entities, ctx.catalog, raw, executed
    )
    chosen = provider if provider is not None else ctx.provider
    record = await asyncio.to_thread(summarize, package, case.recommendations, chosen, now, findings, ctx.pseudonymize)
    data = record.to_dict()
    await conn.execute(
        pg_insert(ai_summaries).values(
            summary_id=stable_hash("summary", case.case_id, version),
            case_id=case.case_id,
            version=version,
            evidence_hash=record.evidence_hash,
            provider=record.provider,
            model=record.model,
            prompt_version=record.prompt_version,
            validation_status=record.validation.status,
            record=data,
            created_at=now,
        )
    )
    await audit.append(
        conn,
        actor,
        "ai.summary_created",
        "case",
        case.case_id,
        {
            "version": version,
            "provider": record.provider,
            "model": record.model,
            "validation": record.validation.status,
            "evidence_hash": record.evidence_hash,
        },
        now,
    )
    return data


async def _executed_actions(conn: AsyncConnection, case_id: str) -> list[dict[str, str]]:
    rows = await conn.execute(
        select(actions.c.step_id, actions.c.status, actions.c.parameters).where(actions.c.case_id == case_id)
    )
    return [
        {"step_id": r.step_id, "status": r.status, "target": ",".join(str(v) for v in (r.parameters or {}).values())}
        for r in rows
    ]


async def _refresh_entities(conn: AsyncConnection, result: AnalysisResult, ctx: AnalysisContext) -> None:
    """Set-based upsert of users/hosts/IPs with first/last seen and flags."""
    hubs = {h.key for h in result.hubs}
    for statement in ENTITY_UPSERTS:
        await conn.execute(text(statement))
    await conn.execute(update(entities).values(hub=False, hub_reason=None))
    for hub in result.hubs:
        await conn.execute(update(entities).where(entities.c.key == hub.key).values(hub=True, hub_reason=hub.reason))
    critical = [c.casefold() for c in ctx.config.critical_assets]
    await conn.execute(
        update(entities).where(and_(entities.c.type == "host", entities.c.key.in_(critical))).values(critical=True)
    )
    del hubs


def case_summary_row(row: Any) -> dict[str, Any]:
    return {k: (format_timestamp(v) if isinstance(v, datetime) else v) for k, v in dict(row).items()}
