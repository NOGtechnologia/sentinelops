"""Alerts, events, entities, rules, exceptions."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelops.api.deps import RuntimeDep, require
from sentinelops.auth.principal import Principal
from sentinelops.normalize.schema import format_timestamp, parse_timestamp
from sentinelops.reports.csv_export import to_csv
from sentinelops.services.cases import row_dict
from sentinelops.storage import audit, jobs
from sentinelops.storage.models import (
    alerts,
    case_alerts,
    cases,
    entities,
    events,
    raw_records,
    rule_exceptions,
    rule_versions,
    rules,
)

router = APIRouter(prefix="/api/v1")


def _p(permission: str) -> Any:
    return Depends(require(permission))


@router.get("/alerts")
async def list_alerts(
    rt: RuntimeDep,
    _: Annotated[Principal, _p("alerts:read")],
    rule_id: str | None = None,
    include_suppressed: bool = False,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    cond: list[Any] = []
    if rule_id:
        cond.append(alerts.c.rule_id == rule_id)
    if not include_suppressed:
        cond.append(alerts.c.suppressed_by.is_(None))
    async with rt.engine.connect() as conn:
        total = (await conn.execute(select(func.count()).select_from(alerts).where(and_(True, *cond)))).scalar()
        rows = (
            await conn.execute(
                select(
                    alerts.c.alert_id,
                    alerts.c.rule_id,
                    alerts.c.rule_version,
                    alerts.c.title_de,
                    alerts.c.level,
                    alerts.c.window_start,
                    alerts.c.window_end,
                    alerts.c.event_count,
                    alerts.c.suppressed_by,
                    alerts.c.false_positive,
                    case_alerts.c.case_id,
                )
                .select_from(alerts.outerjoin(case_alerts, case_alerts.c.alert_id == alerts.c.alert_id))
                .where(and_(True, *cond))
                .order_by(alerts.c.window_end.desc(), alerts.c.alert_id)
                .offset(offset)
                .limit(limit)
            )
        ).mappings()
        return {"total": total, "items": [row_dict(r) for r in rows]}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("alerts:read")]) -> dict[str, Any]:
    async with rt.engine.connect() as conn:
        row = (await conn.execute(select(alerts).where(alerts.c.alert_id == alert_id))).mappings().first()
        if row is None:
            raise HTTPException(404, "alert not found")
        case_id = (await conn.execute(select(case_alerts.c.case_id).where(case_alerts.c.alert_id == alert_id))).scalar()
    meta = rt.ruleset.metas.get(row["rule_id"])
    return {
        **row["data"],
        "false_positive": row["false_positive"],
        "false_positive_reason": row["false_positive_reason"],
        "case_id": case_id,
        "rule": meta.to_dict() | {"yaml": meta.yaml_text} if meta else None,
    }


class FalsePositiveIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


@router.post("/alerts/{alert_id}/false-positive")
async def mark_false_positive(
    alert_id: str, body: FalsePositiveIn, rt: RuntimeDep, principal: Annotated[Principal, _p("alerts:false_positive")]
) -> dict[str, Any]:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        result = await conn.execute(
            update(alerts)
            .where(alerts.c.alert_id == alert_id)
            .values(false_positive=True, false_positive_reason=body.reason, false_positive_by=principal.username)
        )
        if result.rowcount == 0:
            raise HTTPException(404, "alert not found")
        await audit.append(
            conn, principal.username, "alert.false_positive", "alert", alert_id, {"reason": body.reason}, now
        )
    return {"alert_id": alert_id, "false_positive": True}


def _event_conditions(
    q: str | None,
    user: str | None,
    host: str | None,
    ip: str | None,
    action: str | None,
    start: str | None,
    end: str | None,
    assessment: str | None,
) -> list[Any]:
    cond: list[Any] = []
    if user:
        cond.append(events.c.user_key.ilike(f"%{user.casefold()}%"))
    if host:
        cond.append(events.c.host_key.ilike(f"%{host.casefold()}%"))
    if ip:
        cond.append(events.c.source_ip == ip)
    if action:
        cond.append(events.c.action == action)
    if assessment:
        cond.append(events.c.assessment == assessment)
    try:
        if start:
            cond.append(events.c.ts >= parse_timestamp(start))
        if end:
            cond.append(events.c.ts < parse_timestamp(end))
    except ValueError as exc:
        raise HTTPException(422, "invalid time") from exc
    if q:
        matching = select(raw_records.c.raw_record_id).where(
            text(
                "to_tsvector('simple', left(raw_records.content_text, 4000)) @@ plainto_tsquery('simple', :q)"
            ).bindparams(q=q)
        )
        cond.append(or_(events.c.raw_record_id.in_(matching), events.c.user_name.ilike(f"%{q}%")))
    return cond


@router.get("/events")
async def search_events(
    rt: RuntimeDep,
    _: Annotated[Principal, _p("events:read")],
    q: str | None = None,
    user: str | None = None,
    host: str | None = None,
    ip: str | None = None,
    action: str | None = None,
    start: str | None = None,
    end: str | None = None,
    assessment: str | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    cond = _event_conditions(q, user, host, ip, action, start, end, assessment)
    async with rt.engine.connect() as conn:
        rows = (
            await conn.execute(
                select(events.c.data, events.c.assessment)
                .where(and_(True, *cond))
                .order_by(events.c.ts.desc(), events.c.event_id)
                .offset(offset)
                .limit(limit)
            )
        ).all()
    return {"offset": offset, "items": [r.data | {"assessment": r.assessment} for r in rows]}


@router.get("/events/export.csv")
async def export_events(
    rt: RuntimeDep,
    principal: Annotated[Principal, _p("events:read")],
    q: str | None = None,
    user: str | None = None,
    host: str | None = None,
    ip: str | None = None,
    action: str | None = None,
    start: str | None = None,
    end: str | None = None,
    assessment: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100000)] = 10000,
) -> Response:
    cond = _event_conditions(q, user, host, ip, action, start, end, assessment)
    columns = [
        "timestamp",
        "event.id",
        "event.action",
        "event.outcome",
        "event.code",
        "user.name",
        "user.target.name",
        "host.name",
        "source.ip",
        "process.command_line",
        "assessment",
    ]
    async with rt.engine.begin() as conn:
        rows = (
            await conn.execute(
                select(events.c.data, events.c.assessment)
                .where(and_(True, *cond))
                .order_by(events.c.ts, events.c.event_id)
                .limit(limit)
            )
        ).all()
        await audit.append(
            conn,
            principal.username,
            "events.exported",
            "events",
            "csv",
            {"rows": len(rows), "filters": {"q": q, "user": user, "host": host, "ip": ip}},
            rt.clock.now(),
        )
    body = to_csv(columns, [r.data | {"timestamp": r.data["@timestamp"], "assessment": r.assessment} for r in rows])
    return Response(
        body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="sentinelops-events.csv"'},
    )


@router.get("/events/{event_id}")
async def get_event(event_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("events:read")]) -> dict[str, Any]:
    async with rt.engine.connect() as conn:
        row = (
            await conn.execute(
                select(
                    events.c.data,
                    events.c.assessment,
                    raw_records.c.content_text,
                    raw_records.c.position,
                    raw_records.c.run_id,
                )
                .join(raw_records, raw_records.c.raw_record_id == events.c.raw_record_id)
                .where(events.c.event_id == event_id)
            )
        ).first()
    if row is None:
        raise HTTPException(404, "event not found")
    return {
        "event": row.data,
        "assessment": row.assessment,
        "raw": {"text": row.content_text, "position": row.position, "run_id": row.run_id},
    }


@router.get("/entities")
async def list_entities(
    rt: RuntimeDep,
    _: Annotated[Principal, _p("entities:read")],
    type: str | None = None,
    q: str | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    cond: list[Any] = []
    if type:
        cond.append(entities.c.type == type)
    if q:
        cond.append(entities.c.key.ilike(f"%{q.casefold()}%"))
    async with rt.engine.connect() as conn:
        rows = (
            await conn.execute(
                select(entities)
                .where(and_(True, *cond))
                .order_by(entities.c.type, entities.c.key)
                .offset(offset)
                .limit(limit)
            )
        ).mappings()
        return {"items": [row_dict(r) for r in rows]}


@router.get("/rules")
async def list_rules(rt: RuntimeDep, _: Annotated[Principal, _p("rules:read")]) -> list[dict[str, Any]]:
    async with rt.engine.connect() as conn:
        state = {r.rule_id: r.active for r in await conn.execute(select(rules.c.rule_id, rules.c.active))}
        counts = {
            r[0]: (r[1], r[2])
            for r in await conn.execute(
                select(alerts.c.rule_id, func.count(), func.count().filter(alerts.c.false_positive))
                .where(alerts.c.suppressed_by.is_(None))
                .group_by(alerts.c.rule_id)
            )
        }
        resolved = await conn.execute(select(cases.c.status, cases.c.rule_ids).where(cases.c.status.like("resolved%")))
        rule_resolved: dict[str, list[int]] = {}
        for row in resolved:
            for rid in row.rule_ids or []:
                stats = rule_resolved.setdefault(rid, [0, 0])
                stats[0] += 1
                stats[1] += int(row.status == "resolved_false_positive")
    out = []
    for rule_id, meta in sorted(rt.ruleset.metas.items()):
        hits, fp_alerts = counts.get(rule_id, (0, 0))
        res = rule_resolved.get(rule_id, [0, 0])
        out.append(
            meta.to_dict()
            | {
                "active": state.get(rule_id, True),
                "alerts": hits,
                "false_positive_alerts": fp_alerts,
                "false_positive_rate": round(res[1] / res[0], 3) if res[0] else None,
            }
        )
    return out


def _rule_tests(rules_dir: Path, rule_id: str) -> list[dict[str, Any]]:
    path = rules_dir / "tests" / f"{rule_id}.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        {"name": c.get("name"), "expect": c.get("expect"), "events": len(c.get("events") or [])}
        for c in data.get("cases") or []
    ]


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("rules:read")]) -> dict[str, Any]:
    meta = rt.ruleset.metas.get(rule_id)
    if meta is None:
        raise HTTPException(404, "rule not found")
    async with rt.engine.connect() as conn:
        versions = [
            row_dict(r) | {"meta": None}
            for r in (
                await conn.execute(
                    select(rule_versions.c.version, rule_versions.c.content_hash, rule_versions.c.created_at)
                    .where(rule_versions.c.rule_id == rule_id)
                    .order_by(rule_versions.c.created_at)
                )
            ).mappings()
        ]
        active = (await conn.execute(select(rules.c.active).where(rules.c.rule_id == rule_id))).scalar()
        recent = [
            row_dict(r)
            for r in (
                await conn.execute(
                    select(alerts.c.alert_id, alerts.c.window_start, alerts.c.event_count, alerts.c.false_positive)
                    .where(alerts.c.rule_id == rule_id)
                    .order_by(alerts.c.window_start.desc())
                    .limit(20)
                )
            ).mappings()
        ]
    return meta.to_dict() | {
        "yaml": meta.yaml_text,
        "active": True if active is None else active,
        "versions": versions,
        "tests": _rule_tests(rt.rules_dir, rule_id),
        "recent_alerts": recent,
    }


class RuleUpdate(BaseModel):
    active: bool
    reason: str = Field(min_length=3, max_length=1000)


@router.patch("/rules/{rule_id}")
async def update_rule(
    rule_id: str, body: RuleUpdate, rt: RuntimeDep, principal: Annotated[Principal, _p("rules:write")]
) -> dict[str, Any]:
    if rule_id not in rt.ruleset.metas:
        raise HTTPException(404, "rule not found")
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        result = await conn.execute(
            update(rules).where(rules.c.rule_id == rule_id).values(active=body.active, updated_at=now)
        )
        if result.rowcount == 0:
            raise HTTPException(409, "rule not yet registered - run an analysis first")
        await audit.append(
            conn,
            principal.username,
            "rule.activated" if body.active else "rule.deactivated",
            "rule",
            rule_id,
            {"reason": body.reason},
            now,
        )
        await jobs.enqueue(conn, "analyze", {"reason": "rule change"}, now)
    return {"rule_id": rule_id, "active": body.active}


@router.get("/exceptions")
async def list_exceptions(rt: RuntimeDep, _: Annotated[Principal, _p("exceptions:read")]) -> list[dict[str, Any]]:
    files = [
        e.model_dump(mode="json") | {"status": "active" if e.approved_by else "proposed", "origin": "rules/exceptions"}
        for e in rt.file_exceptions
    ]
    async with rt.engine.connect() as conn:
        rows = [
            row_dict(r) | {"origin": "database"}
            for r in (
                await conn.execute(
                    select(rule_exceptions).order_by(rule_exceptions.c.exception_id, rule_exceptions.c.version)
                )
            ).mappings()
        ]
    return files + rows


class ExceptionIn(BaseModel):
    rule_id: str
    description: str = Field(min_length=10, max_length=2000)
    match: dict[str, str] = Field(min_length=1)
    expires: date


@router.post("/exceptions")
async def propose_exception(
    body: ExceptionIn, rt: RuntimeDep, principal: Annotated[Principal, _p("exceptions:propose")]
) -> dict[str, Any]:
    if body.rule_id not in rt.ruleset.metas:
        raise HTTPException(422, "unknown rule")
    now = rt.clock.now()
    if body.expires <= now.date():
        raise HTTPException(422, "expiry must be in the future")
    async with rt.engine.begin() as conn:
        count = (await conn.execute(select(func.count(func.distinct(rule_exceptions.c.exception_id))))).scalar() or 0
        exception_id = f"EXC-{1000 + count + len(rt.file_exceptions):04d}"
        await conn.execute(
            pg_insert(rule_exceptions).values(
                exception_id=exception_id,
                version=1,
                rule_id=body.rule_id,
                description=body.description,
                match=body.match,
                created_by=principal.username,
                approved_by=None,
                expires=body.expires,
                status="proposed",
                created_at=now,
            )
        )
        await audit.append(
            conn, principal.username, "exception.proposed", "exception", exception_id, body.model_dump(mode="json"), now
        )
    return {"exception_id": exception_id, "status": "proposed"}


@router.post("/exceptions/{exception_id}/approve")
async def approve_exception(
    exception_id: str, rt: RuntimeDep, principal: Annotated[Principal, _p("exceptions:approve")]
) -> dict[str, Any]:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        row = (
            (
                await conn.execute(
                    select(rule_exceptions).where(
                        and_(rule_exceptions.c.exception_id == exception_id, rule_exceptions.c.status == "proposed")
                    )
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            raise HTTPException(404, "no proposed exception with this id")
        if row["created_by"] == principal.username:
            raise HTTPException(403, "four-eyes principle: the author cannot approve the exception")
        await conn.execute(
            update(rule_exceptions)
            .where(and_(rule_exceptions.c.exception_id == exception_id, rule_exceptions.c.version == row["version"]))
            .values(status="active", approved_by=principal.username)
        )
        await audit.append(
            conn, principal.username, "exception.approved", "exception", exception_id, {"rule_id": row["rule_id"]}, now
        )
        await jobs.enqueue(conn, "analyze", {"reason": "exception approved"}, now)
    return {"exception_id": exception_id, "status": "active", "approved_at": format_timestamp(now)}
