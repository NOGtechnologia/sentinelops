"""Health, version, auth and dashboard."""

from __future__ import annotations

from datetime import UTC, timedelta
from typing import Annotated, Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelops.api.deps import PrincipalDep, RuntimeDep, require
from sentinelops.auth.principal import DEMO_USERS, Principal, issue_demo_token
from sentinelops.normalize.schema import format_timestamp
from sentinelops.settings import PRODUCT_NAME, SOFTWARE_VERSION
from sentinelops.storage import audit
from sentinelops.storage.models import (
    alerts,
    analysis_state,
    case_entities,
    cases,
    events,
    ingest_runs,
    role_assignments,
    users,
)

router = APIRouter(prefix="/api/v1")
CLOSED = ("resolved_true_positive", "resolved_false_positive", "resolved_benign")


class Health(BaseModel):
    status: str
    database: bool


@router.get("/health", response_model=Health)
async def health(rt: RuntimeDep) -> Health:
    try:
        async with rt.engine.connect() as conn:
            await conn.execute(select(1))
        return Health(status="ok", database=True)
    except Exception:  # health must never raise; report the state instead
        return Health(status="degraded", database=False)


class Version(BaseModel):
    product: str
    version: str
    demo_mode: bool
    demo_now: str | None


@router.get("/version", response_model=Version)
async def version(rt: RuntimeDep) -> Version:
    demo_now = format_timestamp(rt.clock.now()) if rt.settings.demo_mode and rt.settings.demo_now else None
    return Version(product=PRODUCT_NAME, version=SOFTWARE_VERSION, demo_mode=rt.settings.demo_mode, demo_now=demo_now)


class AuthConfig(BaseModel):
    demo_mode: bool
    demo_users: list[dict[str, Any]]
    oidc_issuer: str | None
    oidc_client_id: str
    display_timezone: str


@router.get("/auth/config", response_model=AuthConfig)
async def auth_config(rt: RuntimeDep) -> AuthConfig:
    demo = (
        [{"id": k, "name": v[0], "roles": list(v[1])} for k, v in DEMO_USERS.items()] if rt.settings.demo_mode else []
    )
    return AuthConfig(
        demo_mode=rt.settings.demo_mode,
        demo_users=demo,
        oidc_issuer=rt.settings.oidc_issuer,
        oidc_client_id=rt.settings.oidc_client_id,
        display_timezone=rt.settings.display_timezone,
    )


class DemoLogin(BaseModel):
    user: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type name, not a secret


@router.post("/auth/demo-login", response_model=TokenOut)
async def demo_login(body: DemoLogin, rt: RuntimeDep) -> TokenOut:
    if not rt.settings.demo_mode:
        raise HTTPException(404, "demo login is only available in demo mode")
    if body.user not in DEMO_USERS:
        raise HTTPException(400, "unknown demo user")
    token = issue_demo_token(body.user)
    async with rt.engine.begin() as conn:
        await audit.append(
            conn, f"demo-{body.user}", "auth.login", "user", f"demo-{body.user}", {"method": "demo"}, rt.clock.now()
        )
    return TokenOut(access_token=token)


class Me(BaseModel):
    subject: str
    username: str
    display_name: str
    roles: list[str]
    permissions: list[str]


@router.get("/auth/me", response_model=Me)
async def me(principal: PrincipalDep, rt: RuntimeDep) -> Me:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        known = (await conn.execute(select(users.c.subject).where(users.c.subject == principal.subject))).scalar()
        await conn.execute(
            pg_insert(users)
            .values(
                subject=principal.subject,
                username=principal.username,
                display_name=principal.display_name,
                first_login=now,
                last_login=now,
            )
            .on_conflict_do_update(index_elements=["subject"], set_={"last_login": now})
        )
        for role in principal.roles:
            await conn.execute(
                pg_insert(role_assignments).values(subject=principal.subject, role=role).on_conflict_do_nothing()
            )
        if known is None:
            await audit.append(
                conn,
                principal.username,
                "auth.first_login",
                "user",
                principal.subject,
                {"roles": list(principal.roles)},
                now,
            )
    return Me(
        subject=principal.subject,
        username=principal.username,
        display_name=principal.display_name,
        roles=list(principal.roles),
        permissions=sorted(principal.permissions),
    )


@router.get("/dashboard")
async def dashboard(rt: RuntimeDep, _: Annotated[Principal, Depends(require("dashboard:read"))]) -> dict[str, Any]:
    now = rt.clock.now()
    # "Today" is the calendar day in the display time zone; events stamped after "now" (hosts with clock skew,
    # flagged clock_skew_suspected) are not counted as recent activity.
    local_now = now.astimezone(ZoneInfo(rt.settings.display_timezone))
    day_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)
    until_now = events.c.ts <= now
    async with rt.engine.connect() as conn:
        events_today = (
            await conn.execute(
                select(func.count()).select_from(events).where(and_(events.c.ts >= day_start, until_now))
            )
        ).scalar()
        alerts_24h = (
            await conn.execute(
                select(func.count())
                .select_from(alerts)
                .where(and_(alerts.c.window_end >= now - timedelta(hours=24), alerts.c.suppressed_by.is_(None)))
            )
        ).scalar()
        open_rows = await conn.execute(
            select(cases.c.priority, func.count()).where(cases.c.status.notin_(CLOSED)).group_by(cases.c.priority)
        )
        open_by_priority = dict.fromkeys(("P1", "P2", "P3", "P4"), 0) | {r[0]: r[1] for r in open_rows}
        mtta = (
            await conn.execute(
                select(func.avg(func.extract("epoch", cases.c.first_action_at - cases.c.created_at))).where(
                    cases.c.first_action_at.isnot(None)
                )
            )
        ).scalar()
        hours = await conn.execute(
            select(func.date_trunc("hour", events.c.ts).label("bucket"), func.count())
            .where(and_(events.c.ts >= now - timedelta(hours=24), until_now))
            .group_by("bucket")
            .order_by("bucket")
        )
        days = await conn.execute(
            select(func.date_trunc("day", events.c.ts).label("bucket"), func.count())
            .where(and_(events.c.ts >= now - timedelta(days=7), until_now))
            .group_by("bucket")
            .order_by("bucket")
        )
        alert_hours = await conn.execute(
            select(func.date_trunc("hour", alerts.c.window_end).label("bucket"), func.count())
            .where(and_(alerts.c.window_end >= now - timedelta(hours=24), alerts.c.suppressed_by.is_(None)))
            .group_by("bucket")
            .order_by("bucket")
        )
        alert_days = await conn.execute(
            select(func.date_trunc("day", alerts.c.window_end).label("bucket"), func.count())
            .where(and_(alerts.c.window_end >= now - timedelta(days=7), alerts.c.suppressed_by.is_(None)))
            .group_by("bucket")
            .order_by("bucket")
        )
        top_rules = await conn.execute(
            select(alerts.c.rule_id, alerts.c.title, alerts.c.title_de, func.count().label("n"))
            .where(and_(alerts.c.window_end >= now - timedelta(days=7), alerts.c.suppressed_by.is_(None)))
            .group_by(alerts.c.rule_id, alerts.c.title, alerts.c.title_de)
            .order_by(func.count().desc(), alerts.c.rule_id)
            .limit(8)
        )
        top_entities = await conn.execute(
            select(case_entities.c.type, case_entities.c.display, func.count().label("n"))
            .join(cases, cases.c.case_id == case_entities.c.case_id)
            .where(cases.c.status.notin_(CLOSED))
            .group_by(case_entities.c.type, case_entities.c.display)
            .order_by(func.count().desc(), case_entities.c.display)
            .limit(8)
        )
        last_runs = await conn.execute(
            select(
                ingest_runs.c.source_type,
                func.max(ingest_runs.c.started_at),
                func.sum(ingest_runs.c.accepted),
                func.sum(ingest_runs.c.duplicate),
                func.sum(ingest_runs.c.malformed),
                func.count().filter(ingest_runs.c.status == "failed"),
            )
            .group_by(ingest_runs.c.source_type)
            .order_by(ingest_runs.c.source_type)
        )
        state = (await conn.execute(select(analysis_state).where(analysis_state.c.id == 1))).mappings().first()
        newest = (await conn.execute(select(func.max(events.c.ts)).where(until_now))).scalar()
    return {
        "generated_at": format_timestamp(now),
        "data_as_of": format_timestamp(newest) if newest else None,
        "last_analysis": format_timestamp(state["last_run_at"]) if state and state["last_run_at"] else None,
        "kpis": {
            "events_today": events_today,
            "alerts_24h": alerts_24h,
            "open_cases": open_by_priority,
            "mean_minutes_to_action": round(float(mtta) / 60, 1) if mtta is not None else None,
        },
        "series": {
            "events_24h": [{"t": format_timestamp(r[0]), "n": r[1]} for r in hours],
            "events_7d": [{"t": format_timestamp(r[0]), "n": r[1]} for r in days],
            "alerts_24h": [{"t": format_timestamp(r[0]), "n": r[1]} for r in alert_hours],
            "alerts_7d": [{"t": format_timestamp(r[0]), "n": r[1]} for r in alert_days],
        },
        "top_rules": [
            {"rule_id": r.rule_id, "title": r.title, "title_de": r.title_de, "alerts": r.n} for r in top_rules
        ],
        "top_entities": [{"type": r.type, "display": r.display, "cases": r.n} for r in top_entities],
        "ingestion": [
            {
                "source_type": r[0],
                "last_run": format_timestamp(r[1]),
                "accepted": r[2],
                "duplicate": r[3],
                "malformed": r[4],
                "failed_runs": r[5],
            }
            for r in last_runs
        ],
        "learning_users": len(state["learning_users"] or []) if state else 0,
    }
