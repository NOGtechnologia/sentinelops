"""Cases: queue, detail, timeline, evidence, graph, notes, merge/split, AI
summaries, actions with approvals, reports."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from sentinelops.api.deps import RuntimeDep, require
from sentinelops.auth.principal import Principal
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.schema import format_timestamp, parse_timestamp
from sentinelops.reports.pseudonymize import pseudonymize_report
from sentinelops.reports.render import build_report, render_json, render_markdown, render_pdf
from sentinelops.response.actions import Action, ActionStatus, propose
from sentinelops.response.approvals import Approval, ApprovalError, decide, execute
from sentinelops.response.connectors.simulation import SimulationConnector
from sentinelops.services.cases import (
    NotFoundError,
    as_case_analysis,
    evidence_view,
    graph_view,
    load_case,
    report_input,
    row_dict,
    timeline_items,
)
from sentinelops.storage import audit, jobs
from sentinelops.storage.models import (
    actions,
    ai_summaries,
    analysis_state,
    approvals,
    case_alerts,
    case_entities,
    case_merges,
    cases,
    notes,
    reports,
)
from sentinelops.worker.analysis import AnalysisContext, store_summary

router = APIRouter(prefix="/api/v1")
STATUSES = ("new", "in_progress", "resolved_true_positive", "resolved_false_positive", "resolved_benign")
CLOSED = STATUSES[2:]
Status = Literal["new", "in_progress", "resolved_true_positive", "resolved_false_positive", "resolved_benign"]


def _p(permission: str) -> Any:
    return Depends(require(permission))


async def _case_or_404(conn: AsyncConnection, case_id: str) -> dict[str, Any]:
    row = (await conn.execute(select(cases).where(cases.c.case_id == case_id))).mappings().first()
    if row is None:
        raise HTTPException(404, "case not found")
    return dict(row)


@router.get("/cases")
async def list_cases(
    rt: RuntimeDep,
    _: Annotated[Principal, _p("cases:read")],
    status: Annotated[list[str] | None, Query()] = None,
    priority: Annotated[list[str] | None, Query()] = None,
    q: str | None = None,
    assignee: str | None = None,
    entity: str | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    has_alerts = select(case_alerts.c.case_id).where(case_alerts.c.case_id == cases.c.case_id).exists()
    conditions: list[Any] = [has_alerts]
    if status:
        conditions.append(cases.c.status.in_(status))
    if priority:
        conditions.append(cases.c.priority.in_(priority))
    if assignee:
        conditions.append(cases.c.assignee == assignee)
    if q:
        pattern = f"%{q}%"
        conditions.append(
            or_(cases.c.title_de.ilike(pattern), cases.c.title.ilike(pattern), cases.c.case_id.ilike(pattern))
        )
    if entity:
        conditions.append(
            select(case_entities.c.case_id)
            .where(and_(case_entities.c.case_id == cases.c.case_id, case_entities.c.key.ilike(f"%{entity}%")))
            .exists()
        )
    async with rt.engine.connect() as conn:
        total = (await conn.execute(select(func.count()).select_from(cases).where(and_(*conditions)))).scalar()
        rows = (
            (
                await conn.execute(
                    select(cases)
                    .where(and_(*conditions))
                    .order_by(cases.c.priority, cases.c.score.desc(), cases.c.window_end.desc(), cases.c.case_id)
                    .offset(offset)
                    .limit(limit)
                )
            )
            .mappings()
            .all()
        )
        ids = [r["case_id"] for r in rows]
        ents = (
            await conn.execute(
                select(case_entities)
                .where(case_entities.c.case_id.in_(ids))
                .order_by(case_entities.c.case_id, case_entities.c.type, case_entities.c.key)
            )
        ).mappings()
        counts = await conn.execute(
            select(case_alerts.c.case_id, func.count())
            .where(case_alerts.c.case_id.in_(ids))
            .group_by(case_alerts.c.case_id)
        )
    by_case: dict[str, list[dict[str, str]]] = {}
    for e in ents:
        by_case.setdefault(e["case_id"], []).append({"type": e["type"], "key": e["key"], "display": e["display"]})
    alert_counts = {r[0]: r[1] for r in counts}
    items = []
    for r in rows:
        item = row_dict(r)
        for key in ("recommendations", "injection_findings"):
            item.pop(key, None)
        item["entities"] = by_case.get(r["case_id"], [])
        item["alert_count"] = alert_counts.get(r["case_id"], 0)
        item["prompt_injection"] = bool(r["injection_findings"])
        items.append(item)
    return {"total": total, "offset": offset, "limit": limit, "items": items}


class CaseUpdate(BaseModel):
    status: Status | None = None
    assignee: str | None = Field(default=None, max_length=200)


async def _apply_update(conn: AsyncConnection, case_id: str, body: CaseUpdate, actor: str, now: datetime) -> None:
    case = await _case_or_404(conn, case_id)
    if case["status"] in CLOSED and body.status is None:
        raise HTTPException(409, "case is closed")
    values: dict[str, Any] = {"updated_at": now}
    changes: dict[str, Any] = {}
    if body.status is not None and body.status != case["status"]:
        values["status"] = body.status
        values["closed_at"] = now if body.status in CLOSED else None
        changes["status"] = [case["status"], body.status]
    if body.assignee is not None and body.assignee != case["assignee"]:
        values["assignee"] = body.assignee or None
        changes["assignee"] = [case["assignee"], body.assignee]
    if not changes:
        return
    if case["first_action_at"] is None:
        values["first_action_at"] = now
    await conn.execute(update(cases).where(cases.c.case_id == case_id).values(**values))
    await audit.append(conn, actor, "case.updated", "case", case_id, changes, now)


@router.patch("/cases/bulk")
async def bulk_update(
    rt: RuntimeDep, principal: Annotated[Principal, _p("cases:write")], body: dict[str, Any]
) -> dict[str, Any]:
    ids = body.get("case_ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids) or not 1 <= len(ids) <= 500:
        raise HTTPException(422, "case_ids must be a list of 1-500 case ids")
    update_body = CaseUpdate.model_validate({k: v for k, v in body.items() if k != "case_ids"})
    async with rt.engine.begin() as conn:
        for case_id in sorted(set(ids)):
            await _apply_update(conn, case_id, update_body, principal.username, rt.clock.now())
    return {"updated": len(set(ids))}


@router.get("/cases/{case_id}")
async def get_case(case_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("cases:read")]) -> dict[str, Any]:
    async with rt.engine.connect() as conn:
        try:
            bundle = await load_case(conn, case_id, with_raw=False)
        except NotFoundError as exc:
            raise HTTPException(404, "case not found") from exc
        merges = [
            row_dict(r)
            for r in (
                await conn.execute(
                    select(case_merges)
                    .where(or_(case_merges.c.source_case_id == case_id, case_merges.c.target_case_id == case_id))
                    .order_by(case_merges.c.created_at)
                )
            ).mappings()
        ]
    refs = {
        eid: f"E{i}"
        for i, eid in enumerate(
            sorted(bundle.events_by_id, key=lambda e: (bundle.events_by_id[e].timestamp, e)), start=1
        )
    }
    summary = bundle.latest_summary
    return {
        "case": bundle.case,
        "priority": bundle.priority.to_dict(),
        "evidence_refs": refs,
        "entities": [e.to_dict() for e in bundle.entities],
        "alerts": [
            a.to_dict() | {"false_positive": bundle.alert_rows[a.alert_id]["false_positive"]} for a in bundle.alerts
        ],
        "summary": summary["record"] | {"version": summary["version"]} if summary else None,
        "summary_versions": [
            {
                "version": s["version"],
                "created_at": format_timestamp(s["created_at"]),
                "provider": s["provider"],
                "validation_status": s["validation_status"],
            }
            for s in bundle.summaries
        ],
        "actions": bundle.actions,
        "notes": bundle.notes,
        "merges": merges,
        "event_count": len(bundle.events_by_id),
    }


@router.patch("/cases/{case_id}")
async def update_case(
    case_id: str, body: CaseUpdate, rt: RuntimeDep, principal: Annotated[Principal, _p("cases:write")]
) -> dict[str, str]:
    async with rt.engine.begin() as conn:
        await _apply_update(conn, case_id, body, principal.username, rt.clock.now())
    return {"case_id": case_id}


@router.get("/cases/{case_id}/timeline")
async def case_timeline(
    case_id: str,
    rt: RuntimeDep,
    _: Annotated[Principal, _p("cases:read")],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=10000)] = 5000,
) -> dict[str, Any]:
    async with rt.engine.connect() as conn:
        try:
            bundle = await load_case(conn, case_id, with_raw=False)
        except NotFoundError as exc:
            raise HTTPException(404, "case not found") from exc
    items = timeline_items(bundle)
    return {"total": len(items), "offset": offset, "items": items[offset : offset + limit]}


@router.get("/cases/{case_id}/evidence")
async def case_evidence(case_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("cases:read")]) -> dict[str, Any]:
    async with rt.engine.connect() as conn:
        try:
            bundle = await load_case(conn, case_id)
        except NotFoundError as exc:
            raise HTTPException(404, "case not found") from exc
    return evidence_view(bundle, rt.ruleset)


@router.get("/cases/{case_id}/graph")
async def case_graph(case_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("cases:read")]) -> dict[str, Any]:
    async with rt.engine.connect() as conn:
        try:
            bundle = await load_case(conn, case_id, with_raw=False)
        except NotFoundError as exc:
            raise HTTPException(404, "case not found") from exc
        state = (await conn.execute(select(analysis_state.c.hubs).where(analysis_state.c.id == 1))).scalar()
    return graph_view(bundle, {h["key"] for h in state or []})


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


@router.post("/cases/{case_id}/notes")
async def add_note(
    case_id: str, body: NoteIn, rt: RuntimeDep, principal: Annotated[Principal, _p("cases:write")]
) -> dict[str, Any]:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        await _case_or_404(conn, case_id)
        count = (await conn.execute(select(func.count()).select_from(notes).where(notes.c.case_id == case_id))).scalar()
        note_id = stable_hash("note", case_id, count, principal.subject, format_timestamp(now))
        await conn.execute(
            pg_insert(notes).values(
                note_id=note_id, case_id=case_id, author=principal.username, text=body.text, created_at=now
            )
        )
        await conn.execute(
            update(cases)
            .where(and_(cases.c.case_id == case_id, cases.c.first_action_at.is_(None)))
            .values(first_action_at=now)
        )
        await audit.append(conn, principal.username, "case.note_added", "case", case_id, {"note_id": note_id}, now)
    return {"note_id": note_id}


class MergeIn(BaseModel):
    source_case_id: str


@router.post("/cases/{case_id}/merge")
async def merge_cases(
    case_id: str, body: MergeIn, rt: RuntimeDep, principal: Annotated[Principal, _p("cases:merge")]
) -> dict[str, Any]:
    now = rt.clock.now()
    if body.source_case_id == case_id:
        raise HTTPException(422, "cannot merge a case into itself")
    async with rt.engine.begin() as conn:
        for cid in (case_id, body.source_case_id):
            if (await _case_or_404(conn, cid))["status"] in CLOSED:
                raise HTTPException(409, "closed cases cannot be merged")
        alert_ids = sorted(
            r.alert_id
            for r in await conn.execute(
                select(case_alerts.c.alert_id).where(case_alerts.c.case_id == body.source_case_id)
            )
        )
        merge_id = stable_hash("merge", case_id, body.source_case_id, alert_ids, format_timestamp(now))
        await conn.execute(
            update(case_alerts).where(case_alerts.c.case_id == body.source_case_id).values(case_id=case_id, manual=True)
        )
        await conn.execute(
            pg_insert(case_merges).values(
                merge_id=merge_id,
                kind="merge",
                source_case_id=body.source_case_id,
                target_case_id=case_id,
                alert_ids=alert_ids,
                actor=principal.username,
                created_at=now,
            )
        )
        await audit.append(
            conn,
            principal.username,
            "case.merged",
            "case",
            case_id,
            {"source": body.source_case_id, "alerts": alert_ids, "merge_id": merge_id},
            now,
        )
        await jobs.enqueue(conn, "analyze", {"reason": "merge"}, now)
    return {"merge_id": merge_id, "moved_alerts": len(alert_ids)}


class SplitIn(BaseModel):
    alert_ids: list[str] = Field(min_length=1)


@router.post("/cases/{case_id}/split")
async def split_case(
    case_id: str, body: SplitIn, rt: RuntimeDep, principal: Annotated[Principal, _p("cases:merge")]
) -> dict[str, Any]:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        case = await _case_or_404(conn, case_id)
        if case["status"] in CLOSED:
            raise HTTPException(409, "closed cases cannot be split")
        current = {
            r.alert_id
            for r in await conn.execute(select(case_alerts.c.alert_id).where(case_alerts.c.case_id == case_id))
        }
        moving = sorted(set(body.alert_ids))
        if not set(moving) <= current or set(moving) == current:
            raise HTTPException(422, "alert_ids must be a proper subset of the case's alerts")
        new_id = stable_hash("case-split", case_id, moving)
        values = {
            k: v
            for k, v in case.items()
            if k not in ("case_id", "status", "assignee", "created_at", "updated_at", "closed_at", "first_action_at")
        }
        await conn.execute(
            pg_insert(cases)
            .values(case_id=new_id, status="new", created_at=now, updated_at=now, **values)
            .on_conflict_do_nothing()
        )
        await conn.execute(
            update(case_alerts).where(case_alerts.c.alert_id.in_(moving)).values(case_id=new_id, manual=True)
        )
        merge_id = stable_hash("split", case_id, new_id, moving, format_timestamp(now))
        await conn.execute(
            pg_insert(case_merges).values(
                merge_id=merge_id,
                kind="split",
                source_case_id=case_id,
                target_case_id=new_id,
                alert_ids=moving,
                actor=principal.username,
                created_at=now,
            )
        )
        await audit.append(
            conn,
            principal.username,
            "case.split",
            "case",
            case_id,
            {"new_case": new_id, "alerts": moving, "merge_id": merge_id},
            now,
        )
        await jobs.enqueue(conn, "analyze", {"reason": "split"}, now)
    return {"merge_id": merge_id, "new_case_id": new_id}


@router.post("/case-merges/{merge_id}/revert")
async def revert_merge(
    merge_id: str, rt: RuntimeDep, principal: Annotated[Principal, _p("cases:merge")]
) -> dict[str, Any]:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        row = (await conn.execute(select(case_merges).where(case_merges.c.merge_id == merge_id))).mappings().first()
        if row is None:
            raise HTTPException(404, "merge not found")
        if row["reverted_at"] is not None:
            raise HTTPException(409, "already reverted")
        # merge: source -> target; split: case -> new case. Both revert target -> source.
        back_to, from_case = row["source_case_id"], row["target_case_id"]
        await conn.execute(
            update(case_alerts)
            .where(and_(case_alerts.c.alert_id.in_(row["alert_ids"]), case_alerts.c.case_id == from_case))
            .values(case_id=back_to, manual=True)
        )
        await conn.execute(update(case_merges).where(case_merges.c.merge_id == merge_id).values(reverted_at=now))
        await audit.append(
            conn,
            principal.username,
            f"case.{row['kind']}_reverted",
            "case",
            back_to,
            {"merge_id": merge_id, "alerts": row["alert_ids"]},
            now,
        )
        await jobs.enqueue(conn, "analyze", {"reason": "revert"}, now)
    return {"merge_id": merge_id, "reverted": True}


@router.get("/cases/{case_id}/ai-summaries")
async def list_summaries(
    case_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("cases:read")]
) -> list[dict[str, Any]]:
    async with rt.engine.connect() as conn:
        await _case_or_404(conn, case_id)
        rows = (
            await conn.execute(
                select(ai_summaries).where(ai_summaries.c.case_id == case_id).order_by(ai_summaries.c.version)
            )
        ).mappings()
        return [r["record"] | {"version": r["version"]} for r in rows]


@router.post("/cases/{case_id}/ai-summaries")
async def regenerate_summary(
    case_id: str, rt: RuntimeDep, principal: Annotated[Principal, _p("ai:generate")]
) -> dict[str, Any]:
    """Explicit regeneration (spec 8.5): creates a new version, the old one stays."""
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        try:
            bundle = await load_case(conn, case_id)
        except NotFoundError as exc:
            raise HTTPException(404, "case not found") from exc
        version = (max((s["version"] for s in bundle.summaries), default=0)) + 1
        ctx: AnalysisContext = rt.analysis_context()
        data = await store_summary(
            conn,
            as_case_analysis(bundle),
            bundle.events_by_id,
            bundle.raw_text,
            [],
            ctx,
            now,
            version,
            actor=principal.username,
        )
    return data | {"version": version}


# --- actions -----------------------------------------------------------------------


def _action_from_row(row: dict[str, Any]) -> Action:
    return Action(
        row["action_id"],
        row["case_id"],
        row["step_id"],
        dict(row["parameters"]),
        row["proposed_by"],
        row["proposed_at"],
        row["source"],
        row["reason"],
        ActionStatus(row["status"]),
    )


@router.get("/cases/{case_id}/actions")
async def list_actions(
    case_id: str, rt: RuntimeDep, _: Annotated[Principal, _p("actions:read")]
) -> list[dict[str, Any]]:
    async with rt.engine.connect() as conn:
        try:
            bundle = await load_case(conn, case_id, with_raw=False)
        except NotFoundError as exc:
            raise HTTPException(404, "case not found") from exc
    return bundle.actions


class ProposeIn(BaseModel):
    step_id: str
    parameters: dict[str, str]
    reason: str = Field(min_length=1, max_length=2000)
    source: Literal["analyst", "playbook", "ai"] = "analyst"


@router.post("/cases/{case_id}/actions")
async def propose_action(
    case_id: str, body: ProposeIn, rt: RuntimeDep, principal: Annotated[Principal, _p("actions:propose")]
) -> dict[str, Any]:
    now = rt.clock.now()
    response_steps = frozenset(s.id for s in rt.catalog.values() if s.action)
    try:
        action = propose(
            case_id, body.step_id, body.parameters, principal.username, now, body.source, body.reason, response_steps
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    async with rt.engine.begin() as conn:
        await _case_or_404(conn, case_id)
        await conn.execute(
            pg_insert(actions)
            .values(
                action_id=action.action_id,
                case_id=case_id,
                step_id=action.step_id,
                parameters=action.parameters,
                proposed_by=action.proposed_by,
                proposed_at=now,
                source=action.source,
                reason=action.reason,
                status=action.status.value,
                updated_at=now,
            )
            .on_conflict_do_nothing()
        )
        await conn.execute(
            update(cases)
            .where(and_(cases.c.case_id == case_id, cases.c.first_action_at.is_(None)))
            .values(first_action_at=now)
        )
        await audit.append(
            conn,
            principal.username,
            "action.proposed",
            "action",
            action.action_id,
            {"case_id": case_id, "step_id": action.step_id, "parameters": action.parameters, "source": action.source},
            now,
        )
    return action.to_dict()


class DecisionIn(BaseModel):
    decision: Literal["approved", "rejected"]
    reason: str = Field(min_length=1, max_length=2000)


async def _load_action(conn: AsyncConnection, action_id: str) -> tuple[Action, Approval | None]:
    row = (await conn.execute(select(actions).where(actions.c.action_id == action_id))).mappings().first()
    if row is None:
        raise HTTPException(404, "action not found")
    appr = (await conn.execute(select(approvals).where(approvals.c.action_id == action_id))).mappings().first()
    approval = (
        Approval(
            appr["action_id"],
            appr["parameters_hash"],
            appr["decision"],
            appr["approver"],
            appr["reason"],
            appr["decided_at"],
            appr["signature"],
        )
        if appr
        else None
    )
    return _action_from_row(dict(row)), approval


@router.post("/actions/{action_id}/decision")
async def decide_action(
    action_id: str, body: DecisionIn, rt: RuntimeDep, principal: Annotated[Principal, _p("actions:decide")]
) -> dict[str, Any]:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        action, _ = await _load_action(conn, action_id)
        try:
            new_action, approval = decide(
                action,
                body.decision,
                principal.username,
                principal.roles,
                body.reason,
                now,
                rt.approval_secret,
                rt.settings.four_eyes,
            )
        except ApprovalError as exc:
            raise HTTPException(403, str(exc)) from exc
        await conn.execute(
            pg_insert(approvals).values(
                action_id=action_id,
                parameters_hash=approval.parameters_hash,
                decision=approval.decision,
                approver=approval.approver,
                reason=approval.reason,
                decided_at=now,
                signature=approval.signature,
            )
        )
        await conn.execute(
            update(actions)
            .where(actions.c.action_id == action_id)
            .values(status=new_action.status.value, updated_at=now)
        )
        await audit.append(
            conn,
            principal.username,
            f"action.{body.decision}",
            "action",
            action_id,
            {"reason": body.reason, "case_id": action.case_id},
            now,
        )
    return new_action.to_dict() | {"approval": approval.to_dict()}


@router.post("/actions/{action_id}/execute")
async def execute_action(
    action_id: str, rt: RuntimeDep, principal: Annotated[Principal, _p("actions:execute")]
) -> dict[str, Any]:
    now = rt.clock.now()
    refusal: str | None = None
    async with rt.engine.begin() as conn:
        action, approval = await _load_action(conn, action_id)
        try:
            new_action, result = execute(
                action, approval, SimulationConnector(), rt.approval_secret, rt.settings.four_eyes
            )
        except ApprovalError as exc:
            refusal = str(exc)
        if refusal is None:
            await conn.execute(
                update(actions)
                .where(actions.c.action_id == action_id)
                .values(status=new_action.status.value, execution=result.to_dict(), updated_at=now)
            )
            await audit.append(
                conn,
                principal.username,
                f"action.{new_action.status.value}",
                "action",
                action_id,
                result.to_dict(),
                now,
            )
        else:
            # Refusals are audited too (committed, not rolled back with the request).
            await audit.append(
                conn, principal.username, "action.execution_refused", "action", action_id, {"reason": refusal}, now
            )
    if refusal is not None:
        raise HTTPException(403, refusal)
    return new_action.to_dict() | {"execution": result.to_dict()}


# --- reports -------------------------------------------------------------------------

MEDIA = {"json": "application/json", "md": "text/markdown; charset=utf-8", "pdf": "application/pdf"}


@router.get("/cases/{case_id}/report")
async def case_report(
    case_id: str,
    rt: RuntimeDep,
    principal: Annotated[Principal, _p("reports:export")],
    format: Literal["json", "md", "pdf"] = "json",
    created_at: str | None = None,
    pseudonymize: bool = False,
) -> Response:
    try:
        created = parse_timestamp(created_at) if created_at else rt.clock.now()
    except ValueError as exc:
        raise HTTPException(422, "created_at must be ISO 8601") from exc
    async with rt.engine.begin() as conn:
        try:
            bundle = await load_case(conn, case_id)
        except NotFoundError as exc:
            raise HTTPException(404, "case not found") from exc
        report = build_report(await report_input(conn, bundle, rt.config.config_hash()), created)
        if pseudonymize:
            report = pseudonymize_report(report)
        if format == "json":
            body = render_json(report)
        elif format == "md":
            body = render_markdown(report).encode("utf-8")
        else:
            body = render_pdf(report)
        digest = hashlib.sha256(body).hexdigest()
        now = rt.clock.now()
        await conn.execute(
            pg_insert(reports)
            .values(
                report_id=stable_hash("report", case_id, format, digest, format_timestamp(now)),
                case_id=case_id,
                format=format,
                sha256=digest,
                metadata=report["metadata"],
                created_by=principal.username,
                created_at=now,
            )
            .on_conflict_do_nothing()
        )
        await audit.append(
            conn,
            principal.username,
            "report.exported",
            "case",
            case_id,
            {"format": format, "sha256": digest, "pseudonymized": pseudonymize},
            now,
        )
    filename = f"sentinelops-case-{case_id[:12]}.{format}"
    return Response(
        body,
        media_type=MEDIA[format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "X-Content-SHA256": digest},
    )
