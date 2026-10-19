"""Ingestion (upload, bulk API), data quality, audit, administration, aggregate report."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelops.api.deps import RuntimeDep, ingest_principal, require
from sentinelops.auth.principal import Principal, new_ingest_token
from sentinelops.ingest.runs import ingest_stream
from sentinelops.ingest.sources import UnsupportedSourceError, known_source_types, validate_source_type
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.quality import DEFAULT_LIMITS
from sentinelops.normalize.schema import format_timestamp, parse_timestamp
from sentinelops.reports.aggregate import CaseFacts, build_aggregate
from sentinelops.reports.csv_export import to_csv
from sentinelops.services.cases import row_dict
from sentinelops.settings import SOFTWARE_VERSION
from sentinelops.storage import audit, jobs
from sentinelops.storage.audit import verify_chain
from sentinelops.storage.models import (
    audit_log,
    cases,
    ingest_runs,
    ingest_tokens,
    raw_records,
    role_assignments,
    sources,
    users,
)

router = APIRouter(prefix="/api/v1")
MAX_UPLOAD_BYTES = DEFAULT_LIMITS.max_file_bytes
CHUNK = 1 << 20


def _p(permission: str) -> Any:
    return Depends(require(permission))


def _check_source_type(rt: Any, source_type: str) -> None:
    try:
        validate_source_type(source_type, rt.profiles)
    except UnsupportedSourceError as exc:
        raise HTTPException(422, str(exc)) from exc


async def _spool(read: Any, gzip_input: bool) -> tuple[Path, str]:
    """Stream a request body or upload to a temporary file (size limited)."""
    digest = hashlib.sha256()
    size = 0
    handle = tempfile.NamedTemporaryFile(prefix="sentinelops-", suffix=".upload", delete=False)  # noqa: SIM115 - closed below
    path = Path(handle.name)
    try:
        if gzip_input:
            compressed = io.BytesIO()
            async for chunk in read():
                compressed.write(chunk)
                if compressed.tell() > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "upload too large")
            compressed.seek(0)
            try:
                with gzip.GzipFile(fileobj=compressed) as gz:
                    while block := gz.read(CHUNK):
                        size += len(block)
                        if size > MAX_UPLOAD_BYTES:
                            raise HTTPException(413, "decompressed upload too large")
                        digest.update(block)
                        handle.write(block)
            except (OSError, EOFError) as exc:
                raise HTTPException(400, "invalid gzip data") from exc
        else:
            async for chunk in read():
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "upload too large")
                digest.update(chunk)
                handle.write(chunk)
    except BaseException:
        handle.close()
        await asyncio.to_thread(path.unlink, missing_ok=True)
        raise
    handle.close()
    return path, digest.hexdigest()


async def _ingest_file(
    rt: Any, path: Path, digest: str, source_type: str, timezone: str, file_name: str, channel: str, actor: str
) -> dict[str, Any]:
    try:
        stream = await asyncio.to_thread(path.open, "rb")
        with stream:
            result = await ingest_stream(
                rt.engine,
                stream,
                digest,
                source_type=source_type,
                timezone=timezone,
                file_name=file_name,
                channel=channel,
                actor=actor,
                profiles=rt.profiles,
                now=rt.clock.now(),
            )
    finally:
        await asyncio.to_thread(path.unlink, missing_ok=True)
    return result.to_dict()


@router.post("/uploads")
async def upload(
    rt: RuntimeDep,
    principal: Annotated[Principal, _p("ingest:write")],
    file: Annotated[UploadFile, File()],
    source_type: Annotated[str, Form()],
    timezone: Annotated[str, Form()] = "UTC",
) -> dict[str, Any]:
    _check_source_type(rt, source_type)

    async def read() -> Any:
        while chunk := await file.read(CHUNK):
            yield chunk

    path, digest = await _spool(read, gzip_input=(file.filename or "").endswith(".gz"))
    return await _ingest_file(
        rt, path, digest, source_type, timezone, file.filename or "upload", "upload", principal.username
    )


@router.post("/ingest/{source_type}")
async def bulk_ingest(
    source_type: str,
    request: Request,
    rt: RuntimeDep,
    principal: Annotated[Principal, Depends(ingest_principal)],
    timezone: str = "UTC",
) -> dict[str, Any]:
    """Bulk ingest of NDJSON (or any supported text format); ``Content-Encoding: gzip`` is accepted."""
    _check_source_type(rt, source_type)
    path, digest = await _spool(request.stream, gzip_input=request.headers.get("content-encoding") == "gzip")
    return await _ingest_file(rt, path, digest, source_type, timezone, f"api:{source_type}", "api", principal.username)


@router.get("/quality/summary")
async def quality_summary(rt: RuntimeDep, _: Annotated[Principal, _p("quality:read")]) -> dict[str, Any]:
    async with rt.engine.connect() as conn:
        totals = (
            await conn.execute(
                select(
                    func.sum(ingest_runs.c.accepted),
                    func.sum(ingest_runs.c.duplicate),
                    func.sum(ingest_runs.c.malformed),
                    func.count(),
                )
            )
        ).first()
        codes = await conn.execute(
            select(raw_records.c.error_code, func.count())
            .where(raw_records.c.status == "malformed")
            .group_by(raw_records.c.error_code)
            .order_by(raw_records.c.error_code)
        )
        by_source = await conn.execute(
            select(
                ingest_runs.c.source_type,
                func.sum(ingest_runs.c.accepted),
                func.sum(ingest_runs.c.duplicate),
                func.sum(ingest_runs.c.malformed),
            )
            .group_by(ingest_runs.c.source_type)
            .order_by(ingest_runs.c.source_type)
        )
    accepted, duplicate, malformed, runs = (int(v or 0) for v in totals) if totals else (0, 0, 0, 0)
    return {
        "runs": runs,
        "accepted": accepted,
        "duplicate": duplicate,
        "malformed": malformed,
        "error_codes": {r[0]: r[1] for r in codes},
        "by_source": [
            {"source_type": r[0], "accepted": int(r[1] or 0), "duplicate": int(r[2] or 0), "malformed": int(r[3] or 0)}
            for r in by_source
        ],
    }


@router.get("/quality/runs")
async def quality_runs(
    rt: RuntimeDep, _: Annotated[Principal, _p("quality:read")], limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[dict[str, Any]]:
    async with rt.engine.connect() as conn:
        rows = (
            await conn.execute(
                select(ingest_runs).order_by(ingest_runs.c.started_at.desc(), ingest_runs.c.run_id).limit(limit)
            )
        ).mappings()
        return [row_dict(r) for r in rows]


@router.get("/quality/quarantine")
async def quarantine(
    rt: RuntimeDep,
    _: Annotated[Principal, _p("quality:read")],
    run_id: str | None = None,
    code: str | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    cond: list[Any] = [raw_records.c.status == "malformed"]
    if run_id:
        cond.append(raw_records.c.run_id == run_id)
    if code:
        cond.append(raw_records.c.error_code == code)
    async with rt.engine.connect() as conn:
        total = (await conn.execute(select(func.count()).select_from(raw_records).where(and_(*cond)))).scalar()
        rows = (
            await conn.execute(
                select(
                    raw_records.c.raw_record_id,
                    raw_records.c.run_id,
                    raw_records.c.position,
                    raw_records.c.error_code,
                    raw_records.c.error_detail,
                    raw_records.c.error_position,
                    func.left(raw_records.c.content_text, 2000).label("content"),
                    ingest_runs.c.file_name,
                    ingest_runs.c.source_type,
                )
                .join(ingest_runs, ingest_runs.c.run_id == raw_records.c.run_id)
                .where(and_(*cond))
                .order_by(raw_records.c.run_id, raw_records.c.position)
                .offset(offset)
                .limit(limit)
            )
        ).mappings()
        return {"total": total, "items": [dict(r) for r in rows]}


@router.post("/quality/runs/{run_id}/reprocess")
async def reprocess(
    run_id: str, rt: RuntimeDep, principal: Annotated[Principal, _p("quality:reprocess")]
) -> dict[str, Any]:
    """Re-run the malformed records of a run with the current parsers/profiles
    (e.g. after a mapping profile was corrected). The originals stay in place."""
    async with rt.engine.connect() as conn:
        run = (await conn.execute(select(ingest_runs).where(ingest_runs.c.run_id == run_id))).mappings().first()
        if run is None:
            raise HTTPException(404, "run not found")
        rows = (
            await conn.execute(
                select(raw_records.c.content, raw_records.c.content_text)
                .where(and_(raw_records.c.run_id == run_id, raw_records.c.status == "malformed"))
                .order_by(raw_records.c.position)
            )
        ).all()
    if not rows:
        return {"reprocessed": 0}
    payload = b"\n".join((r.content if r.content is not None else r.content_text.encode("utf-8")) for r in rows) + b"\n"
    digest = hashlib.sha256(payload).hexdigest()
    result = await ingest_stream(
        rt.engine,
        io.BytesIO(payload),
        digest,
        source_type=run["source_type"],
        timezone=run["timezone"],
        file_name=f"reprocess:{run['file_name']}",
        channel="reprocess",
        actor=principal.username,
        profiles=rt.profiles,
        now=rt.clock.now(),
    )
    return {"reprocessed": len(rows), "run": result.to_dict()}


@router.get("/audit")
async def audit_entries(
    rt: RuntimeDep,
    _: Annotated[Principal, _p("audit:read")],
    object_id: str | None = None,
    action: str | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    verify: bool = False,
) -> dict[str, Any]:
    cond: list[Any] = []
    if object_id:
        cond.append(audit_log.c.object_id == object_id)
    if action:
        cond.append(audit_log.c.action.like(f"{action}%"))
    async with rt.engine.connect() as conn:
        rows = (
            (
                await conn.execute(
                    select(audit_log)
                    .where(and_(True, *cond))
                    .order_by(audit_log.c.seq.desc())
                    .offset(offset)
                    .limit(limit)
                )
            )
            .mappings()
            .all()
        )
        broken: list[int] | None = None
        if verify:
            chain = (await conn.execute(select(audit_log).order_by(audit_log.c.seq))).mappings().all()
            broken = verify_chain([dict(r) for r in chain])
    return {"items": [row_dict(r) for r in rows], "chain_broken_at": broken}


class TokenIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)


@router.get("/admin/ingest-tokens")
async def list_tokens(rt: RuntimeDep, _: Annotated[Principal, _p("admin:manage")]) -> list[dict[str, Any]]:
    async with rt.engine.connect() as conn:
        rows = (
            await conn.execute(
                select(
                    ingest_tokens.c.token_id,
                    ingest_tokens.c.name,
                    ingest_tokens.c.created_by,
                    ingest_tokens.c.created_at,
                    ingest_tokens.c.revoked_at,
                ).order_by(ingest_tokens.c.created_at)
            )
        ).mappings()
        return [row_dict(r) for r in rows]


@router.post("/admin/ingest-tokens")
async def create_token(
    body: TokenIn, rt: RuntimeDep, principal: Annotated[Principal, _p("admin:manage")]
) -> dict[str, Any]:
    token_id, token, token_hash = new_ingest_token()
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        await conn.execute(
            pg_insert(ingest_tokens).values(
                token_id=token_id, name=body.name, token_hash=token_hash, created_by=principal.username, created_at=now
            )
        )
        await audit.append(
            conn, principal.username, "ingest_token.created", "ingest_token", token_id, {"name": body.name}, now
        )
    return {"token_id": token_id, "token": token, "note": "The token is shown only once."}


@router.delete("/admin/ingest-tokens/{token_id}")
async def revoke_token(token_id: str, rt: RuntimeDep, principal: Annotated[Principal, _p("admin:manage")]) -> Response:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        result = await conn.execute(
            update(ingest_tokens)
            .where(and_(ingest_tokens.c.token_id == token_id, ingest_tokens.c.revoked_at.is_(None)))
            .values(revoked_at=now)
        )
        if result.rowcount == 0:
            raise HTTPException(404, "active token not found")
        await audit.append(conn, principal.username, "ingest_token.revoked", "ingest_token", token_id, {}, now)
    return Response(status_code=204)


@router.get("/admin/users")
async def list_users(rt: RuntimeDep, _: Annotated[Principal, _p("admin:manage")]) -> list[dict[str, Any]]:
    async with rt.engine.connect() as conn:
        rows = (await conn.execute(select(users).order_by(users.c.username))).mappings().all()
        roles = await conn.execute(select(role_assignments))
    by_user: dict[str, list[str]] = {}
    for r in roles:
        by_user.setdefault(r.subject, []).append(r.role)
    return [row_dict(r) | {"roles": sorted(by_user.get(r["subject"], []))} for r in rows]


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    source_type: str = Field(min_length=1, max_length=64)
    timezone: str = Field(default="UTC", max_length=64)


@router.get("/admin/sources")
async def list_sources(rt: RuntimeDep, _: Annotated[Principal, _p("admin:manage")]) -> dict[str, Any]:
    """Configured data sources (presets for uploads, drop folder and API) and all known source types."""
    async with rt.engine.connect() as conn:
        rows = (await conn.execute(select(sources).order_by(sources.c.name))).mappings().all()
    return {"items": [row_dict(r) for r in rows], "source_types": known_source_types(rt.profiles)}


@router.post("/admin/sources", status_code=201)
async def create_source(
    body: SourceIn, rt: RuntimeDep, principal: Annotated[Principal, _p("admin:manage")]
) -> dict[str, Any]:
    _check_source_type(rt, body.source_type)
    try:
        ZoneInfo(body.timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(422, f"unknown timezone {body.timezone!r}") from exc
    now = rt.clock.now()
    source_id = stable_hash("source", body.name, length=16)
    async with rt.engine.begin() as conn:
        result = await conn.execute(
            pg_insert(sources)
            .values(
                source_id=source_id,
                name=body.name,
                source_type=body.source_type,
                timezone=body.timezone,
                created_at=now,
            )
            .on_conflict_do_nothing()
        )
        if result.rowcount == 0:
            raise HTTPException(409, "a source with this name exists")
        await audit.append(conn, principal.username, "source.created", "source", source_id, body.model_dump(), now)
    return {"source_id": source_id, **body.model_dump(), "created_at": format_timestamp(now)}


@router.delete("/admin/sources/{source_id}", status_code=204)
async def delete_source(
    source_id: str, rt: RuntimeDep, principal: Annotated[Principal, _p("admin:manage")]
) -> Response:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        result = await conn.execute(sources.delete().where(sources.c.source_id == source_id))
        if result.rowcount == 0:
            raise HTTPException(404, "source not found")
        await audit.append(conn, principal.username, "source.deleted", "source", source_id, {}, now)
    return Response(status_code=204)


@router.get("/admin/settings")
async def effective_settings(rt: RuntimeDep, _: Annotated[Principal, _p("admin:manage")]) -> dict[str, Any]:
    """Effective configuration without secrets. Changes are made through environment variables (operations.md)."""
    s = rt.settings
    return {
        "software_version": SOFTWARE_VERSION,
        "demo_mode": s.demo_mode,
        "display_timezone": s.display_timezone,
        "auth": {"oidc_issuer": s.oidc_issuer, "oidc_audience": s.oidc_audience, "roles_claim": s.oidc_roles_claim},
        "four_eyes": s.four_eyes,
        "ai": {
            "provider": s.llm_provider,
            "model": s.llm_model,
            "base_url": s.llm_base_url,
            "cloud_opt_in": s.llm_cloud_opt_in,
            "pseudonymize": s.llm_pseudonymize,
            "api_key_configured": bool(s.llm_api_key),
        },
        "ingest": {
            "drop_folder": s.drop_folder,
            "drop_folder_timezone": s.drop_folder_timezone,
            "syslog_port": s.syslog_port,
            "syslog_timezone": s.syslog_timezone,
            "max_upload_bytes": MAX_UPLOAD_BYTES,
        },
        "retention_days": {
            "events": s.retention_events_days,
            "raw_records": s.retention_raw_days,
            "closed_cases": s.retention_closed_cases_days,
            "jobs": s.retention_jobs_days,
        },
        "detection": {"config_hash": rt.config.config_hash(), "config": rt.config.model_dump(mode="json")},
    }


@router.post("/admin/analysis")
async def trigger_analysis(rt: RuntimeDep, principal: Annotated[Principal, _p("analysis:run")]) -> dict[str, Any]:
    now = rt.clock.now()
    async with rt.engine.begin() as conn:
        job_id = await jobs.enqueue(conn, "analyze", {"reason": "manual", "by": principal.username}, now)
        await audit.append(conn, principal.username, "analysis.requested", "analysis", str(job_id), {}, now)
    return {"job_id": job_id}


@router.get("/reports/aggregate")
async def aggregate_report(
    rt: RuntimeDep,
    principal: Annotated[Principal, _p("reports:export")],
    start: str | None = None,
    end: str | None = None,
    format: Literal["json", "csv"] = "json",
) -> Response:
    now = rt.clock.now()
    try:
        end_t = parse_timestamp(end) if end else now
        start_t = parse_timestamp(start) if start else end_t - timedelta(days=7)
    except ValueError as exc:
        raise HTTPException(422, "start/end must be ISO 8601") from exc
    async with rt.engine.begin() as conn:
        rows = (await conn.execute(select(cases))).mappings().all()
        await audit.append(
            conn,
            principal.username,
            "report.aggregate_exported",
            "report",
            "aggregate",
            {"start": format_timestamp(start_t), "end": format_timestamp(end_t)},
            now,
        )
    facts = [
        CaseFacts(
            r["case_id"],
            r["priority"],
            r["status"],
            tuple(r["rule_ids"] or ()),
            r["created_at"],
            r["first_action_at"],
            r["closed_at"],
        )
        for r in rows
    ]
    report = build_aggregate(facts, start_t, end_t, now)
    if format == "csv":
        body = to_csv(["rule_id", "cases"], report["top_rules"])
        return Response(body, media_type="text/csv; charset=utf-8")
    return Response(json.dumps(report, sort_keys=True, indent=2), media_type="application/json")
