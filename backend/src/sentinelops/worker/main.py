"""Worker loop: claims jobs from the PostgreSQL queue and runs them."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from sentinelops.detection.exceptions import RuleException
from sentinelops.ingest.runs import ingest_path
from sentinelops.runtime import Runtime
from sentinelops.storage import jobs
from sentinelops.storage.models import rule_exceptions
from sentinelops.storage.retention import RetentionPolicy, apply_retention
from sentinelops.worker.analysis import run_analysis

log = logging.getLogger("sentinelops.worker")


async def effective_exceptions(rt: Runtime) -> list[RuleException]:
    """File-based exceptions plus approved exceptions from the database."""
    items = list(rt.file_exceptions)
    known = {e.id for e in items}
    async with rt.engine.connect() as conn:
        rows = await conn.execute(select(rule_exceptions).where(rule_exceptions.c.status == "active"))
        for row in rows.mappings():
            if row["exception_id"] in known:
                continue
            items.append(
                RuleException(
                    id=row["exception_id"],
                    version=row["version"],
                    rule_id=row["rule_id"],
                    description=row["description"],
                    match=row["match"],
                    created_by=row["created_by"],
                    approved_by=row["approved_by"],
                    expires=row["expires"],
                )
            )
    return sorted(items, key=lambda e: e.id)


async def run_job(rt: Runtime, job: dict[str, Any]) -> None:
    kind = job["kind"]
    payload = job["payload"]
    if kind == "analyze":
        await run_analysis(rt.engine, rt.analysis_context(await effective_exceptions(rt)), rt.clock.now())
    elif kind == "ingest_file":
        path = Path(payload["path"])
        try:
            await ingest_path(
                rt.engine,
                path,
                source_type=payload["source_type"],
                timezone=payload["timezone"],
                file_name=payload["file_name"],
                channel=payload["channel"],
                actor=payload["actor"],
                profiles=rt.profiles,
                now=rt.clock.now(),
            )
        finally:
            if payload.get("delete_after"):
                await asyncio.to_thread(path.unlink, missing_ok=True)
    elif kind == "retention":
        await apply_retention(rt.engine, RetentionPolicy.from_settings(rt.settings), rt.clock.now(), "worker")
    else:
        raise ValueError(f"unknown job kind {kind}")


async def work_once(rt: Runtime, worker_id: str) -> bool:
    async with rt.engine.begin() as conn:
        job = await jobs.claim(conn, worker_id, rt.clock.now())
    if job is None:
        return False
    error: str | None = None
    try:
        await run_job(rt, job)
    except Exception as exc:  # the job is retried or marked failed, the worker keeps running
        log.exception("job %s failed", job["job_id"])
        error = f"{type(exc).__name__}: {exc}"
    async with rt.engine.begin() as conn:
        await jobs.finish(conn, job["job_id"], rt.clock.now(), error, job["attempts"] + 1)
    return True


RETENTION_INTERVAL = timedelta(days=1)


async def schedule_retention(rt: Runtime, last: datetime | None) -> datetime | None:
    """Queue the retention job once per interval (deduplicated across workers)."""
    now = rt.clock.now()
    if last is not None and now - last < RETENTION_INTERVAL:
        return last
    async with rt.engine.begin() as conn:
        await jobs.enqueue(conn, "retention", {}, now)
    return now


async def run_forever(rt: Runtime, poll_seconds: float = 2.0, stop: asyncio.Event | None = None) -> None:
    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    last_retention: datetime | None = None
    while stop is None or not stop.is_set():
        last_retention = await schedule_retention(rt, last_retention)
        if not await work_once(rt, worker_id):
            await asyncio.sleep(poll_seconds)
