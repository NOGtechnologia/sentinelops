"""Worker loop: claims jobs from the PostgreSQL queue and runs them."""

from __future__ import annotations

import asyncio
import io
import logging
import os
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from sentinelops.detection.exceptions import RuleException
from sentinelops.ingest.drop_folder import DropFolderScanner
from sentinelops.ingest.runs import ingest_path, ingest_stream
from sentinelops.ingest.syslog_receiver import Sink, SyslogCollector, serve
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
        # Only after success: a failed import keeps the file for the retry.
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


def syslog_sink(rt: Runtime) -> Sink:
    async def sink(source_type: str, data: bytes, sha256: str) -> None:
        await ingest_stream(
            rt.engine,
            io.BytesIO(data),
            sha256,
            source_type=source_type,
            timezone=rt.settings.syslog_timezone,
            file_name=f"syslog/{source_type}",
            channel="syslog",
            actor="syslog",
            profiles=rt.profiles,
            now=rt.clock.now(),
        )

    return sink


async def run_forever(rt: Runtime, poll_seconds: float = 2.0, stop: asyncio.Event | None = None) -> None:
    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    stop = stop or asyncio.Event()
    last_retention: datetime | None = None
    scanner = (
        DropFolderScanner(Path(rt.settings.drop_folder), rt.settings.drop_folder_timezone)
        if rt.settings.drop_folder
        else None
    )
    receiver: asyncio.Task[None] | None = None
    if rt.settings.syslog_port:
        collector = SyslogCollector(syslog_sink(rt))
        receiver = asyncio.create_task(serve(collector, rt.settings.syslog_host, rt.settings.syslog_port, stop))
    try:
        while not stop.is_set():
            last_retention = await schedule_retention(rt, last_retention)
            if scanner is not None:
                await scanner.scan(rt.engine, rt.profiles, rt.clock.now())
            if not await work_once(rt, worker_id):
                await asyncio.sleep(poll_seconds)
    finally:
        stop.set()
        if receiver is not None:
            await receiver
