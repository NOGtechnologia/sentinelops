"""PostgreSQL-backed job queue (ADR-0004): ``SELECT ... FOR UPDATE SKIP LOCKED``.

No additional broker. Jobs are idempotent (analysis recomputes deterministic
results), so at-least-once delivery is sufficient.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from sentinelops.storage.models import jobs

MAX_ATTEMPTS = 3


async def enqueue(
    conn: AsyncConnection, kind: str, payload: dict[str, Any], now: datetime, dedupe: bool = True
) -> int | None:
    """Queue a job; with ``dedupe`` a queued job of the same kind is reused."""
    if dedupe:
        existing = (
            await conn.execute(
                select(jobs.c.job_id).where(and_(jobs.c.kind == kind, jobs.c.status == "queued")).limit(1)
            )
        ).scalar()
        if existing is not None:
            return int(existing)
    result = await conn.execute(
        insert(jobs)
        .values(kind=kind, payload=payload, status="queued", run_after=now, created_at=now)
        .returning(jobs.c.job_id)
    )
    value = result.scalar()
    return int(value) if value is not None else None


async def claim(conn: AsyncConnection, worker: str, now: datetime) -> dict[str, Any] | None:
    row = (
        (
            await conn.execute(
                select(jobs)
                .where(and_(jobs.c.status == "queued", jobs.c.run_after <= now))
                .order_by(jobs.c.job_id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        return None
    await conn.execute(
        update(jobs)
        .where(jobs.c.job_id == row["job_id"])
        .values(status="running", locked_by=worker, locked_at=now, attempts=row["attempts"] + 1)
    )
    return dict(row)


async def finish(
    conn: AsyncConnection, job_id: int, now: datetime, error: str | None = None, attempts: int = 1
) -> None:
    if error is None:
        values: dict[str, Any] = {"status": "done", "finished_at": now, "error": None}
    elif attempts < MAX_ATTEMPTS:
        values = {"status": "queued", "run_after": now + timedelta(seconds=30 * attempts), "error": error}
    else:
        values = {"status": "failed", "finished_at": now, "error": error}
    await conn.execute(update(jobs).where(jobs.c.job_id == job_id).values(**values))
