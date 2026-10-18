"""Database backed ingestion runs (spec 5).

Streams a file through :func:`process_stream`, writes raw records and events
in batches and guarantees idempotency:

* a file whose SHA-256 was already imported completely is skipped,
* events are inserted with ``ON CONFLICT DO NOTHING``; an event id that
  already exists turns the raw record into a ``duplicate`` that references
  the original raw record - duplicates never reach the detection.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, BinaryIO
from zoneinfo import ZoneInfo

from sqlalchemy import and_, func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from sentinelops.ingest.local import file_sha256
from sentinelops.ingest.processing import RecordOutcome, process_stream
from sentinelops.normalize.dedupe import Deduplicator, stable_hash
from sentinelops.normalize.identities import host_key, user_key
from sentinelops.normalize.schema import CanonicalEvent, RecordStatus
from sentinelops.parsers.base import ParseContext
from sentinelops.parsers.json_mapped import MappingProfile
from sentinelops.parsers.registry import get_parser
from sentinelops.storage import audit, jobs
from sentinelops.storage.models import events, ingest_runs, raw_records

BATCH = 5000


@dataclass(frozen=True)
class RunResult:
    run_id: str
    status: str
    accepted: int
    duplicate: int
    malformed: int
    file_sha256: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def event_row(event: CanonicalEvent) -> dict[str, Any]:
    f = event.fields
    return {
        "event_id": event.event_id,
        "ts": event.timestamp,
        "day": event.timestamp.date(),
        "ingested_at": f["event.ingested"],
        "source_type": f.get("log.source_type", ""),
        "action": f.get("event.action"),
        "outcome": f.get("event.outcome"),
        "code": f.get("event.code"),
        "user_name": f.get("user.name"),
        "user_key": user_key(f.get("user.name")),
        "target_user": f.get("user.target.name"),
        "host_name": f.get("host.name"),
        "host_key": host_key(f.get("host.name")),
        "source_ip": f.get("source.ip"),
        "raw_record_id": f["log.raw_record_id"],
        "assessment": "normal",
        "time_quality": f.get("event.time_quality"),
        "data": event.to_dict(),
    }


def raw_row(outcome: RecordOutcome, run_id: str, now: datetime) -> dict[str, Any]:
    """Raw records are stored unchanged: valid UTF-8 as text (lossless), anything
    else additionally as the original bytes."""
    error = outcome.error
    try:
        text_value = outcome.raw.content.decode("utf-8")
        lossless = "\x00" not in text_value
    except UnicodeDecodeError:
        text_value, lossless = outcome.raw.text(), False
    return {
        "raw_record_id": outcome.raw_record_id,
        "run_id": run_id,
        "position": outcome.raw.position,
        "byte_offset": outcome.raw.offset,
        "content": None if lossless else outcome.raw.content,
        "content_text": text_value.replace("\x00", "\\x00"),
        "status": outcome.status.value,
        "error_code": error.code.value if error else None,
        "error_detail": error.detail if error else None,
        "error_position": error.position if error else None,
        "event_id": outcome.event_id,
        "duplicate_of": outcome.duplicate_of,
        "created_at": now,
    }


EVENT_COLUMNS = tuple(c.name for c in events.columns)
RAW_COLUMNS = tuple(c.name for c in raw_records.columns)


@dataclass(frozen=True)
class Prepared:
    outcome: RecordOutcome
    event_record: tuple[Any, ...] | None
    raw: dict[str, Any]


class _Writer:
    """Batch writer using PostgreSQL ``COPY`` into temporary tables followed by
    ``INSERT ... SELECT ... ON CONFLICT DO NOTHING`` (fast and still idempotent)."""

    def __init__(self, conn: AsyncConnection, run_id: str, now: datetime) -> None:
        self.conn = conn
        self.run_id = run_id
        self.now = now
        self.pending: list[Prepared] = []
        self.days: set[date] = set()
        self.counts = {s.value: 0 for s in RecordStatus}
        self.prepared = False

    def prepare(self, outcomes: list[RecordOutcome]) -> list[Prepared]:
        """CPU work (row building, JSON) - called in the parser thread."""
        out: list[Prepared] = []
        for outcome in outcomes:
            record = None
            if outcome.event is not None:
                row = event_row(outcome.event)
                row["data"] = json.dumps(row["data"], ensure_ascii=False)
                record = tuple(row[c] for c in EVENT_COLUMNS)
            out.append(Prepared(outcome, record, raw_row(outcome, self.run_id, self.now)))
        return out

    async def _driver(self) -> Any:
        # Make sure SQLAlchemy has opened the transaction before the raw
        # connection is used - otherwise statements run in autocommit mode and
        # the ON COMMIT DROP temp tables vanish immediately.
        await self.conn.execute(text("SELECT 1"))
        raw = await self.conn.get_raw_connection()
        driver = raw.driver_connection
        if driver is None:  # pragma: no cover - asyncpg always provides one
            raise RuntimeError("no asyncpg connection")
        if not self.prepared:
            await driver.execute(
                "CREATE TEMP TABLE IF NOT EXISTS tmp_events (LIKE events INCLUDING DEFAULTS) ON COMMIT DROP;"
                "CREATE TEMP TABLE IF NOT EXISTS tmp_raw (LIKE raw_records INCLUDING DEFAULTS) ON COMMIT DROP;"
            )
            self.prepared = True
        return driver

    async def _insert_events(self, records: list[tuple[Any, ...]]) -> set[str]:
        driver = await self._driver()
        await driver.execute("TRUNCATE tmp_events")
        await driver.copy_records_to_table("tmp_events", records=records, columns=EVENT_COLUMNS)
        result = await driver.fetch(
            "INSERT INTO events SELECT * FROM tmp_events ON CONFLICT (event_id, ts) DO NOTHING RETURNING event_id"
        )
        return {r["event_id"] for r in result}

    async def _insert_raw(self, rows: list[dict[str, Any]]) -> None:
        driver = await self._driver()
        await driver.execute("TRUNCATE tmp_raw")
        await driver.copy_records_to_table(
            "tmp_raw", records=[tuple(r[c] for c in RAW_COLUMNS) for r in rows], columns=RAW_COLUMNS
        )
        await driver.execute("INSERT INTO raw_records SELECT * FROM tmp_raw ON CONFLICT (raw_record_id) DO NOTHING")

    async def flush(self) -> None:
        if not self.pending:
            return
        batch, self.pending = self.pending, []
        accepted = [p for p in batch if p.event_record is not None]
        new_days = {p.outcome.event.timestamp.date() for p in accepted if p.outcome.event is not None} - self.days
        for day in sorted(new_days):
            await self.conn.execute(text("SELECT ensure_event_partition(:d)"), {"d": day})
        self.days |= new_days
        inserted: set[str] = set()
        if accepted:
            inserted = await self._insert_events([p.event_record for p in accepted if p.event_record is not None])
        existing_ids = [p.outcome.event_id for p in accepted if p.outcome.event_id not in inserted]
        originals: dict[str, str] = {}
        if existing_ids:
            rows = await self.conn.execute(
                select(events.c.event_id, events.c.raw_record_id).where(events.c.event_id.in_(existing_ids))
            )
            originals = {r.event_id: r.raw_record_id for r in rows}
        raw_rows: list[dict[str, Any]] = []
        for item in batch:
            row = item.raw
            if item.event_record is not None and item.outcome.event_id not in inserted:
                # Already stored by an earlier run: a duplicate of that record.
                row = {
                    **row,
                    "status": RecordStatus.DUPLICATE.value,
                    "duplicate_of": originals.get(str(item.outcome.event_id)),
                }
            self.counts[row["status"]] += 1
            raw_rows.append(row)
        await self._insert_raw(raw_rows)


async def ingest_stream(
    engine: AsyncEngine,
    stream: BinaryIO,
    file_sha: str,
    *,
    source_type: str,
    timezone: str,
    file_name: str,
    channel: str,
    actor: str,
    profiles: Mapping[str, MappingProfile],
    now: datetime,
    reference_utc: datetime | None = None,
) -> RunResult:
    started = time.perf_counter()
    parser = get_parser(source_type, profiles)
    async with engine.begin() as conn:
        # Deterministic and unique: the run number makes repeated imports distinct.
        number = (await conn.execute(select(func.count()).select_from(ingest_runs))).scalar() or 0
        run_id = stable_hash("run", file_sha, source_type, file_name, now.isoformat(), number + 1)
        done = (
            await conn.execute(
                select(ingest_runs.c.run_id)
                .where(and_(ingest_runs.c.file_sha256 == file_sha, ingest_runs.c.status == "completed"))
                .limit(1)
            )
        ).scalar()
        status = "skipped_duplicate_file" if done else "running"
        await conn.execute(
            insert(ingest_runs).values(
                run_id=run_id,
                source_type=source_type,
                timezone=timezone,
                file_name=file_name[:500],
                file_sha256=file_sha,
                channel=channel,
                status=status,
                started_at=now,
                created_by=actor,
            )
        )
        if done:
            await audit.append(
                conn,
                actor,
                "ingest.skipped_duplicate_file",
                "ingest_run",
                run_id,
                {"file": file_name, "sha256": file_sha, "original_run": done},
                now,
            )
            return RunResult(run_id, status, 0, 0, 0, file_sha, 0)
    try:
        async with engine.begin() as conn:
            writer = _Writer(conn, run_id, now)
            ctx = ParseContext(reference_utc=reference_utc or now, timezone=ZoneInfo(timezone))
            outcomes = process_stream(parser, stream, ctx, Deduplicator(), file_sha, now)

            def next_batch() -> list[Prepared]:
                return writer.prepare(list(itertools.islice(outcomes, BATCH)))

            # Parsing is CPU bound and runs in a thread; the next batch is parsed
            # while the current one is written (pipelining).
            pending = asyncio.ensure_future(asyncio.to_thread(next_batch))
            while True:
                batch = await pending
                if not batch:
                    break
                pending = asyncio.ensure_future(asyncio.to_thread(next_batch))
                writer.pending.extend(batch)
                await writer.flush()
            await writer.flush()
            duration = int((time.perf_counter() - started) * 1000)
            await conn.execute(
                update(ingest_runs)
                .where(ingest_runs.c.run_id == run_id)
                .values(
                    status="completed",
                    accepted=writer.counts["accepted"],
                    duplicate=writer.counts["duplicate"],
                    malformed=writer.counts["malformed"],
                    finished_at=now,
                    duration_ms=duration,
                )
            )
            await audit.append(
                conn,
                actor,
                "ingest.completed",
                "ingest_run",
                run_id,
                {"file": file_name, "source_type": source_type, **writer.counts},
                now,
            )
            if writer.counts["accepted"]:
                await jobs.enqueue(conn, "analyze", {"reason": "ingest", "run_id": run_id}, now)
            return RunResult(
                run_id,
                "completed",
                writer.counts["accepted"],
                writer.counts["duplicate"],
                writer.counts["malformed"],
                file_sha,
                duration,
            )
    except Exception as exc:
        async with engine.begin() as conn:
            await conn.execute(
                update(ingest_runs)
                .where(ingest_runs.c.run_id == run_id)
                .values(status="failed", finished_at=now, error=f"{type(exc).__name__}: {exc}"[:2000])
            )
        raise


async def ingest_path(engine: AsyncEngine, path: Path, **kwargs: Any) -> RunResult:
    digest = file_sha256(path)
    with path.open("rb") as stream:
        return await ingest_stream(engine, stream, digest, file_name=kwargs.pop("file_name", path.name), **kwargs)
