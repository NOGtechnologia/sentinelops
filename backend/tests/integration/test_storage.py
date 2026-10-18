"""Migrations, partitions, audit log immutability, queue, idempotent ingestion."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from sentinelops.ingest.runs import ingest_path
from sentinelops.parsers.json_mapped import load_profiles
from sentinelops.settings import PROFILES_DIR
from sentinelops.storage import audit, jobs
from sentinelops.storage.db import make_engine
from sentinelops.storage.models import audit_log, events, ingest_runs, raw_records
from tests.integration.conftest import Database, migrate

pytestmark = pytest.mark.integration
NOW = datetime(2026, 3, 12, 9, 30, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


async def _tables(url: str) -> set[str]:
    engine = make_engine(url)
    async with engine.connect() as conn:
        rows = await conn.execute(text("select tablename from pg_tables where schemaname = 'public'"))
        names = {r[0] for r in rows}
    await engine.dispose()
    return names


def test_migrations_up_down_up(empty_db: Database) -> None:
    migrate(empty_db.url)
    assert {"events", "cases", "audit_log", "raw_records", "jobs"} <= asyncio.run(_tables(empty_db.url))
    migrate(empty_db.url, down=True)
    assert asyncio.run(_tables(empty_db.url)) == {"alembic_version"}
    migrate(empty_db.url)
    assert "events_default" in asyncio.run(_tables(empty_db.url))


async def test_audit_log_is_append_only_and_chained(fresh_db: Database) -> None:
    engine = make_engine(fresh_db.url)
    try:
        async with engine.begin() as conn:
            first = await audit.append(conn, "a", "x.one", "case", "c1", {"k": 1}, NOW)
            second = await audit.append(conn, "b", "x.two", "case", "c1", {"k": 2}, NOW + timedelta(seconds=1))
        assert first != second
        for statement in ("UPDATE audit_log SET actor = 'evil'", "DELETE FROM audit_log", "TRUNCATE audit_log"):
            with pytest.raises(DBAPIError, match="append-only"):
                async with engine.begin() as conn:
                    await conn.execute(text(statement))
        async with engine.connect() as conn:
            rows = [dict(r) for r in (await conn.execute(select(audit_log).order_by(audit_log.c.seq))).mappings()]
        assert audit.verify_chain(rows) == []
        rows[0]["details"] = {"k": 99}
        assert audit.verify_chain(rows) == [rows[0]["seq"]]
    finally:
        await engine.dispose()


async def test_partitions_and_retention(fresh_db: Database) -> None:
    engine = make_engine(fresh_db.url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("select ensure_event_partition('2026-03-01'::date)"))
            await conn.execute(text("select ensure_event_partition('2026-03-01'::date)"))  # idempotent
            await conn.execute(text("select ensure_event_partition('2026-03-05'::date)"))
            dropped = (await conn.execute(text("select drop_event_partitions_before('2026-03-03'::date)"))).scalar()
            names = {
                r[0]
                for r in await conn.execute(text("select tablename from pg_tables where tablename like 'events_2%'"))
            }
        assert dropped == 1
        assert names == {"events_20260305"}
    finally:
        await engine.dispose()


async def test_job_queue_claim_retry_and_dedupe(fresh_db: Database) -> None:
    engine = make_engine(fresh_db.url)
    try:
        async with engine.begin() as conn:
            a = await jobs.enqueue(conn, "analyze", {}, NOW)
            b = await jobs.enqueue(conn, "analyze", {}, NOW)
            c = await jobs.enqueue(conn, "ingest_file", {"x": 1}, NOW, dedupe=False)
        assert a == b
        async with engine.begin() as conn:
            job = await jobs.claim(conn, "w1", NOW)
            assert job is not None
            assert job["job_id"] == a
            await jobs.finish(conn, a, NOW, "boom", attempts=1)
        async with engine.begin() as conn:
            nxt = await jobs.claim(conn, "w1", NOW)
            assert nxt is not None
            assert nxt["job_id"] == c  # failed job waits for its retry delay
            await jobs.finish(conn, c, NOW)
            assert await jobs.claim(conn, "w1", NOW) is None
            retried = await jobs.claim(conn, "w1", NOW + timedelta(minutes=5))
            assert retried is not None
            await jobs.finish(conn, a, NOW, "boom", attempts=3)
            status = (await conn.execute(text("select status from jobs where job_id = :id"), {"id": a})).scalar()
        assert status == "failed"
    finally:
        await engine.dispose()


async def test_ingest_is_idempotent(fresh_db: Database, tmp_path: Path) -> None:
    engine = make_engine(fresh_db.url)
    profiles = load_profiles(PROFILES_DIR, NOW)
    log = FIXTURES / "syslog_3164" / "auth.log"
    try:
        first = await ingest_path(
            engine,
            log,
            source_type="syslog_3164",
            timezone="Europe/Berlin",
            channel="test",
            actor="t",
            profiles=profiles,
            now=NOW,
        )
        again = await ingest_path(
            engine,
            log,
            source_type="syslog_3164",
            timezone="Europe/Berlin",
            channel="test",
            actor="t",
            profiles=profiles,
            now=NOW,
        )
        copy = tmp_path / "auth-copy.log"
        copy.write_bytes(log.read_bytes() + b"\n")  # different file hash, same records
        third = await ingest_path(
            engine,
            copy,
            source_type="syslog_3164",
            timezone="Europe/Berlin",
            channel="test",
            actor="t",
            profiles=profiles,
            now=NOW,
        )
        async with engine.connect() as conn:
            event_count = (await conn.execute(select(func.count()).select_from(events))).scalar()
            dupes = (
                await conn.execute(
                    select(func.count()).select_from(raw_records).where(raw_records.c.status == "duplicate")
                )
            ).scalar()
            runs = (await conn.execute(select(ingest_runs.c.status).order_by(ingest_runs.c.started_at))).scalars().all()
            originals = (
                await conn.execute(
                    select(func.count()).select_from(raw_records).where(raw_records.c.duplicate_of.isnot(None))
                )
            ).scalar()
        assert (first.accepted, first.malformed) == (13, 2)
        assert again.status == "skipped_duplicate_file"
        assert (third.accepted, third.duplicate, third.malformed) == (0, 13, 2)
        assert event_count == 13
        assert dupes == 13
        assert originals == 13
        assert sorted(runs) == ["completed", "completed", "skipped_duplicate_file"]
    finally:
        await engine.dispose()
