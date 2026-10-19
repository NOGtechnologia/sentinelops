"""Retention per data type (spec 16.2): evidence chain and open cases are protected."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Table, func, insert, select
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinelops.ingest.runs import ingest_path
from sentinelops.parsers.json_mapped import load_profiles
from sentinelops.settings import PROFILES_DIR
from sentinelops.storage import jobs
from sentinelops.storage.db import make_engine
from sentinelops.storage.models import audit_log, cases, events, notes, raw_records
from sentinelops.storage.retention import RetentionPolicy, apply_retention, events_cutoff
from tests.integration.conftest import Database

pytestmark = pytest.mark.integration
INGESTED = datetime(2026, 3, 12, 9, 30, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _case(case_id: str, status: str, start: datetime, closed_at: datetime | None) -> dict[str, object]:
    return {
        "case_id": case_id,
        "title": case_id,
        "title_de": case_id,
        "status": status,
        "priority": "P3",
        "score": 40,
        "window_start": start,
        "window_end": start + timedelta(hours=1),
        "related_case_ids": [],
        "tactics": [],
        "rule_ids": [],
        "recommendations": [],
        "injection_findings": [],
        "created_at": start,
        "updated_at": start,
        "closed_at": closed_at,
    }


async def _count(engine: AsyncEngine, table: Table) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(select(func.count()).select_from(table))).scalar() or 0)


def test_events_cutoff_respects_open_cases() -> None:
    now = datetime(2026, 6, 1, 0, 30, tzinfo=UTC)
    assert events_cutoff(now, 0, None) is None
    assert str(events_cutoff(now, 30, None)) == "2026-05-02"
    old_case = datetime(2026, 4, 1, 23, 0, tzinfo=UTC)
    assert str(events_cutoff(now, 30, old_case)) == "2026-04-01"


async def test_retention_deletes_in_evidence_order(fresh_db: Database) -> None:
    engine = make_engine(fresh_db.url)
    try:
        await ingest_path(
            engine,
            FIXTURES / "syslog_3164" / "auth.log",
            source_type="syslog_3164",
            timezone="Europe/Berlin",
            channel="test",
            actor="t",
            profiles=load_profiles(PROFILES_DIR, INGESTED),
            now=INGESTED,
        )
        async with engine.begin() as conn:
            first_event = (await conn.execute(select(func.min(events.c.ts)))).scalar()
            assert first_event is not None
            old = first_event - timedelta(days=400)
            await conn.execute(
                insert(cases).values(_case("closed-old", "resolved_benign", old, old + timedelta(days=1)))
            )
            await conn.execute(
                insert(notes).values(note_id="n1", case_id="closed-old", author="a", text="x", created_at=old)
            )
            await conn.execute(insert(cases).values(_case("open-recent", "in_progress", first_event, None)))
            await jobs.enqueue(conn, "analyze", {}, INGESTED)
        events_before = await _count(engine, events)
        raw_before = await _count(engine, raw_records)
        assert events_before > 0

        later = INGESTED + timedelta(days=500)
        policy = RetentionPolicy(events_days=90, raw_days=90, closed_cases_days=365, jobs_days=30)

        # The open case pins the cut-off to its first day: nothing of its evidence may go.
        dry = await apply_retention(engine, policy, later, dry_run=True)
        assert dry.events == 0
        assert dry.closed_cases == 1
        assert await _count(engine, cases) == 2

        result = await apply_retention(engine, policy, later, actor="test")
        assert result.events == 0
        assert await _count(engine, events) == events_before
        assert result.closed_cases == 1
        assert await _count(engine, cases) == 1
        assert await _count(engine, notes) == 0
        # raw lines with a surviving event stay; only event-less raw lines (duplicates/malformed) may go
        assert await _count(engine, raw_records) == raw_before - result.raw_records

        # Once the case is closed, the evidence follows the event period.
        async with engine.begin() as conn:
            await conn.execute(
                cases.update()
                .where(cases.c.case_id == "open-recent")
                .values(status="resolved_true_positive", closed_at=INGESTED)
            )
        final = await apply_retention(engine, policy, later, actor="test")
        assert final.events == events_before
        assert await _count(engine, events) == 0
        assert await _count(engine, raw_records) == 0
        async with engine.connect() as conn:
            actions = (await conn.execute(select(audit_log.c.action).order_by(audit_log.c.seq))).scalars().all()
        assert actions.count("retention.applied") == 2  # dry runs are not audited
    finally:
        await engine.dispose()
