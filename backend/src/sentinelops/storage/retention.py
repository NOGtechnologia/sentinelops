"""Retention per data type (spec 16.2).

Rules that keep the evidence chain intact:

* **Events** are dropped by whole UTC-day partitions. The cut-off never passes
  the earliest event of a case that is not closed - open investigations keep
  their evidence.
* **Raw records** are deleted only when they are older than their own period
  *and* their normalised event is gone (or there never was one: duplicates,
  malformed lines). Raw lines therefore never disappear before their event.
* **Closed cases** (with alerts, notes, summaries, actions, approvals, reports)
  are deleted after their period, but only once their events are gone too -
  otherwise a re-analysis would recreate them.
* **Finished jobs** are deleted after their period.
* The **audit log** is never deleted by the application (append-only trigger,
  hash chain). Archiving is an operator task (``docs/operations.md``).

Every run writes an audit entry with the counts; ``dry_run`` only counts (its
raw-record count does not include raw lines whose events would be dropped in
the same run - they follow in the real run).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from sentinelops.settings import Settings
from sentinelops.storage import audit

# Constant SQL only; all values are bound parameters.
_OPEN_CASES_START = "SELECT min(window_start) FROM cases WHERE status <> 'closed'"
_COUNT_EVENTS = "SELECT count(*) FROM events WHERE ts < :cutoff"
_DROP_PARTITIONS = "SELECT drop_event_partitions_before(:cutoff)"
_DELETE_DEFAULT_PARTITION = "DELETE FROM events_default WHERE ts < :cutoff"
_COUNT_RAW = (
    "SELECT count(*) FROM raw_records r WHERE r.created_at < :cutoff AND "
    "(r.event_id IS NULL OR NOT EXISTS (SELECT 1 FROM events e WHERE e.event_id = r.event_id))"
)
_DELETE_RAW = (
    "DELETE FROM raw_records r WHERE r.created_at < :cutoff AND "
    "(r.event_id IS NULL OR NOT EXISTS (SELECT 1 FROM events e WHERE e.event_id = r.event_id))"
)
_SELECT_CASES = (
    "SELECT case_id FROM cases WHERE status = 'closed' AND closed_at < :closed_cutoff "
    "AND window_end < :events_cutoff ORDER BY case_id"
)
#: Dependent rows first; alerts last (cascades to alert_events and case_alerts).
_DELETE_CASE_ROWS = (
    "DELETE FROM approvals WHERE action_id IN (SELECT action_id FROM actions WHERE case_id = ANY(:ids))",
    "DELETE FROM actions WHERE case_id = ANY(:ids)",
    "DELETE FROM notes WHERE case_id = ANY(:ids)",
    "DELETE FROM ai_summaries WHERE case_id = ANY(:ids)",
    "DELETE FROM priority_explanations WHERE case_id = ANY(:ids)",
    "DELETE FROM case_entities WHERE case_id = ANY(:ids)",
    "DELETE FROM reports WHERE case_id = ANY(:ids)",
    "DELETE FROM case_merges WHERE source_case_id = ANY(:ids) OR target_case_id = ANY(:ids)",
    "DELETE FROM alerts WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = ANY(:ids))",
    "DELETE FROM case_alerts WHERE case_id = ANY(:ids)",
    "DELETE FROM cases WHERE case_id = ANY(:ids)",
)
_COUNT_JOBS = "SELECT count(*) FROM jobs WHERE finished_at IS NOT NULL AND finished_at < :cutoff"
_DELETE_JOBS = "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < :cutoff"


@dataclass(frozen=True)
class RetentionPolicy:
    events_days: int = 90
    raw_days: int = 90
    closed_cases_days: int = 365
    jobs_days: int = 30

    @classmethod
    def from_settings(cls, settings: Settings) -> RetentionPolicy:
        return cls(
            events_days=settings.retention_events_days,
            raw_days=settings.retention_raw_days,
            closed_cases_days=settings.retention_closed_cases_days,
            jobs_days=settings.retention_jobs_days,
        )


@dataclass
class RetentionResult:
    dry_run: bool
    events_cutoff: str | None = None
    events: int = 0
    raw_records: int = 0
    closed_cases: int = 0
    jobs: int = 0
    case_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "events_cutoff": self.events_cutoff,
            "events": self.events,
            "raw_records": self.raw_records,
            "closed_cases": self.closed_cases,
            "jobs": self.jobs,
        }


def events_cutoff(now: datetime, days: int, open_case_start: datetime | None) -> date | None:
    """First UTC day that is kept (partitions are UTC days), ``None`` = keep forever."""
    if days <= 0:
        return None
    cutoff = (now.astimezone(UTC) - timedelta(days=days)).date()
    if open_case_start is not None:
        cutoff = min(cutoff, open_case_start.astimezone(UTC).date())
    return cutoff


async def _apply(conn: AsyncConnection, policy: RetentionPolicy, now: datetime, dry_run: bool) -> RetentionResult:
    result = RetentionResult(dry_run=dry_run)
    open_start = (await conn.execute(text(_OPEN_CASES_START))).scalar()
    cutoff_day = events_cutoff(now, policy.events_days, open_start)
    if cutoff_day is not None:
        result.events_cutoff = cutoff_day.isoformat()
        cutoff_ts = datetime(cutoff_day.year, cutoff_day.month, cutoff_day.day, tzinfo=UTC)
        params = {"cutoff": cutoff_day}
        result.events = int((await conn.execute(text(_COUNT_EVENTS), {"cutoff": cutoff_ts})).scalar() or 0)
        if not dry_run:
            await conn.execute(text(_DROP_PARTITIONS), params)
            await conn.execute(text(_DELETE_DEFAULT_PARTITION), {"cutoff": cutoff_ts})
        if policy.closed_cases_days > 0:
            rows = await conn.execute(
                text(_SELECT_CASES),
                {"closed_cutoff": now - timedelta(days=policy.closed_cases_days), "events_cutoff": cutoff_ts},
            )
            result.case_ids = [r[0] for r in rows]
            result.closed_cases = len(result.case_ids)
            if result.case_ids and not dry_run:
                for statement in _DELETE_CASE_ROWS:
                    await conn.execute(text(statement), {"ids": result.case_ids})
    if policy.raw_days > 0:
        raw_params = {"cutoff": now - timedelta(days=policy.raw_days)}
        if dry_run:
            result.raw_records = int((await conn.execute(text(_COUNT_RAW), raw_params)).scalar() or 0)
        else:
            result.raw_records = (await conn.execute(text(_DELETE_RAW), raw_params)).rowcount
    if policy.jobs_days > 0:
        job_params = {"cutoff": now - timedelta(days=policy.jobs_days)}
        if dry_run:
            result.jobs = int((await conn.execute(text(_COUNT_JOBS), job_params)).scalar() or 0)
        else:
            result.jobs = (await conn.execute(text(_DELETE_JOBS), job_params)).rowcount
    return result


async def apply_retention(
    engine: AsyncEngine, policy: RetentionPolicy, now: datetime, actor: str = "system", dry_run: bool = False
) -> RetentionResult:
    async with engine.begin() as conn:
        result = await _apply(conn, policy, now, dry_run)
        if not dry_run:
            details = result.to_dict() | {"policy": policy.__dict__, "case_ids": result.case_ids}
            await audit.append(conn, actor, "retention.applied", "system", "retention", details, now)
    return result
