"""Append-only, hash-chained audit log (spec 16.1).

The database trigger rejects UPDATE/DELETE/TRUNCATE; the hash chain makes
tampering with exported copies detectable (``verify_chain``).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncConnection

from sentinelops.normalize.schema import format_timestamp
from sentinelops.storage.models import audit_log

GENESIS = "0" * 64
AUDIT_LOCK = 734_221  # advisory lock id serialising appends


def entry_hash(
    prev_hash: str, ts: datetime, actor: str, action: str, object_type: str, object_id: str, details: dict[str, Any]
) -> str:
    payload = json.dumps(
        [prev_hash, format_timestamp(ts), actor, action, object_type, object_id, details],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def append(
    conn: AsyncConnection,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    details: dict[str, Any],
    now: datetime,
) -> str:
    await conn.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": AUDIT_LOCK})
    prev = (await conn.execute(select(audit_log.c.hash).order_by(audit_log.c.seq.desc()).limit(1))).scalar()
    prev_hash = prev or GENESIS
    digest = entry_hash(prev_hash, now, actor, action, object_type, object_id, details)
    await conn.execute(
        insert(audit_log).values(
            ts=now,
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            details=details,
            prev_hash=prev_hash,
            hash=digest,
        )
    )
    return digest


def verify_chain(rows: Sequence[dict[str, Any]]) -> list[int]:
    """Return the sequence numbers of entries whose hash does not verify."""
    broken: list[int] = []
    prev = GENESIS
    for row in rows:
        expected = entry_hash(
            prev, row["ts"], row["actor"], row["action"], row["object_type"], row["object_id"], row["details"]
        )
        if row["prev_hash"] != prev or row["hash"] != expected:
            broken.append(int(row["seq"]))
        prev = row["hash"]
    return broken
