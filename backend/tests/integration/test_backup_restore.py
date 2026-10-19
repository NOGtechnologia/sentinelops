"""Backup and restore as documented in docs/operations.md (spec Phase 10): pg_dump -Fc, pg_restore.

The restored database must contain the same data, a valid audit hash chain and keep the audit log
append-only (the trigger is part of the dump).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from sentinelops.storage import audit
from sentinelops.storage.db import make_engine
from sentinelops.storage.models import alerts, audit_log, cases, events, raw_records
from tests.integration.conftest import _create_db, _drop_db

pytestmark = pytest.mark.integration


def _tool(name: str) -> str | None:
    folder = os.environ.get("SENTINELOPS_PG_BIN")
    if folder:
        candidate = shutil.which(name, path=folder)
        if candidate:
            return candidate
    return shutil.which(name)


def _libpq(url: str) -> tuple[list[str], dict[str, str]]:
    """Connection arguments for the PostgreSQL client tools; the password goes through the environment."""
    u = make_url(url)
    args = ["-h", u.host or "localhost", "-p", str(u.port or 5432), "-U", u.username or "postgres"]
    env = os.environ | ({"PGPASSWORD": u.password} if u.password else {})
    return args, env


async def _snapshot(url: str) -> tuple[dict[str, int], list[int], str]:
    engine = make_engine(url)
    try:
        async with engine.connect() as conn:
            counts = {
                table.name: (await conn.execute(select(func.count()).select_from(table))).scalar_one()
                for table in (events, raw_records, alerts, cases, audit_log)
            }
            rows = [dict(r) for r in (await conn.execute(select(audit_log).order_by(audit_log.c.seq))).mappings()]
            version = (await conn.execute(text("select version_num from alembic_version"))).scalar_one()
        return counts, audit.verify_chain(rows), str(version)
    finally:
        await engine.dispose()


async def _audit_is_append_only(url: str) -> None:
    engine = make_engine(url)
    try:
        with pytest.raises(DBAPIError, match="append-only"):
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM audit_log"))
    finally:
        await engine.dispose()


def test_backup_and_restore(demo_db: str, pg_server: str, tmp_path: Path) -> None:
    pg_dump, pg_restore = _tool("pg_dump"), _tool("pg_restore")
    if pg_dump is None or pg_restore is None:
        if os.environ.get("SENTINELOPS_REQUIRE_PG_TOOLS"):
            pytest.fail("pg_dump/pg_restore not found (SENTINELOPS_PG_BIN)")
        # Justification: the PostgreSQL client tools are not part of the Python environment. CI sets
        # SENTINELOPS_REQUIRE_PG_TOOLS, so there the test can never be skipped.
        pytest.skip("pg_dump/pg_restore not available; set SENTINELOPS_PG_BIN")
    dump = tmp_path / "sentinelops.dump"
    source = make_url(demo_db)
    args, env = _libpq(demo_db)
    # S603: fixed argument lists without a shell; host, user and database come from the test configuration
    dump_cmd = [pg_dump, *args, "-Fc", "-f", str(dump), source.database or ""]
    subprocess.run(dump_cmd, check=True, env=env)  # noqa: S603 - see above

    name = f"so_restore_{uuid.uuid4().hex[:8]}"
    target = asyncio.run(_create_db(pg_server, name))
    try:
        restore_cmd = [pg_restore, *args, "--no-owner", "--exit-on-error", "-d", name, str(dump)]
        subprocess.run(restore_cmd, check=True, env=env)  # noqa: S603 - see above
        before, after = asyncio.run(_snapshot(demo_db)), asyncio.run(_snapshot(target))
        assert after == before
        counts, broken_links, _ = after
        assert broken_links == []
        assert counts["cases"] >= 10  # the shared demo database; other tests may have split cases
        asyncio.run(_audit_is_append_only(target))
    finally:
        asyncio.run(_drop_db(pg_server, name))
