"""Integration test infrastructure: a real PostgreSQL 16.

* ``SENTINELOPS_TEST_DATABASE_URL`` (an admin URL to an existing server,
  e.g. ``postgresql+asyncpg://user@localhost:5432/postgres``) is used when set
  (CI service container, local installation);
* otherwise Testcontainers starts ``postgres:16-alpine``.

Each test session works in fresh databases that are dropped afterwards.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelops.api.app import create_app
from sentinelops.runtime import Runtime
from tests.integration.demo_data import generate_dataset, load_sync, settings_for

BACKEND = Path(__file__).resolve().parents[2]


def _server_url() -> Iterator[str]:
    url = os.environ.get("SENTINELOPS_TEST_DATABASE_URL")
    if url:
        yield url
        return
    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError:  # pragma: no cover - dev dependency
        pytest.skip("integration tests need PostgreSQL: set SENTINELOPS_TEST_DATABASE_URL or install testcontainers")
    try:
        container = PostgresContainer("postgres:16-alpine", driver="asyncpg")
        container.start()
    except Exception as exc:  # pragma: no cover - environment specific (no Docker)
        pytest.skip(
            f"integration tests need PostgreSQL: no SENTINELOPS_TEST_DATABASE_URL and Docker unavailable ({exc})"
        )
    try:
        yield container.get_connection_url()
    finally:
        container.stop()


@pytest.fixture(scope="session")
def pg_server() -> Iterator[str]:
    yield from _server_url()


async def _create_db(server: str, name: str) -> str:
    engine = create_async_engine(server, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await engine.dispose()
    return make_url(server).set(database=name).render_as_string(hide_password=False)


async def _drop_db(server: str, name: str) -> None:
    engine = create_async_engine(server, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    await engine.dispose()


def migrate(url: str, down: bool = False) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    previous = os.environ.get("SENTINELOPS_DATABASE_URL")
    os.environ["SENTINELOPS_DATABASE_URL"] = url
    try:
        if down:
            command.downgrade(cfg, "base")
        else:
            command.upgrade(cfg, "head")
    finally:
        if previous is None:
            os.environ.pop("SENTINELOPS_DATABASE_URL", None)
        else:
            os.environ["SENTINELOPS_DATABASE_URL"] = previous


@dataclass
class Database:
    server: str
    name: str
    url: str


@pytest.fixture
def fresh_db(pg_server: str) -> Iterator[Database]:
    name = f"so_test_{uuid.uuid4().hex[:10]}"
    url = asyncio.run(_create_db(pg_server, name))
    migrate(url)
    try:
        yield Database(pg_server, name, url)
    finally:
        asyncio.run(_drop_db(pg_server, name))


@pytest.fixture
def empty_db(pg_server: str) -> Iterator[Database]:
    name = f"so_test_{uuid.uuid4().hex[:10]}"
    url = asyncio.run(_create_db(pg_server, name))
    try:
        yield Database(pg_server, name, url)
    finally:
        asyncio.run(_drop_db(pg_server, name))


# --- shared API fixtures --------------------------------------------------------------


@pytest.fixture(scope="session")
def demo_db(pg_server: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    dataset = generate_dataset(tmp_path_factory.mktemp("demo") / "dev")
    name = f"so_api_{uuid.uuid4().hex[:8]}"
    url = asyncio.run(_create_db(pg_server, name))
    migrate(url)
    summary = load_sync(url, dataset)
    assert summary["cases"] == 10
    try:
        yield url
    finally:
        asyncio.run(_drop_db(pg_server, name))


@pytest.fixture
async def client(demo_db: str, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setenv("SENTINELOPS_RATE_LIMIT", "false")
    rt = Runtime(settings_for(demo_db))
    app = create_app(rt)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        c.app = app  # type: ignore[attr-defined]  # test convenience
        yield c
    await rt.engine.dispose()
