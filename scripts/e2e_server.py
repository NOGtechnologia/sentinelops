"""Start a fresh demo instance for end-to-end tests and screenshots (no Docker needed).

1. (Re)creates the database ``SENTINELOPS_E2E_DB`` (default ``sentinelops_e2e``) on the PostgreSQL server
   given by ``SENTINELOPS_E2E_ADMIN_URL`` (e.g. ``postgresql+asyncpg://postgres@localhost:5432/postgres``),
2. migrates it and loads the Musterfirma demo data (seed ``dev``, fixed demo clock),
3. serves API + built web app (``frontend/dist``) on ``E2E_PORT`` (default 8001).

Used by ``e2e/playwright.config.ts`` (``webServer``) locally and in CI.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

ROOT = Path(__file__).resolve().parents[1]
DEMO_NOW = "2026-03-12T10:30:00+01:00"


async def recreate(admin_url: str, name: str) -> None:
    engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await engine.dispose()


def main() -> int:
    admin_url = os.environ.get("SENTINELOPS_E2E_ADMIN_URL")
    if not admin_url:
        print("SENTINELOPS_E2E_ADMIN_URL is required", file=sys.stderr)
        return 2
    name = os.environ.get("SENTINELOPS_E2E_DB", "sentinelops_e2e")
    if not name.replace("_", "").isalnum():
        print("invalid database name", file=sys.stderr)
        return 2
    port = os.environ.get("E2E_PORT", "8001")
    dataset = Path(os.environ.get("E2E_DATASET", ".cache/e2e-dataset"))
    if not dataset.is_absolute():
        dataset = ROOT / dataset  # relative to the repository, independent of the working directory
    static = ROOT / "frontend" / "dist"
    if not (static / "index.html").exists():
        print("frontend/dist is missing - run `pnpm --dir frontend build` first", file=sys.stderr)
        return 2

    asyncio.run(recreate(admin_url, name))
    env = {
        **os.environ,
        "SENTINELOPS_DATABASE_URL": make_url(admin_url).set(database=name).render_as_string(hide_password=False),
        "SENTINELOPS_DEMO_MODE": "true",
        "SENTINELOPS_DEMO_NOW": DEMO_NOW,
        "SENTINELOPS_STATIC_DIR": str(static),
        "SENTINELOPS_APPROVAL_SECRET": "e2e-approval-secret-not-for-production-000",
        "SENTINELOPS_LLM_PROVIDER": os.environ.get("SENTINELOPS_LLM_PROVIDER", "mock"),
        "SENTINELOPS_INPROCESS_WORKER": "true",
        # Many logins in a short time; the rate limiter itself is covered by API tests.
        "SENTINELOPS_RATE_LIMIT": "false",
    }
    cli = [sys.executable, "-m", "sentinelops.cli"]
    subprocess.run([*cli, "migrate"], env=env, check=True, cwd=ROOT / "backend")  # noqa: S603 - fixed arguments
    subprocess.run(  # noqa: S603 - fixed arguments
        [*cli, "demo-load", "--out", str(dataset)], env=env, check=True, cwd=ROOT / "backend"
    )
    print(f"e2e instance ready on http://127.0.0.1:{port}", flush=True)
    return subprocess.call([*cli, "serve", "--host", "127.0.0.1", "--port", port], env=env, cwd=ROOT / "backend")  # noqa: S603


if __name__ == "__main__":
    sys.exit(main())
