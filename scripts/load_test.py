"""Nightly load test (spec 15.7).

* ~1 million events (Musterfirma, ~20 days at 50,000 events/day) are generated and ingested into a
  fresh database: >= 3,000 events/s,
* detection and case building run completely,
* API p95 < 300 ms for the case list and the case detail,
* peak memory (RSS) is reported; a regression of more than 20 % against the reference values in
  ``docs/performance-baseline.json`` fails the run.

Usage: SENTINELOPS_E2E_ADMIN_URL=postgresql+asyncpg://user@host/postgres python scripts/load_test.py
"""

from __future__ import annotations

import asyncio
import json
import os
import statistics
import sys
import time
from datetime import date
from pathlib import Path

import httpx
from musterfirma.generate import GeneratorConfig, generate
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelops.api.app import create_app
from sentinelops.auth.principal import issue_demo_token
from sentinelops.ingest.runs import ingest_path
from sentinelops.runtime import Runtime
from sentinelops.settings import Settings
from sentinelops.worker.analysis import run_analysis
from sentinelops.worker.main import effective_exceptions

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "performance-baseline.json"
TARGETS = {"ingest_events_per_s": 3000.0, "api_p95_ms": 300.0}
MAX_REGRESSION = 0.20


def peak_rss_mb() -> float:
    try:
        import resource  # noqa: PLC0415 - POSIX only

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except ImportError:  # pragma: no cover - Windows
        return 0.0


def _append(path: Path, text_: str) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text_)


async def recreate(admin_url: str, name: str) -> str:
    engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await engine.dispose()
    return make_url(admin_url).set(database=name).render_as_string(hide_password=False)


async def p95(client: httpx.AsyncClient, url: str, headers: dict[str, str], runs: int = 40) -> float:
    timings = []
    for _ in range(runs):
        started = time.perf_counter()
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        timings.append((time.perf_counter() - started) * 1000)
    return statistics.quantiles(timings, n=20)[18]


async def main() -> int:
    admin = os.environ["SENTINELOPS_E2E_ADMIN_URL"]
    data_dir = Path(os.environ.get("LOAD_DATASET", str(ROOT / ".cache" / "load-dataset")))
    if not (data_dir / "ground_truth.json").exists():
        generate(GeneratorConfig(seed="holdout", start=date(2026, 2, 20), events_per_day=50_000), data_dir)
    url = await recreate(admin, "sentinelops_load")
    os.environ["SENTINELOPS_DATABASE_URL"] = url
    from sentinelops.cli import cmd_migrate  # noqa: PLC0415 - needs the database URL in the environment

    cmd_migrate(type("Args", (), {"down": False})())
    rt = Runtime(Settings(database_url=url, demo_mode=True, demo_now="2026-03-12T10:30:00+01:00"))
    truth = json.loads((data_dir / "ground_truth.json").read_text(encoding="utf-8"))
    started = time.perf_counter()
    accepted = 0
    for entry in truth["files"]:
        result = await ingest_path(
            rt.engine,
            data_dir / entry["path"],
            source_type=entry["source_type"],
            timezone=entry["timezone"],
            file_name=entry["path"],
            channel="load",
            actor="load",
            profiles=rt.profiles,
            now=rt.clock.now(),
        )
        accepted += result.accepted
    ingest_s = time.perf_counter() - started
    started = time.perf_counter()
    analysis = await run_analysis(
        rt.engine, rt.analysis_context(await effective_exceptions(rt)), rt.clock.now(), "load"
    )
    analysis_s = time.perf_counter() - started

    app = create_app(rt)
    headers = {"Authorization": f"Bearer {issue_demo_token('analyst')}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://load") as client:
        cases = (await client.get("/api/v1/cases", headers=headers)).json()
        case_id = cases["items"][0]["case_id"]
        list_p95 = await p95(client, "/api/v1/cases", headers)
        detail_p95 = await p95(client, f"/api/v1/cases/{case_id}", headers)
    await rt.engine.dispose()

    result = {
        "events": accepted,
        "ingest_seconds": round(ingest_s, 1),
        "ingest_events_per_s": round(accepted / ingest_s),
        "analysis_seconds": round(analysis_s, 1),
        "cases": analysis.get("cases"),
        "api_p95_ms": round(max(list_p95, detail_p95), 1),
        "api_list_p95_ms": round(list_p95, 1),
        "api_detail_p95_ms": round(detail_p95, 1),
        "peak_rss_mb": round(peak_rss_mb()),
    }
    print(json.dumps(result, indent=1))
    problems = []
    if result["events"] < 900_000:
        problems.append(f"only {result['events']} events ingested")
    if result["ingest_events_per_s"] < TARGETS["ingest_events_per_s"]:
        problems.append(f"ingestion {result['ingest_events_per_s']} events/s < 3000")
    if result["api_p95_ms"] > TARGETS["api_p95_ms"]:
        problems.append(f"API p95 {result['api_p95_ms']} ms > 300 ms")
    if BASELINE.exists():
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        for key, higher_is_better in (
            ("ingest_events_per_s", True),
            ("analysis_seconds", False),
            ("api_p95_ms", False),
        ):
            ref = baseline.get(key)
            if not ref:
                continue
            change = (result[key] - ref) / ref
            if (higher_is_better and change < -MAX_REGRESSION) or (not higher_is_better and change > MAX_REGRESSION):
                problems.append(f"{key} regressed by {abs(change):.0%} (reference {ref}, now {result[key]})")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        table = "## Load test\n\n| Metric | Value |\n|---|---|\n" + "".join(
            f"| {k} | {v} |\n" for k, v in result.items()
        )
        await asyncio.to_thread(_append, Path(summary), table)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
