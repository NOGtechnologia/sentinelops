"""CLI commands and the job worker against a real database."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from sentinelops import cli
from sentinelops.runtime import Runtime
from sentinelops.storage import jobs
from sentinelops.storage.models import cases, events, ingest_runs
from sentinelops.storage.models import jobs as jobs_table
from sentinelops.worker.main import run_job, schedule_retention, work_once
from tests.integration.conftest import Database
from tests.integration.demo_data import generate_dataset, settings_for

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def small_dataset(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_dataset(tmp_path_factory.mktemp("cli") / "dev", events_per_day=1500)


def test_rules_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["rules", "check"]) == 0
    assert "alerting rules" in capsys.readouterr().out
    assert cli.main(["rules", "test"]) == 0
    assert "rule test cases passed" in capsys.readouterr().out
    assert cli.main(["rules", "catalog-check"]) == 0


def test_benchmark_command(small_dataset: Path, tmp_path: Path) -> None:
    md, js = tmp_path / "b.md", tmp_path / "b.json"
    assert cli.main(["benchmark", str(small_dataset), "--markdown", str(md), "--json", str(js)]) == 0
    assert "Recall je Szenario" in md.read_text(encoding="utf-8")
    assert json.loads(js.read_text(encoding="utf-8"))["failures"] == []


def test_benchmark_command_with_normal_dataset(small_dataset: Path, tmp_path: Path) -> None:
    from musterfirma.generate import GeneratorConfig, generate

    normal = tmp_path / "normal"
    generate(GeneratorConfig(seed="dev", events_per_day=1500, scenarios=False, quality=False), normal)
    assert cli.main(["benchmark", str(small_dataset), "--normal", str(normal)]) == 0


def test_migrate_ingest_analyze_commands(
    empty_db: Database, small_dataset: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SENTINELOPS_DATABASE_URL", empty_db.url)
    monkeypatch.setenv("SENTINELOPS_DEMO_MODE", "true")
    monkeypatch.setenv("SENTINELOPS_DEMO_NOW", "2026-03-12T10:30:00+01:00")
    assert cli.main(["migrate"]) == 0
    assert (
        cli.main(
            [
                "ingest",
                str(FIXTURES / "syslog_3164" / "auth.log"),
                "--source-type",
                "syslog_3164",
                "--timezone",
                "Europe/Berlin",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)[0]["accepted"] == 13
    with pytest.raises(SystemExit):
        cli.main(["ingest", str(FIXTURES / "syslog_3164" / "auth.log")])
    assert cli.main(["ingest", str(small_dataset)]) == 0
    capsys.readouterr()
    assert cli.main(["analyze"]) == 0
    assert json.loads(capsys.readouterr().out)["cases"] >= 10
    assert cli.main(["retention", "--dry-run"]) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["dry_run"] is True
    assert cli.main(["retention"]) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied == dry | {"dry_run": False}
    assert cli.main(["demo-load", "--out", str(small_dataset)]) == 0
    assert cli.main(["migrate", "--down"]) == 0


def test_worker_runs_queued_jobs(fresh_db: Database, tmp_path: Path) -> None:
    async def scenario() -> None:
        rt = Runtime(settings_for(fresh_db.url))
        try:
            upload = tmp_path / "auth.log"
            upload.write_bytes((FIXTURES / "syslog_3164" / "auth.log").read_bytes())
            async with rt.engine.begin() as conn:
                await jobs.enqueue(
                    conn,
                    "ingest_file",
                    {
                        "path": str(upload),
                        "source_type": "syslog_3164",
                        "timezone": "Europe/Berlin",
                        "file_name": "auth.log",
                        "channel": "drop_folder",
                        "actor": "test",
                        "delete_after": True,
                    },
                    rt.clock.now(),
                    dedupe=False,
                )
                await jobs.enqueue(conn, "bogus", {}, rt.clock.now(), dedupe=False)
            assert await work_once(rt, "w1")  # ingest (also queues an analysis)
            assert await work_once(rt, "w1")  # bogus job fails and is retried later
            assert await work_once(rt, "w1")  # analysis
            assert not await work_once(rt, "w1")
            assert not upload.exists()
            async with rt.engine.connect() as conn:
                assert (await conn.execute(select(func.count()).select_from(events))).scalar() == 13
                assert (await conn.execute(select(ingest_runs.c.channel))).scalar() == "drop_folder"
                assert (await conn.execute(select(func.count()).select_from(cases))).scalar() >= 1
            with pytest.raises(ValueError, match="unknown job kind"):
                await run_job(rt, {"kind": "nope", "payload": {}})
            # retention is queued once per interval and runs as a normal job
            first = await schedule_retention(rt, None)
            assert await schedule_retention(rt, first) == first
            assert await work_once(rt, "w1")
            async with rt.engine.connect() as conn:
                kinds = (await conn.execute(select(jobs_table.c.kind, jobs_table.c.status))).all()
            assert ("retention", "done") in kinds
        finally:
            await rt.engine.dispose()

    asyncio.run(scenario())
