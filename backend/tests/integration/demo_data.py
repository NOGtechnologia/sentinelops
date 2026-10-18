"""Session-wide demo dataset: generated once, loaded into a fresh database."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from musterfirma.generate import GeneratorConfig, generate

from sentinelops.ingest.runs import ingest_path
from sentinelops.runtime import Runtime
from sentinelops.settings import Settings
from sentinelops.worker.analysis import run_analysis
from sentinelops.worker.main import effective_exceptions

DEMO_NOW = "2026-03-12T10:30:00+01:00"
SMALL_EVENTS_PER_DAY = 4000


@dataclass(frozen=True)
class DemoEnv:
    url: str
    dataset: Path


def settings_for(url: str) -> Settings:
    return Settings(database_url=url, demo_mode=True, demo_now=DEMO_NOW, approval_secret="x" * 40)


def generate_dataset(target: Path, seed: str = "dev", events_per_day: int = SMALL_EVENTS_PER_DAY) -> Path:
    if not (target / "ground_truth.json").exists():
        target.mkdir(parents=True, exist_ok=True)
        generate(GeneratorConfig(seed=seed, events_per_day=events_per_day), target)
    return target


async def load_into(url: str, dataset: Path) -> dict[str, object]:
    import json

    rt = Runtime(settings_for(url))
    try:
        truth = json.loads((dataset / "ground_truth.json").read_text(encoding="utf-8"))
        accepted = 0
        for entry in truth["files"]:
            result = await ingest_path(
                rt.engine,
                dataset / entry["path"],
                source_type=entry["source_type"],
                timezone=entry["timezone"],
                file_name=entry["path"],
                channel="test",
                actor="test",
                profiles=rt.profiles,
                now=rt.clock.now(),
            )
            accepted += result.accepted
        analysis = await run_analysis(rt.engine, rt.analysis_context(await effective_exceptions(rt)), rt.clock.now())
        return {"accepted": accepted, **analysis}
    finally:
        await rt.engine.dispose()


def load_sync(url: str, dataset: Path) -> dict[str, object]:
    return asyncio.run(load_into(url, dataset))
