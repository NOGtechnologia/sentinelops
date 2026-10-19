"""Detection benchmark on the ``holdout`` seed (spec 15.4) - never used to tune rules.

Full volume (50,000 events per working day). The Markdown table is written to
``$SENTINELOPS_BENCHMARK_REPORT`` (CI job summary) when set.
"""

from __future__ import annotations

import os
import time
from datetime import date
from pathlib import Path

import pytest
from musterfirma.generate import GeneratorConfig, generate

from sentinelops.evaluation.benchmark import THRESHOLDS, evaluate, evaluate_normal_only

pytestmark = pytest.mark.benchmark


@pytest.fixture(scope="module")
def holdout(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("holdout")
    generate(GeneratorConfig(seed="holdout", events_per_day=50_000), root)
    return root


@pytest.fixture(scope="module")
def normal_only(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("normal")
    generate(
        GeneratorConfig(seed="holdout", events_per_day=50_000, scenarios=False, quality=False, start=date(2026, 3, 11)),
        root,
    )
    return root


def test_benchmark_holdout(holdout: Path) -> None:
    started = time.perf_counter()
    report, result = evaluate(holdout)
    elapsed = time.perf_counter() - started
    target = os.environ.get("SENTINELOPS_BENCHMARK_REPORT")
    if target:
        Path(target).write_text(
            report.markdown() + f"\nLaufzeit (Parsing + Erkennung + Fallbildung): {elapsed:.1f} s\n", encoding="utf-8"
        )
    assert report.failures() == []
    assert report.recall >= THRESHOLDS["recall_per_scenario"]
    assert report.single_case_share == 1.0
    assert all(p >= THRESHOLDS["precision_per_rule"] for p in report.precision.values())
    trap = next(s for s in report.scenarios if s.id == "S09")
    assert trap.priority == "P4"
    assert len(result.cases) == 10


def test_benchmark_normal_behaviour(normal_only: Path) -> None:
    report = evaluate_normal_only(normal_only)
    assert report.events >= 50_000
    assert report.normal_cases["P1"] + report.normal_cases["P2"] == 0
    assert report.normal_cases["P3"] + report.normal_cases["P4"] <= 5


def test_fifty_thousand_events_under_sixty_seconds(normal_only: Path) -> None:
    """Spec 5.7: 50,000 events incl. detection and case building in < 60 s."""
    started = time.perf_counter()
    report = evaluate_normal_only(normal_only)
    elapsed = time.perf_counter() - started
    per_50k = elapsed * 50_000 / report.events
    assert per_50k < 60, f"{per_50k:.1f} s per 50,000 events"
