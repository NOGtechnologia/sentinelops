"""Acceptance tests A1-A8 (spec 19) share the generated dataset and PostgreSQL."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from sentinelops.correlation.analysis import AnalysisResult
from sentinelops.evaluation.benchmark import load_dataset, locator_map, run_analysis
from sentinelops.ingest.local import LocalIngestResult
from tests.integration.conftest import empty_db, fresh_db, pg_server  # noqa: F401 - re-exported fixtures
from tests.integration.demo_data import generate_dataset


@dataclass
class Dataset:
    root: Path
    truth: dict[str, Any]
    ingest: LocalIngestResult
    now: datetime
    result: AnalysisResult
    locators: dict[tuple[str, int], str]

    def evidence(self, scenario: str) -> set[str]:
        entry = next(s for s in self.truth["scenarios"] if s["id"] == scenario)
        return {self.locators[(loc["file"], loc["position"])] for loc in entry["evidence"]}


@pytest.fixture(scope="session")
def dataset_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_dataset(tmp_path_factory.mktemp("acceptance") / "dev")


@pytest.fixture(scope="session")
def dataset(dataset_dir: Path) -> Dataset:
    truth, ingest, now = load_dataset(dataset_dir)
    result = run_analysis(ingest.events, now)
    return Dataset(dataset_dir, truth, ingest, now, result, locator_map(dataset_dir, truth, ingest))


def labels(dataset_root: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((dataset_root / "ground_truth.json").read_text(encoding="utf-8"))
    return data
