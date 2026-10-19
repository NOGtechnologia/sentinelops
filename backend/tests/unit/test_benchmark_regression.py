"""Benchmark gate against main: more than one percentage point worse fails (spec 15.4)."""

from __future__ import annotations

from sentinelops.evaluation.benchmark import regressions

BASE = {"recall": 1.0, "single_case_share": 1.0, "precision": {"SO-AUTH-001": 0.95, "SO-AUTH-002": 1.0}}


def test_equal_or_better_is_fine() -> None:
    assert regressions(BASE, BASE) == []
    better = {**BASE, "precision": {"SO-AUTH-001": 1.0, "SO-AUTH-002": 1.0, "SO-NEW-001": 0.5}}
    assert regressions(better, BASE) == []


def test_one_point_is_tolerated_more_is_not() -> None:
    within = {**BASE, "recall": 0.99}
    assert regressions(within, BASE) == []
    worse = {**BASE, "recall": 0.98, "precision": {"SO-AUTH-001": 0.93, "SO-AUTH-002": 1.0}}
    problems = regressions(worse, BASE)
    assert len(problems) == 2
    assert problems[0].startswith("recall")
    assert problems[1].startswith("precision SO-AUTH-001")


def test_rule_without_alerts_counts_as_zero_precision() -> None:
    gone = {**BASE, "precision": {"SO-AUTH-001": 0.95}}
    assert regressions(gone, BASE) == ["precision SO-AUTH-002: 0.0000 < 1.0000 on main (> 1% worse)"]
