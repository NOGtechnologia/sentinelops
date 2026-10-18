"""Rule checks (spec 15.3): load + validate every rule, run the rule tests,
enforce >= 2 positive / >= 2 negative cases per alerting rule."""

from __future__ import annotations

import pytest

from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.exceptions import load_exceptions
from sentinelops.detection.rule_tests import CaseResult, run_rule_tests
from sentinelops.detection.sigma_loader import RuleSet, load_ruleset
from sentinelops.investigation.catalog import catalog_ids
from sentinelops.settings import RULES_DIR

CONFIG = DetectionConfig()


@pytest.fixture(scope="module")
def ruleset() -> RuleSet:
    return load_ruleset(RULES_DIR, CONFIG, catalog_ids())


@pytest.fixture(scope="module")
def results(ruleset: RuleSet) -> tuple[list[CaseResult], list[str]]:
    return run_rule_tests(RULES_DIR / "tests", ruleset, CONFIG, load_exceptions(RULES_DIR / "exceptions"))


def test_every_rule_has_enough_tests(results: tuple[list[CaseResult], list[str]]) -> None:
    _, problems = results
    assert problems == []


def test_all_rule_tests_pass(results: tuple[list[CaseResult], list[str]]) -> None:
    cases, _ = results
    failed = [f"{c.rule_id}: {c.name} (expected {c.expect}, got {c.alerts} alerts)" for c in cases if not c.passed]
    assert failed == []


def test_catalog_v1_complete(ruleset: RuleSet) -> None:
    required = {
        "SO-AUTH-001",
        "SO-AUTH-002",
        "SO-AUTH-003",
        "SO-AUTH-004",
        "SO-AUTH-005",
        "SO-AUTH-006",
        "SO-PRIV-001",
        "SO-PRIV-002",
        "SO-PRIV-003",
        "SO-ACC-001",
        "SO-ACC-002",
        "SO-DEF-001",
    }
    assert required <= set(ruleset.metas)
    assert any(m.source == "sigmahq" for m in ruleset.metas.values())


def test_metadata_complete(ruleset: RuleSet) -> None:
    for meta in ruleset.metas.values():
        assert meta.tactics, meta.rule_id
        assert meta.techniques, meta.rule_id
        assert meta.playbooks, meta.rule_id
        assert meta.title_de, meta.rule_id
        assert meta.description_de, meta.rule_id
        assert meta.level in ("informational", "low", "medium", "high", "critical")
        assert meta.maturity in ("stable", "test", "experimental")


def test_ruleset_hash_is_stable(ruleset: RuleSet) -> None:
    again = load_ruleset(RULES_DIR, CONFIG, catalog_ids())
    assert again.ruleset_hash == ruleset.ruleset_hash
    other = load_ruleset(RULES_DIR, DetectionConfig(case_window_seconds=3600), catalog_ids())
    assert other.ruleset_hash != ruleset.ruleset_hash
