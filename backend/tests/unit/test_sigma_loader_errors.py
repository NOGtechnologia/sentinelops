"""Loading failures are explicit (spec 6.1: unsupported features never ignored)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sentinelops.detection.config import DetectionConfig, ThresholdOverride
from sentinelops.detection.sigma_loader import RuleLoadError, _timespan_seconds, load_ruleset
from sentinelops.investigation.catalog import catalog_ids
from sentinelops.settings import RULES_DIR

GOOD_META = """sentinelops:
  rule_id: SO-TEST-001
  version: 1
  title_de: Test
  description_de: Test
  playbooks: [VERIFY_ACCOUNT_ACTIVITY]
"""


def rules_copy(tmp_path: Path) -> Path:
    target = tmp_path / "rules"
    shutil.copytree(RULES_DIR, target, ignore=shutil.ignore_patterns("tests"))
    return target


def add(rules: Path, name: str, text: str, folder: str = "sigma/custom") -> None:
    (rules / folder / name).write_text(text, encoding="utf-8")


def rule(detection: str, extra: str = GOOD_META, header: str = "") -> str:
    return f"""title: Test rule
id: 7a1d1f6e-1111-4111-8111-000000000001
status: stable
{header}author: t
date: 2026-10-18
tags: [attack.credential-access, attack.t1110]
logsource: {{product: sentinelops}}
detection:
{detection}
level: high
{extra}"""


def load(rules: Path, config: DetectionConfig | None = None) -> object:
    return load_ruleset(rules, config or DetectionConfig(), catalog_ids())


def test_valid_extra_rule_loads(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    add(rules, "x.yml", rule("  sel:\n    event.action: logon\n  condition: sel"))
    ruleset = load(rules)
    assert "SO-TEST-001" in ruleset.metas  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (GOOD_META.replace("SO-TEST-001", "bad id"), "invalid rule_id"),
        (GOOD_META.replace("version: 1", "version: 0"), "version"),
        (GOOD_META.replace("[VERIFY_ACCOUNT_ACTIVITY]", "[]"), "playbook reference"),
        (GOOD_META.replace("VERIFY_ACCOUNT_ACTIVITY", "MAKE_COFFEE"), "unknown playbook"),
        (GOOD_META.replace("  title_de: Test\n", ""), "title_de"),
    ],
)
def test_metadata_problems(tmp_path: Path, extra: str, message: str) -> None:
    rules = rules_copy(tmp_path)
    add(rules, "x.yml", rule("  sel:\n    event.action: logon\n  condition: sel", extra))
    with pytest.raises(RuleLoadError, match=message):
        load(rules)


def test_missing_tags_and_bad_level(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    text = rule("  sel:\n    a: 1\n  condition: sel").replace("tags: [attack.credential-access, attack.t1110]\n", "")
    add(rules, "x.yml", text.replace("level: high", "level: high"))
    with pytest.raises(RuleLoadError, match="ATT&CK tactic"):
        load(rules)


def test_unsupported_features_fail_loading(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    add(rules, "x.yml", rule("  sel:\n    group.name|expand: '%undefined_placeholder%'\n  condition: sel"))
    with pytest.raises(RuleLoadError, match="placeholder"):
        load(rules)


def test_pipe_condition_rejected(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    add(rules, "x.yml", rule("  sel:\n    a: 1\n  condition: sel | count() > 5"))
    with pytest.raises(RuleLoadError):
        load(rules)


def test_unsupported_correlation_type(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    add(
        rules,
        "x.yml",
        """title: Sum
id: 7a1d1f6e-1111-4111-8111-000000000002
status: stable
tags: [attack.credential-access, attack.t1110]
correlation:
  type: value_sum
  rules: [so_helper_logon_failed]
  group-by: [user.name]
  timespan: 5m
  condition: {field: source.port, gte: 10}
level: high
"""
        + GOOD_META,
        folder="correlations",
    )
    with pytest.raises(RuleLoadError, match="not supported"):
        load(rules)


def test_correlation_lt_condition_rejected(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    add(
        rules,
        "x.yml",
        """title: Few
id: 7a1d1f6e-1111-4111-8111-000000000003
status: stable
tags: [attack.credential-access, attack.t1110]
correlation:
  type: event_count
  rules: [so_helper_logon_failed]
  group-by: [user.name]
  timespan: 5m
  condition: {lt: 3}
level: high
"""
        + GOOD_META,
        folder="correlations",
    )
    with pytest.raises(RuleLoadError, match="condition lt"):
        load(rules)


def test_sigmahq_rule_requires_curation(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    add(rules, "extra.yml", rule("  sel:\n    EventID: 4720\n  condition: sel", extra=""), folder="sigma/sigmahq")
    with pytest.raises(RuleLoadError, match="curation.yaml"):
        load(rules)


def test_duplicate_ids_and_names(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    add(rules, "x.yml", rule("  sel:\n    a: 1\n  condition: sel"))
    add(rules, "y.yml", rule("  sel:\n    a: 1\n  condition: sel"))
    with pytest.raises(RuleLoadError):
        load(rules)


def test_sequence_extension_validation(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    path = rules / "correlations" / "so-auth-003.yml"
    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace("then: so_helper_logon_success", "then: nothing_here"), encoding="utf-8")
    with pytest.raises(RuleLoadError, match="sequence.then"):
        load(rules)
    path.write_text(original.replace("  same:\n", "  bogus: 1\n  same:\n"), encoding="utf-8")
    with pytest.raises(RuleLoadError, match="unsupported sequence keys"):
        load(rules)
    path.write_text(original.replace("    - so_auth_002\n", "    - so_helper_logon_failed\n"), encoding="utf-8")
    with pytest.raises(RuleLoadError, match="first_any"):
        load(rules)
    path.write_text(
        original.replace("sentinelops_extension: sequence", "sentinelops_extension: magic"), encoding="utf-8"
    )
    with pytest.raises(RuleLoadError, match="unknown extension"):
        load(rules)


def test_threshold_overrides_apply(tmp_path: Path) -> None:
    cfg = DetectionConfig(
        thresholds={
            "SO-AUTH-001": ThresholdOverride(count=3, timespan_seconds=60),
            "SO-AUTH-003": ThresholdOverride(timespan_seconds=120),
        }
    )
    ruleset = load_ruleset(RULES_DIR, cfg, catalog_ids())
    corr = next(c for c in ruleset.correlations if c.meta.rule_id == "SO-AUTH-001")
    assert (corr.count, corr.timespan_seconds) == (3, 60)
    assert ruleset.sequences[0].timespan_seconds == 120


def test_timespan_parsing() -> None:
    assert _timespan_seconds("90s") == 90
    assert _timespan_seconds("2h") == 7200
    with pytest.raises(RuleLoadError):
        _timespan_seconds("soon")


def test_missing_pipeline(tmp_path: Path) -> None:
    rules = rules_copy(tmp_path)
    shutil.rmtree(rules / "pipelines")
    (rules / "pipelines").mkdir()
    with pytest.raises(RuleLoadError, match="pipeline"):
        load(rules)
