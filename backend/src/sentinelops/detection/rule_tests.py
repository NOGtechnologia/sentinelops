"""Rule test runner (spec 15.3): ``rules/tests/<RULE_ID>.yaml``.

Each file holds cases with a list of event specifications. Every alerting
rule needs >= 2 positive (``expect: alert``) and >= 2 negative cases; a rule
without tests fails the check. Cases are evaluated with the complete rule set
(including exceptions), exactly as in production.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml

from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.engine import run_detection
from sentinelops.detection.exceptions import RuleException
from sentinelops.detection.sigma_loader import RuleSet
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.identities import canonical_ip
from sentinelops.normalize.schema import CanonicalEvent

_DURATION = re.compile(r"(\d+)([dhms])")
_UNITS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
MIN_POSITIVE = 2
MIN_NEGATIVE = 2


def parse_duration(text: str | int | None) -> timedelta:
    if text is None:
        return timedelta(0)
    value = str(text).strip()
    if not re.fullmatch(r"(\d+[dhms])+", value):
        raise ValueError(f"invalid duration {text!r}")
    return timedelta(seconds=sum(int(n) * _UNITS[u] for n, u in _DURATION.findall(value)))


@dataclass(frozen=True)
class CaseResult:
    rule_id: str
    name: str
    expect: str
    alerts: int
    passed: bool


def build_events(case: dict[str, Any], case_key: str) -> list[CanonicalEvent]:
    start = datetime.fromisoformat(str(case["start"]).replace("Z", "+00:00"))
    events: list[CanonicalEvent] = []
    for spec_index, spec in enumerate(case.get("events") or []):
        offset = parse_duration(spec.get("offset"))
        repeat = int(spec.get("repeat", 1))
        every = parse_duration(spec.get("every"))
        vary: dict[str, list[Any]] = spec.get("vary") or {}
        for i in range(repeat):
            fields = dict(spec.get("fields") or {})
            for name, values in vary.items():
                fields[name] = values[i % len(values)]
            if "source.ip" in fields:
                fields["source.ip"] = canonical_ip(str(fields["source.ip"])) or fields["source.ip"]
            fields.setdefault("event.outcome", "unknown")
            when = start + offset + every * i
            event_id = stable_hash("rule-test", case_key, spec_index, i)
            events.append(CanonicalEvent(event_id, when, fields, dict(spec.get("original") or {})))
    return events


def iter_test_files(tests_dir: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    for path in sorted(tests_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "rule_id" not in data:
            raise ValueError(f"{path.name}: rule_id missing")
        yield path, data


def run_rule_tests(
    tests_dir: Path, ruleset: RuleSet, config: DetectionConfig, exceptions: list[RuleException]
) -> tuple[list[CaseResult], list[str]]:
    """Return case results and coverage problems (rules without enough tests)."""
    results: list[CaseResult] = []
    counts: dict[str, list[int]] = {rule_id: [0, 0] for rule_id in ruleset.alerting_rule_ids()}
    problems: list[str] = []
    tz = ZoneInfo("Europe/Berlin")
    for path, data in iter_test_files(tests_dir):
        rule_id = str(data["rule_id"])
        if rule_id not in counts:
            problems.append(f"{path.name}: tests for unknown rule {rule_id}")
            continue
        for case in data.get("cases") or []:
            expect = case.get("expect")
            if expect not in ("alert", "no_alert"):
                problems.append(f"{path.name}: case {case.get('name')!r} has invalid expect {expect!r}")
                continue
            events = build_events(case, f"{rule_id}/{case['name']}")
            now = max(e.timestamp for e in events)
            detection = run_detection(events, ruleset, config, exceptions, now, tz)
            alerts = [a for a in detection.active_alerts if a.rule_id == rule_id]
            passed = bool(alerts) if expect == "alert" else not alerts
            counts[rule_id][0 if expect == "alert" else 1] += 1
            results.append(CaseResult(rule_id, str(case["name"]), expect, len(alerts), passed))
    for rule_id, (positive, negative) in sorted(counts.items()):
        if positive < MIN_POSITIVE or negative < MIN_NEGATIVE:
            problems.append(
                f"{rule_id}: needs >= {MIN_POSITIVE} positive and >= {MIN_NEGATIVE} negative tests "
                f"(has {positive}/{negative})"
            )
    return results, problems
