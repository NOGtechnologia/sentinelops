"""Aggregate report for a period (spec 10): cases by priority, top rules,
false positive rates and handling times."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from statistics import median
from typing import Any

from sentinelops.normalize.schema import format_timestamp


@dataclass(frozen=True)
class CaseFacts:
    case_id: str
    priority: str
    status: str
    rule_ids: tuple[str, ...]
    created_at: datetime
    first_action_at: datetime | None
    resolved_at: datetime | None


def build_aggregate(cases: Sequence[CaseFacts], start: datetime, end: datetime, created_at: datetime) -> dict[str, Any]:
    in_period = sorted((c for c in cases if start <= c.created_at < end), key=lambda c: (c.created_at, c.case_id))
    by_priority = Counter(c.priority for c in in_period)
    by_status = Counter(c.status for c in in_period)
    rules = Counter(r for c in in_period for r in set(c.rule_ids))
    resolved_rules: Counter[str] = Counter()
    fp_rules: Counter[str] = Counter()
    for case in in_period:
        if case.status.startswith("resolved"):
            for rule in set(case.rule_ids):
                resolved_rules[rule] += 1
                if case.status == "resolved_false_positive":
                    fp_rules[rule] += 1
    to_action = [(c.first_action_at - c.created_at).total_seconds() / 60 for c in in_period if c.first_action_at]
    to_resolve = [(c.resolved_at - c.created_at).total_seconds() / 60 for c in in_period if c.resolved_at]
    return {
        "period": {"start": format_timestamp(start), "end": format_timestamp(end)},
        "created_at": format_timestamp(created_at),
        "cases": len(in_period),
        "by_priority": {p: by_priority.get(p, 0) for p in ("P1", "P2", "P3", "P4")},
        "by_status": dict(sorted(by_status.items())),
        "top_rules": [
            {"rule_id": r, "cases": n} for r, n in sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        ],
        "false_positive_rate": {r: round(fp_rules[r] / resolved_rules[r], 4) for r in sorted(resolved_rules)},
        "median_minutes_to_first_action": round(median(to_action), 1) if to_action else None,
        "median_minutes_to_resolution": round(median(to_resolve), 1) if to_resolve else None,
    }
