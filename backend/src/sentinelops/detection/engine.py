"""Detection engine: base rules -> single-event alerts, correlations,
sequences and baselines -> exceptions. Pure and deterministic: the result
depends only on the events, the rule set, the config and the injected time.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo

from sentinelops.correlation.alerts import Alert, alert_id, merge_entities
from sentinelops.detection import baselines
from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.correlation import BaseMatch, evaluate_count, evaluate_sequence, evaluate_temporal
from sentinelops.detection.exceptions import RuleException, apply_exceptions
from sentinelops.detection.sigma_loader import BaseRule, RuleSet
from sentinelops.normalize.schema import CanonicalEvent


@dataclass
class DetectionResult:
    alerts: list[Alert]
    base_match_counts: dict[str, int] = field(default_factory=dict)
    learning_users: list[str] = field(default_factory=list)

    @property
    def active_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if not a.suppressed]

    def suspicious_event_ids(self) -> set[str]:
        return {eid for a in self.active_alerts for eid in a.event_ids}


class _RuleIndex:
    def __init__(self, rules: Iterable[BaseRule]) -> None:
        self.ungated: list[BaseRule] = []
        self.gated: dict[str, dict[str, list[BaseRule]]] = defaultdict(lambda: defaultdict(list))
        for rule in sorted(rules, key=lambda r: r.name):
            gate = rule.detection.gate
            if gate is None:
                self.ungated.append(rule)
                continue
            field_name, values = gate
            for value in sorted(values):
                self.gated[field_name][value].append(rule)

    def candidates(self, event: CanonicalEvent) -> list[BaseRule]:
        out = list(self.ungated)
        for field_name, table in self.gated.items():
            value = event.fields.get(field_name)
            if value is not None:
                out.extend(table.get(str(value).casefold(), ()))
        return out


def _single_alert(rule: BaseRule, match: BaseMatch) -> Alert:
    meta = rule.meta
    assert meta is not None
    event = match.event
    return Alert(
        alert_id=alert_id(meta.rule_id, meta.version, [event.event_id], event.timestamp),
        rule_id=meta.rule_id,
        rule_version=meta.version,
        rule_hash=meta.content_hash,
        kind="single",
        title=meta.title,
        title_de=meta.title_de,
        level=meta.level,
        maturity=meta.maturity,
        tactics=meta.tactics,
        techniques=meta.techniques,
        event_ids=(event.event_id,),
        window_start=event.timestamp,
        window_end=event.timestamp,
        group_key=(),
        entities=merge_entities([event]),
        explanation={"type": "single", **match.explanation},
        privilege_change=meta.privilege_change,
        success_after_failures=meta.success_after_failures,
    )


def run_detection(
    events: Sequence[CanonicalEvent],
    ruleset: RuleSet,
    config: DetectionConfig,
    exceptions: Sequence[RuleException],
    now: datetime,
    tz: ZoneInfo,
) -> DetectionResult:
    unique = {e.event_id: e for e in events}  # duplicates never count twice
    ordered = sorted(unique.values(), key=lambda e: (e.timestamp, e.event_id))
    index = _RuleIndex(ruleset.base_rules.values())
    matches: dict[str, list[BaseMatch]] = defaultdict(list)
    for event in ordered:
        get = event.get
        for rule in index.candidates(event):
            explanation = rule.detection.match(get)
            if explanation is not None:
                matches[rule.name].append(BaseMatch(rule.name, event, explanation.to_dict()))

    alerts: list[Alert] = []
    for name in sorted(matches):
        rule = ruleset.base_rules[name]
        if rule.meta is not None:
            alerts.extend(_single_alert(rule, m) for m in matches[name])

    corr_alerts: dict[str, list[Alert]] = {}
    for corr in sorted(ruleset.correlations, key=lambda c: c.meta.rule_id):
        if corr.type in ("event_count", "value_count"):
            combined = [m for r in corr.rules for m in matches.get(r, [])]
            produced = evaluate_count(corr, combined)
        else:
            produced = evaluate_temporal(corr, {r: matches.get(r, []) for r in corr.rules})
        corr_alerts[corr.meta.name or corr.meta.rule_id] = produced
        alerts.extend(produced)

    alerts = apply_exceptions(alerts, exceptions, unique, now)
    active_by_name: dict[str, list[Alert]] = defaultdict(list)
    names_by_rule_id = {c.meta.rule_id: (c.meta.name or c.meta.rule_id) for c in ruleset.correlations}
    for alert in alerts:
        if not alert.suppressed and alert.rule_id in names_by_rule_id:
            active_by_name[names_by_rule_id[alert.rule_id]].append(alert)

    late: list[Alert] = []
    for seq in sorted(ruleset.sequences, key=lambda s: s.meta.rule_id):
        firsts = [a for name in seq.first_any for a in active_by_name.get(name, [])]
        late.extend(evaluate_sequence(seq, firsts, matches.get(seq.then, []), unique))
    learning: list[str] = []
    for baseline in sorted(ruleset.baselines, key=lambda b: b.meta.rule_id):
        result = baselines.evaluate(baseline.meta, ordered, config.baseline, tz, frozenset(config.hub_entities))
        late.extend(result.alerts)
        learning.extend(result.learning_users)
    alerts.extend(apply_exceptions(late, exceptions, unique, now))

    by_id: dict[str, Alert] = {}
    for alert in alerts:
        by_id.setdefault(alert.alert_id, alert)
    final = sorted(by_id.values(), key=lambda a: (a.window_start, a.rule_id, a.alert_id))
    return DetectionResult(
        alerts=final,
        base_match_counts={name: len(items) for name, items in sorted(matches.items())},
        learning_users=sorted(set(learning)),
    )
