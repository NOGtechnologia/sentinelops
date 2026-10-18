"""Evaluation of Sigma correlation rules and the ``sequence`` extension.

Semantics (ADR-0003, docs/detection-catalog.md):

* **event_count / value_count** - matches of the referenced rules are grouped
  by the ``group-by`` fields and split into *bursts* (a gap larger than the
  timespan ends a burst). A burst raises one alert if any sliding window of
  ``timespan`` inside it satisfies the condition. The alert contains *all*
  events of the burst. Bursts are independent of processing order and of
  batch boundaries, which makes alert ids stable.
* **temporal / temporal_ordered** - all referenced rules must match for the
  same group within ``timespan`` (in list order for ``temporal_ordered``).
* **sequence** (extension) - a match of the ``then`` rule for a group that a
  ``first_any`` correlation alert covered shortly before.

Group values are normalised (user names case-insensitively without domain,
host short names, canonical IPs) so ``MUSTERFIRMA\\Erika`` and ``erika``
form one group.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sentinelops.correlation.alerts import Alert, alert_id, merge_entities
from sentinelops.detection.sigma_loader import CorrelationRule, RuleMeta, SequenceRule
from sentinelops.normalize.identities import canonical_ip, host_key, user_key
from sentinelops.normalize.schema import CanonicalEvent, format_timestamp


@dataclass(frozen=True, slots=True)
class BaseMatch:
    rule: str
    event: CanonicalEvent
    explanation: dict[str, Any]


def normalise_group_value(field: str, value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = str(value)
    if field.startswith("user.") and field.endswith(".name"):
        return user_key(text)
    if field in ("host.name", "source.host"):
        return host_key(text)
    if field.endswith(".ip"):
        return canonical_ip(text) or text.casefold()
    return text.casefold()


def group_key(event: CanonicalEvent, fields: Sequence[str]) -> tuple[str, ...] | None:
    values: list[str] = []
    for name in fields:
        value = normalise_group_value(name, event.get(name))
        if value is None:
            return None
        values.append(value)
    return tuple(values)


def _bursts(matches: list[BaseMatch], gap: timedelta) -> list[list[BaseMatch]]:
    bursts: list[list[BaseMatch]] = []
    for match in matches:
        if bursts and match.event.timestamp - bursts[-1][-1].event.timestamp <= gap:
            bursts[-1].append(match)
        else:
            bursts.append([match])
    return bursts


_OPS: dict[str, Callable[[int, int], bool]] = {
    "gte": lambda value, threshold: value >= threshold,
    "gt": lambda value, threshold: value > threshold,
    "eq": lambda value, threshold: value == threshold,
}


def _max_window(burst: list[BaseMatch], span: timedelta, value_field: str | None) -> tuple[int, datetime, datetime]:
    """Largest count (or distinct value count) in any window of length ``span``."""
    best, best_start, best_end = 0, burst[0].event.timestamp, burst[0].event.timestamp
    left = 0
    counts: dict[str, int] = defaultdict(int)
    for right, match in enumerate(burst):
        if value_field is not None:
            value = normalise_group_value(value_field, match.event.get(value_field))
            if value is not None:
                counts[value] += 1
        while match.event.timestamp - burst[left].event.timestamp > span:
            if value_field is not None:
                old = normalise_group_value(value_field, burst[left].event.get(value_field))
                if old is not None:
                    counts[old] -= 1
                    if counts[old] == 0:
                        del counts[old]
            left += 1
        current = len(counts) if value_field is not None else right - left + 1
        if current > best:
            best, best_start, best_end = current, burst[left].event.timestamp, match.event.timestamp
    return best, best_start, best_end


def _make_alert(meta: RuleMeta, anchor: Sequence[Any], events: list[CanonicalEvent], explanation: dict[str, Any],
                key: tuple[tuple[str, str], ...], thresholds: dict[str, Any], related: tuple[str, ...] = ()) -> Alert:
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    start, end = ordered[0].timestamp, ordered[-1].timestamp
    return Alert(
        alert_id=alert_id(meta.rule_id, meta.version, anchor, start),
        rule_id=meta.rule_id,
        rule_version=meta.version,
        rule_hash=meta.content_hash,
        kind=meta.kind,
        title=meta.title,
        title_de=meta.title_de,
        level=meta.level,
        maturity=meta.maturity,
        tactics=meta.tactics,
        techniques=meta.techniques,
        event_ids=tuple(dict.fromkeys(e.event_id for e in ordered)),
        window_start=start,
        window_end=end,
        group_key=key,
        entities=merge_entities(ordered),
        explanation=explanation,
        thresholds=thresholds,
        related_alert_ids=related,
        privilege_change=meta.privilege_change,
        success_after_failures=meta.success_after_failures,
    )


def evaluate_count(rule: CorrelationRule, matches: list[BaseMatch]) -> list[Alert]:
    """event_count and value_count."""
    if rule.op not in _OPS or rule.count is None:
        raise ValueError(f"{rule.meta.rule_id}: unsupported correlation condition {rule.op}")
    check = _OPS[rule.op]
    span = timedelta(seconds=rule.timespan_seconds)
    groups: dict[tuple[str, ...], list[BaseMatch]] = defaultdict(list)
    for match in matches:
        key = group_key(match.event, rule.group_by)
        if key is not None:
            groups[key].append(match)
    alerts: list[Alert] = []
    thresholds = {"count": rule.count, "op": rule.op, "timespan_seconds": rule.timespan_seconds}
    if rule.value_field:
        thresholds["field"] = rule.value_field
    for key in sorted(groups):
        ordered = sorted(groups[key], key=lambda m: (m.event.timestamp, m.event.event_id))
        unique = list({m.event.event_id: m for m in ordered}.values())
        for burst in _bursts(unique, span):
            value, w_start, w_end = _max_window(burst, span, rule.value_field if rule.type == "value_count" else None)
            if not check(value, rule.count):
                continue
            named_key = tuple(zip(rule.group_by, key, strict=True))
            explanation = {
                "type": rule.type,
                "condition": f"{rule.op} {rule.count}" + (f" distinct {rule.value_field}" if rule.value_field else ""),
                "observed": value,
                "timespan_seconds": rule.timespan_seconds,
                "densest_window": {"start": format_timestamp(w_start), "end": format_timestamp(w_end)},
                "group_by": {k: v for k, v in named_key},
                "events_in_burst": len(burst),
                "referenced_rules": list(rule.rules),
            }
            alerts.append(_make_alert(rule.meta, [list(key), burst[0].event.event_id], [m.event for m in burst],
                                      explanation, named_key, thresholds))
    return alerts


def evaluate_temporal(rule: CorrelationRule, matches_by_rule: dict[str, list[BaseMatch]]) -> list[Alert]:
    span = timedelta(seconds=rule.timespan_seconds)
    ordered_mode = rule.type == "temporal_ordered"
    tagged: list[tuple[datetime, str, int, BaseMatch]] = []
    for index, name in enumerate(rule.rules):
        for match in matches_by_rule.get(name, []):
            tagged.append((match.event.timestamp, match.event.event_id, index, match))
    tagged.sort(key=lambda t: (t[0], t[1], t[2]))
    state: dict[tuple[str, ...], dict[int, BaseMatch]] = defaultdict(dict)
    alerts: list[Alert] = []
    last_rule = len(rule.rules) - 1
    for timestamp, _, index, match in tagged:
        key = group_key(match.event, rule.group_by)
        if key is None:
            continue
        seen = state[key]
        for old_index in [i for i, m in seen.items() if timestamp - m.event.timestamp > span]:
            del seen[old_index]
        if ordered_mode:
            if index > 0 and (index - 1) not in seen:
                continue
            seen[index] = match
            complete = index == last_rule
        else:
            seen[index] = match
            complete = len(seen) == len(rule.rules)
        if not complete:
            continue
        chain = [seen[i] for i in sorted(seen)]
        named_key = tuple(zip(rule.group_by, key, strict=True))
        explanation = {
            "type": rule.type,
            "condition": " -> ".join(rule.rules) if ordered_mode else " & ".join(rule.rules),
            "timespan_seconds": rule.timespan_seconds,
            "group_by": {k: v for k, v in named_key},
            "chain": [{"rule": m.rule, "event_id": m.event.event_id, "time": format_timestamp(m.event.timestamp)} for m in chain],
        }
        alerts.append(_make_alert(rule.meta, [list(key), *[m.event.event_id for m in chain]], [m.event for m in chain],
                                  explanation, named_key, {"timespan_seconds": rule.timespan_seconds}))
        state[key] = {}
    return alerts


def evaluate_sequence(rule: SequenceRule, first_alerts: list[Alert], then_matches: list[BaseMatch],
                      events_by_id: dict[str, CanonicalEvent]) -> list[Alert]:
    span = timedelta(seconds=rule.timespan_seconds)
    coverage: dict[tuple[str, ...], list[tuple[Alert, list[CanonicalEvent]]]] = defaultdict(list)
    for alert in sorted(first_alerts, key=lambda a: (a.window_start, a.alert_id)):
        per_key: dict[tuple[str, ...], list[CanonicalEvent]] = defaultdict(list)
        for event_id in alert.event_ids:
            event = events_by_id[event_id]
            key = group_key(event, rule.group_by)
            if key is not None:
                per_key[key].append(event)
        for key, events in per_key.items():
            coverage[key].append((alert, events))
    used: set[tuple[str, tuple[str, ...]]] = set()
    alerts: list[Alert] = []
    for match in sorted(then_matches, key=lambda m: (m.event.timestamp, m.event.event_id)):
        key = group_key(match.event, rule.group_by)
        if key is None:
            continue
        same_values = group_key(match.event, rule.same) if rule.same else ()
        if same_values is None:
            continue
        for first, events in coverage.get(key, []):
            t = match.event.timestamp
            if not (first.window_start <= t <= first.window_end + span):
                continue
            if rule.same and not any(group_key(e, rule.same) == same_values for e in events):
                continue
            marker = (first.alert_id, key)
            if marker in used:
                continue
            used.add(marker)
            named_key = tuple(zip(rule.group_by, key, strict=True))
            failures = len(events)
            explanation = {
                "type": "sequence",
                "condition": f"({' | '.join(rule.first_any)}) -> {rule.then}"
                + (f" with same {', '.join(rule.same)}" if rule.same else ""),
                "timespan_seconds": rule.timespan_seconds,
                "group_by": {k: v for k, v in named_key},
                "preceding_alert": {"alert_id": first.alert_id, "rule_id": first.rule_id, "failures_for_group": failures},
                "success_event_id": match.event.event_id,
                "success_time": format_timestamp(t),
                "matched": match.explanation.get("matched", []),
            }
            alerts.append(_make_alert(rule.meta, [list(key), match.event.event_id], [*events, match.event], explanation,
                                      named_key, {"timespan_seconds": rule.timespan_seconds}, related=(first.alert_id,)))
    return alerts
