"""Transparent, additive case priority with evidence (spec 7.3).

Each factor contributes a fixed, configurable number of points and names the
events that justify it. The score is clamped to 0..100 and mapped to P1..P4.
Properties (tested with Hypothesis): adding an aggravating factor never lowers
the score, removing a mitigating factor never lowers it either.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any
from zoneinfo import ZoneInfo

from sentinelops.correlation.alerts import Alert
from sentinelops.detection.config import DetectionConfig
from sentinelops.normalize.identities import host_key, user_key
from sentinelops.normalize.schema import CanonicalEvent

LEVEL_ORDER = ("informational", "low", "medium", "high", "critical")
MAX_EVIDENCE = 5


@dataclass(frozen=True)
class Factor:
    code: str
    contribution: int
    label_de: str
    label_en: str
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "contribution": self.contribution,
            "label_de": self.label_de,
            "label_en": self.label_en,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class PriorityResult:
    score: int
    level: str  # P1..P4
    factors: tuple[Factor, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "level": self.level, "factors": [f.to_dict() for f in self.factors]}


@dataclass(frozen=True)
class RuleStats:
    resolved: int
    false_positives: int

    @property
    def rate(self) -> float:
        return self.false_positives / self.resolved if self.resolved else 0.0


def level_for(score: int, cfg: DetectionConfig) -> str:
    weights = cfg.priority
    if score >= weights.p1:
        return "P1"
    if score >= weights.p2:
        return "P2"
    if score >= weights.p3:
        return "P3"
    return "P4"


def _matches_any(name: str, patterns: Sequence[str]) -> bool:
    return any(fnmatchcase(name.casefold(), p.casefold()) for p in patterns)


def _evidence(ids: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(ids))[:MAX_EVIDENCE]


def compute_priority(
    alerts: Sequence[Alert],
    events_by_id: Mapping[str, CanonicalEvent],
    cfg: DetectionConfig,
    rule_stats: Mapping[str, RuleStats] | None = None,
    tz: ZoneInfo | None = None,
) -> PriorityResult:
    if not alerts:
        raise ValueError("a case has at least one alert")
    tz = tz or ZoneInfo("Europe/Berlin")
    weights = cfg.priority
    ordered = sorted(alerts, key=lambda a: (-LEVEL_ORDER.index(a.level), a.window_start, a.alert_id))
    top = ordered[0]
    factors: list[Factor] = [
        Factor(
            "max_severity",
            weights.severity[top.level],
            f"Höchster Regel-Schweregrad: {top.level} ({top.rule_id} {top.title_de})",
            f"Highest rule severity: {top.level} ({top.rule_id} {top.title})",
            _evidence(top.event_ids),
        )
    ]

    successes = [a for a in alerts if a.success_after_failures]
    if successes:
        first = min(successes, key=lambda a: (a.window_end, a.alert_id))
        success_id = str(first.explanation.get("success_event_id", first.event_ids[-1]))
        success = events_by_id.get(success_id)
        failures = int(first.explanation.get("preceding_alert", {}).get("failures_for_group", len(first.event_ids) - 1))
        ip = str(success.fields.get("source.ip", "?")) if success else "?"
        when = success.timestamp.astimezone(tz).strftime("%H:%M") if success else "?"
        factors.append(
            Factor(
                "success_after_failures",
                weights.success_after_failures,
                f"Erfolgreiche Anmeldung von {ip} um {when} nach {failures} Fehlschlägen",
                f"Successful logon from {ip} at {when} after {failures} failures",
                _evidence([success_id, *first.event_ids[:2]]),
            )
        )

    privileged: list[str] = []
    privileged_names: list[str] = []
    for alert in sorted(alerts, key=lambda a: (a.window_start, a.alert_id)):
        for eid in alert.event_ids:
            event = events_by_id.get(eid)
            if event is None:
                continue
            for name_field in ("user.name", "user.target.name"):
                name = event.fields.get(name_field)
                if isinstance(name, str) and _matches_any(user_key(name) or name, cfg.expected_privileged_accounts):
                    privileged.append(eid)
                    privileged_names.append(name)
            if event.action == "user-added-to-group" and _matches_any(
                str(event.fields.get("group.name", "")), cfg.privileged_groups
            ):
                privileged.append(eid)
                privileged_names.append(str(event.fields.get("user.target.name") or event.fields.get("user.name")))
            if event.action == "special-privileges-assigned":
                privileged.append(eid)
                privileged_names.append(str(event.fields.get("user.name")))
    if privileged:
        names = ", ".join(sorted(set(privileged_names)))
        factors.append(
            Factor(
                "privileged_account",
                weights.privileged_account,
                f"Privilegiertes Konto beteiligt: {names}",
                f"Privileged account involved: {names}",
                _evidence(privileged),
            )
        )

    critical: list[str] = []
    critical_names: set[str] = set()
    critical_set = {h.casefold() for h in cfg.critical_assets}
    for alert in sorted(alerts, key=lambda a: (a.window_start, a.alert_id)):
        for eid in alert.event_ids:
            event = events_by_id.get(eid)
            host = host_key(str(event.fields.get("host.name"))) if event else None
            if host and host in critical_set:
                critical.append(eid)
                critical_names.add(host)
    if critical:
        names = ", ".join(sorted(critical_names))
        factors.append(
            Factor(
                "critical_asset",
                weights.critical_asset,
                f"Kritisches Asset beteiligt: {names}",
                f"Critical asset involved: {names}",
                _evidence(critical),
            )
        )

    changes = [a for a in alerts if a.privilege_change]
    if changes:
        rules = ", ".join(sorted({a.rule_id for a in changes}))
        factors.append(
            Factor(
                "privilege_change",
                weights.privilege_change,
                f"Rechteänderung im Fall ({rules})",
                f"Privilege change in case ({rules})",
                _evidence([e for a in sorted(changes, key=lambda a: a.window_start) for e in a.event_ids]),
            )
        )

    tactics = sorted({t for a in alerts for t in a.tactics})
    if len(tactics) >= 2:
        bonus = min(weights.per_extra_tactic * (len(tactics) - 1), weights.max_tactic_bonus)
        factors.append(
            Factor(
                "attack_tactics",
                bonus,
                f"{len(tactics)} ATT&CK-Taktiken: {', '.join(tactics)}",
                f"{len(tactics)} ATT&CK tactics: {', '.join(tactics)}",
                _evidence([a.event_ids[0] for a in sorted(alerts, key=lambda a: a.window_start)]),
            )
        )

    if top.maturity == "experimental":
        factors.append(
            Factor(
                "experimental_rule",
                weights.experimental_penalty,
                f"Regel {top.rule_id} hat Reifegrad experimental",
                f"Rule {top.rule_id} is experimental",
                _evidence(top.event_ids),
            )
        )

    stats = (rule_stats or {}).get(top.rule_id)
    if stats is not None and stats.resolved >= 3 and stats.rate > 0:
        share = min(1.0, stats.rate / cfg.high_false_positive_rate)
        penalty = round(weights.max_false_positive_penalty * share)
        if penalty:
            factors.append(
                Factor(
                    "false_positive_rate",
                    penalty,
                    f"Historische Fehlalarmquote von {top.rule_id}: {stats.rate:.0%} "
                    f"({stats.false_positives}/{stats.resolved})",
                    f"Historical false positive rate of {top.rule_id}: {stats.rate:.0%}",
                    (),
                )
            )

    score = max(0, min(100, sum(f.contribution for f in factors)))
    return PriorityResult(score, level_for(score, cfg), tuple(factors))
