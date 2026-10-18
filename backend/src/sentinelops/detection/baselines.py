"""Baseline detector SO-AUTH-005 "unusual logon" (spec 6.4).

Deterministic and explainable: the profile of a user consists of the source
networks, target hosts and logon hours seen on *previous* days within the
learning window. Without enough history no alert is raised; the user is
reported as "baseline under construction" instead.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, timedelta
from zoneinfo import ZoneInfo

from sentinelops.correlation.alerts import Alert, alert_id, is_machine_account, merge_entities
from sentinelops.detection.config import BaselineConfig
from sentinelops.detection.sigma_loader import RuleMeta
from sentinelops.normalize.identities import canonical_ip, host_key, network_key, user_key
from sentinelops.normalize.schema import CanonicalEvent, format_timestamp


@dataclass
class _Day:
    networks: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    hours: list[float] = field(default_factory=list)
    logons: int = 0


@dataclass(frozen=True)
class BaselineResult:
    alerts: list[Alert]
    learning_users: list[str]  # users with logons but without sufficient history


def quantile(values: list[float], q: float) -> float:
    """Linear interpolation quantile (deterministic, no numpy)."""
    ordered = sorted(values)
    if not ordered:
        raise ValueError("quantile of empty list")
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def is_profile_logon(event: CanonicalEvent, cfg: BaselineConfig) -> bool:
    if event.action != "logon" or event.outcome != "success":
        return False
    name = event.fields.get("user.name")
    if not isinstance(name, str) or is_machine_account(name):
        return False
    logon_type = event.fields.get("logon.type")
    return logon_type is None or logon_type in cfg.logon_types


def _network(event: CanonicalEvent) -> str | None:
    ip = canonical_ip(str(event.fields.get("source.ip") or ""))
    if ip is None or ipaddress.ip_address(ip).is_loopback:
        return None
    return network_key(ip)


def evaluate(meta: RuleMeta, events: Iterable[CanonicalEvent], cfg: BaselineConfig, tz: ZoneInfo,
             hub_hosts: frozenset[str] = frozenset()) -> BaselineResult:
    """``hub_hosts`` (access gateways, DCs) never satisfy the ``new_host``
    criterion: every remote user passes them, a first use is not unusual."""
    holidays = {date.fromisoformat(d) for d in cfg.holidays}
    per_user: dict[str, list[CanonicalEvent]] = defaultdict(list)
    for event in events:
        if is_profile_logon(event, cfg):
            key = user_key(str(event.fields["user.name"]))
            if key:
                per_user[key].append(event)
    alerts: list[Alert] = []
    learning: list[str] = []
    for user in sorted(per_user):
        logons = sorted(per_user[user], key=lambda e: (e.timestamp, e.event_id))
        days: dict[date, _Day] = defaultdict(_Day)
        for event in logons:
            local = event.timestamp.astimezone(tz)
            day = days[local.date()]
            net = _network(event)
            if net:
                day.networks.add(net)
            host = host_key(str(event.fields.get("host.name") or ""))
            if host:
                day.hosts.add(host)
            day.hours.append(local.hour + local.minute / 60)
            day.logons += 1
        insufficient = False
        for event in logons:
            local = event.timestamp.astimezone(tz)
            today = local.date()
            window = [days[d] for d in sorted(days) if today - timedelta(days=cfg.learning_days) <= d < today]
            history_logons = sum(d.logons for d in window)
            if len(window) < cfg.min_active_days or history_logons < cfg.min_logons:
                insufficient = True
                continue
            networks = set().union(*(d.networks for d in window))
            hosts = set().union(*(d.hosts for d in window))
            hours = [h for d in window for h in d.hours]
            criteria: list[dict[str, str]] = []
            net = _network(event)
            if net and net not in networks:
                criteria.append({"criterion": "new_network", "detail": f"{net} not in {sorted(networks) or ['(none)']}"})
            host = host_key(str(event.fields.get("host.name") or ""))
            if host and host not in hosts and host not in hub_hosts:
                criteria.append({"criterion": "new_host", "detail": f"{host} not in {sorted(hosts)}"})
            low = quantile(hours, cfg.hour_quantile_low) - cfg.hour_margin
            high = quantile(hours, cfg.hour_quantile_high) + cfg.hour_margin
            hour = local.hour + local.minute / 60
            if not low <= hour <= high:
                criteria.append({"criterion": "unusual_hour",
                                 "detail": f"{local:%H:%M} outside {_hm(low)}-{_hm(high)} ({tz.key})"})
            if today.weekday() >= 5 or today in holidays:
                criteria.append({"criterion": "off_day", "detail": f"{today.isoformat()} weekend/holiday"})
            if len(criteria) < cfg.min_criteria:
                continue
            explanation = {
                "type": "baseline",
                "criteria": criteria,
                "min_criteria": cfg.min_criteria,
                "history": {"days": len(window), "logons": history_logons,
                            "learning_days": cfg.learning_days},
                "event_time": format_timestamp(event.timestamp),
            }
            alerts.append(Alert(
                alert_id=alert_id(meta.rule_id, meta.version, [event.event_id], event.timestamp),
                rule_id=meta.rule_id, rule_version=meta.version, rule_hash=meta.content_hash, kind="baseline",
                title=meta.title, title_de=meta.title_de, level=meta.level, maturity=meta.maturity,
                tactics=meta.tactics, techniques=meta.techniques, event_ids=(event.event_id,),
                window_start=event.timestamp, window_end=event.timestamp, group_key=(("user.name", user),),
                entities=merge_entities([event]), explanation=explanation,
                thresholds={"min_criteria": cfg.min_criteria, "learning_days": cfg.learning_days,
                            "min_active_days": cfg.min_active_days, "min_logons": cfg.min_logons},
            ))
        if insufficient:
            learning.append(user)
    return BaselineResult(alerts, learning)


def _hm(hours: float) -> str:
    hours = max(0.0, min(hours, 23.99))
    return f"{int(hours):02d}:{round((hours % 1) * 60) % 60:02d}"
