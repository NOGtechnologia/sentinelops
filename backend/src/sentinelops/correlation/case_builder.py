"""Case building (spec 7.2).

Alerts sharing a non-hub entity (user, host, source IP) whose time windows
are at most ``W`` apart belong to the same case - transitively (connected
components). The result is independent of the input order. Case ids are
derived from the first alert of the case.

State handling (closed cases stay unchanged, manual merges/splits) is passed
in as *pinned* assignments so this module stays free of I/O.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sentinelops.correlation.alerts import Alert, Entity, event_entities
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.schema import CanonicalEvent


@dataclass(frozen=True)
class CaseDraft:
    case_id: str
    alert_ids: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    entities: tuple[Entity, ...]
    related_case_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class HubInfo:
    key: str
    type: str
    reason: str  # configured | distinct_users>=N


def case_id_for(first_alert_id: str) -> str:
    return stable_hash("case", first_alert_id)


class _UnionFind:
    def __init__(self, items: Iterable[str]) -> None:
        self.parent = {i: i for i in items}

    def find(self, item: str) -> str:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic: the lexicographically smaller root wins
            if rb < ra:
                ra, rb = rb, ra
            self.parent[rb] = ra


def detect_hubs(events: Iterable[CanonicalEvent], configured: Sequence[str], min_distinct_users: int) -> list[HubInfo]:
    """Configured hubs plus hosts/IPs seen with many distinct users (suggestion).

    Only *successful* activity counts: an attacker address that fails to log
    on with many accounts (password spraying) must never become a hub.
    """
    users_per_entity: dict[tuple[str, str], set[str]] = defaultdict(set)
    for event in events:
        if event.outcome != "success":
            continue
        entities = event_entities(event)
        users = {e.key for e in entities if e.type == "user"}
        if not users:
            continue
        for entity in entities:
            if entity.type in ("host", "ip"):
                users_per_entity[(entity.type, entity.key)] |= users
    hubs = {key.casefold(): HubInfo(key.casefold(), "any", "configured") for key in configured}
    for (etype, key), users in sorted(users_per_entity.items()):
        if len(users) >= min_distinct_users and key not in hubs:
            hubs[key] = HubInfo(key, etype, f"distinct_users>={min_distinct_users} ({len(users)})")
    return [hubs[k] for k in sorted(hubs)]


def _components(alerts: Sequence[Alert], hubs: frozenset[str], window: timedelta) -> _UnionFind:
    uf = _UnionFind(a.alert_id for a in alerts)
    by_entity: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for alert in alerts:
        for entity in alert.entities:
            if entity.key not in hubs:
                by_entity[(entity.type, entity.key)].append(alert)
    for key in sorted(by_entity):
        items = sorted(by_entity[key], key=lambda a: (a.window_start, a.alert_id))
        anchor = items[0]
        max_end = anchor.window_end
        for alert in items[1:]:
            if alert.window_start - max_end <= window:
                uf.union(anchor.alert_id, alert.alert_id)
                max_end = max(max_end, alert.window_end)
            else:
                anchor = alert
                max_end = alert.window_end
    return uf


def build_cases(
    alerts: Sequence[Alert],
    hubs: Iterable[str],
    window: timedelta,
    pinned: Mapping[str, str] | None = None,
    closed_case_ids: frozenset[str] = frozenset(),
) -> list[CaseDraft]:
    """Group active alerts into cases.

    ``pinned`` maps alert ids to existing case ids (stored assignments and
    manual merges/splits). Unpinned alerts that connect to an *open* pinned
    case join it; if they only connect to *closed* cases they form a new case
    that references them (``related_case_ids``).
    """
    pinned = dict(pinned or {})
    active = [a for a in alerts if not a.suppressed]
    by_id = {a.alert_id: a for a in active}
    uf = _components(active, frozenset(h.casefold() for h in hubs), window)
    components: dict[str, list[Alert]] = defaultdict(list)
    for alert in active:
        components[uf.find(alert.alert_id)].append(alert)

    assignment: dict[str, str] = {}
    related: dict[str, set[str]] = defaultdict(set)
    for members in components.values():
        members.sort(key=lambda a: (a.window_start, a.alert_id))
        pinned_cases = sorted({pinned[a.alert_id] for a in members if a.alert_id in pinned})
        open_cases = [c for c in pinned_cases if c not in closed_case_ids]
        free = [a for a in members if a.alert_id not in pinned]
        for alert in members:
            if alert.alert_id in pinned:
                assignment[alert.alert_id] = pinned[alert.alert_id]
        if not free:
            continue
        if open_cases:
            # earliest open case (by its first alert) receives new alerts
            target = min(open_cases, key=lambda c: min((by_id[a].window_start, a) for a, cid in pinned.items()
                                                      if cid == c and a in by_id))
        else:
            target = case_id_for(free[0].alert_id)
            related[target].update(c for c in pinned_cases if c in closed_case_ids)
        for alert in free:
            assignment[alert.alert_id] = target

    grouped: dict[str, list[Alert]] = defaultdict(list)
    for alert_id_, case in assignment.items():
        grouped[case].append(by_id[alert_id_])
    drafts: list[CaseDraft] = []
    for case, members in grouped.items():
        members.sort(key=lambda a: (a.window_start, a.alert_id))
        entities: dict[tuple[str, str], Entity] = {}
        for alert in members:
            for entity in alert.entities:
                entities.setdefault((entity.type, entity.key), entity)
        drafts.append(CaseDraft(
            case_id=case,
            alert_ids=tuple(a.alert_id for a in members),
            window_start=members[0].window_start,
            window_end=max(a.window_end for a in members),
            entities=tuple(sorted(entities.values())),
            related_case_ids=tuple(sorted(related.get(case, ()))),
        ))
    return sorted(drafts, key=lambda d: (d.window_start, d.case_id))
