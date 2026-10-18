"""Recommended next steps of a case from the deterministic playbook catalogue."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sentinelops.correlation.alerts import Alert
from sentinelops.detection.sigma_loader import RuleMeta
from sentinelops.investigation.catalog import PlaybookStep
from sentinelops.normalize.schema import CanonicalEvent


@dataclass(frozen=True)
class Recommendation:
    step_id: str
    action: bool
    title_de: str
    title_en: str
    reason_rules: tuple[str, ...]
    targets: dict[str, list[str]]
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action": self.action,
            "title_de": self.title_de,
            "title_en": self.title_en,
            "reason_rules": list(self.reason_rules),
            "targets": self.targets,
            "evidence": list(self.evidence),
        }


def recommend(
    alerts: Sequence[Alert],
    events_by_id: Mapping[str, CanonicalEvent],
    metas: Mapping[str, RuleMeta],
    catalog: Mapping[str, PlaybookStep],
) -> list[Recommendation]:
    reasons: dict[str, set[str]] = {}
    evidence: dict[str, list[str]] = {}
    for alert in sorted(alerts, key=lambda a: (a.window_start, a.alert_id)):
        meta = metas.get(alert.rule_id)
        if meta is None:
            continue
        for step in meta.playbooks:
            reasons.setdefault(step, set()).add(alert.rule_id)
            evidence.setdefault(step, []).append(alert.event_ids[0])
    users = sorted({e.display for a in alerts for e in a.entities if e.type == "user"}, key=str.casefold)
    hosts = sorted({e.display for a in alerts for e in a.entities if e.type == "host"}, key=str.casefold)
    ips = sorted({e.display for a in alerts for e in a.entities if e.type == "ip"})
    groups = sorted({
        str(events_by_id[eid].fields["group.name"])
        for a in alerts for eid in a.event_ids
        if eid in events_by_id and events_by_id[eid].fields.get("group.name")
    })
    available = {"user": users, "host": hosts, "ip": ips, "group": groups}
    out: list[Recommendation] = []
    for step_id in sorted(reasons, key=lambda s: (catalog[s].priority, s)):
        step = catalog[step_id]
        out.append(Recommendation(
            step_id=step.id,
            action=step.action,
            title_de=step.title_de,
            title_en=step.title_en,
            reason_rules=tuple(sorted(reasons[step_id])),
            targets={p: available.get(p, []) for p in step.parameters},
            evidence=tuple(dict.fromkeys(evidence[step_id]))[:5],
        ))
    return out
