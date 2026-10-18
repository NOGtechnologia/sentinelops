"""End-to-end analysis without I/O: events -> alerts -> cases -> priority.

Used by the worker (with the database as source/sink), the CLI, the
benchmark and the acceptance tests - one code path for all of them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo

from sentinelops.correlation.alerts import Alert
from sentinelops.correlation.case_builder import CaseDraft, HubInfo, build_cases, detect_hubs
from sentinelops.correlation.priority import PriorityResult, RuleStats, compute_priority
from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.engine import DetectionResult, run_detection
from sentinelops.detection.exceptions import RuleException
from sentinelops.detection.sigma_loader import RuleSet
from sentinelops.investigation.catalog import PlaybookStep
from sentinelops.investigation.recommendations import Recommendation, recommend
from sentinelops.normalize.schema import CanonicalEvent


@dataclass(frozen=True)
class CaseAnalysis:
    draft: CaseDraft
    alerts: tuple[Alert, ...]
    priority: PriorityResult
    recommendations: tuple[Recommendation, ...]
    title: str
    title_de: str

    @property
    def case_id(self) -> str:
        return self.draft.case_id


@dataclass
class AnalysisResult:
    detection: DetectionResult
    hubs: list[HubInfo]
    cases: list[CaseAnalysis]
    events_by_id: dict[str, CanonicalEvent] = field(default_factory=dict)

    def case_of_alert(self) -> dict[str, str]:
        return {aid: c.case_id for c in self.cases for aid in c.draft.alert_ids}


def case_title(alerts: Sequence[Alert]) -> tuple[str, str]:
    """Title from the most severe alert plus the main entity."""
    levels = ("informational", "low", "medium", "high", "critical")
    top = sorted(alerts, key=lambda a: (-levels.index(a.level), a.window_start, a.alert_id))[0]
    users = [e.display for e in top.entities if e.type == "user"]
    hosts = [e.display for e in top.entities if e.type == "host"]
    subject = users[0] if len(users) == 1 else (f"{len(users)} Konten" if users else (hosts[0] if hosts else ""))
    subject_en = users[0] if len(users) == 1 else (f"{len(users)} accounts" if users else (hosts[0] if hosts else ""))
    more = len(alerts) - 1
    suffix_de = f" (+{more} weitere Alarme)" if more > 1 else (" (+1 weiterer Alarm)" if more == 1 else "")
    suffix_en = f" (+{more} more alerts)" if more > 1 else (" (+1 more alert)" if more == 1 else "")
    return (f"{top.title}: {subject_en}{suffix_en}".strip(": "), f"{top.title_de}: {subject}{suffix_de}".strip(": "))


def analyze(
    events: Sequence[CanonicalEvent],
    ruleset: RuleSet,
    config: DetectionConfig,
    exceptions: Sequence[RuleException],
    catalog: Mapping[str, PlaybookStep],
    now: datetime,
    tz: ZoneInfo,
    pinned: Mapping[str, str] | None = None,
    closed_case_ids: frozenset[str] = frozenset(),
    rule_stats: Mapping[str, RuleStats] | None = None,
) -> AnalysisResult:
    events_by_id = {e.event_id: e for e in events}
    detection = run_detection(list(events_by_id.values()), ruleset, config, exceptions, now, tz)
    hubs = detect_hubs(events_by_id.values(), config.hub_entities, config.hub_min_distinct_users)
    drafts = build_cases(detection.active_alerts, [h.key for h in hubs], config.case_window, pinned, closed_case_ids)
    alerts_by_id = {a.alert_id: a for a in detection.alerts}
    cases: list[CaseAnalysis] = []
    for draft in drafts:
        alerts = tuple(alerts_by_id[aid] for aid in draft.alert_ids)
        title_en, title_de = case_title(alerts)
        cases.append(CaseAnalysis(
            draft=draft,
            alerts=alerts,
            priority=compute_priority(alerts, events_by_id, config, rule_stats, tz),
            recommendations=tuple(recommend(alerts, events_by_id, ruleset.metas, catalog)),
            title=title_en,
            title_de=title_de,
        ))
    return AnalysisResult(detection, hubs, cases, events_by_id)
