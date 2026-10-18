"""Detection benchmark against generator ground truth (spec 15.4).

Metrics:

* **recall per scenario** - the scenario lands in a case whose alerts include
  all expected rules and cover all evidence events,
* **precision per rule** - share of a rule's active alerts whose events are
  (by majority) evidence of some scenario,
* **false positives on normal behaviour** - alerts/cases not attributable to
  any scenario, by priority,
* **one case per scenario** - all evidence of a scenario in exactly one case,
* **priority bounds** - case priority within the expected min/max.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from sentinelops.correlation.analysis import AnalysisResult, analyze
from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.exceptions import load_exceptions
from sentinelops.detection.sigma_loader import load_ruleset
from sentinelops.ingest.local import InputFile, LocalIngestResult, ingest_files
from sentinelops.investigation.catalog import default_catalog
from sentinelops.parsers.json_mapped import load_profiles
from sentinelops.settings import PROFILES_DIR, RULES_DIR

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

THRESHOLDS = {
    "recall_per_scenario": 0.95,
    "precision_per_rule": 0.90,
    "normal_p1_p2": 0,
    "normal_p3_p4": 5,
    "single_case_share": 1.0,
}


@dataclass
class ScenarioResult:
    id: str
    title: str
    detected: bool
    single_case: bool
    case_id: str | None
    priority: str | None
    priority_ok: bool
    expected_rules: list[str]
    found_rules: list[str]
    evidence_covered: int
    evidence_total: int


@dataclass
class BenchmarkReport:
    seed: str
    events: int
    scenarios: list[ScenarioResult]
    precision: dict[str, float]
    alerts_per_rule: dict[str, int]
    normal_cases: Counter[str] = field(default_factory=Counter)
    duplicates: int = 0

    @property
    def recall(self) -> float:
        return sum(s.detected for s in self.scenarios) / len(self.scenarios) if self.scenarios else 1.0

    @property
    def single_case_share(self) -> float:
        return sum(s.single_case for s in self.scenarios) / len(self.scenarios) if self.scenarios else 1.0

    def failures(self) -> list[str]:
        problems: list[str] = []
        for s in self.scenarios:
            if not s.detected:
                problems.append(
                    f"{s.id} not detected (rules {s.found_rules}, evidence {s.evidence_covered}/{s.evidence_total})"
                )
            if not s.single_case:
                problems.append(f"{s.id} not in exactly one case")
            if not s.priority_ok:
                problems.append(f"{s.id} priority {s.priority} outside expected bounds")
        for rule, value in sorted(self.precision.items()):
            if value < THRESHOLDS["precision_per_rule"]:
                problems.append(f"precision {rule} = {value:.2f}")
        high = self.normal_cases["P1"] + self.normal_cases["P2"]
        low = self.normal_cases["P3"] + self.normal_cases["P4"]
        if high > THRESHOLDS["normal_p1_p2"]:
            problems.append(f"{high} P1/P2 cases on normal behaviour")
        if low > THRESHOLDS["normal_p3_p4"]:
            problems.append(f"{low} P3/P4 cases on normal behaviour")
        return problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "events": self.events,
            "recall": round(self.recall, 4),
            "single_case_share": round(self.single_case_share, 4),
            "precision": {k: round(v, 4) for k, v in sorted(self.precision.items())},
            "alerts_per_rule": dict(sorted(self.alerts_per_rule.items())),
            "normal_cases": dict(sorted(self.normal_cases.items())),
            "scenarios": [s.__dict__ for s in self.scenarios],
            "failures": self.failures(),
        }

    def markdown(self) -> str:
        lines = [
            f"### Erkennungs-Benchmark (Seed `{self.seed}`, {self.events} Events)",
            "",
            "| Metrik | Wert | Schwelle |",
            "|---|---|---|",
            f"| Recall je Szenario | {self.recall:.2f} | ≥ {THRESHOLDS['recall_per_scenario']:.2f} |",
            f"| Szenarien in genau einem Fall | {self.single_case_share:.0%} | 100 % |",
            f"| Fehlalarm-Fälle P1/P2 (Normalverhalten) | {self.normal_cases['P1'] + self.normal_cases['P2']} | 0 |",
            f"| Fehlalarm-Fälle P3/P4 (Normalverhalten) | {self.normal_cases['P3'] + self.normal_cases['P4']} | ≤ 5 |",
            "",
            "| Szenario | erkannt | Fall | Priorität | Regeln |",
            "|---|---|---|---|---|",
        ]
        lines.extend(
            f"| {s.id} {s.title} | {'✅' if s.detected else '❌'} | {'1' if s.single_case else '❌'} | "
            f"{s.priority or '-'} {'✅' if s.priority_ok else '❌'} | {', '.join(s.found_rules)} |"
            for s in self.scenarios
        )
        lines += ["", "| Regel | Alarme | Precision |", "|---|---|---|"]
        for rule in sorted(self.alerts_per_rule):
            lines.append(f"| {rule} | {self.alerts_per_rule[rule]} | {self.precision.get(rule, 1.0):.2f} |")
        return "\n".join(lines) + "\n"


def load_dataset(root: Path, keep_outcomes: bool = True) -> tuple[dict[str, Any], LocalIngestResult, datetime]:
    truth = json.loads((root / "ground_truth.json").read_text(encoding="utf-8"))
    now = datetime.fromisoformat(truth["demo_now"])
    profiles = load_profiles(PROFILES_DIR, now)
    files = [InputFile(root / f["path"], f["source_type"], f["timezone"]) for f in truth["files"]]
    return truth, ingest_files(files, profiles, now, keep_outcomes=keep_outcomes), now


def locator_map(root: Path, truth: dict[str, Any], ingest: LocalIngestResult) -> dict[tuple[str, int], str]:
    out: dict[tuple[str, int], str] = {}
    for f in truth["files"]:
        for outcome in ingest.outcomes.get(str(root / f["path"]), []):
            if outcome.event_id is not None:
                out[(f["path"], outcome.raw.position)] = outcome.event_id
    return out


def run_analysis(events: list[Any], now: datetime, config: DetectionConfig | None = None) -> AnalysisResult:
    cfg = config or DetectionConfig()
    ruleset = load_ruleset(RULES_DIR, cfg, frozenset(default_catalog()))
    exceptions = load_exceptions(RULES_DIR / "exceptions")
    return analyze(events, ruleset, cfg, exceptions, default_catalog(), now, ZoneInfo("Europe/Berlin"))


def evaluate(root: Path, config: DetectionConfig | None = None) -> tuple[BenchmarkReport, AnalysisResult]:
    truth, ingest, now = load_dataset(root)
    result = run_analysis(ingest.events, now, config)
    locmap = locator_map(root, truth, ingest)
    evidence_owner: dict[str, str] = {}
    scenario_evidence: dict[str, set[str]] = {}
    for scenario in truth["scenarios"]:
        ids = {locmap[(loc["file"], loc["position"])] for loc in scenario["evidence"]}
        scenario_evidence[scenario["id"]] = ids
        for eid in ids:
            evidence_owner[eid] = scenario["id"]

    active = result.detection.active_alerts
    per_rule_total: Counter[str] = Counter()
    per_rule_tp: Counter[str] = Counter()
    for alert in active:
        per_rule_total[alert.rule_id] += 1
        owners = Counter(evidence_owner.get(eid) for eid in alert.event_ids)
        owner, count = owners.most_common(1)[0]
        if owner is not None and count * 2 >= len(alert.event_ids):
            per_rule_tp[alert.rule_id] += 1
    precision = {r: per_rule_tp[r] / per_rule_total[r] for r in per_rule_total}

    case_of_alert = result.case_of_alert()
    cases_by_id = {c.case_id: c for c in result.cases}
    scenario_results: list[ScenarioResult] = []
    for scenario in truth["scenarios"]:
        ids = scenario_evidence[scenario["id"]]
        alerts = [a for a in active if ids & set(a.event_ids)]
        covered = set().union(*(set(a.event_ids) for a in alerts)) & ids if alerts else set()
        case_ids = sorted({case_of_alert[a.alert_id] for a in alerts if a.alert_id in case_of_alert})
        found = sorted({a.rule_id for a in alerts})
        single = len(case_ids) == 1
        case = cases_by_id.get(case_ids[0]) if single else None
        priority = case.priority.level if case else None
        expected = scenario["expected_rules"]
        rules_ok = set(expected) <= set(found)
        priority_ok = priority is not None and PRIORITY_RANK[priority] <= PRIORITY_RANK[scenario["min_priority"]]
        if priority is not None and scenario.get("max_priority"):
            priority_ok = priority_ok and PRIORITY_RANK[priority] >= PRIORITY_RANK[scenario["max_priority"]]
        scenario_results.append(
            ScenarioResult(
                id=scenario["id"],
                title=scenario["title"],
                detected=rules_ok and covered == ids and single,
                single_case=single,
                case_id=case_ids[0] if single else None,
                priority=priority,
                priority_ok=priority_ok,
                expected_rules=expected,
                found_rules=found,
                evidence_covered=len(covered),
                evidence_total=len(ids),
            )
        )

    normal_cases: Counter[str] = Counter()
    for case in result.cases:
        owned = any(evidence_owner.get(eid) for a in case.alerts for eid in a.event_ids)
        if not owned:
            normal_cases[case.priority.level] += 1
    report = BenchmarkReport(
        seed=truth["seed"],
        events=len(ingest.events),
        scenarios=scenario_results,
        precision=precision,
        alerts_per_rule=dict(per_rule_total),
        normal_cases=normal_cases,
    )
    return report, result


def evaluate_normal_only(root: Path) -> BenchmarkReport:
    """Dataset generated with ``--no-scenarios``: every case is a false positive."""
    truth, ingest, now = load_dataset(root, keep_outcomes=False)
    result = run_analysis(ingest.events, now)
    normal: Counter[str] = Counter(c.priority.level for c in result.cases)
    per_rule: dict[str, int] = defaultdict(int)
    for alert in result.detection.active_alerts:
        per_rule[alert.rule_id] += 1
    return BenchmarkReport(truth["seed"], len(ingest.events), [], dict.fromkeys(per_rule, 0.0), dict(per_rule), normal)
