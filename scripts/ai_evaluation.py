"""Optional nightly evaluation with a real model (spec 8.6) - a report, not a gate.

For every case of the generated ``dev`` dataset the configured provider (SENTINELOPS_LLM_*) writes a
summary; the validator decides what survives. Reported: share of rejected statements and how many
scenario cases have at least one validated fact citing scenario evidence (ground-truth coverage).
Prints a Markdown table (appended to the job summary).
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from musterfirma.generate import GeneratorConfig, generate

from sentinelops.ai.providers import ProviderConfig, build_provider
from sentinelops.ai.service import summarize
from sentinelops.evaluation.benchmark import load_dataset, locator_map, run_analysis
from sentinelops.investigation.catalog import default_catalog

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    provider = build_provider(
        ProviderConfig(
            os.environ.get("SENTINELOPS_LLM_PROVIDER", "none"),
            os.environ.get("SENTINELOPS_LLM_BASE_URL"),
            os.environ.get("SENTINELOPS_LLM_MODEL"),
            os.environ.get("SENTINELOPS_LLM_API_KEY"),
            os.environ.get("SENTINELOPS_LLM_CLOUD_OPT_IN", "false").lower() == "true",
        )
    )
    if provider is None:
        print("no provider configured - nothing to evaluate")
        return 0
    data = ROOT / ".cache" / "ai-eval-dataset"
    if not (data / "ground_truth.json").exists():
        generate(GeneratorConfig(seed="dev", events_per_day=5000), data)
    truth, ingest, now = load_dataset(data)
    result = run_analysis(ingest.events, now)
    locmap = locator_map(data, truth, ingest)
    scenario_of = {
        locmap[(loc["file"], loc["position"])]: s["id"]
        for s in truth["scenarios"]
        for loc in s["evidence"]
        if (loc["file"], loc["position"]) in locmap
    }
    catalog = default_catalog()
    rows = []
    statements = rejected = covered = scenario_cases = 0
    for case in result.cases:
        events = {e: result.events_by_id[e] for a in case.alerts for e in a.event_ids if e in result.events_by_id}
        from sentinelops.ai.evidence import build_package  # noqa: PLC0415 - keeps the script header short

        package = build_package(case.draft.case_id, case.alerts, events, case.priority, case.draft.entities, catalog)
        record = summarize(package, case.recommendations, provider, datetime.now(UTC))
        output = record.output
        accepted = len(output.get("facts", [])) + len(output.get("hypotheses", []))
        dropped = len(record.validation.rejected)
        statements += accepted + dropped
        rejected += dropped
        ref_to_event = {i.ref: i.event_id for i in package.items}
        scenarios = {scenario_of[e] for e in events if e in scenario_of}
        if scenarios:
            scenario_cases += 1
            cited = {ref_to_event.get(r) for f in output.get("facts", []) for r in f.get("evidence", [])}
            if any(scenario_of.get(e) in scenarios for e in cited if e):
                covered += 1
        rows.append((case.title_de, record.validation.status, accepted, dropped, record.error or ""))
    print(f"## AI evaluation ({provider.name}/{provider.model})\n")
    print("| Case | Validation | Kept statements | Rejected | Error |\n|---|---|---:|---:|---|")
    for title, status, kept, dropped, error in rows:
        print(f"| {title} | {status} | {kept} | {dropped} | {error[:80]} |")
    share = rejected / statements if statements else 0.0
    coverage = covered / scenario_cases if scenario_cases else 0.0
    print(
        f"\nRejected statements: {share:.1%} · ground-truth coverage: {coverage:.1%} of {scenario_cases} scenario cases"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
