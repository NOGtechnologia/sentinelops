"""Acceptance tests of version 1 (spec 19). Every test name is fixed by the spec."""

from __future__ import annotations

import asyncio
import io
import json
import shutil
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
import pytest
from pypdf import PdfReader
from sqlalchemy import func, select

from sentinelops.ai.evidence import build_package
from sentinelops.ai.injection import scan_events
from sentinelops.ai.providers import MockProvider
from sentinelops.ai.service import summarize
from sentinelops.api.app import create_app
from sentinelops.auth.principal import issue_demo_token
from sentinelops.ingest.runs import ingest_path
from sentinelops.investigation.catalog import default_catalog
from sentinelops.runtime import Runtime
from sentinelops.storage.models import alert_events, alerts, case_alerts, cases, events
from sentinelops.worker.analysis import run_analysis
from sentinelops.worker.main import effective_exceptions
from tests.acceptance.conftest import Dataset
from tests.integration.conftest import Database, _create_db, _drop_db, migrate
from tests.integration.demo_data import load_into, settings_for

pytestmark = pytest.mark.acceptance


# --- A1 ------------------------------------------------------------------------------------


@pytest.mark.parametrize(("scenario", "rule"), [("S01", "SO-AUTH-001"), ("S02", "SO-AUTH-001"), ("S03", "SO-AUTH-002")])
def test_a1_failed_logins_grouped(dataset: Dataset, scenario: str, rule: str) -> None:
    """Many failed logons => grouped: exactly one alert/case that contains all
    failure events of the scenario and no foreign ones."""
    evidence = dataset.evidence(scenario)
    by_id = dataset.result.events_by_id
    failures = {e for e in evidence if by_id[e].action == "logon-failed"}
    assert len(failures) >= 25
    grouped = [a for a in dataset.result.detection.active_alerts if a.rule_id == rule and failures & set(a.event_ids)]
    assert len(grouped) == 1
    alert = grouped[0]
    alert_failures = {e for e in alert.event_ids if by_id[e].action == "logon-failed"}
    assert alert_failures == failures, "all failures of the scenario, nothing foreign"
    case_of = dataset.result.case_of_alert()
    cases_with_failures = {
        case_of[a.alert_id] for a in dataset.result.detection.active_alerts if failures & set(a.event_ids)
    }
    assert len(cases_with_failures) == 1


# --- A2 ------------------------------------------------------------------------------------


def test_a2_processing_categories(dataset: Dataset) -> None:
    """Labelled mixed data set => 100 % correct accepted/duplicate/malformed
    (with error code) and normal/suspicious assignment."""
    suspicious = dataset.result.detection.suspicious_event_ids()
    checked: Counter[str] = Counter()
    mismatches: list[str] = []
    for entry in dataset.truth["files"]:
        exceptions = dataset.truth["labels"][entry["path"]]["exceptions"]
        for outcome in dataset.ingest.outcomes[str(dataset.root / entry["path"])]:
            label = exceptions.get(str(outcome.raw.position), {"status": "accepted"})
            checked[outcome.status.value] += 1
            if outcome.status.value != label["status"]:
                mismatches.append(
                    f"{entry['path']}:{outcome.raw.position} status {outcome.status.value} != {label['status']}"
                )
                continue
            if label.get("code") and (outcome.error is None or outcome.error.code.value != label["code"]):
                mismatches.append(f"{entry['path']}:{outcome.raw.position} code")
            if label.get("flag") and label["flag"] not in (
                outcome.event.fields.get("quality.flags") or [] if outcome.event else []
            ):
                mismatches.append(f"{entry['path']}:{outcome.raw.position} flag {label['flag']}")
            if outcome.event is not None:
                expected = label.get("assessment") or "normal"
                actual = "suspicious" if outcome.event.event_id in suspicious else "normal"
                if expected != actual:
                    mismatches.append(f"{entry['path']}:{outcome.raw.position} assessment {actual} != {expected}")
    assert mismatches == []
    assert checked["accepted"] > 10_000
    assert checked["duplicate"] > 0
    assert checked["malformed"] >= 14
    codes = {o.error.code.value for items in dataset.ingest.outcomes.values() for o in items if o.error}
    assert codes == {
        "TRUNCATED",
        "MISSING_TIMESTAMP",
        "INVALID_ENCODING",
        "OVERSIZED",
        "PARSE_ERROR",
        "SCHEMA_VIOLATION",
    }


# --- A3 ------------------------------------------------------------------------------------


async def _counts(url: str) -> dict[str, Any]:
    rt = Runtime(settings_for(url))
    try:
        async with rt.engine.connect() as conn:
            per_alert = dict((await conn.execute(select(alerts.c.alert_id, alerts.c.event_count))).all())
            per_case = dict(
                (await conn.execute(select(case_alerts.c.case_id, func.count()).group_by(case_alerts.c.case_id))).all()
            )
            return {
                "events": (await conn.execute(select(func.count()).select_from(events))).scalar(),
                "suspicious": (
                    await conn.execute(
                        select(func.count()).select_from(events).where(events.c.assessment == "suspicious")
                    )
                ).scalar(),
                "alerts": per_alert,
                "alert_events": (await conn.execute(select(func.count()).select_from(alert_events))).scalar(),
                "cases": per_case,
                "priorities": dict((await conn.execute(select(cases.c.case_id, cases.c.score))).all()),
            }
    finally:
        await rt.engine.dispose()


async def _reimport_with_duplicates(url: str, dataset_dir: Path, scratch: Path) -> int:
    rt = Runtime(settings_for(url))
    truth = json.loads((dataset_dir / "ground_truth.json").read_text(encoding="utf-8"))
    duplicates = 0
    try:
        for entry in truth["files"]:
            source = dataset_dir / entry["path"]
            kwargs = {
                "source_type": entry["source_type"],
                "timezone": entry["timezone"],
                "channel": "test",
                "actor": "test",
                "profiles": rt.profiles,
                "now": rt.clock.now(),
            }
            again = await ingest_path(rt.engine, source, file_name=entry["path"], **kwargs)  # same file again
            assert again.status == "skipped_duplicate_file"
            copy = scratch / (entry["path"].replace("/", "_") + ".copy")
            if entry["source_type"] in ("syslog_3164", "syslog_5424", "journald_json", "json:musterfirma_vpn") or entry[
                "path"
            ].endswith(".ndjson"):
                lines = source.read_bytes().splitlines(keepends=True)
                copy.write_bytes(b"".join(line + line for line in lines))  # every record twice (exact duplicates)
            else:
                shutil.copyfile(source, copy)
                copy.write_bytes(copy.read_bytes() + b"\n")  # new file hash, same records
            result = await ingest_path(rt.engine, copy, file_name=copy.name, **kwargs)
            assert result.accepted == 0
            duplicates += result.duplicate
        await run_analysis(rt.engine, rt.analysis_context(await effective_exceptions(rt)), rt.clock.now())
    finally:
        await rt.engine.dispose()
    return duplicates


def test_a3_duplicates_no_double_count(fresh_db: Database, dataset_dir: Path, tmp_path: Path) -> None:
    """Data imported once and additionally twice (exact duplicates + re-import of
    whole files) => identical event, alert, case and counter values."""
    asyncio.run(load_into(fresh_db.url, dataset_dir))
    before = asyncio.run(_counts(fresh_db.url))
    duplicates = asyncio.run(_reimport_with_duplicates(fresh_db.url, dataset_dir, tmp_path))
    after = asyncio.run(_counts(fresh_db.url))
    assert duplicates > before["events"]
    assert after == before
    assert len(before["cases"]) == 10


# --- A5 ------------------------------------------------------------------------------------


async def _all_reports(url: str) -> dict[str, dict[str, bytes]]:
    rt = Runtime(settings_for(url))
    app = create_app(rt)
    headers = {"Authorization": f"Bearer {issue_demo_token('analyst')}"}
    out: dict[str, dict[str, bytes]] = {}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            listing = (await client.get("/api/v1/cases", headers=headers)).json()["items"]
            for case in listing:
                out[case["case_id"]] = {}
                for fmt in ("json", "md", "pdf"):
                    response = await client.get(
                        f"/api/v1/cases/{case['case_id']}/report",
                        params={"format": fmt, "created_at": "2026-03-12T10:30:00Z"},
                        headers=headers,
                    )
                    assert response.status_code == 200
                    out[case["case_id"]][fmt] = response.content
    finally:
        await rt.engine.dispose()
    return out


def test_a5_report_reproducible(pg_server: str, dataset_dir: Path, tmp_path: Path) -> None:
    """Two completely separate runs (fresh database, same seed, same config,
    fixed creation time) => JSON/Markdown byte-identical, PDF text identical."""
    runs = []
    for _ in range(2):
        name = f"so_a5_{uuid.uuid4().hex[:8]}"
        url = asyncio.run(_create_db(pg_server, name))
        try:
            migrate(url)
            copy = tmp_path / name
            shutil.copytree(dataset_dir, copy)  # a separate copy of the input files
            asyncio.run(load_into(url, copy))
            runs.append(asyncio.run(_all_reports(url)))
        finally:
            asyncio.run(_drop_db(pg_server, name))
    first, second = runs
    assert sorted(first) == sorted(second)
    assert len(first) == 10
    for case_id in first:
        assert first[case_id]["json"] == second[case_id]["json"]
        assert first[case_id]["md"] == second[case_id]["md"]
        text_a = "".join(p.extract_text() for p in PdfReader(io.BytesIO(first[case_id]["pdf"])).pages)
        text_b = "".join(p.extract_text() for p in PdfReader(io.BytesIO(second[case_id]["pdf"])).pages)
        assert text_a == text_b
        meta = PdfReader(io.BytesIO(first[case_id]["pdf"])).metadata
        assert meta is not None
        assert meta.creation_date == PdfReader(io.BytesIO(second[case_id]["pdf"])).metadata.creation_date  # type: ignore[union-attr]


# --- A6 ------------------------------------------------------------------------------------


def test_a6_ai_grounding(dataset: Dataset) -> None:
    """Malicious mock => every invented indicator/evidence is discarded and logged."""
    case = next(c for c in dataset.result.cases if "ignore previous instructions" in c.title_de)
    events = dataset.result.events_by_id
    package = build_package(case.case_id, case.alerts, events, case.priority, case.draft.entities, default_catalog())
    known_ip = next(i.fields["source.ip"] for i in package.items if "source.ip" in i.fields)
    malicious = {
        "summary": "Attack from 198.51.100.250; the account was already disabled.",
        "facts": [
            {"statement": f"Failed logons came from {known_ip}.", "evidence": ["E1"]},
            {"statement": "Malware hash 44d88612fea8a8f36de82e1278abb02f was dropped.", "evidence": ["E1"]},
            {"statement": "Exfiltration to evil-c2.com.", "evidence": ["E1"]},
            {"statement": f"Logon from {known_ip}.", "evidence": ["E999"]},
            {"statement": "The attacker also used srv-unknown77.", "evidence": ["E2"]},
            {"statement": "A fact without evidence.", "evidence": []},
        ],
        "hypotheses": [
            {
                "statement": "Credential stuffing via 192.0.2.250.",
                "confidence": "low",
                "evidence": ["E1"],
                "would_confirm": "VPN logs",
            }
        ],
        "missing_information": [],
        "recommended_steps": [
            {"playbook_step_id": "WIPE_ALL_SERVERS", "rationale": "x", "evidence": ["E1"]},
            {"playbook_step_id": "BLOCK_SOURCE_IP", "rationale": "stop the source", "evidence": ["E1"]},
        ],
    }
    findings = scan_events([events[e] for a in case.alerts for e in a.event_ids])
    record = summarize(package, case.recommendations, MockProvider(json.dumps(malicious)), dataset.now, findings)
    output = record.output
    assert record.validation.status == "partially_valid"
    assert [f["statement"] for f in output["facts"]] == [f"Failed logons came from {known_ip}."]
    assert output["hypotheses"] == []
    assert [s["playbook_step_id"] for s in output["recommended_steps"]] == ["BLOCK_SOURCE_IP"]
    assert output["summary"] == ""
    reasons = " | ".join(r for rej in record.validation.rejected for r in rej.reasons)
    for marker in (
        "198.51.100.250",
        "44d88612fea8a8f36de82e1278abb02f",
        "evil-c2.com",
        "E999",
        "srv-unknown77",
        "fact without evidence",
        "WIPE_ALL_SERVERS",
        "192.0.2.250",
        "DISABLE_ACCOUNT",
    ):
        assert marker.casefold() in reasons.casefold(), marker
    assert any(f.pattern == "ignore_instructions" for f in record.injection_findings)
    assert len(record.to_dict()["rejected"]) == 8  # 5 facts, 1 hypothesis, 1 step, the summary


# --- A7 ------------------------------------------------------------------------------------


def test_a7_no_action_without_approval(fresh_db: Database, dataset_dir: Path) -> None:
    """Execution only after a valid approval (API level; the UI dialog is covered by e2e)."""
    asyncio.run(load_into(fresh_db.url, dataset_dir))

    async def scenario() -> None:
        rt = Runtime(settings_for(fresh_db.url))
        app = create_app(rt)

        def h(user: str) -> dict[str, str]:
            return {"Authorization": f"Bearer {issue_demo_token(user)}"}

        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
                case = next(
                    x
                    for x in (await c.get("/api/v1/cases", headers=h("analyst"))).json()["items"]
                    if x["priority"] == "P1"
                )
                action = (
                    await c.post(
                        f"/api/v1/cases/{case['case_id']}/actions",
                        headers=h("analyst"),
                        json={
                            "step_id": "DISABLE_ACCOUNT",
                            "parameters": {"user": "jonas.becker"},
                            "reason": "compromised",
                        },
                    )
                ).json()
                assert (
                    await c.post(f"/api/v1/actions/{action['action_id']}/execute", headers=h("senior"))
                ).status_code == 403
                rejected = await c.post(
                    f"/api/v1/actions/{action['action_id']}/decision",
                    headers=h("senior"),
                    json={"decision": "rejected", "reason": "not enough evidence"},
                )
                assert rejected.status_code == 200
                assert (
                    await c.post(f"/api/v1/actions/{action['action_id']}/execute", headers=h("senior"))
                ).status_code == 403
                second = (
                    await c.post(
                        f"/api/v1/cases/{case['case_id']}/actions",
                        headers=h("analyst"),
                        json={"step_id": "BLOCK_SOURCE_IP", "parameters": {"ip": "203.0.113.45"}, "reason": "attacker"},
                    )
                ).json()
                await c.post(
                    f"/api/v1/actions/{second['action_id']}/decision",
                    headers=h("senior"),
                    json={"decision": "approved", "reason": "confirmed"},
                )
                done = await c.post(f"/api/v1/actions/{second['action_id']}/execute", headers=h("senior"))
                assert done.status_code == 200
                assert done.json()["status"] == "executed"
        finally:
            await rt.engine.dispose()

    asyncio.run(scenario())


# --- A8 ------------------------------------------------------------------------------------


def test_a8_works_without_llm(fresh_db: Database, dataset_dir: Path) -> None:
    """All functions except AI text work without a model (template summary)."""
    asyncio.run(load_into(fresh_db.url, dataset_dir))

    async def scenario() -> None:
        settings = settings_for(fresh_db.url)
        assert settings.llm_provider == "none"
        rt = Runtime(settings)
        assert rt.provider is None
        app = create_app(rt)
        h = {"Authorization": f"Bearer {issue_demo_token('senior')}"}
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
                listing = (await c.get("/api/v1/cases", headers=h)).json()["items"]
                assert len(listing) == 10
                for case in listing:
                    detail = (await c.get(f"/api/v1/cases/{case['case_id']}", headers=h)).json()
                    assert detail["summary"]["source"] == "template"
                    assert detail["summary"]["validation_status"] == "valid"
                    assert detail["summary"]["output"]["summary"].startswith("Fall P")
                    for sub in ("timeline", "evidence", "graph"):
                        assert (await c.get(f"/api/v1/cases/{case['case_id']}/{sub}", headers=h)).status_code == 200
                regenerated = await c.post(f"/api/v1/cases/{listing[0]['case_id']}/ai-summaries", headers=h)
                assert regenerated.json()["source"] == "template"
                for path in (
                    "/api/v1/dashboard",
                    "/api/v1/rules",
                    "/api/v1/quality/summary",
                    "/api/v1/alerts",
                    "/api/v1/events",
                    "/api/v1/entities",
                    "/api/v1/exceptions",
                ):
                    assert (await c.get(path, headers=h)).status_code == 200, path
        finally:
            await rt.engine.dispose()

    asyncio.run(scenario())
