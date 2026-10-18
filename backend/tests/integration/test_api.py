"""API tests against a real database loaded with the generated demo data."""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pypdf import PdfReader

from sentinelops.api.app import PermissionMapError, check_route_permissions, create_app, iter_api_routes
from sentinelops.auth.principal import DEMO_USERS, issue_demo_token, role_matrix, route_permissions
from sentinelops.runtime import Runtime
from tests.integration.conftest import _create_db, _drop_db, migrate
from tests.integration.demo_data import generate_dataset, load_sync, settings_for

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def demo_db(pg_server: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    dataset = generate_dataset(tmp_path_factory.mktemp("demo") / "dev")
    name = f"so_api_{uuid.uuid4().hex[:8]}"
    url = asyncio.run(_create_db(pg_server, name))
    migrate(url)
    summary = load_sync(url, dataset)
    assert summary["cases"] == 10
    try:
        yield url
    finally:
        asyncio.run(_drop_db(pg_server, name))


@pytest.fixture
async def client(demo_db: str, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setenv("SENTINELOPS_RATE_LIMIT", "false")
    rt = Runtime(settings_for(demo_db))
    app = create_app(rt)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        c.app = app  # type: ignore[attr-defined]  # test convenience
        yield c
    await rt.engine.dispose()


def auth(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_demo_token(user)}"}


async def case_by_title(client: httpx.AsyncClient, fragment: str) -> dict[str, Any]:
    cases = (await client.get("/api/v1/cases", headers=auth("analyst"))).json()["items"]
    return next(c for c in cases if fragment in c["title_de"])


# --- permissions -------------------------------------------------------------------


def _fill(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


async def test_every_route_enforces_authentication_and_permissions(client: httpx.AsyncClient) -> None:
    app = client.app  # type: ignore[attr-defined]
    mapping = route_permissions()
    matrix = role_matrix()
    users_by_role = {roles[0]: uid for uid, (_, roles) in DEMO_USERS.items()}
    checked = 0
    for route in iter_api_routes(app.routes):
        if not route.path.startswith("/api/"):
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            permission = mapping[f"{method} {route.path}"]
            url = _fill(route.path)
            if permission == "public":
                continue
            response = await client.request(method, url)
            assert response.status_code == 401, f"{method} {route.path} without token"
            if permission in ("authenticated", "ingest:token"):
                continue
            for role, perms in matrix.items():
                if permission in perms:
                    continue
                response = await client.request(method, url, headers=auth(users_by_role[role]))
                assert response.status_code == 403, f"{method} {route.path} as {role}: {response.status_code}"
                checked += 1
    assert checked > 50


def test_missing_permission_entry_fails_the_build() -> None:
    from fastapi import FastAPI

    app = FastAPI()

    @app.get("/api/v1/unmapped")
    async def unmapped() -> dict[str, str]:
        return {}

    with pytest.raises(PermissionMapError, match="GET /api/v1/unmapped"):
        check_route_permissions(app)


async def test_invalid_tokens_rejected(client: httpx.AsyncClient) -> None:
    for header in ("Bearer nonsense", "Basic abc", "Bearer soi_abc_def"):
        response = await client.get("/api/v1/cases", headers={"Authorization": header})
        assert response.status_code == 401


# --- public and auth -------------------------------------------------------------------


async def test_public_endpoints_and_security_headers(client: httpx.AsyncClient) -> None:
    health = await client.get("/api/v1/health")
    assert health.json() == {"status": "ok", "database": True}
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]
    assert health.headers["x-content-type-options"] == "nosniff"
    version = (await client.get("/api/v1/version")).json()
    assert version["demo_mode"] is True
    assert version["demo_now"] == "2026-03-12T09:30:00.000000Z"
    config = (await client.get("/api/v1/auth/config")).json()
    assert [u["id"] for u in config["demo_users"]] == list(DEMO_USERS)
    token = (await client.post("/api/v1/auth/demo-login", json={"user": "senior"})).json()["access_token"]
    me = (await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})).json()
    assert me["roles"] == ["senior_analyst"]
    assert "actions:decide" in me["permissions"]
    assert (await client.post("/api/v1/auth/demo-login", json={"user": "root"})).status_code == 400


async def test_cross_origin_writes_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/demo-login", json={"user": "analyst"}, headers={"Origin": "https://evil.example"}
    )
    assert response.status_code == 403


# --- dashboard and queue --------------------------------------------------------------


async def test_dashboard(client: httpx.AsyncClient) -> None:
    data = (await client.get("/api/v1/dashboard", headers=auth("analyst"))).json()
    assert data["kpis"]["open_cases"]["P1"] == 3
    assert data["kpis"]["alerts_24h"] > 0
    assert data["series"]["events_7d"]
    assert data["top_rules"]
    assert {i["source_type"] for i in data["ingestion"]} >= {"windows_xml", "syslog_3164"}


async def test_case_queue_filters(client: httpx.AsyncClient) -> None:
    all_cases = (await client.get("/api/v1/cases", headers=auth("analyst"))).json()
    assert all_cases["total"] == 10
    assert [c["priority"] for c in all_cases["items"]] == sorted(c["priority"] for c in all_cases["items"])
    p1 = (await client.get("/api/v1/cases", params={"priority": ["P1"]}, headers=auth("analyst"))).json()
    assert p1["total"] == 3
    by_entity = (await client.get("/api/v1/cases", params={"entity": "jonas.becker"}, headers=auth("analyst"))).json()
    assert by_entity["total"] == 1
    injection = next(c for c in all_cases["items"] if c["prompt_injection"])
    assert "ignore previous instructions" in injection["title_de"]


# --- case detail ------------------------------------------------------------------------


async def test_case_detail_timeline_evidence_graph(client: httpx.AsyncClient) -> None:
    case = await case_by_title(client, "Aufnahme in privilegierte Gruppe")
    cid = case["case_id"]
    detail = (await client.get(f"/api/v1/cases/{cid}", headers=auth("analyst"))).json()
    assert detail["priority"]["level"] == "P1"
    codes = [f["code"] for f in detail["priority"]["factors"]]
    assert codes[:2] == ["max_severity", "success_after_failures"]
    assert detail["summary"]["source"] == "template"
    assert detail["summary"]["validation_status"] == "valid"
    assert {a["rule_id"] for a in detail["alerts"]} >= {"SO-AUTH-001", "SO-AUTH-003", "SO-PRIV-001", "SO-PRIV-002"}
    timeline = (await client.get(f"/api/v1/cases/{cid}/timeline", headers=auth("analyst"))).json()
    assert timeline["total"] >= 40
    evidence = (await client.get(f"/api/v1/cases/{cid}/evidence", headers=auth("analyst"))).json()
    priv = next(a for a in evidence["alerts"] if a["rule_id"] == "SO-PRIV-001")
    assert "privileged_groups" in priv["rule"]["yaml"]
    assert priv["explanation"]["matched"][0]["field"] == "event.action"
    assert "Domain Admins" in priv["events"][0]["raw"]
    graph = (await client.get(f"/api/v1/cases/{cid}/graph", headers=auth("analyst"))).json()
    assert any(n["label"] == "203.0.113.45" for n in graph["nodes"])
    assert graph["edges"]
    assert (await client.get("/api/v1/cases/nope", headers=auth("analyst"))).status_code == 404


async def test_status_assignee_notes_and_audit(client: httpx.AsyncClient) -> None:
    case = await case_by_title(client, "Password Spraying")
    cid = case["case_id"]
    response = await client.patch(
        f"/api/v1/cases/{cid}", json={"status": "in_progress", "assignee": "demo.analyst"}, headers=auth("analyst")
    )
    assert response.status_code == 200
    note = await client.post(
        f"/api/v1/cases/{cid}/notes", json={"text": "<b>checked</b> firewall"}, headers=auth("analyst")
    )
    assert note.status_code == 200
    detail = (await client.get(f"/api/v1/cases/{cid}", headers=auth("analyst"))).json()
    assert detail["case"]["status"] == "in_progress"
    assert detail["case"]["first_action_at"] is not None
    assert detail["notes"][0]["text"] == "<b>checked</b> firewall"
    log = (await client.get("/api/v1/audit", params={"object_id": cid, "verify": True}, headers=auth("auditor"))).json()
    assert {e["action"] for e in log["items"]} >= {"case.updated", "case.note_added"}
    assert log["chain_broken_at"] == []
    bulk = await client.patch("/api/v1/cases/bulk", json={"case_ids": [cid], "status": "new"}, headers=auth("analyst"))
    assert bulk.json() == {"updated": 1}


# --- actions: A7 (API part) -------------------------------------------------------------


async def test_a7_no_action_without_approval(client: httpx.AsyncClient) -> None:
    case = await case_by_title(client, "Aufnahme in privilegierte Gruppe")
    cid = case["case_id"]
    proposed = await client.post(
        f"/api/v1/cases/{cid}/actions",
        json={"step_id": "DISABLE_ACCOUNT", "parameters": {"user": "jonas.becker"}, "reason": "account compromised"},
        headers=auth("analyst"),
    )
    assert proposed.status_code == 200
    action_id = proposed.json()["action_id"]
    # nobody can execute a proposed action
    assert (await client.post(f"/api/v1/actions/{action_id}/execute", headers=auth("senior"))).status_code == 403
    # analysts cannot decide
    assert (
        await client.post(
            f"/api/v1/actions/{action_id}/decision",
            json={"decision": "approved", "reason": "x"},
            headers=auth("analyst"),
        )
    ).status_code == 403
    approved = await client.post(
        f"/api/v1/actions/{action_id}/decision",
        json={"decision": "approved", "reason": "verified with owner"},
        headers=auth("senior"),
    )
    assert approved.status_code == 200
    assert approved.json()["approval"]["signature"]
    executed = await client.post(f"/api/v1/actions/{action_id}/execute", headers=auth("senior"))
    assert executed.status_code == 200
    assert executed.json()["status"] == "executed"
    assert "SIMULATION" in executed.json()["execution"]["details"]
    again = await client.post(f"/api/v1/actions/{action_id}/execute", headers=auth("senior"))
    assert again.status_code == 403
    bad = await client.post(
        f"/api/v1/cases/{cid}/actions",
        json={"step_id": "VERIFY_ACCOUNT_ACTIVITY", "parameters": {}, "reason": "x"},
        headers=auth("analyst"),
    )
    assert bad.status_code == 422
    log = (await client.get("/api/v1/audit", params={"object_id": action_id}, headers=auth("auditor"))).json()
    assert {e["action"] for e in log["items"]} >= {
        "action.proposed",
        "action.approved",
        "action.executed",
        "action.execution_refused",
    }


async def test_four_eyes_on_actions(client: httpx.AsyncClient) -> None:
    case = await case_by_title(client, "Laterale Bewegung")
    proposed = await client.post(
        f"/api/v1/cases/{case['case_id']}/actions",
        json={"step_id": "ISOLATE_HOST", "parameters": {"host": "ws-0031"}, "reason": "lateral movement"},
        headers=auth("senior"),
    )
    action_id = proposed.json()["action_id"]
    own = await client.post(
        f"/api/v1/actions/{action_id}/decision", json={"decision": "approved", "reason": "ok"}, headers=auth("senior")
    )
    assert own.status_code == 403
    assert "four-eyes" in own.json()["detail"]


# --- false positives and exceptions (A4 backend part) -------------------------------------


async def test_false_positive_and_exception_flow(client: httpx.AsyncClient) -> None:
    case = await case_by_title(client, "Konto gesperrt")
    detail = (await client.get(f"/api/v1/cases/{case['case_id']}", headers=auth("analyst"))).json()
    alert_id = detail["alerts"][0]["alert_id"]
    marked = await client.post(
        f"/api/v1/alerts/{alert_id}/false-positive",
        json={"reason": "typos after password change"},
        headers=auth("analyst"),
    )
    assert marked.status_code == 200
    alert = (await client.get(f"/api/v1/alerts/{alert_id}", headers=auth("analyst"))).json()
    assert alert["false_positive"] is True
    assert alert["rule"]["rule_id"] == "SO-AUTH-007"
    proposal = await client.post(
        "/api/v1/exceptions",
        json={
            "rule_id": "SO-AUTH-007",
            "description": "Lockouts of lena.hoffmann after the planned password change",
            "match": {"user.target.name": "lena.hoffmann"},
            "expires": "2026-04-30",
        },
        headers=auth("analyst"),
    )
    assert proposal.status_code == 200
    exc_id = proposal.json()["exception_id"]
    assert (await client.post(f"/api/v1/exceptions/{exc_id}/approve", headers=auth("analyst"))).status_code == 403
    approved = await client.post(f"/api/v1/exceptions/{exc_id}/approve", headers=auth("senior"))
    assert approved.json()["status"] == "active"
    listed = (await client.get("/api/v1/exceptions", headers=auth("analyst"))).json()
    assert {e.get("exception_id") or e.get("id") for e in listed} >= {"EXC-0001", exc_id}
    log = (await client.get("/api/v1/audit", headers=auth("auditor"))).json()["items"]
    assert {"alert.false_positive", "exception.proposed", "exception.approved"} <= {e["action"] for e in log}


# --- rules, events, entities, quality -----------------------------------------------------


async def test_rules_events_entities(client: httpx.AsyncClient) -> None:
    rules = (await client.get("/api/v1/rules", headers=auth("engineer"))).json()
    assert {r["rule_id"] for r in rules} >= {"SO-AUTH-001", "SIGMAHQ-D99B79D2"}
    rule = (await client.get("/api/v1/rules/SO-AUTH-001", headers=auth("engineer"))).json()
    assert rule["tests"]
    assert rule["versions"]
    events = (
        await client.get(
            "/api/v1/events", params={"user": "jonas.becker", "action": "logon-failed"}, headers=auth("analyst")
        )
    ).json()
    assert len(events["items"]) == 40
    assert all(e["assessment"] == "suspicious" for e in events["items"])
    one = (await client.get(f"/api/v1/events/{events['items'][0]['event.id']}", headers=auth("analyst"))).json()
    assert "TargetUserName" in one["raw"]["text"]
    fulltext = (await client.get("/api/v1/events", params={"q": "ATTACKER-PC"}, headers=auth("analyst"))).json()
    assert fulltext["items"]
    csv_text = (await client.get("/api/v1/events/export.csv", params={"user": "ignore"}, headers=auth("analyst"))).text
    assert csv_text.startswith('"timestamp"')
    entities = (
        await client.get("/api/v1/entities", params={"type": "host", "q": "dc0"}, headers=auth("analyst"))
    ).json()
    assert {e["key"] for e in entities["items"]} == {"dc01", "dc02"}
    assert all(e["hub"] for e in entities["items"])


async def test_rule_deactivation_requires_engineer(client: httpx.AsyncClient) -> None:
    body = {"active": False, "reason": "noisy in test"}
    assert (await client.patch("/api/v1/rules/SO-AUTH-004", json=body, headers=auth("analyst"))).status_code == 403
    assert (await client.patch("/api/v1/rules/SO-AUTH-004", json=body, headers=auth("engineer"))).status_code == 200
    rules = (await client.get("/api/v1/rules", headers=auth("engineer"))).json()
    assert next(r for r in rules if r["rule_id"] == "SO-AUTH-004")["active"] is False
    body["active"] = True
    assert (await client.patch("/api/v1/rules/SO-AUTH-004", json=body, headers=auth("engineer"))).status_code == 200


async def test_quality_views(client: httpx.AsyncClient) -> None:
    summary = (await client.get("/api/v1/quality/summary", headers=auth("analyst"))).json()
    assert summary["malformed"] == 14
    assert summary["duplicate"] > 0
    assert set(summary["error_codes"]) == {
        "TRUNCATED",
        "MISSING_TIMESTAMP",
        "INVALID_ENCODING",
        "OVERSIZED",
        "PARSE_ERROR",
        "SCHEMA_VIOLATION",
    }
    quarantine = (
        await client.get("/api/v1/quality/quarantine", params={"code": "INVALID_ENCODING"}, headers=auth("analyst"))
    ).json()
    assert quarantine["total"] == 1
    assert "\\xff" in quarantine["items"][0]["content"]
    runs = (await client.get("/api/v1/quality/runs", headers=auth("analyst"))).json()
    run_id = next(r["run_id"] for r in runs if r["malformed"])
    reprocessed = (await client.post(f"/api/v1/quality/runs/{run_id}/reprocess", headers=auth("engineer"))).json()
    assert reprocessed["reprocessed"] > 0


# --- ingestion -----------------------------------------------------------------------------


async def test_upload_and_token_ingest(client: httpx.AsyncClient, tmp_path: Path) -> None:
    line = b'{"ts": 1773309000000, "seq": 777001, "gateway": "vpn01", "type": "auth_fail", "result": "fail", "user": "x.y"}\n'
    files = {"file": ("vpn.ndjson", line, "application/x-ndjson")}
    up = await client.post(
        "/api/v1/uploads", data={"source_type": "json:musterfirma_vpn"}, files=files, headers=auth("admin")
    )
    assert up.status_code == 200
    assert up.json()["accepted"] == 1
    bad_type = await client.post("/api/v1/uploads", data={"source_type": "nope"}, files=files, headers=auth("admin"))
    assert bad_type.status_code == 422
    token = (
        await client.post("/api/v1/admin/ingest-tokens", json={"name": "forwarder-1"}, headers=auth("admin"))
    ).json()
    body = gzip.compress(line.replace(b"777001", b"777002"))
    ingest = await client.post(
        "/api/v1/ingest/json:musterfirma_vpn",
        content=body,
        headers={"Authorization": f"Bearer {token['token']}", "Content-Encoding": "gzip"},
    )
    assert ingest.status_code == 200
    assert ingest.json()["accepted"] == 1
    # user tokens are not accepted by ... the ingest API needs ingest:write
    assert (
        await client.post("/api/v1/ingest/json:musterfirma_vpn", content=line, headers=auth("analyst"))
    ).status_code == 403
    revoke = await client.delete(f"/api/v1/admin/ingest-tokens/{token['token_id']}", headers=auth("admin"))
    assert revoke.status_code == 204
    again = await client.post(
        "/api/v1/ingest/json:musterfirma_vpn", content=line, headers={"Authorization": f"Bearer {token['token']}"}
    )
    assert again.status_code == 401
    tokens = (await client.get("/api/v1/admin/ingest-tokens", headers=auth("admin"))).json()
    assert "token_hash" not in tokens[0]
    users = (await client.get("/api/v1/admin/users", headers=auth("admin"))).json()
    assert isinstance(users, list)
    job = (await client.post("/api/v1/admin/analysis", headers=auth("admin"))).json()
    assert job["job_id"]


# --- reports (A5 at API level) --------------------------------------------------------------


async def test_reports_reproducible_and_escaped(client: httpx.AsyncClient) -> None:
    case = await case_by_title(client, "ignore previous instructions")
    cid = case["case_id"]
    params = {"created_at": "2026-03-12T10:30:00Z"}
    a = await client.get(f"/api/v1/cases/{cid}/report", params={**params, "format": "json"}, headers=auth("analyst"))
    b = await client.get(f"/api/v1/cases/{cid}/report", params={**params, "format": "json"}, headers=auth("analyst"))
    assert a.content == b.content
    report = json.loads(a.content)
    assert report["metadata"]["created_at"] == "2026-03-12T10:30:00.000000Z"
    assert report["injection_findings"]
    md = (
        await client.get(f"/api/v1/cases/{cid}/report", params={**params, "format": "md"}, headers=auth("analyst"))
    ).text
    assert "<img src=x onerror=alert(1)>" not in md.split("## Belegauszüge")[0].replace(
        "`<img src=x onerror=alert(1)>`", ""
    )
    pdf = await client.get(f"/api/v1/cases/{cid}/report", params={**params, "format": "pdf"}, headers=auth("analyst"))
    assert pdf.headers["content-type"] == "application/pdf"
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "Prompt-Injection" in text
    agg = (
        await client.get("/api/v1/reports/aggregate", params={"start": "2026-03-01T00:00:00Z"}, headers=auth("auditor"))
    ).json()
    assert agg["cases"] == 10
    csv_agg = await client.get("/api/v1/reports/aggregate", params={"format": "csv"}, headers=auth("auditor"))
    assert csv_agg.text.startswith('"rule_id"')


async def test_ai_summary_regeneration_creates_new_version(client: httpx.AsyncClient) -> None:
    case = await case_by_title(client, "Brute Force auf ein Konto: anna")
    cid = case["case_id"]
    new = await client.post(f"/api/v1/cases/{cid}/ai-summaries", headers=auth("analyst"))
    assert new.status_code == 200
    assert new.json()["version"] == 2
    versions = (await client.get(f"/api/v1/cases/{cid}/ai-summaries", headers=auth("analyst"))).json()
    assert [v["version"] for v in versions] == [1, 2]
    assert (await client.post(f"/api/v1/cases/{cid}/ai-summaries", headers=auth("auditor"))).status_code == 403


async def test_merge_split_and_revert(client: httpx.AsyncClient) -> None:
    a = await case_by_title(client, "Brute Force auf ein Konto: anna")
    b = await case_by_title(client, "Password Spraying")
    merged = await client.post(
        f"/api/v1/cases/{a['case_id']}/merge", json={"source_case_id": b["case_id"]}, headers=auth("senior")
    )
    assert merged.status_code == 200
    detail = (await client.get(f"/api/v1/cases/{a['case_id']}", headers=auth("analyst"))).json()
    assert len(detail["alerts"]) == 2
    revert = await client.post(f"/api/v1/case-merges/{merged.json()['merge_id']}/revert", headers=auth("senior"))
    assert revert.status_code == 200
    assert (
        await client.post(f"/api/v1/case-merges/{merged.json()['merge_id']}/revert", headers=auth("senior"))
    ).status_code == 409
    detail = (await client.get(f"/api/v1/cases/{a['case_id']}", headers=auth("analyst"))).json()
    assert len(detail["alerts"]) == 1
    p1 = await case_by_title(client, "Aufnahme in privilegierte Gruppe")
    alerts = (await client.get(f"/api/v1/cases/{p1['case_id']}", headers=auth("analyst"))).json()["alerts"]
    split = await client.post(
        f"/api/v1/cases/{p1['case_id']}/split", json={"alert_ids": [alerts[-1]["alert_id"]]}, headers=auth("senior")
    )
    assert split.status_code == 200
    assert (
        await client.post(f"/api/v1/case-merges/{split.json()['merge_id']}/revert", headers=auth("senior"))
    ).status_code == 200
    assert (
        await client.post(
            f"/api/v1/cases/{p1['case_id']}/merge", json={"source_case_id": p1["case_id"]}, headers=auth("senior")
        )
    ).status_code == 422
