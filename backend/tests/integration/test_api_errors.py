"""Error and edge paths of the API."""

from __future__ import annotations

import httpx
import pytest

from sentinelops.api.security import RateLimitMiddleware, content_security_policy
from sentinelops.auth.principal import issue_demo_token

pytestmark = pytest.mark.integration


def auth(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_demo_token(user)}"}


async def first_case(client: httpx.AsyncClient, fragment: str = "") -> str:
    items = (await client.get("/api/v1/cases", headers=auth("analyst"))).json()["items"]
    return str(next(c["case_id"] for c in items if fragment in c["title_de"]))


async def test_not_found_paths(client: httpx.AsyncClient) -> None:
    h = auth("senior")
    for method, url in (
        ("GET", "/api/v1/cases/nope/timeline"),
        ("GET", "/api/v1/cases/nope/evidence"),
        ("GET", "/api/v1/cases/nope/graph"),
        ("GET", "/api/v1/cases/nope/actions"),
        ("GET", "/api/v1/cases/nope/ai-summaries"),
        ("POST", "/api/v1/cases/nope/ai-summaries"),
        ("GET", "/api/v1/cases/nope/report"),
        ("GET", "/api/v1/alerts/nope"),
        ("GET", "/api/v1/events/nope"),
        ("GET", "/api/v1/rules/NOPE"),
        ("POST", "/api/v1/case-merges/nope/revert"),
        ("POST", "/api/v1/exceptions/EXC-9999/approve"),
    ):
        response = await client.request(method, url, headers=h)
        assert response.status_code == 404, (method, url, response.status_code)
    assert (await client.post("/api/v1/actions/nope/execute", headers=h)).status_code == 404
    assert (await client.post("/api/v1/cases/nope/notes", json={"text": "x"}, headers=h)).status_code == 404
    assert (await client.patch("/api/v1/cases/nope", json={"status": "in_progress"}, headers=h)).status_code == 404
    assert (
        await client.post("/api/v1/alerts/nope/false-positive", json={"reason": "abc"}, headers=h)
    ).status_code == 404
    assert (
        await client.patch("/api/v1/rules/NOPE", json={"active": False, "reason": "abc"}, headers=auth("engineer"))
    ).status_code == 404


async def test_validation_errors(client: httpx.AsyncClient) -> None:
    h = auth("senior")
    cid = await first_case(client)
    assert (await client.patch(f"/api/v1/cases/{cid}", json={"status": "done"}, headers=h)).status_code == 422
    assert (await client.patch("/api/v1/cases/bulk", json={"case_ids": []}, headers=h)).status_code == 422
    assert (await client.patch("/api/v1/cases/bulk", json={"case_ids": "x"}, headers=h)).status_code == 422
    assert (
        await client.get(f"/api/v1/cases/{cid}/report", params={"created_at": "yesterday"}, headers=h)
    ).status_code == 422
    assert (await client.get("/api/v1/events", params={"start": "noon"}, headers=h)).status_code == 422
    assert (await client.get("/api/v1/reports/aggregate", params={"start": "noon"}, headers=h)).status_code == 422
    assert (await client.post(f"/api/v1/cases/{cid}/split", json={"alert_ids": ["nope"]}, headers=h)).status_code == 422
    assert (
        await client.post(
            "/api/v1/exceptions",
            json={"rule_id": "NOPE", "description": "long enough text", "match": {"a": "b"}, "expires": "2030-01-01"},
            headers=h,
        )
    ).status_code == 422
    assert (
        await client.post(
            "/api/v1/exceptions",
            json={
                "rule_id": "SO-AUTH-001",
                "description": "long enough text",
                "match": {"a": "b"},
                "expires": "2020-01-01",
            },
            headers=h,
        )
    ).status_code == 422
    assert (
        await client.post("/api/v1/admin/ingest-tokens", json={"name": "x"}, headers=auth("admin"))
    ).status_code == 422
    assert (await client.delete("/api/v1/admin/ingest-tokens/nope", headers=auth("admin"))).status_code == 404


async def test_closed_cases_are_protected(client: httpx.AsyncClient) -> None:
    h = auth("senior")
    cid = await first_case(client, "Konto angelegt")
    other = await first_case(client, "Sicherheitsprotokoll")
    assert (
        await client.patch(f"/api/v1/cases/{cid}", json={"status": "resolved_benign"}, headers=h)
    ).status_code == 200
    detail = (await client.get(f"/api/v1/cases/{cid}", headers=h)).json()
    assert detail["case"]["closed_at"] is not None
    assert (await client.patch(f"/api/v1/cases/{cid}", json={"assignee": "x"}, headers=h)).status_code == 409
    assert (
        await client.post(f"/api/v1/cases/{other}/merge", json={"source_case_id": cid}, headers=h)
    ).status_code == 409
    alerts = detail["alerts"]
    assert (
        await client.post(f"/api/v1/cases/{cid}/split", json={"alert_ids": [alerts[0]["alert_id"]]}, headers=h)
    ).status_code == 409
    filtered = (
        await client.get("/api/v1/cases", params={"status": ["resolved_benign"], "q": "Konto"}, headers=h)
    ).json()
    assert filtered["total"] == 1
    assert (await client.patch(f"/api/v1/cases/{cid}", json={"status": "in_progress"}, headers=h)).status_code == 200
    assert (await client.patch(f"/api/v1/cases/{cid}", json={}, headers=h)).status_code == 200


async def test_alerts_listing_and_suppressed(client: httpx.AsyncClient) -> None:
    h = auth("analyst")
    active = (await client.get("/api/v1/alerts", headers=h)).json()
    everything = (await client.get("/api/v1/alerts", params={"include_suppressed": True}, headers=h)).json()
    assert everything["total"] == active["total"] + 1  # svc_monitor (EXC-0001)
    by_rule = (await client.get("/api/v1/alerts", params={"rule_id": "SO-AUTH-001"}, headers=h)).json()
    assert by_rule["total"] == 4
    entities = (await client.get("/api/v1/entities", params={"q": "jonas"}, headers=h)).json()
    assert entities["items"]


async def test_duplicate_proposal_and_decision(client: httpx.AsyncClient) -> None:
    cid = await first_case(client, "Laterale Bewegung")
    body = {"step_id": "RESET_PASSWORD", "parameters": {"user": "thomas.klein"}, "reason": "compromised"}
    first = (await client.post(f"/api/v1/cases/{cid}/actions", json=body, headers=auth("analyst"))).json()
    decided = await client.post(
        f"/api/v1/actions/{first['action_id']}/decision",
        json={"decision": "approved", "reason": "ok"},
        headers=auth("senior"),
    )
    assert decided.status_code == 200
    again = await client.post(
        f"/api/v1/actions/{first['action_id']}/decision",
        json={"decision": "approved", "reason": "ok"},
        headers=auth("senior"),
    )
    assert again.status_code == 403
    listed = (await client.get(f"/api/v1/cases/{cid}/actions", headers=auth("analyst"))).json()
    assert any(a["approval"] for a in listed)


def test_security_helpers() -> None:
    assert "connect-src 'self' https://idp.example" in content_security_policy("https://idp.example")
    assert "connect-src 'self';" in content_security_policy(None)
    # a path in the issuer would only allow that exact path, not the token endpoint below it
    csp = content_security_policy("http://localhost:8081/realms/sentinelops")
    assert "connect-src 'self' http://localhost:8081;" in csp
    assert "connect-src 'self';" in content_security_policy("not a url")


async def test_rate_limit_middleware() -> None:
    from fastapi import FastAPI

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, enabled=True)

    @app.post("/api/v1/auth/demo-login")
    async def login() -> dict[str, str]:
        return {}

    @app.get("/other")
    async def other() -> dict[str, str]:
        return {}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        codes = [(await c.post("/api/v1/auth/demo-login")).status_code for _ in range(22)]
        assert codes.count(429) == 2
        assert (await c.get("/other")).status_code == 200


async def test_spa_and_static_serving(demo_db: str, tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path

    from sentinelops.api.app import create_app
    from sentinelops.runtime import Runtime
    from tests.integration.demo_data import settings_for

    static = Path(str(tmp_path))
    (static / "assets").mkdir()
    (static / "fonts").mkdir()
    (static / "index.html").write_text("<!doctype html><title>SentinelOps</title>", encoding="utf-8")
    (static / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    (static / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    base = settings_for(demo_db)
    from dataclasses import replace

    rt = Runtime(replace(base, static_dir=str(static)))
    monkeypatch.setenv("SENTINELOPS_INPROCESS_WORKER", "true")
    app = create_app(rt)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert "SentinelOps" in (await c.get("/cases/abc")).text
        assert (await c.get("/favicon.svg")).text == "<svg/>"
        assert (await c.get("/assets/app.js")).status_code == 200
        assert (await c.get("/api/unknown")).status_code == 404
        assert "SentinelOps" in (await c.get("/../../etc/passwd")).text
    async with app.router.lifespan_context(app):
        pass
