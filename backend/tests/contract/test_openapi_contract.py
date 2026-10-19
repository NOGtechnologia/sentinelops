"""API contract (spec 15.2): Schemathesis against the OpenAPI document - no 5xx, conforming responses.

Runs a real Uvicorn server on its own database with demo data, so generated requests (including
writes) cannot disturb other tests.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import uuid
from collections.abc import Iterator

import httpx
import pytest
import schemathesis
import uvicorn
from hypothesis import HealthCheck, settings
from schemathesis.checks import not_a_server_error, response_schema_conformance

from sentinelops.api.app import create_app
from sentinelops.auth.principal import issue_demo_token
from sentinelops.runtime import Runtime
from tests.integration.conftest import _create_db, _drop_db, migrate
from tests.integration.demo_data import generate_dataset, load_sync, settings_for

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def api_url(pg_server: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    name = f"so_contract_{uuid.uuid4().hex[:8]}"
    url = asyncio.run(_create_db(pg_server, name))
    migrate(url)
    load_sync(url, generate_dataset(tmp_path_factory.mktemp("contract") / "dev", events_per_day=1500))
    port = _free_port()
    app = create_app(Runtime(settings_for(url)))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base}/api/v1/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    try:
        yield base
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        asyncio.run(_drop_db(pg_server, name))


@pytest.fixture(scope="module")
def api_schema(api_url: str) -> schemathesis.BaseSchema:
    return schemathesis.openapi.from_url(f"{api_url}/api/openapi.json")


schema = schemathesis.pytest.from_fixture("api_schema")


def _check(case: schemathesis.Case, user: str) -> None:
    headers = {"Authorization": f"Bearer {issue_demo_token(user)}"}
    if case.path == "/api/v1/ingest/{source_type}":
        headers.pop("Authorization")  # ingest tokens only; 401 is the documented answer
    # No 5xx and documented response schemas. Status codes like 403/404/409/422 are deliberate answers to
    # generated (often invalid) requests, so status-code conformance is not part of the contract.
    case.call_and_validate(headers=headers, checks=[not_a_server_error, response_schema_conformance])


@schema.parametrize()
@settings(max_examples=12, deadline=None, suppress_health_check=list(HealthCheck))
def test_api_contract_as_senior_analyst(case: schemathesis.Case) -> None:
    _check(case, "senior")


@schema.parametrize()
@settings(max_examples=12, deadline=None, suppress_health_check=list(HealthCheck))
def test_api_contract_as_admin(case: schemathesis.Case) -> None:
    _check(case, "admin")
