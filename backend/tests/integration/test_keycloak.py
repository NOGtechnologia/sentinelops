"""OIDC end to end with the bundled Keycloak realm (spec 15.2: Testcontainers for PostgreSQL and Keycloak).

Starts quay.io/keycloak/keycloak with deploy/keycloak/realm-sentinelops.json plus a test-only client that
allows the password grant, obtains a real access token and calls the API with it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from sentinelops.api.app import create_app
from sentinelops.auth.principal import OidcVerifier
from sentinelops.runtime import Runtime
from tests.integration.demo_data import settings_for

pytestmark = pytest.mark.integration

IMAGE = "quay.io/keycloak/keycloak:26.7.5@sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85"
REALM = Path(__file__).resolve().parents[3] / "deploy" / "keycloak" / "realm-sentinelops.json"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=20)  # noqa: S607 - PATH lookup
    except (OSError, subprocess.SubprocessError):
        return False
    return True


# Justification for the conditional skip: the test needs a Docker daemon (Testcontainers). CI runners
# provide one, so the test always runs in CI; developer machines without Docker skip it explicitly.
requires_docker = pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available")


@pytest.fixture(scope="module")
def keycloak(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    from testcontainers.core.container import DockerContainer  # only needed with Docker

    realm = json.loads(REALM.read_text(encoding="utf-8"))
    realm["clients"].append(
        {
            "clientId": "sentinelops-test",
            "enabled": True,
            "publicClient": True,
            "directAccessGrantsEnabled": True,
            "standardFlowEnabled": False,
            "protocolMappers": realm["clients"][0]["protocolMappers"],
        }
    )
    for user in realm["users"]:
        for credential in user["credentials"]:
            credential["temporary"] = False
    folder = tmp_path_factory.mktemp("realm")
    realm_file = folder / "realm-sentinelops.json"
    realm_file.write_text(json.dumps(realm), encoding="utf-8")
    # pytest creates temporary folders with mode 0700; Keycloak runs as a different user in the container
    # and could not read the bind-mounted realm (first CI run: it exited, every request was refused).
    folder.chmod(0o755)
    realm_file.chmod(0o644)
    container = (
        DockerContainer(IMAGE)
        .with_command("start-dev --import-realm")
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", "test-only-admin")
        .with_volume_mapping(str(folder), "/opt/keycloak/data/import", "ro")
        .with_exposed_ports(8080)
    )
    with container:
        base = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
        issuer = f"{base}/realms/sentinelops"
        for _ in range(180):
            try:
                if httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            stdout, stderr = container.get_logs()
            logs = (stdout + stderr).decode("utf-8", "replace")[-4000:]
            pytest.fail(f"Keycloak did not become ready within 180 s; container log tail:\n{logs}")
        yield issuer


def _token(issuer: str, username: str, password: str) -> str:
    response = httpx.post(
        f"{issuer}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "sentinelops-test", "username": username, "password": password},
        timeout=10,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


@requires_docker
def test_keycloak_token_is_verified_with_roles_and_audience(keycloak: str) -> None:
    verifier = OidcVerifier(keycloak, "sentinelops", "realm_access.roles")
    principal = verifier.verify(_token(keycloak, "sam.senior", "demo-only-senior"))
    assert principal.username == "sam.senior"
    assert principal.roles == ("senior_analyst",)


@requires_docker
async def test_api_accepts_keycloak_tokens_and_enforces_roles(keycloak: str, demo_db: str) -> None:
    settings = settings_for(demo_db)
    rt = Runtime(replace(settings, demo_mode=False, oidc_issuer=keycloak))
    app = create_app(rt)
    analyst = _token(keycloak, "erika.analyst", "demo-only-analyst")
    auditor = _token(keycloak, "audrey.auditor", "demo-only-auditor")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        me = (await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst}"})).json()
        assert me["roles"] == ["analyst"]
        audit = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {analyst}"})
        assert audit.status_code == 403
        assert (await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {auditor}"})).status_code == 200
        # demo tokens are rejected outside demo mode
        assert (await client.post("/api/v1/auth/demo-login", json={"user": "admin"})).status_code == 404
    await rt.engine.dispose()
