from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from sentinelops.auth.principal import (
    AuthError,
    OidcVerifier,
    Principal,
    hash_token,
    issue_demo_token,
    new_ingest_token,
    role_matrix,
    route_permissions,
    verify_demo_token,
)

ISSUER = "https://idp.musterfirma.example/realms/sentinelops"


def keypair() -> tuple[Any, dict[str, Any]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    return key, jwk


def transport(jwk: dict[str, Any], calls: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"jwks_uri": f"{ISSUER}/protocol/openid-connect/certs"})
        return httpx.Response(200, json={"keys": [jwk]})

    return httpx.MockTransport(handler)


def token(key: Any, **claims: Any) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": "sentinelops",
        "sub": "u-1",
        "iat": now,
        "exp": now + 300,
        "preferred_username": "erika",
        "name": "Erika",
        "realm_access": {"roles": ["analyst", "unknown"]},
    }
    payload.update(claims)
    return jwt.encode(
        payload, key, algorithm="RS256", headers={"kid": claims.pop("kid", "k1") if "kid" in claims else "k1"}
    )


def test_oidc_token_verified_with_jwks_and_cached() -> None:
    key, jwk = keypair()
    calls: list[str] = []
    verifier = OidcVerifier(ISSUER, "sentinelops", "realm_access.roles", transport=transport(jwk, calls))
    principal = verifier.verify(token(key))
    assert principal == Principal("u-1", "erika", "Erika", ("analyst",))
    verifier.verify(token(key))
    assert len(calls) == 2  # discovery + JWKS only once


def test_oidc_internal_jwks_url_skips_discovery_but_checks_issuer() -> None:
    key, jwk = keypair()
    calls: list[str] = []
    verifier = OidcVerifier(
        ISSUER,
        "sentinelops",
        "realm_access.roles",
        transport=transport(jwk, calls),
        jwks_url="http://keycloak:8080/realms/sentinelops/protocol/openid-connect/certs",
    )
    assert verifier.verify(token(key)).username == "erika"
    assert calls == ["/realms/sentinelops/protocol/openid-connect/certs"]
    with pytest.raises(AuthError):
        verifier.verify(token(key, iss="http://keycloak:8080/realms/sentinelops"))


@pytest.mark.parametrize(
    "claims",
    [{"aud": "other"}, {"iss": "https://evil.example"}, {"exp": int(time.time()) - 10}],
)
def test_oidc_rejects_wrong_claims(claims: dict[str, Any]) -> None:
    key, jwk = keypair()
    verifier = OidcVerifier(ISSUER, "sentinelops", "realm_access.roles", transport=transport(jwk, []))
    with pytest.raises(AuthError):
        verifier.verify(token(key, **claims))


def test_oidc_rejects_foreign_key_and_garbage() -> None:
    key, jwk = keypair()
    other, _ = keypair()
    verifier = OidcVerifier(ISSUER, "sentinelops", "realm_access.roles", transport=transport(jwk, []))
    with pytest.raises(AuthError):
        verifier.verify(token(other))
    with pytest.raises(AuthError):
        verifier.verify("not-a-jwt")
    unknown_kid = jwt.encode({"sub": "x"}, key, algorithm="RS256", headers={"kid": "nope"})
    with pytest.raises(AuthError, match="unknown signing key"):
        verifier.verify(unknown_kid)


def test_oidc_roles_claim_not_a_list() -> None:
    key, jwk = keypair()
    verifier = OidcVerifier(ISSUER, "sentinelops", "realm_access.roles", transport=transport(jwk, []))
    assert verifier.verify(token(key, realm_access={"roles": "admin"})).roles == ()
    nested = OidcVerifier(ISSUER, "sentinelops", "a.b.c", transport=transport(jwk, []))
    assert nested.verify(token(key)).roles == ()


def test_demo_tokens() -> None:
    principal = verify_demo_token(issue_demo_token("senior"))
    assert principal.roles == ("senior_analyst",)
    assert principal.can("actions:decide")
    assert not verify_demo_token(issue_demo_token("analyst")).can("actions:decide")
    with pytest.raises(AuthError):
        issue_demo_token("root")
    with pytest.raises(AuthError):
        verify_demo_token(issue_demo_token("analyst", now=time.time() - 10 * 3600))


def test_ingest_tokens_and_permission_files() -> None:
    token_id, full, digest = new_ingest_token()
    assert full.startswith(f"soi_{token_id}_")
    assert hash_token(full) == digest
    matrix = role_matrix()
    assert set(matrix) == {"analyst", "senior_analyst", "detection_engineer", "admin", "auditor"}
    assert "actions:decide" not in matrix["analyst"]
    assert "actions:decide" in matrix["senior_analyst"]
    assert all(":" in p or p in ("public", "authenticated") for p in route_permissions().values())
