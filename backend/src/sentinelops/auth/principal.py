"""Authentication: OIDC access tokens, demo tokens, ingest tokens; RBAC.

* **OIDC** (production): RS256/ES256 access tokens of the configured issuer
  (Keycloak in the Compose stack) are verified against the issuer's JWKS;
  roles come from a configurable claim (default ``realm_access.roles``).
* **Demo tokens** exist only when ``SENTINELOPS_DEMO_MODE=true``: HS256 tokens
  for the five fictitious demo users, clearly marked in the UI.
* **Ingest tokens** (``soi_<id>_<secret>``) authenticate the bulk ingest API
  only; they are stored as SHA-256 hashes and can be revoked.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import httpx
import jwt
import yaml

ROLES = ("analyst", "senior_analyst", "detection_engineer", "admin", "auditor")
DEMO_USERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "analyst": ("Demo Analyst (L1)", ("analyst",)),
    "senior": ("Demo Senior Analyst (L2)", ("senior_analyst",)),
    "engineer": ("Demo Detection Engineer", ("detection_engineer",)),
    "admin": ("Demo Administrator", ("admin",)),
    "auditor": ("Demo Auditor", ("auditor",)),
}
PERMISSIONS_FILE = Path(__file__).resolve().parent.parent / "api" / "permissions.yaml"
DEMO_ISSUER = "sentinelops-demo"


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    display_name: str
    roles: tuple[str, ...]
    kind: str = "user"  # user | ingest_token

    @property
    def permissions(self) -> frozenset[str]:
        matrix = role_matrix()
        return frozenset(p for r in self.roles for p in matrix.get(r, ()))

    def can(self, permission: str) -> bool:
        return permission in self.permissions


@cache
def _permissions_doc() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(PERMISSIONS_FILE.read_text(encoding="utf-8"))
    return data


def role_matrix() -> dict[str, tuple[str, ...]]:
    return {role: tuple(perms) for role, perms in _permissions_doc()["roles"].items()}


def route_permissions() -> dict[str, str]:
    return dict(_permissions_doc()["routes"])


def _claim(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def demo_secret() -> bytes:
    return hashlib.sha256(b"sentinelops-demo-token-secret").digest()


def issue_demo_token(user: str, now: float | None = None, ttl: int = 8 * 3600) -> str:
    if user not in DEMO_USERS:
        raise AuthError("unknown demo user")
    display, roles = DEMO_USERS[user]
    issued = int(now if now is not None else time.time())
    payload = {
        "iss": DEMO_ISSUER,
        "sub": f"demo-{user}",
        "preferred_username": f"demo.{user}",
        "name": display,
        "roles": list(roles),
        "iat": issued,
        "exp": issued + ttl,
    }
    return jwt.encode(payload, demo_secret(), algorithm="HS256")


def verify_demo_token(token: str) -> Principal:
    try:
        payload = jwt.decode(token, demo_secret(), algorithms=["HS256"], issuer=DEMO_ISSUER)
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid demo token: {exc}") from exc
    roles = tuple(r for r in payload.get("roles", []) if r in ROLES)
    return Principal(str(payload["sub"]), str(payload["preferred_username"]), str(payload.get("name", "")), roles)


class OidcVerifier:
    """Verifies access tokens of one issuer; caches the JWKS for 10 minutes."""

    def __init__(
        self, issuer: str, audience: str, roles_claim: str, transport: httpx.BaseTransport | None = None
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.roles_claim = roles_claim
        self.transport = transport
        self._jwks: dict[str, Any] | None = None
        self._fetched = 0.0

    def _keys(self) -> dict[str, Any]:
        if self._jwks is None or time.time() - self._fetched > 600:
            with httpx.Client(timeout=10, transport=self.transport) as client:
                config = client.get(f"{self.issuer}/.well-known/openid-configuration").json()
                self._jwks = client.get(config["jwks_uri"]).json()
            self._fetched = time.time()
        return self._jwks

    def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
            keys = self._keys()
            key = next((k for k in keys.get("keys", []) if k.get("kid") == header.get("kid")), None)
            if key is None:
                raise AuthError("unknown signing key")
            signing_key = jwt.PyJWK(key).key
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "ES256", "PS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except (jwt.PyJWTError, httpx.HTTPError, KeyError, ValueError) as exc:
            raise AuthError(f"invalid access token: {exc}") from exc
        raw_roles = _claim(payload, self.roles_claim) or []
        roles = tuple(sorted(r for r in raw_roles if r in ROLES)) if isinstance(raw_roles, list) else ()
        return Principal(
            str(payload["sub"]),
            str(payload.get("preferred_username", payload["sub"])),
            str(payload.get("name", "")),
            roles,
        )


def new_ingest_token() -> tuple[str, str, str]:
    """Return (token_id, full token, sha256 hash). The full token is shown once."""
    token_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    token = f"soi_{token_id}_{secret}"
    return token_id, token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
