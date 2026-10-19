"""FastAPI dependencies: runtime, principal, permission checks."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import and_, select

from sentinelops.auth.principal import AuthError, OidcVerifier, Principal, hash_token, verify_demo_token
from sentinelops.runtime import Runtime
from sentinelops.storage.models import ingest_tokens

#: Upper bound for list offsets (larger values cannot address real rows and would overflow BIGINT).
MAX_OFFSET = 10_000_000


def get_runtime(request: Request) -> Runtime:
    runtime: Runtime = request.app.state.runtime
    return runtime


RuntimeDep = Annotated[Runtime, Depends(get_runtime)]


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
    return token.strip()


def _verifier(request: Request) -> OidcVerifier | None:
    verifier: OidcVerifier | None = getattr(request.app.state, "oidc", None)
    return verifier


async def get_principal(request: Request, rt: RuntimeDep) -> Principal:
    token = _bearer(request)
    try:
        if token.startswith("soi_"):
            raise AuthError("ingest tokens are only valid for the ingest API")
        verifier = _verifier(request)
        if rt.settings.demo_mode:
            try:
                return verify_demo_token(token)
            except AuthError:
                if verifier is None:
                    raise
        if verifier is None:
            raise AuthError("no identity provider configured")
        return verifier.verify(token)
    except AuthError as exc:
        raise HTTPException(401, str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require(permission: str) -> Callable[..., Coroutine[Any, Any, Principal]]:
    async def dependency(principal: PrincipalDep) -> Principal:
        if not principal.can(permission):
            raise HTTPException(403, f"permission {permission} required")
        return principal

    return dependency


async def ingest_principal(request: Request, rt: RuntimeDep) -> Principal:
    """Ingest API: a revocable ingest token or a user with ``ingest:write``."""
    token = _bearer(request)
    if token.startswith("soi_"):
        async with rt.engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        select(ingest_tokens).where(
                            and_(ingest_tokens.c.token_hash == hash_token(token), ingest_tokens.c.revoked_at.is_(None))
                        )
                    )
                )
                .mappings()
                .first()
            )
        if row is None:
            raise HTTPException(401, "invalid or revoked ingest token")
        return Principal(f"ingest-token:{row['token_id']}", row["name"], row["name"], ("ingest",), kind="ingest_token")
    principal = await get_principal(request, rt)
    if not principal.can("ingest:write"):
        raise HTTPException(403, "permission ingest:write required")
    return principal
