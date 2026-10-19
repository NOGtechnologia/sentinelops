"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Iterable, Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import DBAPIError
from starlette.routing import BaseRoute

from sentinelops.api.routes import cases, core, data, operations
from sentinelops.api.security import OriginCheckMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from sentinelops.auth.principal import OidcVerifier, route_permissions
from sentinelops.runtime import Runtime
from sentinelops.settings import PRODUCT_NAME, SOFTWARE_VERSION, Settings
from sentinelops.worker.main import run_forever


class PermissionMapError(RuntimeError):
    pass


def iter_api_routes(routes: Iterable[BaseRoute]) -> Iterator[APIRoute]:
    """All APIRoutes, including those of included routers.

    Since FastAPI 0.14x ``app.routes`` holds included routers as wrapper
    objects (with ``original_router``) instead of flattened routes - a check
    that only looked at ``app.routes`` would silently check nothing. SentinelOps
    routers carry their full prefix, so the paths are complete.
    """
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from iter_api_routes(inner.routes)


def check_route_permissions(app: FastAPI) -> None:
    """Every API route needs an entry in permissions.yaml (spec 16.1)."""
    mapped = route_permissions()
    declared = {
        f"{method} {route.path}"
        for route in iter_api_routes(app.routes)
        if route.path.startswith("/api/")
        for method in (route.methods or set()) - {"HEAD", "OPTIONS"}
    }
    # Second, independent source: the OpenAPI document.
    for path, path_item in app.openapi().get("paths", {}).items():
        declared.update(f"{method.upper()} {path}" for method in path_item if path.startswith("/api/"))
    app.openapi_schema = None  # rebuilt lazily after all routes are registered
    missing = sorted(declared - set(mapped))
    if missing:
        raise PermissionMapError("routes without permissions.yaml entry: " + ", ".join(missing))


def install_openapi_errors(app: FastAPI) -> None:
    """Document the real error shape: ``detail`` is a message, or FastAPI's list of validation errors.

    Semantic checks in the routes answer 422 with a plain message (``{"detail": "unknown rule"}``),
    request validation with the list form. The contract tests validate responses against this schema.
    """
    original = app.openapi

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            schema = original()
            error = schema.get("components", {}).get("schemas", {}).get("HTTPValidationError")
            if error is not None:
                error["properties"]["detail"] = {
                    "title": "Detail",
                    "anyOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"$ref": "#/components/schemas/ValidationError"}},
                    ],
                }
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]  # FastAPI's documented way to customise the schema


def _is_invalid_input(exc: BaseException) -> bool:
    """Database rejected a *value* (SQLSTATE class 22: NUL byte, out of range, bad encoding)."""
    for err in (exc, exc.__cause__, getattr(exc, "orig", None)):
        if isinstance(err, UnicodeError):
            return True
        sqlstate = getattr(err, "sqlstate", None) or getattr(getattr(err, "__cause__", None), "sqlstate", None)
        if isinstance(sqlstate, str) and sqlstate.startswith("22"):
            return True
    return False


def install_input_error_handler(app: FastAPI) -> None:
    """Values PostgreSQL cannot store (NUL bytes, lone surrogates, overflow) are client errors (422), not 500.

    Everything else keeps surfacing as a server error, so real bugs stay visible to the contract tests.
    """

    @app.exception_handler(DBAPIError)
    async def database_error(request: Request, exc: DBAPIError) -> JSONResponse:
        if _is_invalid_input(exc):
            return JSONResponse({"detail": "invalid input value"}, status_code=422)
        raise exc

    @app.exception_handler(UnicodeEncodeError)
    async def encoding_error(request: Request, exc: UnicodeEncodeError) -> JSONResponse:
        return JSONResponse({"detail": "invalid characters in input"}, status_code=422)


def create_app(runtime: Runtime | None = None) -> FastAPI:
    rt = runtime or Runtime(Settings())

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        stop = asyncio.Event()
        task = None
        if os.environ.get("SENTINELOPS_INPROCESS_WORKER", "").lower() in ("1", "true", "yes"):
            task = asyncio.create_task(run_forever(rt, stop=stop))
        try:
            yield
        finally:
            stop.set()
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await rt.engine.dispose()

    app = FastAPI(
        title=f"{PRODUCT_NAME} API",
        version=SOFTWARE_VERSION,
        description="Explainable security operations: from log lines to an investigable case.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.runtime = rt
    app.state.oidc = (
        OidcVerifier(
            rt.settings.oidc_issuer,
            rt.settings.oidc_audience,
            rt.settings.oidc_roles_claim,
            jwks_url=rt.settings.oidc_jwks_url,
        )
        if rt.settings.oidc_issuer
        else None
    )
    for router_module in (core, cases, data, operations):
        app.include_router(router_module.router)
    check_route_permissions(app)
    install_openapi_errors(app)
    install_input_error_handler(app)

    app.add_middleware(
        OriginCheckMiddleware, allowed=set(filter(None, os.environ.get("SENTINELOPS_ALLOWED_ORIGINS", "").split(",")))
    )
    app.add_middleware(RateLimitMiddleware, enabled=os.environ.get("SENTINELOPS_RATE_LIMIT", "true").lower() != "false")
    app.add_middleware(SecurityHeadersMiddleware, oidc_issuer=rt.settings.oidc_issuer)

    static = rt.settings.static_dir
    if static and Path(static, "index.html").exists():
        index = Path(static, "index.html")
        assets = Path(static, "assets")
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")
        fonts = Path(static, "fonts")
        if fonts.exists():
            app.mount("/fonts", StaticFiles(directory=fonts), name="fonts")

        root = Path(static).resolve()
        top_level = {p.name: p for p in root.iterdir() if p.is_file()}

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str) -> FileResponse:
            if path.startswith("api/"):
                raise HTTPException(404)
            # Only files that exist at start-up in the static root are served
            # directly (favicon, robots.txt); everything else is the SPA.
            return FileResponse(top_level.get(path, index))

    return app
