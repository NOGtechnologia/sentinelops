"""HTTP hardening: security headers and simple rate limits (spec 16.1).

The API authenticates with bearer tokens only (no cookies), so classic CSRF
does not apply; state-changing endpoints additionally reject cross-site
``Origin`` headers.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

RATE_LIMITS: tuple[tuple[str, int], ...] = (
    ("/api/v1/auth/", 20),
    ("/api/v1/uploads", 30),
    ("/api/v1/ingest/", 120),
    ("/api/v1/", 1200),
)
WINDOW_SECONDS = 60


def content_security_policy(extra_connect: str | None) -> str:
    connect = "'self'" + (f" {extra_connect}" if extra_connect else "")
    return (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        f"connect-src {connect}; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Callable[..., Awaitable[None]], oidc_issuer: str | None) -> None:
        super().__init__(app)
        self.csp = content_security_policy(oidc_issuer)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", self.csp)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limit per client address and endpoint group (in memory)."""

    def __init__(self, app: Callable[..., Awaitable[None]], enabled: bool = True) -> None:
        super().__init__(app)
        self.enabled = enabled
        self.hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if self.enabled:
            path = request.url.path
            group = next(((prefix, limit) for prefix, limit in RATE_LIMITS if path.startswith(prefix)), None)
            if group is not None:
                client = request.client.host if request.client else "unknown"
                key = (client, group[0])
                now = time.monotonic()
                window = self.hits[key]
                while window and now - window[0] > WINDOW_SECONDS:
                    window.popleft()
                if len(window) >= group[1]:
                    return JSONResponse(
                        {"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(WINDOW_SECONDS)}
                    )
                window.append(now)
        return await call_next(request)


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Reject state-changing browser requests from foreign origins."""

    def __init__(self, app: Callable[..., Awaitable[None]], allowed: set[str]) -> None:
        super().__init__(app)
        self.allowed = allowed

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        origin = request.headers.get("origin")
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and origin:
            own = f"{request.url.scheme}://{request.url.netloc}"
            if origin != own and origin not in self.allowed:
                return JSONResponse({"detail": "cross-origin request rejected"}, status_code=403)
        return await call_next(request)
