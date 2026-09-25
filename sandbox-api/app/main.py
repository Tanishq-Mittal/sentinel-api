"""FastAPI application factory and local-only middleware for the sandbox."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, Response

from .auth import AuthService
from .config import Settings
from .fixtures import FixtureStore
from .routers import auth, health, orders, reports


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies before route processing."""

    def __init__(self, app: Any, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length"},
                )
            if declared_size > self.max_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            body = await request.body()
            if len(body) > self.max_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )
        return await call_next(request)


class ResponseSizeLimitMiddleware(BaseHTTPMiddleware):
    """Buffer small sandbox responses and reject unexpectedly large bodies."""

    def __init__(self, app: Any, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        declared_size = response.headers.get("content-length")
        if declared_size:
            try:
                if int(declared_size) > self.max_bytes:
                    return JSONResponse(
                        status_code=500,
                        content={"detail": "Response exceeds configured size limit"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=500,
                    content={"detail": "Invalid response Content-Length"},
                )
        body = b"".join([chunk async for chunk in response.body_iterator])
        if len(body) > self.max_bytes:
            return JSONResponse(
                status_code=500,
                content={"detail": "Response exceeds configured size limit"},
            )

        headers = dict(response.headers)
        headers.pop("content-length", None)
        return Response(
            content=body,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
            background=response.background,
        )


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Apply a short upper bound to request handling."""

    def __init__(self, app: Any, timeout_seconds: float) -> None:
        super().__init__(app)
        self.timeout_seconds = timeout_seconds

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        try:
            return await asyncio.wait_for(
                call_next(request), timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=408,
                content={"detail": "Request timed out"},
            )


class LocalRedirectGuardMiddleware(BaseHTTPMiddleware):
    """Reject redirects that point outside this local sandbox."""

    def __init__(self, app: Any, server_url: str) -> None:
        super().__init__(app)
        self.server_url = server_url.rstrip("/")

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        if not 300 <= response.status_code < 400:
            return response

        location = response.headers.get("location")
        if not location:
            return response
        is_relative = location.startswith("/") and not location.startswith("//")
        is_local_absolute = location == self.server_url or location.startswith(
            f"{self.server_url}/"
        )
        if not (is_relative or is_local_absolute):
            return JSONResponse(
                status_code=502,
                content={"detail": "External redirects are disabled"},
            )
        return response


_LOCAL_DOCS_JS = r"""
(function () {
  function renderOpenApi(targetSelector) {
    var target = document.querySelector(targetSelector);
    if (!target) return;
    fetch('/openapi.json', { credentials: 'same-origin' })
      .then(function (response) {
        if (!response.ok) throw new Error('Local OpenAPI request failed');
        return response.json();
      })
      .then(function (documentData) {
        target.textContent = JSON.stringify(documentData, null, 2);
        target.style.whiteSpace = 'pre-wrap';
        target.style.wordBreak = 'break-word';
      })
      .catch(function (error) {
        target.textContent = 'Unable to load the local OpenAPI document: ' + error.message;
      });
  }

  function SwaggerUIBundle() {
    renderOpenApi('#swagger-ui');
  }
  SwaggerUIBundle.presets = {
    apis: {},
    SwaggerUIStandalonePreset: {}
  };
  window.SwaggerUIBundle = SwaggerUIBundle;
  window.Redoc = {
    init: function () { renderOpenApi('body'); }
  };
})();
"""

_LOCAL_DOCS_CSS = """
body { font-family: system-ui, sans-serif; margin: 1.5rem; }
#swagger-ui, body > pre { background: #f6f8fa; padding: 1rem; overflow: auto; }
"""

_LOCAL_FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="6" fill="#111827"/>'
    '<path d="M8 22V10h4l4 6 4-6h4v12h-4v-6l-4 6-4-6v6z" fill="#fff"/>'
    '</svg>'
)


def _local_asset(content: str, media_type: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Cache-Control": "no-store"},
    )


def create_app(
    settings: Settings | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    """Create an isolated sandbox app with in-memory fixtures and sessions."""

    settings = settings or Settings.from_env()
    fixtures = FixtureStore()
    auth_service = AuthService(settings, clock=clock)

    app = FastAPI(
        title="SentinelAPI Authorized Local Sandbox",
        version="0.1.0",
        description=(
            "Synthetic localhost-only API for controlled SentinelAPI BOLA/IDOR and "
            "excessive-data-exposure testing. It contains no production data or external targets."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
        servers=[
            {
                "url": settings.server_url,
                "description": "Explicit local sandbox server",
            }
        ],
    )
    app.state.settings = settings
    app.state.fixtures = fixtures
    app.state.auth_service = auth_service

    # The last middleware added is the outermost middleware in Starlette.
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.sentinel_origin],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )
    app.add_middleware(
        RequestSizeLimitMiddleware,
        max_bytes=settings.max_request_bytes,
    )
    app.add_middleware(
        RequestTimeoutMiddleware,
        timeout_seconds=settings.request_timeout_seconds,
    )
    app.add_middleware(
        ResponseSizeLimitMiddleware,
        max_bytes=settings.max_response_bytes,
    )
    app.add_middleware(
        LocalRedirectGuardMiddleware,
        server_url=settings.server_url,
    )

    @app.get("/docs", include_in_schema=False)
    def swagger_ui() -> Response:
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=f"{app.title} - Swagger UI",
            swagger_js_url="/docs/swagger-ui-bundle.js",
            swagger_css_url="/docs/swagger-ui.css",
            swagger_favicon_url="/docs/favicon.svg",
            oauth2_redirect_url=None,
        )

    @app.get("/docs/swagger-ui-bundle.js", include_in_schema=False)
    def swagger_ui_bundle() -> Response:
        return _local_asset(_LOCAL_DOCS_JS, "application/javascript")

    @app.get("/docs/swagger-ui.css", include_in_schema=False)
    def swagger_ui_css() -> Response:
        return _local_asset(_LOCAL_DOCS_CSS, "text/css")

    @app.get("/docs/redoc.standalone.js", include_in_schema=False)
    def redoc_bundle() -> Response:
        return _local_asset(_LOCAL_DOCS_JS, "application/javascript")

    @app.get("/docs/favicon.svg", include_in_schema=False)
    def docs_favicon() -> Response:
        return _local_asset(_LOCAL_FAVICON, "image/svg+xml")

    @app.get("/redoc", include_in_schema=False)
    def redoc() -> Response:
        return get_redoc_html(
            openapi_url="/openapi.json",
            title=f"{app.title} - ReDoc",
            redoc_js_url="/docs/redoc.standalone.js",
            redoc_favicon_url="/docs/favicon.svg",
            with_google_fonts=False,
        )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(orders.router)
    app.include_router(reports.router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=app.state.settings.host,
        port=app.state.settings.port,
        timeout_keep_alive=5,
        access_log=False,
    )
