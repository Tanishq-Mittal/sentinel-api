"""Local service health endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request


router = APIRouter(tags=["health"])


@router.get(
    "/health",
    operation_id="health",
    summary="Check sandbox health",
    description="Returns local fixture-service status without accessing external systems.",
)
def health(request: Request) -> dict[str, object]:
    settings = request.app.state.settings
    return {
        "status": "ok",
        "service": "sentinelapi-sandbox",
        "mode": "local-fixtures",
        "server_url": settings.server_url,
    }
