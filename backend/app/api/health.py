"""
Liveness endpoint.

Deliberately dependency-free: it touches no database, no key material and not
the `bluecash_crypto` extension. A health check that fails when the database is
down cannot tell you *that* the database is down — it just stops answering. A
readiness probe covering those comes later, once there is something to be ready
for.

The response is a fixed shape with no timestamp or request-dependent field, so
it is byte-identical on every call and cheap to assert on.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ..config import Settings, get_settings

router = APIRouter(tags=["ops"])


def settings_for(request: Request) -> Settings:
    """The settings this app was built with.

    `create_app` stores them on `app.state`, so an app constructed with injected
    settings reports those rather than the cached process-wide ones. Falls back
    to the global singleton for an app built some other way.
    """
    return getattr(request.app.state, "settings", None) or get_settings()


SettingsDep = Annotated[Settings, Depends(settings_for)]


class HealthResponse(BaseModel):
    """Body of `GET /health`."""

    status: str
    service: str
    version: str


@router.get("/health", response_model=HealthResponse, summary="Liveness check")
def health(settings: SettingsDep) -> HealthResponse:
    """Report that the process is up and serving.

    Returns `{"status": "ok", "service": ..., "version": ...}`.
    """
    return HealthResponse(
        status="ok",
        service=settings.service_name,
        version=settings.version,
    )
