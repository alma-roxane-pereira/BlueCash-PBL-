"""
Application entry point for the BlueCash mint backend.

Run it with:

    uvicorn app.main:app --host 127.0.0.1 --port 8000

This is Step 1 of the backend: configuration, a health endpoint, and nothing
else. The six protocol endpoints from `API_CONTRACT.md` (`/mint/keys`,
`/mint/registerDevice`, `/mint/issue`, `/audit/root/latest`,
`/settlement/uploadBatch`, `/fraud/revocations`) arrive in later steps, as do
the database and mint key management.

An app factory is used rather than a bare module-level `FastAPI()` so tests can
build isolated instances with their own settings. `app` is still exported for
uvicorn and for the common import path.
"""

from __future__ import annotations

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .api import health, mint, settlement
from .config import Settings, get_settings

DESCRIPTION = """\
Mint, settlement, audit and fraud endpoints for the BlueCash Protocol.

Cryptographic operations are performed by the shared Rust core
(`bluecash-crypto`) through its PyO3 bindings, so the backend and the Android
client run the same implementation of the protocol maths.
"""


def configure_logging(settings: Settings) -> None:
    """Set the root log level from settings, without clobbering uvicorn's format."""
    logging.getLogger().setLevel(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure the mint has an identity and denomination keys before serving.

    Key material is generated once and persisted: the client pins `mint_pub` on
    first contact and refuses a mint whose key later changes, so regenerating on
    restart would brick every registered wallet.

    Imported lazily so that the health path, and anything that merely builds the
    app, stay free of database and crypto imports.
    """
    from .db.session import get_engine, session_scope
    from .mint_keys import bootstrap

    if getattr(app.state, "bootstrap_keys", True):
        from .db.models import Base

        Base.metadata.create_all(get_engine())
        with session_scope() as session:
            bootstrap(session)

    yield


def create_app(settings: Settings | None = None, *, bootstrap_keys: bool = True) -> FastAPI:
    """Build a FastAPI application.

    Passing `settings` overrides the cached process settings, which is what the
    tests use to exercise alternative configurations. `bootstrap_keys=False`
    skips startup key generation, so tests that do not need the mint (the health
    suite) stay fast and database-free.
    """
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        lifespan=lifespan,
        title="BlueCash Mint",
        description=DESCRIPTION,
        version=settings.version,
        # Docs are useful in development and noise in production; the mint
        # exposes no secrets through them either way.
        docs_url="/docs" if not settings.is_production else None,
        redoc_url=None,
    )

    app.state.settings = settings
    app.state.bootstrap_keys = bootstrap_keys
    app.include_router(health.router)
    app.include_router(mint.router)
    app.include_router(settlement.router)

    return app


app = create_app()
