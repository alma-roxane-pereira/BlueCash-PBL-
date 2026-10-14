"""
Centralised settings for the BlueCash mint backend.

Everything environment-dependent is read here, once, so no module reaches for
`os.environ` on its own. Settings are read from the process environment and from
a `.env` file if one is present, with the `BLUECASH_` prefix.

Nothing in this module loads a database, a key file, or the crypto extension.
Importing it must stay cheap and side-effect free, so that `GET /health` can
answer even when the rest of the system is misconfigured.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import __version__


class Settings(BaseSettings):
    """Backend configuration.

    Override any field with an environment variable, e.g.
    `BLUECASH_ENV=production` or `BLUECASH_LOG_LEVEL=DEBUG`.
    """

    model_config = SettingsConfigDict(
        env_prefix="BLUECASH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- identity ----------------------------------------------------------
    service_name: str = "bluecash-mint"
    version: str = __version__

    # --- runtime -----------------------------------------------------------
    env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- HTTP --------------------------------------------------------------
    # Default to loopback. Binding 0.0.0.0 exposes the mint to the network, so
    # it is an explicit choice rather than a default, even in development.
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    # --- database ----------------------------------------------------------
    # Synchronous SQLAlchemy over Python's built-in sqlite3 driver: no extra
    # package, and the mint's work is short CPU-bound crypto rather than
    # long I/O waits, so async buys little here. The schema is written to stay
    # PostgreSQL-compatible, so moving later is a URL change plus a driver.
    database_url: str = "sqlite:///./bluecash.db"

    # Echo every SQL statement. Useful when debugging a migration; far too
    # noisy otherwise.
    database_echo: bool = False

    # --- settlement limits -------------------------------------------------
    # Largest batch `/settlement/uploadBatch` will accept.
    #
    # Verifying one receipt costs roughly five 2048-bit modular exponentiations
    # plus three Ed25519 verifications -- measured at ~6ms here, so 500 receipts
    # is a few seconds of CPU and 5,000 would tie up a worker for half a minute.
    # Neither `API_CONTRACT.md` nor the reference server bounds this, so an
    # unbounded batch is the cheapest denial of service against the mint.
    #
    # 500 is far above anything a real client produces: the wallet syncs
    # periodically via WorkManager, and a merchant would have to accumulate 500
    # offline sales between syncs to approach it. The headroom matters, because
    # `HttpMintApi.kt:30` turns any non-2xx into an exception and `Wallet.kt`
    # only clears receipts it got a result for -- so a client that genuinely
    # exceeded the limit would retry forever rather than splitting the batch.
    max_settlement_batch: int = Field(default=500, ge=1)

    # --- integrity ---------------------------------------------------------
    # Play Integrity verification needs Google's API (network + credentials),
    # so the token is accepted and stored but not verified unless this is on.
    verify_play_integrity: bool = False

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """The process-wide settings singleton.

    Cached so that configuration is read once. Tests that need to vary settings
    should call `get_settings.cache_clear()` first.
    """
    return Settings()
