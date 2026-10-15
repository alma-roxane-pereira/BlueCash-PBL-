"""
Database selection, and the ways it can go wrong during development.

The mint's Ed25519 identity and its four RSA denomination keys live in the database, and
clients pin `mint_pub` on first contact. So the database file *is* the mint: serving the
wrong one does not reset anything, it stands up a different mint that every registered
wallet refuses with "the mint's signing key changed".

That makes an accidental fall back to the default `sqlite:///./bluecash.db` the most
expensive mistake available during a demo, which is why `dev-server.ps1` and `dev-server.sh`
refuse to start without `BLUECASH_DATABASE_URL`. These tests cover the settings behaviour
the scripts rely on.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.config import Settings, get_settings

SCRIPTS = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """`get_settings` is cached process-wide; these tests vary the environment."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# the setting itself
# ---------------------------------------------------------------------------


def test_database_url_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "sqlite:///C:/tmp/ble-mint.db")
    assert Settings().database_url == "sqlite:///C:/tmp/ble-mint.db"


def test_an_explicit_url_is_not_overridden_by_the_default(monkeypatch):
    """The documented failure: a chosen database silently replaced by `./bluecash.db`."""
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "sqlite:///C:/tmp/ble-mint.db")
    settings = Settings()
    assert "bluecash.db" not in settings.database_url
    assert settings.database_url.endswith("ble-mint.db")


def test_the_default_is_only_used_when_nothing_is_configured(monkeypatch):
    monkeypatch.delenv("BLUECASH_DATABASE_URL", raising=False)
    # A `.env` file would also supply it; this asserts the fallback, not the absence of one.
    assert Settings(_env_file=None).database_url == "sqlite:///./bluecash.db"


def test_get_settings_is_cached_so_the_url_cannot_drift(monkeypatch):
    """One process serves one mint: re-reading must not pick up a changed environment."""
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "sqlite:///C:/tmp/first.db")
    first = get_settings()
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "sqlite:///C:/tmp/second.db")
    assert get_settings() is first
    assert get_settings().database_url == first.database_url


# ---------------------------------------------------------------------------
# the dev-server scripts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["dev-server.ps1", "dev-server.sh"])
def test_dev_server_scripts_exist(name):
    assert (SCRIPTS / name).is_file(), f"{name} is referenced by README.md"


@pytest.mark.parametrize("name", ["dev-server.ps1", "dev-server.sh"])
def test_dev_server_refuses_without_an_explicit_database(name):
    """Both scripts must guard the variable, not merely mention it."""
    text = (SCRIPTS / name).read_text(encoding="utf-8")
    assert "BLUECASH_DATABASE_URL" in text
    assert re.search(r"exit\s+1", text), "must exit non-zero when unset"


@pytest.mark.parametrize("name", ["dev-server.ps1", "dev-server.sh"])
def test_dev_server_binds_all_interfaces(name):
    """Phones reach the laptop over the LAN, so loopback-only would defeat the purpose."""
    text = (SCRIPTS / name).read_text(encoding="utf-8")
    assert "0.0.0.0" in text
    assert "--host 127.0.0.1" not in text


@pytest.mark.parametrize("name", ["dev-server.ps1", "dev-server.sh"])
def test_dev_server_does_not_hardcode_an_address(name):
    """The whole point is that the address is discovered, never pinned in the source.

    `0.0.0.0` is the bind address and `127.0.0.1`/`169.254.` appear as filters, so only
    routable literals are rejected here.
    """
    text = (SCRIPTS / name).read_text(encoding="utf-8")
    literals = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    unexpected = [
        ip
        for ip in literals
        if not ip.startswith(("0.0.0.0", "127.", "169.254."))
    ]
    assert not unexpected, f"{name} hardcodes {unexpected}"


# ---------------------------------------------------------------------------
# the deployment URL
# ---------------------------------------------------------------------------


def test_a_bare_postgres_url_is_pinned_to_psycopg3(monkeypatch):
    """Managed hosts hand out `postgresql://`, which SQLAlchemy maps to psycopg2.

    psycopg2 is not in `requirements.txt`, so without this rewrite the mint
    would import-error at startup -- after the deploy reported success.
    """
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "postgresql://u:p@host:5432/bluecash")
    assert Settings().database_url == "postgresql+psycopg://u:p@host:5432/bluecash"


def test_the_legacy_postgres_scheme_is_handled_too(monkeypatch):
    """Some providers still emit the older `postgres://` spelling."""
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "postgres://u:p@host/bluecash")
    assert Settings().database_url.startswith("postgresql+psycopg://")


def test_an_explicit_driver_is_left_alone(monkeypatch):
    url = "postgresql+psycopg://u:p@host/bluecash"
    monkeypatch.setenv("BLUECASH_DATABASE_URL", url)
    assert Settings().database_url == url


def test_sqlite_urls_are_untouched(monkeypatch):
    """Local development must not be affected by a deployment concern."""
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "sqlite:///C:/tmp/ble-mint.db")
    assert Settings().database_url == "sqlite:///C:/tmp/ble-mint.db"


def test_credentials_survive_the_rewrite(monkeypatch):
    """A mangled password would fail to connect for a reason nobody could see."""
    monkeypatch.setenv("BLUECASH_DATABASE_URL", "postgresql://user:p%40ss:word@h:5432/db?sslmode=require")
    rewritten = Settings().database_url
    assert rewritten.endswith("user:p%40ss:word@h:5432/db?sslmode=require")
