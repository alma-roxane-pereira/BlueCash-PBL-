"""
Shared fixtures for the backend test suite.

Every fixture that touches a database uses a temporary file under pytest's
`tmp_path`, and every key is generated fresh for the test. No real runtime
database and no production key material is ever created.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def temp_db_url(tmp_path) -> str:
    """A file-backed SQLite URL inside the test's temporary directory."""
    return f"sqlite:///{(tmp_path / 'mint.db').as_posix()}"


@pytest.fixture
def configured(monkeypatch, temp_db_url):
    """Point the whole backend at a temporary database.

    Settings, engine and sessionmaker are all cached singletons, so each has to
    be cleared for the override to take effect — and cleared again afterwards so
    one test cannot leak its database into the next.
    """
    from app.config import get_settings
    from app.db.session import reset_caches

    monkeypatch.setenv("BLUECASH_DATABASE_URL", temp_db_url)
    get_settings.cache_clear()
    reset_caches()

    yield temp_db_url

    get_settings.cache_clear()
    reset_caches()


@pytest.fixture
def client(configured):
    """A TestClient whose app has bootstrapped keys in the temporary database.

    Entering the context runs startup, which generates the mint identity and
    four 2048-bit RSA denomination keys — a few seconds the first time.
    """
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
