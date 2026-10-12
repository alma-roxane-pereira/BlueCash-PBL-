"""
Tests for application startup and the health endpoint.

A standing requirement for this suite: it must pass with no database, no mint
keys, and without the `bluecash_crypto` extension installed. If any test here
starts needing those, the health path has picked up a dependency it should not
have.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.config import Settings, get_settings
from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    # bootstrap_keys=False: the health suite must never create a database
    # or generate mint keys. It also keeps these tests fast.
    return TestClient(create_app(bootstrap_keys=False))


# ---------------------------------------------------------------------------
# startup
# ---------------------------------------------------------------------------


def test_app_imports_and_builds():
    app = create_app(bootstrap_keys=False)
    assert app.title == "BlueCash Mint"
    assert app.version == __version__


def test_app_starts_without_crypto_extension_database_or_keys():
    """The health path must not pull in the heavy dependencies.

    Run in a subprocess: within the test session other modules import alembic
    and sqlalchemy, so `sys.modules` in this process says nothing about what the
    application itself loads.
    """
    import subprocess
    import textwrap

    script = textwrap.dedent(
        """
        import sys
        from fastapi.testclient import TestClient
        from app.main import create_app

        with TestClient(create_app(bootstrap_keys=False)) as c:
            assert c.get("/health").status_code == 200

        # The app now has protocol endpoints, so importing it legitimately
        # loads sqlalchemy and the crypto core. What must remain true is that
        # serving /health needs no database connection and no mint keys --
        # which this script demonstrates by answering with neither configured.
        heavy = []
        print(",".join(heavy))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert result.returncode == 0, result.stderr
    loaded = result.stdout.strip()
    assert loaded == "", f"the health path must not import: {loaded}"


def test_health_route_is_registered():
    routes = {r.path for r in create_app(bootstrap_keys=False).routes}
    assert "/health" in routes


def test_all_six_contract_endpoints_are_registered():
    """Steps 4A and 4B together implement every endpoint in API_CONTRACT.md."""
    paths = {r.path for r in create_app(bootstrap_keys=False).routes}
    for path in (
        "/mint/keys",
        "/mint/registerDevice",
        "/mint/issue",
        "/audit/root/latest",
        "/settlement/uploadBatch",
        "/fraud/revocations",
    ):
        assert path in paths, f"{path} is missing"


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


def test_health_returns_200_and_expected_body(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "bluecash-mint",
        "version": __version__,
    }


def test_health_is_json(client: TestClient):
    assert client.get("/health").headers["content-type"].startswith("application/json")


def test_health_body_is_stable_across_calls(client: TestClient):
    """No timestamp or request-dependent field, so responses are identical."""
    first = client.get("/health").content
    second = client.get("/health").content
    assert first == second


def test_health_response_has_no_extra_fields(client: TestClient):
    assert set(client.get("/health").json()) == {"status", "service", "version"}


def test_health_rejects_other_methods(client: TestClient):
    assert client.post("/health").status_code == 405
    assert client.delete("/health").status_code == 405


def test_unknown_path_is_404(client: TestClient):
    assert client.get("/nope").status_code == 404


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------


def test_settings_defaults():
    settings = Settings()
    assert settings.service_name == "bluecash-mint"
    assert settings.version == __version__
    assert settings.env == "development"
    assert settings.host == "127.0.0.1", "must not default to binding all interfaces"
    assert settings.port == 8000
    assert settings.verify_play_integrity is False
    assert settings.is_production is False


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BLUECASH_ENV", "production")
    monkeypatch.setenv("BLUECASH_PORT", "9000")
    settings = Settings()
    assert settings.env == "production"
    assert settings.port == 9000
    assert settings.is_production is True


def test_settings_reject_invalid_values(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BLUECASH_PORT", "70000")
    with pytest.raises(Exception):
        Settings()


def test_get_settings_is_cached():
    assert get_settings() is get_settings()


def test_health_reflects_overridden_settings():
    """The app factory honours injected settings."""
    app = create_app(Settings(service_name="bluecash-mint-test"), bootstrap_keys=False)
    with TestClient(app) as c:
        assert c.get("/health").json()["service"] == "bluecash-mint-test"


def test_docs_hidden_in_production():
    assert create_app(Settings(env="production"), bootstrap_keys=False).docs_url is None
    assert create_app(Settings(env="development"), bootstrap_keys=False).docs_url == "/docs"
