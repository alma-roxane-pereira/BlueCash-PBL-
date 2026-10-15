"""
The public status page at `GET /`.

A deployed mint answers on a URL someone will open in a browser, so `/` is the
most-reached route the service has and the one most likely to be read by
somebody who is not a developer. These tests cover the two things that matter
about it: that it tells the truth, and that it gives nothing away when it
cannot.

Every test uses the suite's temporary-database fixtures. Nothing here touches a
real mint.
"""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.api.status import fingerprint
from app.config import Settings, get_settings
from app.db.session import reset_caches
from app.main import create_app


@pytest.fixture
def page(client) -> str:
    response = client.get("/")
    assert response.status_code == 200, response.text
    return response.text


# ---------------------------------------------------------------------------
# what it shows
# ---------------------------------------------------------------------------


def test_the_page_is_served_as_html(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.text.lstrip().startswith("<!doctype html>")


def test_it_names_the_service(page):
    assert "BlueCash Mint" in page
    assert "<title>" in page


def test_it_shows_the_mint_fingerprint(client, page):
    """And it must be the real one, not a plausible-looking string."""
    mint_pub = client.get("/mint/keys").json()["mint_pub"]
    expected = hashlib.sha256(mint_pub.encode()).hexdigest()[:16]
    assert expected in page


def test_the_fingerprint_matches_the_dev_server_convention():
    """`dev-server.ps1` and `.sh` print sha256(public_key_hex)[:16].

    A fingerprint read from the page has to be comparable with one read from a
    database file, or it cannot be used to tell two mints apart.
    """
    key = "a" * 64
    assert fingerprint(key) == hashlib.sha256(key.encode()).hexdigest()[:16]
    assert len(fingerprint(key)) == 16


def test_it_lists_the_configured_denominations(client, page):
    for key in client.get("/mint/keys").json()["keys"]:
        assert f"{key['amount']:,}" in page
        assert key["currency"] in page


def test_it_reports_the_audit_state(client):
    """With leaves present, the real root and the real count are shown."""
    from .test_mint_api import Wallet, get_keys, pick

    wallet = Wallet()
    wallet.register(client)
    for _ in range(2):
        response = client.post("/mint/issue", json=wallet.issue_body(pick(get_keys(client)[1])))
        assert response.status_code == 200, response.text

    latest = client.get("/audit/root/latest").json()
    page = client.get("/").text

    assert latest["root"] in page
    assert latest["tree_size"] == 2
    assert "2 leaves" in page


def test_an_empty_audit_log_is_stated_not_left_blank(page):
    """Nothing has been issued, which is a state worth naming."""
    assert "empty" in page.lower()
    assert "nothing issued yet" in page.lower()


def test_a_single_leaf_is_not_pluralised(client):
    from .test_mint_api import Wallet, get_keys, pick

    wallet = Wallet()
    wallet.register(client)
    client.post("/mint/issue", json=wallet.issue_body(pick(get_keys(client)[1])))

    page = client.get("/").text
    assert "1 leaf" in page
    assert "1 leaves" not in page


def test_it_carries_the_disclaimer(page):
    """The page reports liveness. It must not be read as a security claim."""
    assert "does not certify" in page


def test_it_is_marked_operational_when_healthy(page):
    assert "Operational" in page
    assert 'role="status"' in page  # the accessible label


# ---------------------------------------------------------------------------
# what it must not do
# ---------------------------------------------------------------------------


def test_it_never_exposes_private_key_material(client, page):
    """`d_hex` and the Ed25519 seed are the two values that must never leave."""
    from sqlalchemy import select

    from app.db.models import MintIdentity, MintKey
    from app.db.session import session_scope

    with session_scope() as session:
        identity = session.get(MintIdentity, 1)
        seed = identity.ed25519_seed_hex
        public_key = identity.public_key_hex
        secrets = [k.d_hex for k in session.scalars(select(MintKey)).all()]

    assert seed not in page
    assert secrets, "no keys to check against -- the assertion would be vacuous"
    for secret in secrets:
        assert secret not in page
    # The full public key is not shown either -- only its fingerprint.
    assert public_key not in page


def test_it_leaks_no_configuration_or_paths(page):
    for forbidden in ("sqlite:", "postgresql", "BLUECASH_", "Traceback", "/app/", "C:\\\\"):
        assert forbidden not in page, f"page leaks {forbidden!r}"


def test_it_loads_nothing_from_a_third_party(page):
    """No CDN: a page that phones out watches whoever checks the mint."""
    assert "<script" not in page.lower()
    assert "http://" not in page.replace('xmlns="http://', "")
    assert "cdn" not in page.lower()
    assert "https://" not in page


def test_it_is_responsive(page):
    assert 'name="viewport"' in page


def test_it_makes_no_changes(client):
    """Opening a page must not register, issue, revoke or bootstrap anything."""
    before = client.get("/audit/root/latest").json()
    revocations_before = client.get("/fraud/revocations").json()

    for _ in range(3):
        assert client.get("/").status_code == 200

    # `ts` is a live clock, so compare the state rather than the timestamp.
    after = client.get("/audit/root/latest").json()
    assert (after["root"], after["tree_size"]) == (before["root"], before["tree_size"])
    assert client.get("/fraud/revocations").json() == revocations_before


def test_it_does_not_initialise_a_mint(configured):
    """The dangerous version of this page would bootstrap on first view.

    Built with `bootstrap_keys=False`, the database has no identity. The page
    must report that, not quietly create one -- a mint identity brought into
    existence because somebody opened a URL would be unattributable.
    """
    from app.db.models import MintIdentity
    from app.db.session import get_engine, session_scope

    from app.db.models import Base

    Base.metadata.create_all(get_engine())

    with TestClient(create_app(bootstrap_keys=False)) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "Not initialised" in response.text

    with session_scope() as session:
        assert session.get(MintIdentity, 1) is None, "the page created a mint identity"


# ---------------------------------------------------------------------------
# when the database is unreachable
# ---------------------------------------------------------------------------


def test_a_failing_query_degrades_safely(client, monkeypatch):
    """A public page must not answer a database fault with a stack trace."""
    import app.api.status as status

    def explode(_session):
        raise RuntimeError("connection to server at \"10.0.0.5\", port 5432 failed")

    monkeypatch.setattr(status, "_all_leaves", explode)

    response = client.get("/")
    assert response.status_code == 200
    assert "Status unavailable" in response.text
    # Nothing from the exception may reach the page.
    assert "10.0.0.5" not in response.text
    assert "5432" not in response.text
    assert "RuntimeError" not in response.text
    assert "Traceback" not in response.text


def test_the_degraded_page_still_renders_fully(client, monkeypatch):
    import app.api.status as status

    monkeypatch.setattr(
        status, "_all_leaves", lambda _s: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    page = client.get("/").text
    assert page.lstrip().startswith("<!doctype html>")
    assert "</html>" in page
    assert "boom" not in page


# ---------------------------------------------------------------------------
# escaping
# ---------------------------------------------------------------------------


def test_dynamic_values_are_escaped(client, monkeypatch):
    """Nothing on this page is user-supplied today, which is exactly why the
    escaping needs a test: the next field added might be."""
    import app.api.status as status

    real = status._collect
    monkeypatch.setattr(
        status,
        "_collect",
        lambda s: {**real(s), "fingerprint": "<script>alert(1)</script>"},
    )

    page = client.get("/").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_the_service_name_is_escaped(monkeypatch, configured):
    import app.api.status as status

    settings = Settings(service_name='x"><script>bad()</script>')
    rendered = status._render({"ok": False}, settings)
    assert "<script>bad()</script>" not in rendered


# ---------------------------------------------------------------------------
# production
# ---------------------------------------------------------------------------


@pytest.fixture
def production_client(monkeypatch, temp_db_url):
    monkeypatch.setenv("BLUECASH_DATABASE_URL", temp_db_url)
    monkeypatch.setenv("BLUECASH_ENV", "production")
    get_settings.cache_clear()
    reset_caches()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()
    reset_caches()


def test_production_hides_the_api_documentation(production_client):
    """`/docs` renders the schema; `/openapi.json` *is* the schema. Hiding only
    the first leaves every route and field listed for anyone who asks."""
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert production_client.get(path).status_code == 404, f"{path} is exposed"


def test_the_status_page_still_works_in_production(production_client):
    response = production_client.get("/")
    assert response.status_code == 200
    assert "BlueCash Mint" in response.text


def test_development_still_offers_the_docs(client):
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_the_status_page_is_absent_from_the_schema(client):
    """It is a page for people, not part of the protocol contract."""
    assert "/" not in client.get("/openapi.json").json()["paths"]


# ---------------------------------------------------------------------------
# nothing else moved
# ---------------------------------------------------------------------------


def test_health_is_unchanged(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "bluecash-mint",
        "version": response.json()["version"],
    }


def test_the_protocol_endpoints_are_untouched(client):
    assert client.get("/mint/keys").status_code == 200
    assert client.get("/audit/root/latest").status_code == 200
    assert client.get("/fraud/revocations").status_code == 200
