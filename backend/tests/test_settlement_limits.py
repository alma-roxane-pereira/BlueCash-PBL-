"""
Input-validation limits on settlement.

Two gaps are covered here, neither of which the contract or the reference
server bounds:

* **Batch size** -- `/settlement/uploadBatch` accepted an unbounded list, and
  each receipt costs several 2048-bit modular exponentiations. That is the
  cheapest denial of service against the mint.
* **`merchant_id` length** -- a free-text shop name stored in a `String(64)`
  column. SQLite ignores the limit; PostgreSQL would raise
  `StringDataRightTruncation` and turn a client error into a 500.

Both divergences from the reference are documented in `backend/README.md`.
"""

from __future__ import annotations

from .test_mint_api import Wallet, get_keys, pick
from .test_settlement_api import Payer, build_receipt, settle


def _mint_and_receipt(client, payer, merchant, index, receipt_id=None):
    """A settleable receipt for a freshly minted token."""
    key = pick(get_keys(client)[1])
    token = payer.mint_token(client, key)
    return build_receipt(
        payer,
        merchant,
        token,
        f"ctx-lim-{index}",
        receipt_id=receipt_id or f"lim-{index}",
    )


def _party(client):
    payer, merchant = Payer(), Wallet()
    payer.register(client)
    merchant.register(client)
    return payer, merchant


def _lower_limit_to(monkeypatch, value: int) -> None:
    """Point the backend at a small batch limit for one test.

    The endpoint reads the limit from settings per request, so the boundary
    logic exercised here is the same one production uses -- this only avoids
    minting 500 tokens, which would take minutes.
    """
    from app.config import get_settings

    monkeypatch.setenv("BLUECASH_MAX_SETTLEMENT_BATCH", str(value))
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# batch size
# ---------------------------------------------------------------------------


def test_default_batch_limit_is_configured():
    from app.config import Settings

    assert Settings().max_settlement_batch == 500


def test_batch_limit_must_be_at_least_one(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("BLUECASH_MAX_SETTLEMENT_BATCH", "0")
    try:
        Settings()
    except Exception:
        pass
    else:  # pragma: no cover
        raise AssertionError("a limit of 0 would reject every batch")


def test_empty_batch_is_still_accepted(client):
    """Documented behaviour must survive the new limit."""
    body = settle(client)
    assert body["results"] == []
    assert isinstance(body["revoked"], list)


def test_normal_batch_is_still_accepted(client):
    payer, merchant = _party(client)
    receipts = [_mint_and_receipt(client, payer, merchant, i) for i in range(3)]
    body = settle(client, *receipts)
    assert [r["status"] for r in body["results"]] == ["ACCEPTED"] * 3


def test_batch_exactly_at_the_maximum_is_accepted(client, configured, monkeypatch):
    _lower_limit_to(monkeypatch, 3)
    try:
        payer, merchant = _party(client)
        receipts = [_mint_and_receipt(client, payer, merchant, i) for i in range(3)]

        response = client.post("/settlement/uploadBatch", json={"receipts": receipts})
        assert response.status_code == 200, response.text
        assert [r["status"] for r in response.json()["results"]] == ["ACCEPTED"] * 3
    finally:
        from app.config import get_settings

        get_settings.cache_clear()


def test_batch_one_over_the_maximum_is_rejected(client, configured, monkeypatch):
    _lower_limit_to(monkeypatch, 3)
    try:
        payer, merchant = _party(client)
        receipts = [_mint_and_receipt(client, payer, merchant, i) for i in range(4)]

        response = client.post("/settlement/uploadBatch", json={"receipts": receipts})
        assert response.status_code == 413, response.text
        detail = response.json()["detail"]
        assert "exceeds the maximum" in detail
        assert "4" in detail and "3" in detail
        assert "split it into smaller batches" in detail
    finally:
        from app.config import get_settings

        get_settings.cache_clear()


def test_oversized_batch_leaves_no_partial_state(client, configured, monkeypatch):
    from sqlalchemy import select

    from app.db.models import Balance, SpentToken
    from app.db.session import session_scope

    _lower_limit_to(monkeypatch, 2)
    try:
        payer, merchant = _party(client)
        receipts = [_mint_and_receipt(client, payer, merchant, i) for i in range(3)]

        response = client.post("/settlement/uploadBatch", json={"receipts": receipts})
        assert response.status_code == 413

        with session_scope() as session:
            assert session.scalars(select(SpentToken)).all() == []
            assert session.scalars(select(Balance)).all() == []
    finally:
        from app.config import get_settings

        get_settings.cache_clear()


def test_oversized_batch_is_rejected_before_any_cryptography(
    client, configured, monkeypatch
):
    """The rejection must not cost the work it exists to prevent."""
    from app.api import settlement as settlement_module

    _lower_limit_to(monkeypatch, 1)
    calls = {"n": 0}
    real_verify = settlement_module._verify_receipt

    def counting_verify(*args, **kwargs):
        calls["n"] += 1
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(settlement_module, "_verify_receipt", counting_verify)
    try:
        payer, merchant = _party(client)
        receipts = [_mint_and_receipt(client, payer, merchant, i) for i in range(2)]

        response = client.post("/settlement/uploadBatch", json={"receipts": receipts})
        assert response.status_code == 413
        assert calls["n"] == 0, "no receipt may be verified in a rejected batch"
    finally:
        from app.config import get_settings

        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# merchant_id length
# ---------------------------------------------------------------------------


def _with_merchant_id(receipt: dict, merchant: Wallet, merchant_id: str) -> dict:
    """Re-sign a receipt under a different merchant_id.

    `merchant_id` is part of the signed BCRECEIPT string, so changing it without
    re-signing would fail the signature check instead of the length check.
    """
    receipt = dict(receipt)
    receipt["merchant_id"] = merchant_id
    receipt["merchant_sig"] = merchant.sign(
        "BCRECEIPT|v1|{receipt_id}|{token_id}|{n_ctx}|{x}|{y}|{amount}|{mid}|{ts}".format(
            receipt_id=receipt["receipt_id"],
            token_id=receipt["token"]["token_id"],
            n_ctx=receipt["n_ctx"],
            x=receipt["x"],
            y=receipt["y"],
            amount=receipt["amount"],
            mid=merchant_id,
            ts=receipt["timestamp_ms"],
        )
    )
    return receipt


def test_merchant_id_at_the_maximum_length_is_accepted(client):
    """64 characters: exactly what spent_tokens.merchant_id stores."""
    payer, merchant = _party(client)
    receipt = _with_merchant_id(
        _mint_and_receipt(client, payer, merchant, 0), merchant, "m" * 64
    )
    body = settle(client, receipt)
    assert body["results"][0]["status"] == "ACCEPTED", body


def test_merchant_id_one_over_the_maximum_is_rejected(client):
    """65 characters: a 4xx, not a 500 out of the database."""
    payer, merchant = _party(client)
    receipt = _with_merchant_id(
        _mint_and_receipt(client, payer, merchant, 1), merchant, "m" * 65
    )

    response = client.post("/settlement/uploadBatch", json={"receipts": [receipt]})
    assert response.status_code == 422, response.text
    assert "merchant_id" in response.text


def test_empty_merchant_id_is_rejected(client):
    payer, merchant = _party(client)
    receipt = _with_merchant_id(
        _mint_and_receipt(client, payer, merchant, 2), merchant, ""
    )

    response = client.post("/settlement/uploadBatch", json={"receipts": [receipt]})
    assert response.status_code == 422, response.text
    assert "merchant_id" in response.text


def test_typical_merchant_names_are_accepted(client):
    """No format restriction beyond length -- these are free-text shop names.

    The client defaults to "shop-" + 6 hex characters but lets the user type
    anything (`ReceiveScreen.kt`), so imposing a character set would reject
    legitimate names.
    """
    payer, merchant = _party(client)
    for index, name in enumerate(
        ["shop-a1b2c3", "Chai Corner", "cafe #2", "shop_01", "A", "Ananya's Store"]
    ):
        receipt = _with_merchant_id(
            _mint_and_receipt(client, payer, merchant, 10 + index), merchant, name
        )
        body = settle(client, receipt)
        assert body["results"][0]["status"] == "ACCEPTED", f"{name}: {body}"


def test_over_length_merchant_id_never_reaches_the_database(client, configured):
    from sqlalchemy import select

    from app.db.models import SpentToken
    from app.db.session import session_scope

    payer, merchant = _party(client)
    receipt = _with_merchant_id(
        _mint_and_receipt(client, payer, merchant, 20), merchant, "m" * 200
    )

    response = client.post("/settlement/uploadBatch", json={"receipts": [receipt]})
    assert response.status_code == 422

    with session_scope() as session:
        stored = session.scalars(select(SpentToken)).all()
        assert all(len(row.merchant_id) <= 64 for row in stored)


def test_merchant_id_length_matches_the_database_column():
    """The schema limit and the column width must not drift apart."""
    from app.db.models import SpentToken
    from app.schemas import ReceiptModel

    column_length = SpentToken.__table__.columns["merchant_id"].type.length
    constraints = ReceiptModel.model_fields["merchant_id"].metadata
    max_length = next(
        getattr(c, "max_length") for c in constraints if hasattr(c, "max_length")
    )
    assert max_length == column_length == 64
