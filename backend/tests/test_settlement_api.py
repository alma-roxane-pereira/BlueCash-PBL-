"""
Endpoint tests for settlement and fraud (Step 4B).

The client side is built here from `API_CONTRACT.md` rather than imported from
the backend, so these exercise the contract rather than agreeing with the
implementation by construction. Signatures are produced with `cryptography`,
the library the reference server uses.

The important ones are the double-spend tests: they drive the protocol's central
security claim end to end — one spend reveals nothing, two reveal the payer.
"""

from __future__ import annotations

import secrets
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import bluecash_crypto as bc

from .test_mint_api import Wallet, _hex, get_keys, pick


# ---------------------------------------------------------------------------
# a spending client
# ---------------------------------------------------------------------------


class Payer(Wallet):
    """A wallet that can mint a token and spend it."""

    def __init__(self) -> None:
        super().__init__()
        self.a1_for: dict[str, int] = {}

    def mint_token(self, client, key: dict) -> dict:
        """Register (if needed), blind-mint a token, and return it unblinded."""
        if self.credential is None:
            self.register(client)
        body = self.issue_body(key)
        response = client.post("/mint/issue", json=body)
        assert response.status_code == 200, response.text
        blind_sig = int(response.json()["blind_sig"], 16)

        sig = bc.unblind(blind_sig, self.last["r"], self.last["n"])
        assert bc.blind_verify(self.last["msg"], sig, self.last["n"], self.last["e"])

        self.token = {
            "token_id": self.last["token_id"],
            "key_id": key["key_id"],
            "amount": key["amount"],
            "currency": key["currency"],
            "expiry_ms": key["expiry_ms"],
            "c0": self.c0,
            "c1": self.last["c1"],
            "sig": _hex(sig),
        }
        # Keyed by token_id: minting another token must not corrupt the share
        # secret of one already in hand.
        self.a1_for.setdefault(self.last["token_id"], self.last["a1"])
        return self.token


def build_receipt(
    payer: Payer,
    merchant: Wallet,
    token: dict,
    n_ctx: str,
    *,
    receipt_id: str | None = None,
    timestamp_ms: int = 1_700_000_000_000,
    amount: int | None = None,
) -> dict:
    """Assemble a signed receipt exactly as the contract specifies."""
    receipt_id = receipt_id or secrets.token_hex(12)
    amount = token["amount"] if amount is None else amount

    x = bc.challenge_x(token["token_id"], n_ctx)
    y = bc.eval_share(payer.a0, payer.a1_for[token["token_id"]], x)
    x_hex, y_hex = _hex(x), _hex(y)

    payer_sig = payer.sign(f"BCSPEND|v1|{token['token_id']}|{n_ctx}|{token['amount']}")
    merchant_id = merchant.credential["cred_id"]
    merchant_sig = merchant.sign(
        f"BCRECEIPT|v1|{receipt_id}|{token['token_id']}|{n_ctx}|{x_hex}|{y_hex}"
        f"|{amount}|{merchant_id}|{timestamp_ms}"
    )

    return {
        "receipt_id": receipt_id,
        "token": token,
        "n_ctx": n_ctx,
        "x": x_hex,
        "y": y_hex,
        "amount": amount,
        "payer_cred": payer.credential,
        "payer_sig": payer_sig,
        "merchant_id": merchant_id,
        "merchant_cred": merchant.credential,
        "merchant_sig": merchant_sig,
        "timestamp_ms": timestamp_ms,
    }


@pytest.fixture
def scene(client):
    """A payer with a minted token, plus two merchants."""
    _, keys = get_keys(client)
    key = pick(keys)

    payer = Payer()
    payer.register(client)
    token = payer.mint_token(client, key)

    shop_a, shop_b = Wallet(), Wallet()
    shop_a.register(client)
    shop_b.register(client)
    return client, payer, token, shop_a, shop_b


def settle(client, *receipts) -> dict:
    response = client.post("/settlement/uploadBatch", json={"receipts": list(receipts)})
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------


def test_first_valid_spend_is_accepted(scene):
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-shop-a")

    body = settle(client, receipt)
    assert body["results"] == [
        {"receipt_id": receipt["receipt_id"], "status": "ACCEPTED", "detail": "settled"}
    ]
    assert body["revoked"] == []


def test_accepted_spend_credits_the_merchant_once(scene, configured):
    from app.db.models import Balance
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-shop-a")
    settle(client, receipt)

    with session_scope() as session:
        balance = session.get(Balance, (receipt["merchant_id"], "merchant", "INR"))
        assert balance is not None and balance.amount == token["amount"]


def test_accepted_spend_persists_the_share_point(scene, configured):
    from app.db.models import SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-shop-a")
    settle(client, receipt)

    with session_scope() as session:
        row = session.get(SpentToken, token["token_id"])
        assert row is not None
        assert row.receipt_id == receipt["receipt_id"]
        assert int(row.x_hex, 16) == int(receipt["x"], 16)
        assert int(row.y_hex, 16) == int(receipt["y"], 16)


def test_two_different_tokens_both_settle(scene):
    client, payer, token, shop_a, _ = scene
    _, keys = get_keys(client)
    second = payer.mint_token(client, pick(keys))

    body = settle(
        client,
        build_receipt(payer, shop_a, token, "ctx-1"),
        build_receipt(payer, shop_a, second, "ctx-2"),
    )
    assert [r["status"] for r in body["results"]] == ["ACCEPTED", "ACCEPTED"]


# ---------------------------------------------------------------------------
# duplicates
# ---------------------------------------------------------------------------


def test_same_receipt_twice_is_duplicate_and_idempotent(scene, configured):
    from app.db.models import Balance
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-shop-a")

    first = settle(client, receipt)
    second = settle(client, receipt)

    assert first["results"][0]["status"] == "ACCEPTED"
    assert second["results"][0]["status"] == "DUPLICATE"
    assert second["results"][0]["detail"] == "already settled"

    with session_scope() as session:
        balance = session.get(Balance, (receipt["merchant_id"], "merchant", "INR"))
        assert balance.amount == token["amount"], "a duplicate must not credit again"


def test_duplicate_within_one_batch_does_not_double_credit(scene, configured):
    from app.db.models import Balance
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-shop-a")

    body = settle(client, receipt, receipt)
    assert [r["status"] for r in body["results"]] == ["ACCEPTED", "DUPLICATE"]

    with session_scope() as session:
        balance = session.get(Balance, (receipt["merchant_id"], "merchant", "INR"))
        assert balance.amount == token["amount"]


# ---------------------------------------------------------------------------
# double spend
# ---------------------------------------------------------------------------


def test_double_spend_is_detected_and_recovers_the_identity(scene):
    """The protocol's central claim, end to end."""
    client, payer, token, shop_a, shop_b = scene

    first = settle(client, build_receipt(payer, shop_a, token, "ctx-shop-a"))
    assert first["results"][0]["status"] == "ACCEPTED"

    second = settle(client, build_receipt(payer, shop_b, token, "ctx-shop-b"))
    result = second["results"][0]

    assert result["status"] == "FRAUD"
    assert "identity secret recovered" in result["detail"]
    assert payer.credential["cred_id"] in result["detail"]
    assert any(r["cred_id"] == payer.credential["cred_id"] for r in second["revoked"])


def test_fraud_does_not_credit_the_second_merchant(scene, configured):
    """A double spend must not pay twice.

    Detection, recovery and revocation are covered above; this covers the money.
    A credit on the FRAUD path would mint value out of nothing -- the second
    merchant would be paid from a token already spent -- and every other test in
    this file would still pass, because none of them looks at B's balance.

    The loss falls on whoever settles second. That is inherent to offline cash,
    and it is what the revocation above exists to deter.
    """
    from sqlalchemy import select

    from app.db.models import Balance, SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, shop_b = scene
    first = build_receipt(payer, shop_a, token, "ctx-shop-a")
    second = build_receipt(payer, shop_b, token, "ctx-shop-b")

    assert settle(client, first)["results"][0]["status"] == "ACCEPTED"
    assert settle(client, second)["results"][0]["status"] == "FRAUD"

    with session_scope() as session:
        paid = session.get(Balance, (first["merchant_id"], "merchant", "INR"))
        assert paid is not None and paid.amount == token["amount"], "A keeps its credit"

        unpaid = session.get(Balance, (second["merchant_id"], "merchant", "INR"))
        assert unpaid is None, "a rejected spend must not even open an account for B"

        rows = session.scalars(select(SpentToken)).all()
        assert len(rows) == 1
        assert rows[0].receipt_id == first["receipt_id"], "A's receipt is the stored one"


def test_revocation_persists_and_is_listed(scene):
    client, payer, token, shop_a, shop_b = scene
    settle(client, build_receipt(payer, shop_a, token, "ctx-shop-a"))
    settle(client, build_receipt(payer, shop_b, token, "ctx-shop-b"))

    body = client.get("/fraud/revocations").json()
    entry = next(r for r in body["revoked"] if r["cred_id"] == payer.credential["cred_id"])
    assert "double-spend" in entry["reason"]
    assert isinstance(entry["ts"], int)


def test_revoked_payer_cannot_mint_again(scene):
    """Revocation must actually bite on the issuance path."""
    client, payer, token, shop_a, shop_b = scene
    settle(client, build_receipt(payer, shop_a, token, "ctx-shop-a"))
    settle(client, build_receipt(payer, shop_b, token, "ctx-shop-b"))

    _, keys = get_keys(client)
    response = client.post("/mint/issue", json=payer.issue_body(pick(keys)))
    assert response.status_code == 403
    assert "revoked" in response.text.lower()


def test_same_context_twice_reveals_nothing(scene):
    """Replaying one context gives the same point, so no identity is recoverable."""
    client, payer, token, shop_a, shop_b = scene
    settle(client, build_receipt(payer, shop_a, token, "ctx-same"))

    # A different receipt id, same context: the share point is identical.
    again = build_receipt(payer, shop_b, token, "ctx-same")
    body = settle(client, again)
    result = body["results"][0]

    assert result["status"] == "FRAUD"
    assert result["detail"] == "double-spend detected"
    assert "recovered" not in result["detail"]
    assert body["revoked"] == [], "nothing was learned, so nobody may be revoked"


def test_forged_second_point_does_not_revoke_an_innocent_payer(scene):
    """Recovery must pass g^a0 == c0 before anyone is revoked."""
    client, payer, token, shop_a, shop_b = scene
    settle(client, build_receipt(payer, shop_a, token, "ctx-shop-a"))

    forged = build_receipt(payer, shop_b, token, "ctx-shop-b")
    # A y that is not on the committed line fails validation outright.
    forged["y"] = _hex((int(forged["y"], 16) + 1) % bc.group_q())
    forged["merchant_sig"] = shop_b.sign(
        f"BCRECEIPT|v1|{forged['receipt_id']}|{token['token_id']}|{forged['n_ctx']}"
        f"|{forged['x']}|{forged['y']}|{forged['amount']}|{forged['merchant_id']}"
        f"|{forged['timestamp_ms']}"
    )

    body = settle(client, forged)
    assert body["results"][0]["status"] == "INVALID"
    assert body["results"][0]["detail"] == "share is not on the committed line"
    assert body["revoked"] == []


def test_double_spend_recovers_the_true_secret(scene):
    """Cross-check the recovery arithmetic against the payer's actual a0."""
    client, payer, token, shop_a, shop_b = scene
    r1 = build_receipt(payer, shop_a, token, "ctx-shop-a")
    r2 = build_receipt(payer, shop_b, token, "ctx-shop-b")
    settle(client, r1)
    settle(client, r2)

    recovered = bc.recover_secret(
        int(r1["x"], 16), int(r1["y"], 16), int(r2["x"], 16), int(r2["y"], 16)
    )
    assert recovered == payer.a0
    assert bc.commit(recovered) == int(token["c0"], 16)


# ---------------------------------------------------------------------------
# invalid receipts
# ---------------------------------------------------------------------------


def _expect_invalid(client, receipt, detail):
    body = settle(client, receipt)
    result = body["results"][0]
    assert result["status"] == "INVALID", result
    assert result["detail"] == detail, result
    return body


def test_expired_token_is_invalid(scene):
    """Past the token's expiry the credential has also expired.

    Credentials live 180 days and denomination keys 365, so no timestamp exists
    where the token is expired but the credential is not. The contract checks
    credentials first (lines 71-73), so that is the detail reported -- asserted
    here rather than papered over, because the ordering is contractual.
    """
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx", timestamp_ms=token["expiry_ms"] + 1)
    _expect_invalid(client, receipt, "payer credential invalid")


def test_token_expiry_is_enforced_when_the_credential_is_still_valid(scene):
    """Isolate the token-expiry check by shortening only the token."""
    client, payer, token, shop_a, _ = scene
    stale = dict(token, expiry_ms=1_600_000_000_000)
    _expect_invalid(
        client,
        build_receipt(payer, shop_a, stale, "ctx", timestamp_ms=1_700_000_000_000),
        "token expired",
    )


def test_unknown_mint_key_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    bad = dict(token, key_id="no-such-key")
    _expect_invalid(client, build_receipt(payer, shop_a, bad, "ctx"), "unknown mint key")


def test_token_not_matching_its_key_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    bad = dict(token, amount=token["amount"] + 1)
    _expect_invalid(
        client,
        build_receipt(payer, shop_a, bad, "ctx", amount=bad["amount"]),
        "token does not match its mint key",
    )


def test_forged_token_signature_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    bad = dict(token, sig=_hex(int(token["sig"], 16) ^ 1))
    _expect_invalid(client, build_receipt(payer, shop_a, bad, "ctx"), "invalid mint signature")


def test_token_from_another_payer_is_invalid(scene):
    """token.c0 must equal payer_cred.c0."""
    client, payer, token, shop_a, shop_b = scene
    receipt = build_receipt(payer, shop_a, token, "ctx")
    receipt["payer_cred"] = shop_b.credential
    _expect_invalid(client, receipt, "token does not belong to this payer")


def test_wrong_share_coordinate_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx")
    receipt["x"] = _hex(int(receipt["x"], 16) + 1)
    _expect_invalid(client, receipt, "wrong share coordinate for this context")


def test_bad_payer_signature_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx")
    receipt["payer_sig"] = "00" * 64
    _expect_invalid(client, receipt, "bad payer signature")


def test_bad_merchant_signature_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx")
    receipt["merchant_sig"] = "00" * 64
    _expect_invalid(client, receipt, "bad merchant signature")


def test_amount_mismatch_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx", amount=token["amount"] + 5)
    _expect_invalid(client, receipt, "amount mismatch")


def test_expired_payer_credential_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(
        payer, shop_a, token, "ctx", timestamp_ms=payer.credential["expiry_ms"] + 1
    )
    body = settle(client, receipt)
    assert body["results"][0]["detail"] in (
        "payer credential invalid",
        "token expired",
    )


def test_forged_credential_is_invalid(scene):
    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx")
    receipt["payer_cred"] = dict(payer.credential, mint_sig="00" * 64)
    _expect_invalid(client, receipt, "payer credential invalid")


def test_invalid_receipt_never_credits_or_persists(scene, configured):
    from sqlalchemy import select

    from app.db.models import Balance, SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx")
    receipt["payer_sig"] = "00" * 64
    settle(client, receipt)

    with session_scope() as session:
        assert session.scalars(select(SpentToken)).all() == []
        assert session.scalars(select(Balance)).all() == []


# ---------------------------------------------------------------------------
# batch behaviour
# ---------------------------------------------------------------------------


def test_mixed_batch_returns_one_result_per_receipt(scene):
    """One bad receipt must not discard the good ones (contract line 86)."""
    client, payer, token, shop_a, shop_b = scene
    _, keys = get_keys(client)
    second = payer.mint_token(client, pick(keys))

    good = build_receipt(payer, shop_a, token, "ctx-good")
    bad = build_receipt(payer, shop_a, second, "ctx-bad")
    bad["merchant_sig"] = "00" * 64

    body = settle(client, good, bad)
    assert len(body["results"]) == 2
    assert body["results"][0] == {
        "receipt_id": good["receipt_id"],
        "status": "ACCEPTED",
        "detail": "settled",
    }
    assert body["results"][1]["status"] == "INVALID"


def test_batch_with_all_invalid_still_returns_200(scene):
    client, payer, token, shop_a, _ = scene
    bad = build_receipt(payer, shop_a, token, "ctx")
    bad["payer_sig"] = "00" * 64
    response = client.post("/settlement/uploadBatch", json={"receipts": [bad]})
    assert response.status_code == 200


def test_empty_batch_is_accepted(client):
    body = settle(client)
    assert body["results"] == []
    assert isinstance(body["revoked"], list)


def test_results_preserve_request_order(scene):
    client, payer, token, shop_a, _ = scene
    _, keys = get_keys(client)
    tokens = [token] + [payer.mint_token(client, pick(keys)) for _ in range(3)]
    receipts = [build_receipt(payer, shop_a, t, f"ctx-{i}") for i, t in enumerate(tokens)]

    body = settle(client, *receipts)
    assert [r["receipt_id"] for r in body["results"]] == [
        r["receipt_id"] for r in receipts
    ]


# ---------------------------------------------------------------------------
# fraud/revocations
# ---------------------------------------------------------------------------


def test_revocations_is_empty_initially(client):
    assert client.get("/fraud/revocations").json() == {"revoked": []}


def test_revocations_shape(scene):
    client, payer, token, shop_a, shop_b = scene
    settle(client, build_receipt(payer, shop_a, token, "ctx-a"))
    settle(client, build_receipt(payer, shop_b, token, "ctx-b"))

    body = client.get("/fraud/revocations").json()
    assert set(body) == {"revoked"}
    for entry in body["revoked"]:
        assert set(entry) == {"cred_id", "reason", "ts"}


def test_revocations_survive_a_restart(configured, scene):
    from fastapi.testclient import TestClient

    from app.db.session import reset_caches
    from app.main import create_app

    client, payer, token, shop_a, shop_b = scene
    settle(client, build_receipt(payer, shop_a, token, "ctx-a"))
    settle(client, build_receipt(payer, shop_b, token, "ctx-b"))
    before = client.get("/fraud/revocations").json()
    assert before["revoked"]

    reset_caches()
    with TestClient(create_app()) as restarted:
        assert restarted.get("/fraud/revocations").json() == before


# ---------------------------------------------------------------------------
# concurrency
# ---------------------------------------------------------------------------


def test_concurrent_settlement_of_one_token_credits_once(scene, configured):
    """Eight simultaneous uploads of the same receipt must credit once."""
    from app.db.models import Balance
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-race")

    statuses: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        response = client.post("/settlement/uploadBatch", json={"receipts": [receipt]})
        with lock:
            statuses.append(response.json()["results"][0]["status"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert statuses.count("ACCEPTED") == 1, statuses
    assert all(s in {"ACCEPTED", "DUPLICATE"} for s in statuses), statuses

    with session_scope() as session:
        balance = session.get(Balance, (receipt["merchant_id"], "merchant", "INR"))
        assert balance.amount == token["amount"], "exactly one credit"


def test_concurrent_distinct_spends_of_one_token_settle_once(scene, configured):
    """Two merchants racing to settle the same token: one wins, one sees fraud."""
    from app.db.models import SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, shop_b = scene
    r1 = build_receipt(payer, shop_a, token, "ctx-a")
    r2 = build_receipt(payer, shop_b, token, "ctx-b")

    results: list[str] = []
    lock = threading.Lock()

    def worker(receipt: dict) -> None:
        response = client.post("/settlement/uploadBatch", json={"receipts": [receipt]})
        with lock:
            results.append(response.json()["results"][0]["status"])

    threads = [threading.Thread(target=worker, args=(r,)) for r in (r1, r2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == ["ACCEPTED", "FRAUD"], results

    with session_scope() as session:
        rows = session.scalars(
            __import__("sqlalchemy").select(SpentToken)
        ).all()
        assert len(rows) == 1, "a token may be settled only once"


# ---------------------------------------------------------------------------
# receipt_id reuse  (regression for audit finding D-1)
# ---------------------------------------------------------------------------


def test_same_receipt_id_on_two_distinct_tokens_is_accepted(scene, configured):
    """Both references key spent state by token_id alone.

    An earlier revision made `receipt_id` globally unique, which turned this
    into INVALID -- a status `Wallet.kt:242` never clears, so the receipt would
    have been retried on every sync forever. Spent state is per token.
    """
    from sqlalchemy import select

    from app.db.models import SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    _, keys = get_keys(client)
    second = payer.mint_token(client, pick(keys))

    shared_id = "shared-receipt-id"
    first_receipt = build_receipt(payer, shop_a, token, "ctx-1", receipt_id=shared_id)
    second_receipt = build_receipt(payer, shop_a, second, "ctx-2", receipt_id=shared_id)

    body = settle(client, first_receipt, second_receipt)
    assert [r["status"] for r in body["results"]] == ["ACCEPTED", "ACCEPTED"], body

    with session_scope() as session:
        rows = session.scalars(
            select(SpentToken).where(SpentToken.receipt_id == shared_id)
        ).all()
        assert {r.token_id for r in rows} == {token["token_id"], second["token_id"]}


def test_same_receipt_id_across_separate_batches_is_accepted(scene):
    """The same divergence, across requests rather than within one batch."""
    client, payer, token, shop_a, _ = scene
    _, keys = get_keys(client)
    second = payer.mint_token(client, pick(keys))

    shared_id = "shared-across-batches"
    first = settle(client, build_receipt(payer, shop_a, token, "ctx-1", receipt_id=shared_id))
    later = settle(client, build_receipt(payer, shop_a, second, "ctx-2", receipt_id=shared_id))

    assert first["results"][0]["status"] == "ACCEPTED"
    assert later["results"][0]["status"] == "ACCEPTED"


def test_reused_receipt_id_credits_each_token_separately(scene, configured):
    """Two tokens sharing a receipt id must both credit the merchant."""
    from app.db.models import Balance
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    _, keys = get_keys(client)
    second = payer.mint_token(client, pick(keys))

    shared_id = "shared-credit"
    settle(
        client,
        build_receipt(payer, shop_a, token, "ctx-1", receipt_id=shared_id),
        build_receipt(payer, shop_a, second, "ctx-2", receipt_id=shared_id),
    )

    merchant_id = shop_a.credential["cred_id"]
    with session_scope() as session:
        balance = session.get(Balance, (merchant_id, "merchant", "INR"))
        assert balance.amount == token["amount"] + second["amount"]


def test_duplicate_still_detected_per_token_after_the_fix(scene, configured):
    """Removing the constraint must not weaken per-token idempotency."""
    from app.db.models import Balance
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-dup", receipt_id="same-id")

    first = settle(client, receipt)
    second = settle(client, receipt)

    assert first["results"][0]["status"] == "ACCEPTED"
    assert second["results"][0]["status"] == "DUPLICATE"
    assert second["results"][0]["detail"] == "already settled"

    with session_scope() as session:
        balance = session.get(Balance, (receipt["merchant_id"], "merchant", "INR"))
        assert balance.amount == token["amount"], "DUPLICATE must not credit twice"


def test_double_spend_path_unchanged_after_the_fix(scene):
    """A different receipt for an already-spent token is still FRAUD."""
    client, payer, token, shop_a, shop_b = scene
    settle(client, build_receipt(payer, shop_a, token, "ctx-a", receipt_id="first"))
    body = settle(client, build_receipt(payer, shop_b, token, "ctx-b", receipt_id="second"))

    result = body["results"][0]
    assert result["status"] == "FRAUD"
    assert "identity secret recovered" in result["detail"]
    assert any(r["cred_id"] == payer.credential["cred_id"] for r in body["revoked"])


def test_concurrent_duplicates_still_credit_once_after_the_fix(scene, configured):
    from app.db.models import Balance
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-race2", receipt_id="raced")

    statuses: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        response = client.post("/settlement/uploadBatch", json={"receipts": [receipt]})
        with lock:
            statuses.append(response.json()["results"][0]["status"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert statuses.count("ACCEPTED") == 1, statuses
    assert all(s in {"ACCEPTED", "DUPLICATE"} for s in statuses), statuses

    with session_scope() as session:
        balance = session.get(Balance, (receipt["merchant_id"], "merchant", "INR"))
        assert balance.amount == token["amount"]


# ---------------------------------------------------------------------------
# transaction boundary
# ---------------------------------------------------------------------------


def test_unexpected_exception_mid_batch_rolls_back_the_whole_batch(
    scene, configured, monkeypatch
):
    """A batch is one transaction: it commits whole or not at all.

    An unexpected failure while settling receipt 2 must undo receipt 1 as well.
    The alternative -- committing the prefix -- would leave the merchant
    credited for a batch the client was told failed, and the client would
    re-upload every receipt in it (`Wallet.kt` only clears receipts it saw a
    result for), double-crediting on the retry.

    The exception is injected rather than provoked, so the test is deterministic
    and does not depend on any particular row being malformed.
    """
    from sqlalchemy import select

    from app.api import settlement as settlement_module
    from app.db.models import Balance, SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    _, keys = get_keys(client)
    second = payer.mint_token(client, pick(keys))

    first_receipt = build_receipt(payer, shop_a, token, "ctx-1")
    second_receipt = build_receipt(payer, shop_a, second, "ctx-2")

    calls = {"n": 0}
    real_credit = settlement_module._credit_merchant

    def exploding_credit(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("injected failure while settling receipt 2")
        return real_credit(*args, **kwargs)

    monkeypatch.setattr(settlement_module, "_credit_merchant", exploding_credit)

    with pytest.raises(RuntimeError, match="injected failure"):
        client.post(
            "/settlement/uploadBatch",
            json={"receipts": [first_receipt, second_receipt]},
        )

    assert calls["n"] == 2, "the first receipt must have been processed first"

    # Nothing from either receipt may survive.
    with session_scope() as session:
        assert session.scalars(select(SpentToken)).all() == [], (
            "receipt 1 was committed despite the batch failing"
        )
        assert session.scalars(select(Balance)).all() == [], (
            "a merchant was credited for a batch that failed"
        )


def test_exception_mid_batch_leaves_no_partial_revocation(
    scene, configured, monkeypatch
):
    """A revocation written earlier in a failed batch must also roll back."""
    from sqlalchemy import select

    from app.api import settlement as settlement_module
    from app.db.models import Revocation, SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, shop_b = scene
    _, keys = get_keys(client)
    second = payer.mint_token(client, pick(keys))

    # Settle once so the next spend of `token` triggers recovery and revocation.
    settle(client, build_receipt(payer, shop_a, token, "ctx-a"))

    fraud_receipt = build_receipt(payer, shop_b, token, "ctx-b")
    good_receipt = build_receipt(payer, shop_a, second, "ctx-c")

    real_credit = settlement_module._credit_merchant

    def exploding_credit(*args, **kwargs):
        raise RuntimeError("injected failure after revocation")

    monkeypatch.setattr(settlement_module, "_credit_merchant", exploding_credit)

    with pytest.raises(RuntimeError, match="injected failure"):
        client.post(
            "/settlement/uploadBatch",
            json={"receipts": [fraud_receipt, good_receipt]},
        )

    monkeypatch.setattr(settlement_module, "_credit_merchant", real_credit)

    with session_scope() as session:
        assert session.scalars(select(Revocation)).all() == [], (
            "a revocation survived a batch that failed"
        )
        # The earlier, separately-committed spend is untouched.
        assert len(session.scalars(select(SpentToken)).all()) == 1


def test_state_is_unchanged_after_a_failed_batch(scene, configured, monkeypatch):
    """A failed batch must be a no-op the client can simply retry."""
    from sqlalchemy import select

    from app.api import settlement as settlement_module
    from app.db.models import Balance, SpentToken
    from app.db.session import session_scope

    client, payer, token, shop_a, _ = scene
    receipt = build_receipt(payer, shop_a, token, "ctx-retry")

    def exploding_credit(*args, **kwargs):
        raise RuntimeError("injected failure")

    monkeypatch.setattr(settlement_module, "_credit_merchant", exploding_credit)
    with pytest.raises(RuntimeError):
        client.post("/settlement/uploadBatch", json={"receipts": [receipt]})

    monkeypatch.undo()

    # The identical batch now succeeds, proving the failure left nothing behind.
    body = settle(client, receipt)
    assert body["results"][0]["status"] == "ACCEPTED"

    with session_scope() as session:
        assert len(session.scalars(select(SpentToken)).all()) == 1
        balance = session.get(Balance, (receipt["merchant_id"], "merchant", "INR"))
        assert balance.amount == token["amount"]
