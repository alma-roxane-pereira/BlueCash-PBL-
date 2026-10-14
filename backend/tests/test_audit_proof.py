"""
`GET /audit/proof/{leaf_index}`.

A published Merkle root is only worth something if a holder can check that their
issuance is actually under it. `POST /mint/issue` returns a proof, but only to
the device that made the issuance and only at that moment; this endpoint serves
the same proof afterwards, to anyone.

Every proof here is checked with `bluecash_crypto.merkle_verify_inclusion` --
the same routine the Android client uses -- rather than by asserting on the
shape of the response. A proof that parses but does not verify is worse than no
proof at all.
"""

from __future__ import annotations

import bluecash_crypto as bc

from .test_mint_api import Wallet, get_keys, pick


def verify(body: dict) -> bool:
    """Run the response through the real verification algorithm."""
    return bc.merkle_verify_inclusion(
        bytes.fromhex(body["leaf"]),
        body["leaf_index"],
        body["tree_size"],
        [bytes.fromhex(p) for p in body["proof"]],
        bytes.fromhex(body["root"]),
    )


def issue(client, wallet: Wallet) -> dict:
    """Blind-sign one token for `wallet`; returns the `/mint/issue` body."""
    key = pick(get_keys(client)[1])
    response = client.post("/mint/issue", json=wallet.issue_body(key))
    assert response.status_code == 200, response.text
    return response.json()


def registered(client) -> Wallet:
    wallet = Wallet()
    wallet.register(client)
    return wallet


def mint_one(client) -> dict:
    """Issue a single token from a fresh device."""
    return issue(client, registered(client))


# ---------------------------------------------------------------------------
# a valid proof
# ---------------------------------------------------------------------------


def test_proof_for_a_single_leaf_tree_verifies(client):
    mint_one(client)

    response = client.get("/audit/proof/0")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["leaf_index"] == 0
    assert body["tree_size"] == 1
    assert body["proof"] == []  # a lone leaf is its own root, so no siblings
    assert verify(body)


def test_every_leaf_of_a_multi_leaf_tree_verifies(client):
    """Odd sizes exercise the uneven split, which is where RFC 6962 trees break."""
    wallet = registered(client)
    for _ in range(5):
        issue(client, wallet)

    for index in range(5):
        body = client.get(f"/audit/proof/{index}").json()
        assert body["leaf_index"] == index
        assert body["tree_size"] == 5
        assert verify(body), f"leaf {index} did not verify"


def test_proof_matches_the_one_issuance_returned(client):
    """The same leaf, proved twice, at the same tree size: identical both times."""
    issued = mint_one(client)

    body = client.get(f"/audit/proof/{issued['leaf_index']}").json()
    assert body["proof"] == issued["proof"]
    assert body["root"] == issued["root"]
    assert body["tree_size"] == issued["tree_size"]


def test_root_agrees_with_the_audit_root_endpoint(client):
    mint_one(client)
    mint_one(client)

    proof = client.get("/audit/proof/1").json()
    latest = client.get("/audit/root/latest").json()
    assert proof["root"] == latest["root"]
    assert proof["tree_size"] == latest["tree_size"]


def test_a_proof_is_self_contained(client):
    """Verification must need nothing beyond the response body."""
    mint_one(client)
    mint_one(client)
    mint_one(client)

    body = client.get("/audit/proof/2").json()
    assert set(body) == {"leaf_index", "leaf", "tree_size", "proof", "root"}
    assert verify(body)


# ---------------------------------------------------------------------------
# bad indices
# ---------------------------------------------------------------------------


def test_index_past_the_end_is_404(client):
    mint_one(client)

    response = client.get("/audit/proof/1")
    assert response.status_code == 404
    assert "1 leaf" in response.json()["detail"]


def test_negative_index_is_404(client):
    mint_one(client)
    assert client.get("/audit/proof/-1").status_code == 404


def test_any_index_on_an_empty_log_is_404(client):
    """Nothing has been issued, so there is no leaf 0 to prove."""
    response = client.get("/audit/proof/0")
    assert response.status_code == 404
    assert "0 leaf" in response.json()["detail"]


def test_a_non_integer_index_is_rejected(client):
    assert client.get("/audit/proof/abc").status_code == 422


# ---------------------------------------------------------------------------
# what the response must not leak
# ---------------------------------------------------------------------------


def test_the_proof_exposes_no_device_or_denomination(client):
    """`cred_id` would say who was issued the token, `key_id` for how much.

    Neither is needed to verify inclusion, and the audit log is public.
    """
    issued = mint_one(client)
    text = client.get(f"/audit/proof/{issued['leaf_index']}").text

    assert "cred_id" not in text
    assert "key_id" not in text
    assert "d10-" not in text and "d50-" not in text


# ---------------------------------------------------------------------------
# tampering
# ---------------------------------------------------------------------------


def test_a_tampered_proof_does_not_verify(client):
    """Guards the test helper itself: `verify` must be able to fail."""
    wallet = registered(client)
    for _ in range(4):
        issue(client, wallet)

    body = client.get("/audit/proof/1").json()
    assert verify(body)

    flipped = bytearray(bytes.fromhex(body["proof"][0]))
    flipped[0] ^= 0x01
    body["proof"][0] = flipped.hex()
    assert not verify(body)


def test_a_proof_does_not_verify_against_the_wrong_leaf(client):
    wallet = registered(client)
    for _ in range(4):
        issue(client, wallet)

    body = client.get("/audit/proof/1").json()
    body["leaf"] = client.get("/audit/proof/2").json()["leaf"]
    assert not verify(body)
