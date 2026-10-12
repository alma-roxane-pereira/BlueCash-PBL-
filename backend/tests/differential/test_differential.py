"""
Differential tests: the backend against the reference server.

Both run on the same key material, so cryptographic outputs are compared
byte for byte rather than merely structurally.

Scope: this compares two Python servers. It says nothing about the Android
client, which has never been run against either.

Run with:

    cd backend
    ../.venv/Scripts/python.exe -m pytest tests/differential -m differential -q
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import bluecash_crypto as bc

from .client import (
    Device,
    blind_token,
    build_receipt,
    hexint,
    new_receipt_id,
    unblind_token,
)
from .compare import (
    assert_close_in_time,
    assert_json_equal,
    assert_responses_equal,
)
from .conftest import register

pytestmark = pytest.mark.differential


def keys_of(pair) -> dict:
    """The 100-unit denomination, as both servers report it."""
    body = pair.backend.get("/mint/keys").json()
    return next(k for k in body["keys"] if k["amount"] == 100)


# ---------------------------------------------------------------------------
# GET /mint/keys
# ---------------------------------------------------------------------------


def test_mint_keys_match(pair):
    ref, be = pair.get("/mint/keys")
    assert_responses_equal(ref, be, "/mint/keys")


def test_neither_server_exposes_the_private_exponent(pair):
    for response in pair.get("/mint/keys"):
        for key in response.json()["keys"]:
            assert "d" not in key


def test_mint_keys_stable_across_calls(pair):
    first = pair.reference.get("/mint/keys").json()
    second = pair.reference.get("/mint/keys").json()
    assert_json_equal(first, second, "reference stability")


# ---------------------------------------------------------------------------
# POST /mint/registerDevice
# ---------------------------------------------------------------------------


def test_registration_agrees_apart_from_the_credential_id(pair, aliases, device):
    """`cred_id` is a uuid4 on both and can never match; everything else must.

    `mint_sig` signs a string containing `cred_id`, so it is checked separately,
    under each server's own `mint_pub`.
    """
    ref, be = register(pair, aliases, device)
    assert ref.status_code == be.status_code == 200

    ref_cred = dict(ref.json()["credential"])
    be_cred = dict(be.json()["credential"])

    assert_close_in_time(ref_cred.pop("expiry_ms"), be_cred.pop("expiry_ms"), "expiry")
    ref_sig, be_sig = ref_cred.pop("mint_sig"), be_cred.pop("mint_sig")
    ref_id, be_id = ref_cred.pop("cred_id"), be_cred.pop("cred_id")

    # Everything that should be identical.
    assert_json_equal(ref_cred, be_cred, "credential")
    assert ref_cred["c0"] == device.c0, "the mint must echo the client's spelling"
    assert len(ref_id) == len(be_id) == 32

    # Each signature verifies under its own server's key -- stronger than
    # comparing the bytes, which cannot match while cred_id differs.
    mint_pub = pair.reference.get("/mint/keys").json()["mint_pub"]
    for cred_id, cred, sig in (
        (ref_id, ref.json()["credential"], ref_sig),
        (be_id, be.json()["credential"], be_sig),
    ):
        message = (
            f"BCCRED|v1|{cred_id}|{cred['device_pub']}|{cred['c0']}|{cred['expiry_ms']}"
        ).encode()
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(mint_pub)).verify(
            bytes.fromhex(sig), message
        )


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("bad signature", lambda b: {**b, "sig": "00" * 64}),
        ("wrong message", lambda b: {**b, "ts": b["ts"] + 1}),
        ("c0 = 1", lambda b: {**b, "c0": "01"}),
        ("c0 = P-1", lambda b: {**b, "c0": hexint(bc.group_p() - 1)}),
        ("malformed hex", lambda b: {**b, "c0": "zz"}),
        ("empty c0", lambda b: {**b, "c0": ""}),
    ],
)
def test_invalid_registration_rejected_identically(pair, device, label, mutate):
    ref, be = pair.post("/mint/registerDevice", mutate(device.register_body()))
    assert_responses_equal(ref, be, f"registration / {label}")


# ---------------------------------------------------------------------------
# POST /mint/issue
# ---------------------------------------------------------------------------


def test_issuance_produces_identical_crypto(pair, aliases, device):
    """`blind_sig`, the audit leaf and the root must match byte for byte.

    They can, because both servers hold the same RSA key and receive the same
    `blinded` value -- which does not depend on `cred_id`.
    """
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)

    ref, be = pair.post_each(
        "/mint/issue",
        request.issue_body(device, "reference", key, ts=1_700_000_000_001),
        request.issue_body(device, "backend", key, ts=1_700_000_000_001),
    )
    ref_body, be_body = assert_responses_equal(ref, be, "/mint/issue")

    # Explicit about the fields that carry the cryptography.
    assert ref_body["blind_sig"] == be_body["blind_sig"]
    assert ref_body["root"] == be_body["root"]
    assert ref_body["proof"] == be_body["proof"]
    assert ref_body["leaf_index"] == be_body["leaf_index"]
    assert ref_body["tree_size"] == be_body["tree_size"]

    # And the signature actually unblinds and verifies.
    unblind_token(request, ref_body["blind_sig"], key)


def test_sequential_issuance_keeps_roots_in_step(pair, aliases, device):
    """Five issuances: the root must agree at every step, not just at the end."""
    register(pair, aliases, device)
    key = keys_of(pair)

    for index in range(5):
        request = blind_token(device, key)
        ts = 1_700_000_100_000 + index
        ref, be = pair.post_each(
            "/mint/issue",
            request.issue_body(device, "reference", key, ts=ts),
            request.issue_body(device, "backend", key, ts=ts),
        )
        ref_body, be_body = assert_responses_equal(ref, be, f"issue #{index}")
        assert ref_body["tree_size"] == be_body["tree_size"]

        ref_root, be_root = pair.get("/audit/root/latest")
        assert_responses_equal(ref_root, be_root, f"root after #{index}", drop=("ts",))


def test_inclusion_proof_verifies_on_both(pair, aliases, device):
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)

    ref, be = pair.post_each(
        "/mint/issue",
        request.issue_body(device, "reference", key, ts=1_700_000_200_000),
        request.issue_body(device, "backend", key, ts=1_700_000_200_000),
    )
    ref_body, be_body = assert_responses_equal(ref, be, "issue for proof")

    import hashlib

    leaf = hashlib.sha256(
        bytes.fromhex(request.blinded_hex) + bytes.fromhex(ref_body["blind_sig"])
    ).digest()
    for body in (ref_body, be_body):
        assert bc.merkle_verify_inclusion(
            leaf,
            body["leaf_index"],
            body["tree_size"],
            [bytes.fromhex(p) for p in body["proof"]],
            bytes.fromhex(body["root"]),
        )


def test_unknown_credential_rejected_identically(pair, aliases, device):
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)
    body = request.issue_body(device, "reference", key, ts=1_700_000_300_000)
    body["cred_id"] = "0" * 32

    ref, be = pair.post("/mint/issue", body)
    assert_responses_equal(ref, be, "issue / unknown credential")


@pytest.mark.parametrize(
    ("label", "field", "value"),
    [
        ("bad signature", "sig", "00" * 64),
        ("unknown key", "key_id", "no-such-key"),
        ("blinded = 0", "blinded", "00"),
    ],
)
def test_invalid_issuance_rejected_identically(pair, aliases, device, label, field, value):
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)

    def body_for(side: str) -> dict:
        body = request.issue_body(device, side, key, ts=1_700_000_400_000)
        body[field] = value
        if field != "sig":
            cred_id = device.cred_id(side)
            body["sig"] = device.sign(
                f"BCISSUE|v1|{cred_id}|{body['key_id']}|{body['blinded']}"
                f"|{device.c0}|{body['ts']}"
            )
        return body

    ref, be = pair.post_each("/mint/issue", body_for("reference"), body_for("backend"))
    assert_responses_equal(ref, be, f"issue / {label}")


def test_blinded_equal_to_modulus_rejected_identically(pair, aliases, device):
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)
    out_of_range = hexint(int(key["n"], 16))

    def body_for(side: str) -> dict:
        cred_id = device.cred_id(side)
        ts = 1_700_000_500_000
        return {
            "cred_id": cred_id,
            "key_id": key["key_id"],
            "blinded": out_of_range,
            "c0": device.c0,
            "ts": ts,
            "sig": device.sign(
                f"BCISSUE|v1|{cred_id}|{key['key_id']}|{out_of_range}|{device.c0}|{ts}"
            ),
        }

    ref, be = pair.post_each("/mint/issue", body_for("reference"), body_for("backend"))
    assert_responses_equal(ref, be, "issue / blinded == n")


def test_equivalent_c0_spelling_accepted_by_both(pair, aliases, device):
    """`c0` is compared numerically, so leading zeros must not matter."""
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)
    padded = "0000" + device.c0

    def body_for(side: str) -> dict:
        cred_id = device.cred_id(side)
        ts = 1_700_000_600_000
        return {
            "cred_id": cred_id,
            "key_id": key["key_id"],
            "blinded": request.blinded_hex,
            "c0": padded,
            "ts": ts,
            "sig": device.sign(
                f"BCISSUE|v1|{cred_id}|{key['key_id']}|{request.blinded_hex}|{padded}|{ts}"
            ),
        }

    ref, be = pair.post_each("/mint/issue", body_for("reference"), body_for("backend"))
    assert_responses_equal(ref, be, "issue / padded c0")
    assert ref.status_code == 200


# ---------------------------------------------------------------------------
# GET /audit/root/latest
# ---------------------------------------------------------------------------


def test_audit_root_matches(pair):
    ref, be = pair.get("/audit/root/latest")
    ref_body, be_body = assert_responses_equal(ref, be, "/audit/root/latest", drop=("ts",))
    assert_close_in_time(ref_body["ts"], be_body["ts"], "audit ts")


# ---------------------------------------------------------------------------
# settlement
# ---------------------------------------------------------------------------


def _mint_for_spending(pair, aliases, device, ts_base: int):
    """Register, mint a token, and return (token, a1, key)."""
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)
    ref, be = pair.post_each(
        "/mint/issue",
        request.issue_body(device, "reference", key, ts=ts_base),
        request.issue_body(device, "backend", key, ts=ts_base),
    )
    ref_body, be_body = assert_responses_equal(ref, be, "issue for spending")
    token = unblind_token(request, ref_body["blind_sig"], key)
    return token, request.a1, key


def _settle(pair, aliases, payer, merchant, token, a1, n_ctx, receipt_id, **kwargs):
    ref_receipt = build_receipt(
        payer, merchant, token, a1, n_ctx, "reference", receipt_id=receipt_id, **kwargs
    )
    be_receipt = build_receipt(
        payer, merchant, token, a1, n_ctx, "backend", receipt_id=receipt_id, **kwargs
    )
    return pair.post_each(
        "/settlement/uploadBatch",
        {"receipts": [ref_receipt]},
        {"receipts": [be_receipt]},
    )


def test_valid_spend_settles_identically(pair, aliases, device):
    merchant = Device()
    token, a1, _ = _mint_for_spending(pair, aliases, device, 1_700_001_000_000)
    register(pair, aliases, merchant)

    ref, be = _settle(
        pair, aliases, device, merchant, token, a1, "ctx-a", new_receipt_id()
    )
    ref_body, be_body = assert_responses_equal(ref, be, "settlement", aliases, drop=("ts",))
    assert ref_body["results"][0]["status"] == "ACCEPTED"
    assert ref_body["results"][0]["detail"] == "settled"


def test_duplicate_receipt_handled_identically(pair, aliases, device):
    merchant = Device()
    token, a1, _ = _mint_for_spending(pair, aliases, device, 1_700_002_000_000)
    register(pair, aliases, merchant)
    receipt_id = new_receipt_id()

    _settle(pair, aliases, device, merchant, token, a1, "ctx-b", receipt_id)
    ref, be = _settle(pair, aliases, device, merchant, token, a1, "ctx-b", receipt_id)

    ref_body, _ = assert_responses_equal(ref, be, "duplicate", aliases, drop=("ts",))
    assert ref_body["results"][0]["status"] == "DUPLICATE"


def test_double_spend_recovery_and_revocation_match(pair, aliases, device):
    """The protocol's central claim, compared across both servers."""
    shop_a, shop_b = Device(), Device()
    token, a1, _ = _mint_for_spending(pair, aliases, device, 1_700_003_000_000)
    register(pair, aliases, shop_a)
    register(pair, aliases, shop_b)

    _settle(pair, aliases, device, shop_a, token, a1, "ctx-shop-a", new_receipt_id())
    ref, be = _settle(
        pair, aliases, device, shop_b, token, a1, "ctx-shop-b", new_receipt_id()
    )

    ref_body, _ = assert_responses_equal(ref, be, "double spend", aliases, drop=("ts",))
    result = ref_body["results"][0]
    assert result["status"] == "FRAUD"
    assert "identity secret recovered" in result["detail"]
    assert ref_body["revoked"], "the payer must be revoked"


def test_same_context_replay_reveals_nothing_on_both(pair, aliases, device):
    shop_a, shop_b = Device(), Device()
    token, a1, _ = _mint_for_spending(pair, aliases, device, 1_700_004_000_000)
    register(pair, aliases, shop_a)
    register(pair, aliases, shop_b)

    _settle(pair, aliases, device, shop_a, token, a1, "ctx-same", new_receipt_id())
    ref, be = _settle(
        pair, aliases, device, shop_b, token, a1, "ctx-same", new_receipt_id()
    )

    ref_body, _ = assert_responses_equal(ref, be, "same-context replay", aliases, drop=("ts",))
    assert ref_body["results"][0]["status"] == "FRAUD"
    assert ref_body["results"][0]["detail"] == "double-spend detected"
    # `revoked` is the full list and the module shares server state, so earlier
    # tests may appear in it. What matters is that *this* payer was not revoked:
    # replaying one context yields the same point twice and reveals nothing.
    revoked_ids = {entry["cred_id"] for entry in ref_body["revoked"]}
    assert device.cred_id("reference") not in revoked_ids, (
        "nothing was learned, so this payer may not be revoked"
    )


def test_same_receipt_id_on_two_tokens_accepted_by_both(pair, aliases, device):
    """Regression for audit finding D-1, verified against the reference."""
    merchant = Device()
    register(pair, aliases, device)
    register(pair, aliases, merchant)
    key = keys_of(pair)
    shared_id = new_receipt_id()

    for index in range(2):
        request = blind_token(device, key)
        ts = 1_700_005_000_000 + index
        ref, be = pair.post_each(
            "/mint/issue",
            request.issue_body(device, "reference", key, ts=ts),
            request.issue_body(device, "backend", key, ts=ts),
        )
        ref_body, _ = assert_responses_equal(ref, be, f"issue {index}")
        token = unblind_token(request, ref_body["blind_sig"], key)

        ref_s, be_s = _settle(
            pair, aliases, device, merchant, token, request.a1, f"ctx-{index}", shared_id
        )
        body, _ = assert_responses_equal(ref_s, be_s, f"shared receipt id {index}", aliases, drop=("ts",))
        assert body["results"][0]["status"] == "ACCEPTED"


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("bad payer signature", lambda r: {**r, "payer_sig": "00" * 64}),
        ("bad merchant signature", lambda r: {**r, "merchant_sig": "00" * 64}),
        ("wrong x", lambda r: {**r, "x": hexint(int(r["x"], 16) + 1)}),
        ("amount mismatch", lambda r: {**r, "amount": r["amount"] + 5}),
        (
            "forged token signature",
            lambda r: {**r, "token": {**r["token"], "sig": hexint(int(r["token"]["sig"], 16) ^ 1)}},
        ),
        (
            "unknown mint key",
            lambda r: {**r, "token": {**r["token"], "key_id": "no-such-key"}},
        ),
        (
            "token expired",
            lambda r: {**r, "token": {**r["token"], "expiry_ms": 1_600_000_000_000}},
        ),
    ],
)
def test_invalid_receipts_rejected_identically(pair, aliases, device, label, mutate):
    merchant = Device()
    token, a1, _ = _mint_for_spending(pair, aliases, device, 1_700_006_000_000)
    register(pair, aliases, merchant)

    ref_receipt = mutate(
        build_receipt(
            device, merchant, token, a1, "ctx-inv", "reference", receipt_id=new_receipt_id()
        )
    )
    be_receipt = mutate(
        build_receipt(
            device, merchant, token, a1, "ctx-inv", "backend",
            receipt_id=ref_receipt["receipt_id"],
        )
    )
    ref, be = pair.post_each(
        "/settlement/uploadBatch",
        {"receipts": [ref_receipt]},
        {"receipts": [be_receipt]},
    )
    body, _ = assert_responses_equal(ref, be, f"invalid receipt / {label}", aliases, drop=("ts",))
    assert body["results"][0]["status"] == "INVALID"


def test_validation_order_matches_when_several_checks_fail(pair, aliases, device):
    """A receipt failing many checks must report the *same first* failure.

    This is what catches a reordering bug; each check passing individually would
    not.
    """
    merchant = Device()
    token, a1, _ = _mint_for_spending(pair, aliases, device, 1_700_007_000_000)
    register(pair, aliases, merchant)

    def broken(side: str) -> dict:
        receipt = build_receipt(
            device, merchant, token, a1, "ctx-multi", side, receipt_id="multi-fail"
        )
        receipt["token"] = {
            **receipt["token"],
            "expiry_ms": 1_600_000_000_000,       # expired
            "sig": hexint(int(receipt["token"]["sig"], 16) ^ 1),  # forged
        }
        receipt["x"] = hexint(int(receipt["x"], 16) + 1)          # wrong coordinate
        receipt["payer_sig"] = "00" * 64                          # bad signature
        receipt["amount"] = receipt["amount"] + 1                 # mismatch
        return receipt

    ref, be = pair.post_each(
        "/settlement/uploadBatch",
        {"receipts": [broken("reference")]},
        {"receipts": [broken("backend")]},
    )
    body, _ = assert_responses_equal(ref, be, "validation order", aliases, drop=("ts",))
    assert body["results"][0]["status"] == "INVALID"


def test_mixed_batch_matches(pair, aliases, device):
    merchant = Device()
    token, a1, _ = _mint_for_spending(pair, aliases, device, 1_700_008_000_000)
    register(pair, aliases, merchant)

    def batch(side: str) -> dict:
        good = build_receipt(
            device, merchant, token, a1, "ctx-good", side, receipt_id="mixed-good"
        )
        bad = build_receipt(
            device, merchant, token, a1, "ctx-bad", side, receipt_id="mixed-bad"
        )
        bad["merchant_sig"] = "00" * 64
        return {"receipts": [good, bad]}

    ref, be = pair.post_each("/settlement/uploadBatch", batch("reference"), batch("backend"))
    body, _ = assert_responses_equal(ref, be, "mixed batch", aliases, drop=("ts",))
    assert [r["status"] for r in body["results"]] == ["ACCEPTED", "INVALID"]


def test_empty_batch_matches(pair, aliases):
    ref, be = pair.post("/settlement/uploadBatch", {"receipts": []})
    assert_responses_equal(ref, be, "empty batch", aliases, drop=("ts",))


# ---------------------------------------------------------------------------
# GET /fraud/revocations
# ---------------------------------------------------------------------------


def test_revocations_match(pair, aliases):
    ref, be = pair.get("/fraud/revocations")
    assert_responses_equal(ref, be, "/fraud/revocations", aliases, drop=("ts",))


# ---------------------------------------------------------------------------
# known divergences -- asserted explicitly so they stay visible
# ---------------------------------------------------------------------------


def test_known_divergence_unknown_fields(pair, device):
    """The backend sets `extra="forbid"`; the reference ignores unknown fields.

    A deliberate, documented difference. Asserted here so that if either side
    changes, this fails and the decision is revisited rather than drifting.
    """
    body = {**device.register_body(), "unexpected_field": "x"}
    ref, be = pair.post("/mint/registerDevice", body)

    assert ref.status_code == 200, "the reference ignores unknown fields"
    assert be.status_code == 422, "the backend rejects them"


def test_known_divergence_malformed_hex_in_blinded(pair, aliases, device):
    """Malformed hex: the reference crashes, the backend validates.

    `server.py` passes `blinded` straight to `int(s, 16)` with no validation, so
    `"zz"` raises an unhandled ValueError and uvicorn returns 500 with a plain
    "Internal Server Error" body. The backend's codec rejects it as a 400 with a
    specific detail.

    This is a deliberate improvement, not an accident, and it only affects input
    that is already invalid -- the Android client never sends non-hex. Asserted
    here so the difference stays visible and is revisited if either side
    changes.
    """
    register(pair, aliases, device)
    key = keys_of(pair)
    request = blind_token(device, key)

    def body_for(side: str) -> dict:
        cred_id = device.cred_id(side)
        ts = 1_700_009_000_000
        return {
            "cred_id": cred_id,
            "key_id": key["key_id"],
            "blinded": "zz",
            "c0": device.c0,
            "ts": ts,
            "sig": device.sign(
                f"BCISSUE|v1|{cred_id}|{key['key_id']}|zz|{device.c0}|{ts}"
            ),
        }

    ref, be = pair.post_each("/mint/issue", body_for("reference"), body_for("backend"))

    assert ref.status_code == 500, "the reference does not validate hex"
    assert be.status_code == 400, "the backend rejects it cleanly"
    assert "not plain hexadecimal" in be.text
