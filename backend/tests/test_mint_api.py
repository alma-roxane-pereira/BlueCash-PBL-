"""
Endpoint tests for the four mint/audit endpoints of Step 4A.

The client side of the protocol is reimplemented here from `API_CONTRACT.md`
rather than imported from the backend, so a test exercises the contract rather
than agreeing with the implementation by construction. Signature verification is
cross-checked with `cryptography` — the library the reference server uses — so
these tests do not merely confirm the Rust core agrees with itself.

Keys are generated per test into a temporary database.
"""

from __future__ import annotations

import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import bluecash_crypto as bc

# ---------------------------------------------------------------------------
# a minimal protocol client
# ---------------------------------------------------------------------------


def _hex(value: int) -> str:
    """Even-length lowercase hex, as the contract requires."""
    h = format(value, "x")
    return h if len(h) % 2 == 0 else "0" + h


class Wallet:
    """A device: an Ed25519 identity key plus a Feldman identity secret."""

    def __init__(self) -> None:
        self.sk = ed25519.Ed25519PrivateKey.generate()
        self.device_pub = self.sk.public_key().public_bytes_raw().hex()
        self.a0 = secrets.randbelow(bc.group_q() - 2) + 1
        self.c0 = _hex(bc.commit(self.a0))
        self.credential: dict | None = None

    def sign(self, message: str) -> str:
        return self.sk.sign(message.encode()).hex()

    def register_body(self, ts: int = 1_700_000_000_000, **overrides) -> dict:
        body = {
            "device_pub": self.device_pub,
            "c0": self.c0,
            "ts": ts,
            "sig": self.sign(f"BCREG|v1|{self.device_pub}|{self.c0}|{ts}"),
        }
        body.update(overrides)
        return body

    def register(self, client, **overrides):
        response = client.post("/mint/registerDevice", json=self.register_body(**overrides))
        if response.status_code == 200:
            self.credential = response.json()["credential"]
        return response

    def issue_body(self, key: dict, ts: int = 1_700_000_000_001, **overrides) -> dict:
        """Blind a fresh token request for `key`."""
        n, e = int(key["n"], 16), int(key["e"], 16)
        token_id = secrets.token_hex(16)
        a1 = secrets.randbelow(bc.group_q() - 2) + 1
        c1 = _hex(bc.commit(a1))
        message = f"BCTOKEN|v1|{key['key_id']}|{token_id}|{self.c0}|{c1}".encode()

        blinded, r = bc.blind(message, n, e)
        self.last = {"token_id": token_id, "a1": a1, "c1": c1, "r": r, "msg": message, "n": n, "e": e}

        cred_id = self.credential["cred_id"]
        blinded_hex = _hex(blinded)
        body = {
            "cred_id": cred_id,
            "key_id": key["key_id"],
            "blinded": blinded_hex,
            "c0": self.c0,
            "ts": ts,
            "sig": self.sign(
                f"BCISSUE|v1|{cred_id}|{key['key_id']}|{blinded_hex}|{self.c0}|{ts}"
            ),
        }
        body.update(overrides)
        return body


def get_keys(client) -> tuple[str, list[dict]]:
    payload = client.get("/mint/keys").json()
    return payload["mint_pub"], payload["keys"]


def pick(keys: list[dict], amount: int = 100) -> dict:
    return next(k for k in keys if k["amount"] == amount)


# ---------------------------------------------------------------------------
# GET /mint/keys
# ---------------------------------------------------------------------------


def test_mint_keys_returns_identity_and_denominations(client):
    response = client.get("/mint/keys")
    assert response.status_code == 200
    body = response.json()

    assert len(bytes.fromhex(body["mint_pub"])) == 32
    assert sorted(k["amount"] for k in body["keys"]) == [10, 50, 100, 500]
    for key in body["keys"]:
        assert set(key) == {"key_id", "amount", "currency", "expiry_ms", "n", "e"}
        assert key["currency"] == "INR"
        assert int(key["e"], 16) == 65537
        assert int(key["n"], 16).bit_length() == 2048


def test_mint_keys_never_exposes_the_private_exponent(client):
    """The single most damaging possible leak from this endpoint."""
    raw = client.get("/mint/keys").text
    body = client.get("/mint/keys").json()
    for key in body["keys"]:
        assert "d" not in key
    assert '"d"' not in raw


def test_mint_keys_is_stable_across_calls(client):
    first = client.get("/mint/keys").json()
    second = client.get("/mint/keys").json()
    assert first == second, "the client pins mint_pub; it must not move"


# ---------------------------------------------------------------------------
# POST /mint/registerDevice
# ---------------------------------------------------------------------------


def test_register_issues_a_credential_the_client_can_verify(client):
    mint_pub, _ = get_keys(client)
    wallet = Wallet()
    response = wallet.register(client)

    assert response.status_code == 200
    cred = response.json()["credential"]
    assert set(cred) == {"cred_id", "device_pub", "c0", "expiry_ms", "mint_sig"}
    assert cred["device_pub"] == wallet.device_pub
    assert cred["c0"] == wallet.c0, "the mint must echo the client's own spelling"

    # Verified with `cryptography`, not the Rust core, so this is a genuine
    # cross-implementation check of the BCCRED format.
    message = (
        f"BCCRED|v1|{cred['cred_id']}|{cred['device_pub']}|{cred['c0']}|{cred['expiry_ms']}"
    ).encode()
    ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(mint_pub)).verify(
        bytes.fromhex(cred["mint_sig"]), message
    )


def test_register_rejects_a_bad_signature(client):
    wallet = Wallet()
    response = client.post(
        "/mint/registerDevice", json=wallet.register_body(sig="00" * 64)
    )
    assert response.status_code == 400
    assert "signature" in response.text.lower()


def test_register_rejects_a_signature_over_the_wrong_message(client):
    wallet = Wallet()
    body = wallet.register_body()
    body["ts"] = body["ts"] + 1  # signature no longer matches the string
    assert client.post("/mint/registerDevice", json=body).status_code == 400


@pytest.mark.parametrize("bad_c0", ["00", "01", "02"])
def test_register_rejects_non_subgroup_commitments(client, bad_c0):
    """c0 must be a quadratic residue with 2 <= c0 <= P-2 (contract line 50)."""
    wallet = Wallet()
    wallet.c0 = bad_c0
    response = client.post("/mint/registerDevice", json=wallet.register_body())
    if bad_c0 == "02" and bc.is_element(2):
        pytest.skip("2 happens to be a subgroup element in this group")
    assert response.status_code == 400
    assert "commitment" in response.text.lower()


def test_register_rejects_c0_at_the_boundary(client):
    wallet = Wallet()
    wallet.c0 = _hex(bc.group_p() - 1)
    assert client.post("/mint/registerDevice", json=wallet.register_body()).status_code == 400


@pytest.mark.parametrize("bad", ["", "zz", "0x0a", " 0a"])
def test_register_rejects_malformed_hex(client, bad):
    wallet = Wallet()
    response = client.post("/mint/registerDevice", json=wallet.register_body(c0=bad))
    assert response.status_code == 400


def test_register_rejects_unknown_fields(client):
    wallet = Wallet()
    body = wallet.register_body()
    body["unexpected"] = "x"
    assert client.post("/mint/registerDevice", json=body).status_code == 422


def test_register_stores_but_does_not_verify_the_integrity_token(client, configured):
    from sqlalchemy import select

    from app.db.models import Device
    from app.db.session import session_scope

    wallet = Wallet()
    wallet.register(client, integrity_token="opaque-play-integrity-token")

    with session_scope() as session:
        device = session.scalars(select(Device)).one()
        assert device.integrity_token == "opaque-play-integrity-token"
        assert device.integrity_verified is False, (
            "storing a token must never imply it was checked"
        )


def test_each_registration_gets_a_distinct_credential(client):
    a, b = Wallet(), Wallet()
    a.register(client)
    b.register(client)
    assert a.credential["cred_id"] != b.credential["cred_id"]


# ---------------------------------------------------------------------------
# POST /mint/issue
# ---------------------------------------------------------------------------


def test_issue_returns_a_signature_that_unblinds_and_verifies(client):
    """The core blind-signature property, end to end."""
    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    response = client.post("/mint/issue", json=wallet.issue_body(key))
    assert response.status_code == 200, response.text
    body = response.json()

    sig = bc.unblind(int(body["blind_sig"], 16), wallet.last["r"], wallet.last["n"])
    assert bc.blind_verify(wallet.last["msg"], sig, wallet.last["n"], wallet.last["e"]), (
        "the unblinded signature must verify against the original token message"
    )


def test_issue_returns_a_verifiable_inclusion_proof(client):
    """The client refuses a token whose proof does not check out (line 61)."""
    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    body = client.post("/mint/issue", json=wallet.issue_body(key)).json()

    leaf = _expected_leaf(wallet, body)
    assert bc.merkle_verify_inclusion(
        leaf,
        body["leaf_index"],
        body["tree_size"],
        [bytes.fromhex(p) for p in body["proof"]],
        bytes.fromhex(body["root"]),
    )


def _expected_leaf(wallet: Wallet, issue_body: dict) -> bytes:
    """SHA256(blinded || blind_sig), the leaf the mint should have appended."""
    import hashlib

    blinded_hex = _hex(
        (bc.fdh(wallet.last["msg"], wallet.last["n"]) * pow(wallet.last["r"], wallet.last["e"], wallet.last["n"]))
        % wallet.last["n"]
    )
    return hashlib.sha256(
        bytes.fromhex(blinded_hex) + bytes.fromhex(issue_body["blind_sig"])
    ).digest()


def test_issue_appends_dense_leaf_indices(client):
    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    indices, sizes = [], []
    for _ in range(5):
        body = client.post("/mint/issue", json=wallet.issue_body(key)).json()
        indices.append(body["leaf_index"])
        sizes.append(body["tree_size"])

    assert indices == [0, 1, 2, 3, 4]
    assert sizes == [1, 2, 3, 4, 5]


def test_issue_proof_verifies_for_every_leaf_in_a_growing_tree(client):
    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    leaves = []
    for _ in range(6):
        body = client.post("/mint/issue", json=wallet.issue_body(key)).json()
        leaves.append(_expected_leaf(wallet, body))
        root = bytes.fromhex(body["root"])
        # Every earlier leaf must still prove against the new root.
        for index, leaf in enumerate(leaves):
            proof = bc.merkle_proof(leaves, index)
            assert bc.merkle_verify_inclusion(leaf, index, len(leaves), proof, root)


def test_issue_rejects_an_unknown_credential(client):
    _, keys = get_keys(client)
    wallet = Wallet()
    wallet.register(client)
    body = wallet.issue_body(pick(keys))
    body["cred_id"] = "does-not-exist"

    response = client.post("/mint/issue", json=body)
    assert response.status_code == 403
    assert "not registered" in response.text.lower()


def test_issue_rejects_a_revoked_credential(client, configured):
    from app.db.models import Revocation
    from app.db.session import session_scope

    _, keys = get_keys(client)
    wallet = Wallet()
    wallet.register(client)

    with session_scope() as session:
        session.add(
            Revocation(cred_id=wallet.credential["cred_id"], reason="test", ts=1)
        )

    response = client.post("/mint/issue", json=wallet.issue_body(pick(keys)))
    assert response.status_code == 403
    assert "revoked" in response.text.lower()


# ---------------------------------------------------------------------------
# revoked identities cannot register again
# ---------------------------------------------------------------------------
#
# Revocations are keyed by `cred_id`, but `cred_id` is minted fresh on every
# registration. The stable identity is `c0`: it is what a recovered double-spend
# secret opens, and it survives a wallet reset on the client. Without a check at
# registration a revoked payer could reset, register again, and mint as if
# nothing had happened -- the revocation would still exist, pointing at a
# credential nobody uses any more.


def _revoke(cred_id: str, reason: str = "test") -> None:
    """Insert a revocation directly, as `test_issue_rejects_a_revoked_credential` does."""
    from app.db.models import Revocation
    from app.db.session import session_scope

    with session_scope() as session:
        session.add(Revocation(cred_id=cred_id, reason=reason, ts=1))


def _device_count() -> int:
    from sqlalchemy import select

    from app.db.models import Device
    from app.db.session import session_scope

    with session_scope() as session:
        return len(session.scalars(select(Device)).all())


def test_register_rejects_a_revoked_identity(client, configured):
    """The same `c0` registering a second time, after revocation."""
    wallet = Wallet()
    assert wallet.register(client).status_code == 200
    _revoke(wallet.credential["cred_id"])

    # A reset client keeps its keys, so this is byte-for-byte the same request
    # shape it sent the first time.
    response = client.post("/mint/registerDevice", json=wallet.register_body())
    assert response.status_code == 403, response.text
    assert "identity revoked" in response.text.lower()


def test_register_still_works_for_an_unrevoked_identity(client, configured):
    """The guard must not become a blanket refusal."""
    revoked = Wallet()
    revoked.register(client)
    _revoke(revoked.credential["cred_id"])

    innocent = Wallet()
    response = innocent.register(client)
    assert response.status_code == 200, response.text
    assert innocent.credential["cred_id"] != revoked.credential["cred_id"]


def test_a_new_cred_id_cannot_bypass_revocation(client, configured):
    """The refusal must land before a new credential exists to escape through.

    `cred_id` is a fresh uuid4 per registration, so a guard that ran after the
    insert would leave an unrevoked credential for the same identity.
    """
    wallet = Wallet()
    wallet.register(client)
    first_cred = wallet.credential["cred_id"]
    _revoke(first_cred)

    before = _device_count()
    response = client.post("/mint/registerDevice", json=wallet.register_body())
    assert response.status_code == 403
    assert _device_count() == before, "no device row may be created for a revoked identity"
    assert "cred_id" not in response.text


def test_revoked_identity_cannot_mint_after_attempted_reregistration(client, configured):
    """End to end, against a revocation the mint produced itself.

    Uses a real double-spend rather than an inserted row, so the whole path --
    secret recovery, revocation, refused re-registration, refused issuance -- is
    exercised as it runs in production.
    """
    from .test_settlement_api import Payer, build_receipt, settle

    _, keys = get_keys(client)
    key = pick(keys)
    payer = Payer()
    payer.register(client)
    token = payer.mint_token(client, key)

    shop_a, shop_b = Wallet(), Wallet()
    shop_a.register(client)
    shop_b.register(client)

    settle(client, build_receipt(payer, shop_a, token, "ctx-a"))
    second = settle(client, build_receipt(payer, shop_b, token, "ctx-b"))
    assert second["results"][0]["status"] == "FRAUD"

    # Re-registering under the same identity is refused ...
    again = client.post("/mint/registerDevice", json=payer.register_body())
    assert again.status_code == 403
    assert "identity revoked" in again.text.lower()

    # ... and the original credential still cannot mint.
    issue = client.post("/mint/issue", json=payer.issue_body(key))
    assert issue.status_code == 403
    assert "revoked" in issue.text.lower()


def test_canonicalisation_cannot_evade_the_check(client, configured):
    """A different spelling of the same `c0` is the same identity.

    `c0_hex` is stored canonically, so a raw-string comparison would let a
    leading zero through. The signature covers the spelling actually sent, so it
    has to be re-signed for the padded form.
    """
    wallet = Wallet()
    wallet.register(client)
    _revoke(wallet.credential["cred_id"])

    padded = "0" + wallet.c0
    ts = 1_700_000_000_002
    body = wallet.register_body(
        ts=ts,
        c0=padded,
        sig=wallet.sign(f"BCREG|v1|{wallet.device_pub}|{padded}|{ts}"),
    )

    response = client.post("/mint/registerDevice", json=body)
    assert response.status_code == 403, response.text
    assert "identity revoked" in response.text.lower()


def test_issue_rejects_a_bad_signature(client):
    _, keys = get_keys(client)
    wallet = Wallet()
    wallet.register(client)
    response = client.post(
        "/mint/issue", json=wallet.issue_body(pick(keys), sig="00" * 64)
    )
    assert response.status_code == 400
    assert "signature" in response.text.lower()


def test_issue_rejects_a_mismatched_c0(client):
    """c0 must equal the registered one (contract line 56)."""
    _, keys = get_keys(client)
    wallet = Wallet()
    wallet.register(client)

    other = Wallet()
    body = wallet.issue_body(pick(keys))
    body["c0"] = other.c0
    body["sig"] = wallet.sign(
        f"BCISSUE|v1|{body['cred_id']}|{body['key_id']}|{body['blinded']}|{other.c0}|{body['ts']}"
    )

    response = client.post("/mint/issue", json=body)
    assert response.status_code == 400
    assert "commitment" in response.text.lower()


def test_issue_accepts_an_equivalent_c0_spelling(client):
    """c0 is compared numerically, so leading zeros must not matter (line 35)."""
    _, keys = get_keys(client)
    wallet = Wallet()
    wallet.register(client)

    padded = "0000" + wallet.c0
    body = wallet.issue_body(pick(keys), c0=padded)
    body["sig"] = wallet.sign(
        f"BCISSUE|v1|{body['cred_id']}|{body['key_id']}|{body['blinded']}|{padded}|{body['ts']}"
    )
    assert client.post("/mint/issue", json=body).status_code == 200


def test_issue_rejects_an_unknown_key(client):
    _, keys = get_keys(client)
    wallet = Wallet()
    wallet.register(client)
    body = wallet.issue_body(pick(keys))
    body["key_id"] = "no-such-key"
    body["sig"] = wallet.sign(
        f"BCISSUE|v1|{body['cred_id']}|no-such-key|{body['blinded']}|{wallet.c0}|{body['ts']}"
    )

    response = client.post("/mint/issue", json=body)
    assert response.status_code == 400
    assert "unknown key" in response.text.lower()


@pytest.mark.parametrize("bad_blinded", ["00", None])
def test_issue_rejects_blinded_values_outside_the_modulus(client, bad_blinded):
    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    body = wallet.issue_body(key)
    value = bad_blinded if bad_blinded is not None else _hex(int(key["n"], 16))
    body["blinded"] = value
    body["sig"] = wallet.sign(
        f"BCISSUE|v1|{body['cred_id']}|{body['key_id']}|{value}|{wallet.c0}|{body['ts']}"
    )

    response = client.post("/mint/issue", json=body)
    assert response.status_code == 400
    assert "range" in response.text.lower()


def test_issue_stores_no_token_id_or_c1(client, configured):
    """Blinding boundary: the mint must learn neither (contract line 62)."""
    from sqlalchemy import select

    from app.db.models import AuditLeaf
    from app.db.session import session_scope

    _, keys = get_keys(client)
    wallet = Wallet()
    wallet.register(client)
    client.post("/mint/issue", json=wallet.issue_body(pick(keys)))

    with session_scope() as session:
        leaf = session.scalars(select(AuditLeaf)).one()
        stored = {c.name: getattr(leaf, c.name) for c in AuditLeaf.__table__.columns}

    assert "token_id" not in stored and "c1" not in stored
    for value in stored.values():
        assert wallet.last["token_id"] not in str(value)
        assert wallet.last["c1"] not in str(value)


def test_concurrent_issuance_produces_dense_unique_indices(client):
    """Two issuances may read the same MAX(leaf_index); neither may win twice."""
    import threading

    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    bodies = [wallet.issue_body(key) for _ in range(8)]
    results: list[dict] = []
    lock = threading.Lock()

    def worker(payload: dict) -> None:
        response = client.post("/mint/issue", json=payload)
        with lock:
            results.append(
                {"status": response.status_code, "body": response.json() if response.status_code == 200 else None}
            )

    threads = [threading.Thread(target=worker, args=(b,)) for b in bodies]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(r["status"] == 200 for r in results), [r["status"] for r in results]
    indices = sorted(r["body"]["leaf_index"] for r in results)
    assert indices == list(range(len(bodies))), f"indices must be dense and unique: {indices}"


# ---------------------------------------------------------------------------
# GET /audit/root/latest
# ---------------------------------------------------------------------------


def test_audit_root_is_empty_string_before_any_issuance(client):
    """Matches server.py:176; the client reads it with getString."""
    body = client.get("/audit/root/latest").json()
    assert body["root"] == ""
    assert body["tree_size"] == 0
    assert isinstance(body["ts"], int)


def test_audit_root_tracks_issuance(client):
    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    issued = client.post("/mint/issue", json=wallet.issue_body(key)).json()
    latest = client.get("/audit/root/latest").json()

    assert latest["root"] == issued["root"]
    assert latest["tree_size"] == issued["tree_size"] == 1
    assert len(bytes.fromhex(latest["root"])) == 32


def test_audit_root_changes_as_leaves_are_added(client):
    _, keys = get_keys(client)
    key = pick(keys)
    wallet = Wallet()
    wallet.register(client)

    roots = []
    for _ in range(3):
        client.post("/mint/issue", json=wallet.issue_body(key))
        roots.append(client.get("/audit/root/latest").json()["root"])

    assert len(set(roots)) == 3, "each issuance must change the root"


# ---------------------------------------------------------------------------
# persistence across restarts
# ---------------------------------------------------------------------------


def test_mint_identity_and_keys_survive_a_restart(configured):
    """Regenerating mint_pub would brick every wallet that pinned it."""
    from fastapi.testclient import TestClient

    from app.db.session import reset_caches
    from app.main import create_app

    with TestClient(create_app()) as first:
        before = first.get("/mint/keys").json()

    reset_caches()

    with TestClient(create_app()) as second:
        after = second.get("/mint/keys").json()

    assert after["mint_pub"] == before["mint_pub"]
    assert after["keys"] == before["keys"]


def test_credentials_and_audit_log_survive_a_restart(configured):
    from fastapi.testclient import TestClient

    from app.db.session import reset_caches
    from app.main import create_app

    with TestClient(create_app()) as first:
        _, keys = get_keys(first)
        wallet = Wallet()
        wallet.register(first)
        issued = first.post("/mint/issue", json=wallet.issue_body(pick(keys))).json()
        cred_id = wallet.credential["cred_id"]

    reset_caches()

    with TestClient(create_app()) as second:
        latest = second.get("/audit/root/latest").json()
        assert latest["root"] == issued["root"]
        assert latest["tree_size"] == 1

        # The credential still works, so issuance continues from index 1.
        wallet.credential["cred_id"] = cred_id
        _, keys2 = get_keys(second)
        again = second.post("/mint/issue", json=wallet.issue_body(pick(keys2))).json()
        assert again["leaf_index"] == 1


def test_no_real_database_is_created(configured, tmp_path):
    from pathlib import Path

    assert tmp_path.as_posix() in configured
    assert not (Path(__file__).resolve().parents[1] / "bluecash.db").exists()
