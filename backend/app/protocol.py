"""
Protocol message formats and crypto calls.

Every cryptographic operation here is performed by the shared Rust core through
its PyO3 bindings (`bluecash_crypto`), so the backend and the Android client run
the same implementation. The one exception is RSA **key generation**, which the
bindings do not expose — see `mint_keys.py`.

# Signed strings

`API_CONTRACT.md` lines 26-34 fix these exactly: UTF-8, `|`-separated, no
whitespace. They are reproduced in `Models.kt` (`object Msg`) and in
`server.py`.

A subtlety that matters more than it looks: these strings embed the hex fields
**exactly as the client sent them**, not a canonicalised form. The client signed
the bytes it built, so re-encoding `c0` from `"000a"` to `"0a"` before verifying
would break an otherwise valid signature. Canonicalisation is for storage and
comparison only — never for signature input.
"""

from __future__ import annotations

import bluecash_crypto as bc

from .codec import bytes_to_hex, hex_to_bytes, hex_to_int, int_to_hex

__all__ = [
    "msg_register",
    "msg_credential",
    "msg_issue",
    "msg_token",
    "msg_spend",
    "msg_receipt",
    "verify_device_signature",
    "mint_sign",
    "mint_public_key",
    "is_subgroup_element",
    "blind_sign",
    "audit_leaf",
    "merkle_root_hex",
    "merkle_proof_hex",
    "EMPTY_ROOT",
]

#: `GET /audit/root/latest` returns an empty string for an empty log, matching
#: `server.py:176`. The crate's `merkle_root` raises on an empty tree rather
#: than inventing a value, so the endpoint special-cases it here.
EMPTY_ROOT = ""


# ---------------------------------------------------------------------------
# signed strings  (API_CONTRACT.md lines 26-34)
# ---------------------------------------------------------------------------


def msg_register(device_pub: str, c0: str, ts: int) -> bytes:
    """`BCREG|v1|{device_pub}|{c0}|{ts}` — signed by the device at registration."""
    return f"BCREG|v1|{device_pub}|{c0}|{ts}".encode()


def msg_credential(cred_id: str, device_pub: str, c0: str, expiry_ms: int) -> bytes:
    """`BCCRED|v1|{cred_id}|{device_pub}|{c0}|{expiry_ms}` — signed by the mint."""
    return f"BCCRED|v1|{cred_id}|{device_pub}|{c0}|{expiry_ms}".encode()


def msg_issue(cred_id: str, key_id: str, blinded: str, c0: str, ts: int) -> bytes:
    """`BCISSUE|v1|{cred_id}|{key_id}|{blinded}|{c0}|{ts}` — signed by the device."""
    return f"BCISSUE|v1|{cred_id}|{key_id}|{blinded}|{c0}|{ts}".encode()


def msg_token(key_id: str, token_id: str, c0: str, c1: str) -> bytes:
    """`BCTOKEN|v1|{key_id}|{token_id}|{c0}|{c1}` — what the mint blind-signs.

    The mint never sees this string: it signs the blinded value instead. Defined
    here for settlement, which verifies the unblinded signature against it.
    """
    return f"BCTOKEN|v1|{key_id}|{token_id}|{c0}|{c1}".encode()


def msg_spend(token_id: str, n_ctx: str, amount: int) -> bytes:
    """`BCSPEND|v1|{token_id}|{n_ctx}|{amount}` — signed by the payer."""
    return f"BCSPEND|v1|{token_id}|{n_ctx}|{amount}".encode()


def msg_receipt(
    receipt_id: str,
    token_id: str,
    n_ctx: str,
    x: str,
    y: str,
    amount: int,
    merchant_id: str,
    timestamp_ms: int,
) -> bytes:
    """`BCRECEIPT|v1|...` — signed by the merchant."""
    return (
        f"BCRECEIPT|v1|{receipt_id}|{token_id}|{n_ctx}|{x}|{y}"
        f"|{amount}|{merchant_id}|{timestamp_ms}"
    ).encode()


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------


def verify_device_signature(device_pub_hex: str, message: bytes, sig_hex: str) -> bool:
    """Verify an Ed25519 signature made by a device.

    Returns `False` on malformed input rather than raising: a bad signature and
    a bad-length key are both "this request is not authentic".
    """
    try:
        pub = hex_to_bytes(device_pub_hex, field="device_pub")
        sig = hex_to_bytes(sig_hex, field="sig")
    except ValueError:
        return False
    return bc.ed25519_verify(pub, message, sig)


def mint_sign(seed_hex: str, message: bytes) -> str:
    """Sign with the mint's Ed25519 identity, returning lowercase hex."""
    return bytes_to_hex(bc.ed25519_sign(hex_to_bytes(seed_hex, field="seed"), message))


def mint_public_key(seed_hex: str) -> str:
    """Derive the mint's public key hex from its seed."""
    return bytes_to_hex(bc.ed25519_public_key(hex_to_bytes(seed_hex, field="seed")))


# ---------------------------------------------------------------------------
# identity commitments
# ---------------------------------------------------------------------------


def is_subgroup_element(c0_hex: str) -> bool:
    """Is `c0` a valid identity commitment?

    `API_CONTRACT.md` line 50 requires `c0` to be a quadratic residue mod P with
    `2 <= c0 <= P-2`. The crate's `is_element` applies exactly that test.
    """
    try:
        return bc.is_element(hex_to_int(c0_hex, field="c0"))
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# blind signing
# ---------------------------------------------------------------------------


def blind_sign(blinded_hex: str, n_hex: str, d_hex: str) -> str:
    """Mint side of the blind signature: `blinded^d mod n`, as canonical hex.

    Raises:
        ValueError: if `blinded` is outside `(0, n)`, which the contract
            requires the mint to reject (line 57).
    """
    blind_sig = bc.sign_blinded(
        hex_to_int(blinded_hex, field="blinded"),
        hex_to_int(n_hex, field="n"),
        hex_to_int(d_hex, field="d"),
    )
    return int_to_hex(blind_sig)


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------


def audit_leaf(blinded_hex: str, blind_sig_hex: str) -> str:
    """The audit leaf for an issuance: `SHA256(blinded_bytes || blind_sig_bytes)`.

    Matches `server.py:168`, including its odd-length accommodation: the client
    may send `blinded` without a leading zero, and the reference pads it before
    hashing. Getting this wrong changes the root and makes the client reject
    every token.

    The result is the raw leaf *data*; `merkle_root_hex` applies the RFC 6962
    `0x00` leaf prefix on top.
    """
    blinded = hex_to_bytes(blinded_hex, field="blinded", pad_odd=True)
    blind_sig = hex_to_bytes(blind_sig_hex, field="blind_sig", pad_odd=True)
    return bytes_to_hex(_sha256(blinded, blind_sig))


def _sha256(*parts: bytes) -> bytes:
    """SHA-256 of the concatenated parts.

    The crate exposes Merkle hashing but not a bare SHA-256, and the audit leaf
    is a plain digest rather than a domain-separated Merkle leaf, so this uses
    hashlib. The Merkle construction itself still goes through the crate.
    """
    import hashlib

    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def merkle_root_hex(leaf_data_hex: list[str]) -> str:
    """The Merkle root over the audit log, as lowercase hex.

    Returns `EMPTY_ROOT` for an empty log, matching `server.py:176`.
    """
    if not leaf_data_hex:
        return EMPTY_ROOT
    leaves = [hex_to_bytes(h, field="leaf") for h in leaf_data_hex]
    return bytes_to_hex(bc.merkle_root(leaves))


def merkle_proof_hex(leaf_data_hex: list[str], index: int) -> list[str]:
    """The inclusion proof for `index`, as a list of lowercase hex hashes."""
    leaves = [hex_to_bytes(h, field="leaf") for h in leaf_data_hex]
    return [bytes_to_hex(p) for p in bc.merkle_proof(leaves, index)]
