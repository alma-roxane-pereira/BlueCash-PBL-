"""
Mint key bootstrap.

The mint needs one Ed25519 identity and one RSA keypair per denomination. Both
are generated once and then persisted, because `API_CONTRACT.md` lines 46-47
say the client **pins** `mint_pub` on first contact and refuses a mint whose key
later changes. Regenerating on restart would brick every wallet that has already
registered, and would invalidate every token already in circulation.

# Why `cryptography` appears here

RSA **key generation** is the one operation the `bluecash_crypto` bindings do
not expose, so it uses `cryptography` — exactly as the reference server does
(`server.py:82`). This is key generation, not a protocol operation: every
cryptographic step the protocol actually specifies (blind signing, Ed25519
signing and verification, subgroup tests, Merkle hashing) goes through the Rust
core. Flagged here so the exception is visible rather than buried.

SECURITY: the generated private exponents and the Ed25519 seed are written to
the database. In a real deployment they belong in an HSM or KMS; the proposal's
threat model assumes that. Nothing here ever returns them to a caller.
"""

from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.orm import Session

import bluecash_crypto as bc

from .codec import bytes_to_hex, int_to_hex
from .db.models import MintIdentity, MintKey

#: Denominations the mint issues, in the contract's currency.
DEFAULT_DENOMINATIONS: tuple[int, ...] = (10, 50, 100, 500)
DEFAULT_CURRENCY = "INR"

#: `API_CONTRACT.md` line 15 fixes RSA-2048 with e = 65537.
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537

#: The reference gives denomination keys a one-year life (`server.py:79`).
KEY_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000

#: Credentials last 180 days (`server.py:150`).
CREDENTIAL_LIFETIME_MS = 180 * 24 * 60 * 60 * 1000


def now_ms() -> int:
    """Current time in epoch milliseconds, the protocol's unit."""
    return int(time.time() * 1000)


def get_or_create_identity(session: Session) -> MintIdentity:
    """Load the mint's Ed25519 identity, generating it on first run.

    The seed comes from the Rust core's OS randomness.
    """
    identity = session.get(MintIdentity, 1)
    if identity is not None:
        return identity

    seed_hex = bytes_to_hex(bc.ed25519_generate_seed())
    identity = MintIdentity(
        id=1,
        ed25519_seed_hex=seed_hex,
        public_key_hex=bytes_to_hex(
            bc.ed25519_public_key(bytes.fromhex(seed_hex))
        ),
    )
    session.add(identity)
    session.flush()
    return identity


def _generate_rsa_key(key_id: str, amount: int, currency: str, expiry_ms: int) -> MintKey:
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )
    numbers = private_key.private_numbers()
    return MintKey(
        key_id=key_id,
        amount=amount,
        currency=currency,
        expiry_ms=expiry_ms,
        n_hex=int_to_hex(numbers.public_numbers.n),
        e_hex=int_to_hex(numbers.public_numbers.e),
        d_hex=int_to_hex(numbers.d),
        active=True,
    )


def get_or_create_denominations(
    session: Session,
    denominations: tuple[int, ...] = DEFAULT_DENOMINATIONS,
    currency: str = DEFAULT_CURRENCY,
    expiry_ms: int | None = None,
) -> list[MintKey]:
    """Load the denomination keys, generating any that are missing.

    Key ids follow the contract's example form, `d{amount}-{year}`
    (`API_CONTRACT.md` line 42).

    Generating four 2048-bit RSA keys takes a few seconds, which is why this
    runs once at startup rather than per request.
    """
    expiry_ms = expiry_ms if expiry_ms is not None else now_ms() + KEY_LIFETIME_MS
    year = time.gmtime(expiry_ms / 1000).tm_year

    existing = {k.amount: k for k in session.scalars(select(MintKey)).all()}
    keys: list[MintKey] = []

    for amount in denominations:
        key = existing.get(amount)
        if key is None:
            key = _generate_rsa_key(f"d{amount}-{year}", amount, currency, expiry_ms)
            session.add(key)
            session.flush()
        keys.append(key)

    return keys


def bootstrap(session: Session) -> tuple[MintIdentity, list[MintKey]]:
    """Ensure the mint has an identity and its denomination keys.

    Idempotent: safe to call on every startup.
    """
    identity = get_or_create_identity(session)
    keys = get_or_create_denominations(session)
    return identity, keys
