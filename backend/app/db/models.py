"""
Database schema for the BlueCash mint.

Each table exists to satisfy a specific requirement in `API_CONTRACT.md`; the
docstrings cite which. Nothing here adds protocol behaviour the contract does
not call for.

# Conventions

* **Epoch milliseconds** (`*_ms`) are the protocol's own time unit and are
  stored as `BigInteger`, exactly as they arrive on the wire. Separate
  `created_at` columns hold server-side wall-clock time for operations; the two
  are not interchangeable.
* **Hex columns** store the canonical form produced by `codec.int_to_hex`
  (even-length lowercase). Canonicalising on write means a database index can be
  used for lookups while still honouring the contract's rule that these fields
  compare numerically — `"0a"`, `"A"` and `"000a"` all normalise to `"0a"`.
* **Types** are chosen to be PostgreSQL-compatible so the move off SQLite is a
  URL change.

# Secret material

`MintIdentity.ed25519_seed_hex` and `MintKey.d_hex` are private keys. They live
here because the mint must sign with them. In a real deployment they belong in
an HSM or a KMS, as the proposal's threat model assumes — see the module-level
warning on each. No model exposes them through a serialiser; the API layer
selects columns explicitly.
"""

from __future__ import annotations

import datetime as _dt

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for every mint table."""


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


# ---------------------------------------------------------------------------
# Mint keys
# ---------------------------------------------------------------------------


class MintIdentity(Base):
    """The mint's Ed25519 signing identity — the `mint_pub` of `GET /mint/keys`.

    A single row (`id = 1`). The contract says the client **pins** `mint_pub` on
    first contact and refuses a mint whose key later changes
    (`API_CONTRACT.md` lines 46-47), so this must survive restarts: regenerating
    it bricks every wallet that has already registered.

    SECURITY: `ed25519_seed_hex` is a private key.
    """

    __tablename__ = "mint_identity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    public_key_hex: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    ed25519_seed_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("id = 1", name="ck_mint_identity_singleton"),
    )


class MintKey(Base):
    """One RSA denomination key, as listed by `GET /mint/keys` (lines 39-47).

    `key_id` fixes amount, currency and expiry — the contract requires a token's
    amount/expiry/currency to match its key at settlement (line 73), so these
    are authoritative here rather than taken from the token.

    SECURITY: `d_hex` is the private exponent. It must never reach a response;
    `server.py:143` filters it, and so must we.
    """

    __tablename__ = "mint_keys"

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(8), nullable=False, default="INR")
    expiry_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)

    n_hex: Mapped[str] = mapped_column(Text, nullable=False)
    e_hex: Mapped[str] = mapped_column(String(16), nullable=False)
    d_hex: Mapped[str] = mapped_column(Text, nullable=False)

    # Lets a denomination be withdrawn without deleting the key, so tokens
    # already in circulation still verify at settlement.
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("amount > 0", name="ck_mint_keys_amount_positive"),
        Index("ix_mint_keys_active", "active"),
    )


# ---------------------------------------------------------------------------
# Devices and credentials
# ---------------------------------------------------------------------------


class Device(Base):
    """A registered device credential, issued by `POST /mint/registerDevice`.

    The contract is explicit about why this row exists (line 52):

    > Remember `cred_id -> (device_pub, c0)`: this is how a recovered secret is
    > mapped to a person.

    `c0_hex` is therefore indexed: double-spend recovery computes `g^a0` and
    looks up the credential whose `c0` matches (`server.py:203`).

    PRIVACY: this table is deliberately linkable. It is what makes a
    double-spender identifiable, and it is also why honest spends are *not*
    anonymous in the shipped design — the BBS+ credential that would have given
    unlinkability is not implemented. Recorded here so the limitation is visible
    in the schema rather than only in prose.
    """

    __tablename__ = "devices"

    cred_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_pub: Mapped[str] = mapped_column(String(64), nullable=False)
    c0_hex: Mapped[str] = mapped_column(Text, nullable=False)
    expiry_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mint_sig: Mapped[str] = mapped_column(String(128), nullable=False)

    # Accepted and stored, never treated as proof of anything: real Play
    # Integrity verification needs Google's API. `integrity_verified` stays
    # false until that is actually implemented.
    integrity_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    integrity_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    registered_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    revocation: Mapped["Revocation | None"] = relationship(
        back_populates="device", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Not unique: two devices could in principle commit to the same secret,
        # and `server.py:203` takes the first match rather than erroring.
        Index("ix_devices_c0_hex", "c0_hex"),
        Index("ix_devices_device_pub", "device_pub"),
    )


class Revocation(Base):
    """A revoked credential, as served by `GET /fraud/revocations` (lines 92-94).

    Written when settlement recovers an identity secret from two spends of one
    token (lines 82-85). One row per credential: revocation is terminal, so the
    primary key doubles as the uniqueness constraint.
    """

    __tablename__ = "revocations"

    cred_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("devices.cred_id", ondelete="CASCADE"), primary_key=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)

    device: Mapped[Device] = relationship(back_populates="revocation")

    __table_args__ = (Index("ix_revocations_ts", "ts"),)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class AuditLeaf(Base):
    """One leaf of the public Merkle audit log, appended by `POST /mint/issue`.

    The leaf is `SHA256(blinded_bytes || blind_sig_bytes)` (lines 57-60,
    `server.py:168`). `leaf_index` is the position in the tree and is what the
    endpoint returns alongside `tree_size`, so it must be a dense, gapless,
    append-only sequence starting at 0 — the inclusion proof is computed from
    position.

    BLINDING: this table holds no `token_id` and no `c1`. The mint never sees
    them (line 62), which is what makes issuance unlinkable from settlement.
    `cred_id` records *who asked for* an issuance, which the mint already
    authenticated and needs in order to debit the account; it does not reveal
    *which token* resulted.
    """

    __tablename__ = "audit_leaves"

    leaf_index: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    leaf_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    cred_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("devices.cred_id", ondelete="RESTRICT"), nullable=False
    )
    key_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("mint_keys.key_id", ondelete="RESTRICT"), nullable=False
    )

    issued_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("leaf_index >= 0", name="ck_audit_leaves_index_non_negative"),
        Index("ix_audit_leaves_cred_id", "cred_id"),
    )


# ---------------------------------------------------------------------------
# Settlement
# ---------------------------------------------------------------------------


class SpentToken(Base):
    """The first settled spend of a token, per `POST /settlement/uploadBatch`.

    The contract's dispositions (lines 79-85) are decided entirely from this
    row:

    * no row -> `ACCEPTED`; store `(receipt_id, x, y)`
    * same `receipt_id` -> `DUPLICATE`, idempotent and harmless
    * different `receipt_id` -> `FRAUD`; the stored `(x, y)` and the incoming
      one are the two points that recover the payer's identity secret

    Keyed by `token_id`, so a second spend of the same token always collides
    here regardless of which merchant uploads it.
    """

    __tablename__ = "spent_tokens"

    token_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    receipt_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # The revealed share point. Kept as canonical hex: these are protocol
    # integers, and recovery compares and inverts them numerically.
    x_hex: Mapped[str] = mapped_column(Text, nullable=False)
    y_hex: Mapped[str] = mapped_column(Text, nullable=False)

    n_ctx: Mapped[str] = mapped_column(Text, nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payer_cred_id: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)

    settled_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("amount > 0", name="ck_spent_tokens_amount_positive"),
        # Indexed for the duplicate check, but deliberately NOT unique.
        #
        # An earlier revision made this unique, reasoning that a receipt id
        # identifies one spend. Neither reference implementation agrees:
        # `server.py:190-192` and `SimulatedMint.kt:87-92` both key spent state
        # by `token_id` alone and never compare receipt ids across tokens. Under
        # the unique constraint, a merchant reusing one receipt id for two
        # different tokens got INVALID here and ACCEPTED from both references —
        # and because `Wallet.kt:242` only clears a receipt on
        # ACCEPTED/DUPLICATE/FRAUD, that receipt would have been retried forever.
        #
        # Duplicate protection comes from `token_id` being the primary key, which
        # is what the contract actually specifies (lines 79-85).
        Index("ix_spent_tokens_receipt_id", "receipt_id"),
        Index("ix_spent_tokens_merchant_id", "merchant_id"),
        Index("ix_spent_tokens_payer_cred_id", "payer_cred_id"),
    )


# ---------------------------------------------------------------------------
# Balances
# ---------------------------------------------------------------------------


class Balance(Base):
    """Account balances for the contract's "debit the account" (line 59) and
    "credit the merchant" (line 80).

    The contract defines no balance endpoint and the Android client never reads
    one (`HttpMintApi.kt` has no such call), so this is bookkeeping for the
    mint's own records and the audit story — not a protocol surface.

    `account_ref` is a credential id for a device and the receipt's
    `merchant_id` for a merchant. The contract does not require those to be the
    same namespace, so `kind` disambiguates rather than assuming they are.
    Amounts are whole currency units, matching the contract's integer `amount`.
    """

    __tablename__ = "balances"

    account_ref: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    currency: Mapped[str] = mapped_column(String(8), primary_key=True, default="INR")

    amount: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
    )

    __table_args__ = (
        CheckConstraint("kind IN ('device', 'merchant')", name="ck_balances_kind"),
        Index("ix_balances_kind", "kind"),
    )


#: Every model, in dependency order — handy for tests and for truncation.
ALL_MODELS = (
    MintIdentity,
    MintKey,
    Device,
    Revocation,
    AuditLeaf,
    SpentToken,
    Balance,
)
