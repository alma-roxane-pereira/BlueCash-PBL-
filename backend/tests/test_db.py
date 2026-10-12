"""
Tests for the database layer: schema creation, persistence, and constraints.

Every test uses a temporary SQLite file created under pytest's `tmp_path`, so no
real runtime database is ever written. Nothing here performs cryptography or
generates keys — the hex values are fixtures, not real key material.
"""

from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

from app.config import Settings
from app.db import (
    ALL_MODELS,
    AuditLeaf,
    Balance,
    Device,
    MintIdentity,
    MintKey,
    Revocation,
    SpentToken,
    create_all,
    create_db_engine,
    drop_all,
    session_scope,
)

EXPECTED_TABLES = {
    "mint_identity",
    "mint_keys",
    "devices",
    "revocations",
    "audit_leaves",
    "spent_tokens",
    "balances",
}


@pytest.fixture
def engine(tmp_path):
    """A temporary file-backed SQLite database.

    A file rather than `:memory:` so that persistence across sessions is a real
    property being tested, not an artefact of a shared in-memory connection.
    """
    url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    eng = create_db_engine(Settings(database_url=url))
    create_all(eng)
    yield eng
    eng.dispose()


# ---------------------------------------------------------------------------
# fixtures for rows
# ---------------------------------------------------------------------------


def make_device(session, cred_id="cred-1", c0_hex="0a", device_pub="ab" * 32):
    device = Device(
        cred_id=cred_id,
        device_pub=device_pub,
        c0_hex=c0_hex,
        expiry_ms=1_800_000_000_000,
        mint_sig="cd" * 64,
    )
    session.add(device)
    session.flush()
    return device


def make_key(session, key_id="d100-2027", amount=100):
    key = MintKey(
        key_id=key_id,
        amount=amount,
        currency="INR",
        expiry_ms=1_830_211_200_000,
        n_hex="bb59",
        e_hex="010001",
        d_hex="1629",
    )
    session.add(key)
    session.flush()
    return key


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------


def test_create_all_builds_every_table(engine):
    assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES


def test_all_models_are_exported():
    assert len(ALL_MODELS) == len(EXPECTED_TABLES)
    assert {m.__tablename__ for m in ALL_MODELS} == EXPECTED_TABLES


def test_drop_all_removes_every_table(engine):
    drop_all(engine)
    assert inspect(engine).get_table_names() == []


@pytest.mark.parametrize(
    ("table", "expected"),
    [
        ("devices", {"ix_devices_c0_hex", "ix_devices_device_pub"}),
        (
            "spent_tokens",
            {
                "ix_spent_tokens_receipt_id",
                "ix_spent_tokens_merchant_id",
                "ix_spent_tokens_payer_cred_id",
            },
        ),
        ("audit_leaves", {"ix_audit_leaves_cred_id"}),
        ("revocations", {"ix_revocations_ts"}),
    ],
)
def test_protocol_lookup_indexes_exist(engine, table, expected):
    """Indexes backing the lookups the protocol actually performs."""
    names = {ix["name"] for ix in inspect(engine).get_indexes(table)}
    assert expected <= names


def test_receipt_id_index_is_not_unique(engine):
    """Receipt ids must be indexed but NOT unique.

    Neither reference implementation compares receipt ids across tokens, so a
    unique constraint here would reject a batch both references accept. See the
    comment on SpentToken.__table_args__.
    """
    ix = {i["name"]: i for i in inspect(engine).get_indexes("spent_tokens")}
    assert bool(ix["ix_spent_tokens_receipt_id"]["unique"]) is False


def test_sqlite_enforces_foreign_keys(engine):
    """SQLite ignores FKs unless the pragma is set per connection."""
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


# ---------------------------------------------------------------------------
# persistence across sessions
# ---------------------------------------------------------------------------


def test_rows_persist_across_sessions(engine):
    with session_scope(engine) as s:
        make_key(s)
        make_device(s, cred_id="cred-persist", c0_hex="0abc")

    # A brand new session, so this reads from the file rather than the identity map.
    with session_scope(engine) as s:
        device = s.get(Device, "cred-persist")
        assert device is not None
        assert device.c0_hex == "0abc"
        assert device.integrity_verified is False
        assert device.registered_at is not None


def test_persistence_survives_engine_disposal(engine, tmp_path):
    with session_scope(engine) as s:
        make_device(s, cred_id="cred-reopen")
    engine.dispose()

    reopened = create_db_engine(
        Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    )
    with session_scope(reopened) as s:
        assert s.get(Device, "cred-reopen") is not None
    reopened.dispose()


# ---------------------------------------------------------------------------
# mint identity and keys
# ---------------------------------------------------------------------------


def test_mint_identity_is_a_singleton(engine):
    with session_scope(engine) as s:
        s.add(MintIdentity(id=1, public_key_hex="ab" * 32, ed25519_seed_hex="cd" * 32))

    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(MintIdentity(id=2, public_key_hex="ef" * 32, ed25519_seed_hex="11" * 32))


def test_mint_key_amount_must_be_positive(engine):
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(
                MintKey(
                    key_id="bad",
                    amount=0,
                    currency="INR",
                    expiry_ms=1,
                    n_hex="00",
                    e_hex="010001",
                    d_hex="00",
                )
            )


def test_mint_key_id_is_unique(engine):
    with session_scope(engine) as s:
        make_key(s, key_id="d100-2027")
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            make_key(s, key_id="d100-2027")


def test_mint_keys_default_to_active(engine):
    with session_scope(engine) as s:
        key = make_key(s)
        assert key.active is True


# ---------------------------------------------------------------------------
# devices
# ---------------------------------------------------------------------------


def test_device_lookup_by_c0_is_the_fraud_recovery_path(engine):
    """Settlement recovers g^a0 and finds the credential whose c0 matches."""
    with session_scope(engine) as s:
        make_device(s, cred_id="cred-a", c0_hex="0a", device_pub="11" * 32)
        make_device(s, cred_id="cred-b", c0_hex="0b", device_pub="22" * 32)

    with session_scope(engine) as s:
        found = s.scalars(select(Device).where(Device.c0_hex == "0b")).all()
        assert [d.cred_id for d in found] == ["cred-b"]


def test_duplicate_c0_is_allowed(engine):
    """Two devices may commit to the same secret; the reference takes the first."""
    with session_scope(engine) as s:
        make_device(s, cred_id="cred-1", c0_hex="0a", device_pub="11" * 32)
        make_device(s, cred_id="cred-2", c0_hex="0a", device_pub="22" * 32)

    with session_scope(engine) as s:
        assert len(s.scalars(select(Device).where(Device.c0_hex == "0a")).all()) == 2


def test_cred_id_is_unique(engine):
    with session_scope(engine) as s:
        make_device(s, cred_id="dup")
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            make_device(s, cred_id="dup")


def test_integrity_token_is_optional_and_never_pre_verified(engine):
    with session_scope(engine) as s:
        plain = make_device(s, cred_id="no-token")
        with_token = Device(
            cred_id="with-token",
            device_pub="33" * 32,
            c0_hex="0c",
            expiry_ms=1,
            mint_sig="00" * 64,
            integrity_token="opaque-token",
        )
        s.add(with_token)
        s.flush()
        assert plain.integrity_token is None
        assert with_token.integrity_token == "opaque-token"
        # Storing a token must never imply it was checked.
        assert with_token.integrity_verified is False


# ---------------------------------------------------------------------------
# revocations
# ---------------------------------------------------------------------------


def test_revocation_requires_an_existing_device(engine):
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(Revocation(cred_id="ghost", reason="double-spend", ts=1))


def test_revocation_is_one_per_credential(engine):
    with session_scope(engine) as s:
        make_device(s, cred_id="cheat")
        s.add(Revocation(cred_id="cheat", reason="double-spend", ts=1))

    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(Revocation(cred_id="cheat", reason="again", ts=2))


def test_revocation_relationship_round_trips(engine):
    with session_scope(engine) as s:
        make_device(s, cred_id="cheat2")
        s.add(Revocation(cred_id="cheat2", reason="double-spend of token abc", ts=1700))

    with session_scope(engine) as s:
        device = s.get(Device, "cheat2")
        assert device.revocation is not None
        assert device.revocation.reason.startswith("double-spend")
        assert device.revocation.ts == 1700


def test_device_without_revocation_reads_as_none(engine):
    with session_scope(engine) as s:
        make_device(s, cred_id="honest")
    with session_scope(engine) as s:
        assert s.get(Device, "honest").revocation is None


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------


def test_audit_leaves_are_dense_and_ordered(engine):
    """leaf_index is a position in the tree, so it must be gapless from 0."""
    with session_scope(engine) as s:
        make_key(s)
        make_device(s, cred_id="issuer")
        for i in range(5):
            s.add(
                AuditLeaf(
                    leaf_index=i,
                    leaf_hash=f"{i:064x}",
                    cred_id="issuer",
                    key_id="d100-2027",
                )
            )

    with session_scope(engine) as s:
        rows = s.scalars(select(AuditLeaf).order_by(AuditLeaf.leaf_index)).all()
        assert [r.leaf_index for r in rows] == [0, 1, 2, 3, 4]


def test_audit_leaf_index_is_unique(engine):
    with session_scope(engine) as s:
        make_key(s)
        make_device(s, cred_id="issuer")
        s.add(AuditLeaf(leaf_index=0, leaf_hash="aa" * 32, cred_id="issuer", key_id="d100-2027"))

    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(
                AuditLeaf(leaf_index=0, leaf_hash="bb" * 32, cred_id="issuer", key_id="d100-2027")
            )


def test_audit_leaf_hash_is_unique(engine):
    with session_scope(engine) as s:
        make_key(s)
        make_device(s, cred_id="issuer")
        s.add(AuditLeaf(leaf_index=0, leaf_hash="aa" * 32, cred_id="issuer", key_id="d100-2027"))

    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(
                AuditLeaf(leaf_index=1, leaf_hash="aa" * 32, cred_id="issuer", key_id="d100-2027")
            )


def test_audit_leaf_requires_known_credential_and_key(engine):
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(AuditLeaf(leaf_index=0, leaf_hash="aa" * 32, cred_id="ghost", key_id="ghost"))


def test_audit_leaf_index_cannot_be_negative(engine):
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            make_key(s)
            make_device(s, cred_id="issuer")
            s.add(
                AuditLeaf(leaf_index=-1, leaf_hash="aa" * 32, cred_id="issuer", key_id="d100-2027")
            )


def test_audit_log_stores_no_token_id_or_c1(engine):
    """Blinding means the mint never learns these (API_CONTRACT.md line 62)."""
    columns = {c.name for c in AuditLeaf.__table__.columns}
    assert "token_id" not in columns
    assert "c1" not in columns and "c1_hex" not in columns


# ---------------------------------------------------------------------------
# spent tokens
# ---------------------------------------------------------------------------


def _spend(token_id="tok-1", receipt_id="r-1", x="0a", y="0b"):
    return SpentToken(
        token_id=token_id,
        receipt_id=receipt_id,
        x_hex=x,
        y_hex=y,
        n_ctx="ctx-shop-a",
        amount=100,
        merchant_id="merchant-1",
        payer_cred_id="cred-1",
        timestamp_ms=1_700_000_000_000,
    )


def test_spent_token_is_keyed_by_token_id(engine):
    """A second spend of the same token must collide, whoever uploads it."""
    with session_scope(engine) as s:
        s.add(_spend())

    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(_spend(receipt_id="r-2"))


def test_receipt_id_may_repeat_across_tokens(engine):
    """Matches the reference: spent state is keyed by token_id alone."""
    with session_scope(engine) as s:
        s.add(_spend(token_id="tok-1", receipt_id="r-1"))
    with session_scope(engine) as s:
        s.add(_spend(token_id="tok-2", receipt_id="r-1"))

    with session_scope(engine) as s:
        rows = s.scalars(select(SpentToken).where(SpentToken.receipt_id == "r-1")).all()
        assert {r.token_id for r in rows} == {"tok-1", "tok-2"}


def test_spent_token_keeps_the_share_point_for_recovery(engine):
    """The stored (x, y) is one of the two points that recovers a0."""
    with session_scope(engine) as s:
        s.add(_spend(x="1f", y="2e"))

    with session_scope(engine) as s:
        row = s.get(SpentToken, "tok-1")
        assert (row.x_hex, row.y_hex) == ("1f", "2e")
        assert row.receipt_id == "r-1"


def test_spent_token_amount_must_be_positive(engine):
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            spend = _spend()
            spend.amount = 0
            s.add(spend)


# ---------------------------------------------------------------------------
# balances
# ---------------------------------------------------------------------------


def test_balance_is_keyed_by_ref_kind_and_currency(engine):
    with session_scope(engine) as s:
        s.add(Balance(account_ref="a", kind="device", currency="INR", amount=100))
        s.add(Balance(account_ref="a", kind="merchant", currency="INR", amount=50))
        s.add(Balance(account_ref="a", kind="device", currency="USD", amount=7))

    with session_scope(engine) as s:
        assert len(s.scalars(select(Balance)).all()) == 3


def test_duplicate_balance_key_is_rejected(engine):
    with session_scope(engine) as s:
        s.add(Balance(account_ref="a", kind="device", currency="INR", amount=1))
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(Balance(account_ref="a", kind="device", currency="INR", amount=2))


def test_balance_kind_is_constrained(engine):
    with pytest.raises(IntegrityError):
        with session_scope(engine) as s:
            s.add(Balance(account_ref="a", kind="nonsense", currency="INR", amount=1))


def test_balance_may_go_negative(engine):
    """No constraint forbids it: an overdrawn account is a real state the
    reconciliation job needs to see rather than fail to write."""
    with session_scope(engine) as s:
        s.add(Balance(account_ref="a", kind="device", currency="INR", amount=-5))
    with session_scope(engine) as s:
        assert s.get(Balance, ("a", "device", "INR")).amount == -5


# ---------------------------------------------------------------------------
# isolation
# ---------------------------------------------------------------------------


def test_tests_never_touch_a_real_database(engine, tmp_path):
    """Every fixture database lives under tmp_path."""
    url = str(engine.url)
    assert str(tmp_path.as_posix()) in url
    assert "bluecash.db" not in url


def test_session_scope_rolls_back_on_error(engine):
    with pytest.raises(RuntimeError):
        with session_scope(engine) as s:
            make_device(s, cred_id="doomed")
            raise RuntimeError("boom")

    with session_scope(engine) as s:
        assert s.get(Device, "doomed") is None


def test_sqlite_version_is_recent_enough():
    assert sqlite3.sqlite_version_info >= (3, 35), "needs modern SQLite"
