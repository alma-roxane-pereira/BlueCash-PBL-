"""
Settlement and fraud endpoints.

* `POST /settlement/uploadBatch` (`API_CONTRACT.md` lines 67-91)
* `GET  /fraud/revocations`      (lines 92-94)

This is where the protocol's central security claim is enforced: a token spent
once reveals one point of the payer's identity line, which says nothing; spent
twice it reveals two, which determine the line and expose the payer. Everything
below exists to make that work without trusting anyone.

# Validation order

The checks run in the contract's order (lines 71-78), which is also
`verify_receipt`'s order in `server.py:120-135`. Order is observable: a receipt
failing several checks reports the first one, and the Android tests assert on
those strings. The `detail` values here match the reference verbatim.

# Status codes

A failed receipt is **not** an HTTP error. The contract specifies 200 with a
per-receipt `status` of `ACCEPTED | DUPLICATE | FRAUD | INVALID` (lines 79-90),
so one bad receipt in a batch never discards the good ones. Neither endpoint
here raises `HTTPException` during normal operation; where other endpoints do,
the body is FastAPI's JSON envelope (`{"detail": "..."}`), matching the
reference server, which raises the same exception type.

# Transaction boundary

A batch is one transaction. An unexpected failure part-way through rolls the
whole batch back, so a merchant is never credited for a batch the client was
told had failed -- which would otherwise double-credit on the client's retry,
since `Wallet.kt` re-uploads any receipt it did not see a result for.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import bluecash_crypto as bc

from .. import mint_keys, protocol
from ..codec import CodecError, hex_to_int, int_to_hex
from ..config import Settings, get_settings
from ..db.models import Balance, Device, MintIdentity, MintKey, Revocation, SpentToken
from ..db.session import get_session
from ..schemas import (
    CredentialModel,
    ReceiptModel,
    ReceiptResult,
    RevocationModel,
    RevocationsResponse,
    TokenModel,
    UploadBatchRequest,
    UploadBatchResponse,
)

router = APIRouter(tags=["settlement"])

ACCEPTED = "ACCEPTED"
DUPLICATE = "DUPLICATE"
FRAUD = "FRAUD"
INVALID = "INVALID"


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def _verify_credential(cred: CredentialModel, mint_pub_hex: str, at_ms: int) -> bool:
    """A credential is valid if the mint signed it and it has not expired.

    Uses the credential's own `c0` spelling, because that is what the mint
    signed at registration.
    """
    if cred.expiry_ms <= at_ms:
        return False
    message = protocol.msg_credential(
        cred.cred_id, cred.device_pub, cred.c0, cred.expiry_ms
    )
    return protocol.verify_device_signature(mint_pub_hex, message, cred.mint_sig)


def _verify_token(token: TokenModel, key: MintKey | None, at_ms: int) -> str | None:
    """Validate a token against its denomination key. Returns a detail or None."""
    if token.expiry_ms <= at_ms:
        return "token expired"
    if key is None:
        return "unknown mint key"
    if (key.amount, key.expiry_ms, key.currency) != (
        token.amount,
        token.expiry_ms,
        token.currency,
    ):
        return "token does not match its mint key"

    message = protocol.msg_token(token.key_id, token.token_id, token.c0, token.c1)
    try:
        n = hex_to_int(key.n_hex, field="n")
        e = hex_to_int(key.e_hex, field="e")
        sig = hex_to_int(token.sig, field="sig")
    except CodecError:
        return "invalid mint signature"
    if not bc.blind_verify(message, sig, n, e):
        return "invalid mint signature"

    if not protocol.is_subgroup_element(token.c0) or not protocol.is_subgroup_element(
        token.c1
    ):
        return "invalid commitments"
    return None


def _verify_receipt(
    receipt: ReceiptModel, key: MintKey | None, mint_pub_hex: str
) -> str | None:
    """Run every contract check on one receipt. Returns a detail, or None if valid."""
    at = receipt.timestamp_ms
    token = receipt.token

    if not _verify_credential(receipt.payer_cred, mint_pub_hex, at):
        return "payer credential invalid"
    if not _verify_credential(receipt.merchant_cred, mint_pub_hex, at):
        return "merchant credential invalid"

    if (detail := _verify_token(token, key, at)) is not None:
        return detail

    try:
        c0 = hex_to_int(token.c0, field="c0")
        c1 = hex_to_int(token.c1, field="c1")
        payer_c0 = hex_to_int(receipt.payer_cred.c0, field="payer_cred.c0")
        x = hex_to_int(receipt.x, field="x")
        y = hex_to_int(receipt.y, field="y")
    except CodecError as exc:
        return str(exc)

    # The token must belong to the payer presenting it: compared numerically,
    # per line 35, so an equivalent spelling is still a match.
    if c0 != payer_c0:
        return "token does not belong to this payer"

    # The coordinate must be the one this token and context determine, so a
    # payer cannot choose a point that leaks nothing or reuse one to stay hidden.
    if x != bc.challenge_x(token.token_id, receipt.n_ctx):
        return "wrong share coordinate for this context"

    # g^y == c0 * c1^x (mod P), with 0 <= y < Q. Checked by the Rust core.
    if not bc.verify_share(c0, c1, x, y):
        return "share is not on the committed line"

    if not protocol.verify_device_signature(
        receipt.payer_cred.device_pub,
        protocol.msg_spend(token.token_id, receipt.n_ctx, token.amount),
        receipt.payer_sig,
    ):
        return "bad payer signature"

    if receipt.amount != token.amount:
        return "amount mismatch"

    if not protocol.verify_device_signature(
        receipt.merchant_cred.device_pub,
        protocol.msg_receipt(
            receipt.receipt_id,
            token.token_id,
            receipt.n_ctx,
            receipt.x,
            receipt.y,
            receipt.amount,
            receipt.merchant_id,
            receipt.timestamp_ms,
        ),
        receipt.merchant_sig,
    ):
        return "bad merchant signature"

    return None


# ---------------------------------------------------------------------------
# bookkeeping
# ---------------------------------------------------------------------------


def _credit_merchant(session: Session, merchant_id: str, amount: int, currency: str) -> None:
    """Credit a merchant for an accepted spend.

    Called exactly once per token, inside the same transaction as the
    `SpentToken` insert — so a duplicate or a lost race cannot double-credit.
    """
    key = (merchant_id, "merchant", currency)
    balance = session.get(Balance, key)
    if balance is None:
        session.add(
            Balance(
                account_ref=merchant_id, kind="merchant", currency=currency, amount=amount
            )
        )
    else:
        balance.amount += amount


def _revoke(session: Session, cred_id: str, reason: str) -> bool:
    """Record a revocation, ignoring a credential already revoked."""
    if session.get(Revocation, cred_id) is not None:
        return False
    savepoint = session.begin_nested()
    try:
        session.add(Revocation(cred_id=cred_id, reason=reason, ts=mint_keys.now_ms()))
        savepoint.commit()
        return True
    except IntegrityError:
        savepoint.rollback()
        return False


def _all_revocations(session: Session) -> list[RevocationModel]:
    rows = session.scalars(select(Revocation).order_by(Revocation.ts)).all()
    return [
        RevocationModel(cred_id=r.cred_id, reason=r.reason, ts=r.ts) for r in rows
    ]


# ---------------------------------------------------------------------------
# double-spend recovery
# ---------------------------------------------------------------------------


def _handle_double_spend(
    session: Session, receipt: ReceiptModel, prior: SpentToken
) -> str:
    """Recover the payer's identity from two spends of one token.

    `a1 = (y2-y1)/(x2-x1) mod Q`, then `a0 = y1 - a1*x1 mod Q` (lines 82-84),
    computed by the Rust core.

    A credential is revoked **only** when the recovered secret passes the
    contract's check, `g^a0 == c0`. Without it, a merchant who submitted a
    malformed second point could get an innocent payer revoked. Recovery can
    also legitimately fail — if the coordinates coincide mod Q there is only
    one point and nothing to learn — so the default detail says a double-spend
    was detected without claiming an identity was found.
    """
    detail = "double-spend detected"

    try:
        x1 = hex_to_int(prior.x_hex, field="x1")
        y1 = hex_to_int(prior.y_hex, field="y1")
        x2 = hex_to_int(receipt.x, field="x2")
        y2 = hex_to_int(receipt.y, field="y2")
        c0 = hex_to_int(receipt.token.c0, field="c0")
    except CodecError:
        return detail

    recovered = bc.recover_secret(x1, y1, x2, y2)
    if recovered is None:
        # Same coordinate twice: no new information.
        return detail

    # The recovered secret must actually open the published commitment.
    if bc.commit(recovered) != c0:
        return detail

    cred_id = session.scalar(
        select(Device.cred_id).where(Device.c0_hex == int_to_hex(c0)).limit(1)
    )
    if cred_id is None:
        return detail

    _revoke(session, cred_id, f"double-spend of token {receipt.token.token_id[:12]}")
    return f"double-spend: identity secret recovered, credential {cred_id} revoked"


# ---------------------------------------------------------------------------
# POST /settlement/uploadBatch
# ---------------------------------------------------------------------------


def _settle_one(
    session: Session, receipt: ReceiptModel, key: MintKey | None, mint_pub_hex: str
) -> ReceiptResult:
    """Validate and dispose of a single receipt."""
    detail = _verify_receipt(receipt, key, mint_pub_hex)
    if detail is not None:
        return ReceiptResult(receipt_id=receipt.receipt_id, status=INVALID, detail=detail)

    token_id = receipt.token.token_id
    prior = session.get(SpentToken, token_id)

    if prior is None:
        # First spend. The insert and the credit share one savepoint, so a
        # concurrent settlement of the same token cannot produce two credits.
        savepoint = session.begin_nested()
        try:
            session.add(
                SpentToken(
                    token_id=token_id,
                    receipt_id=receipt.receipt_id,
                    x_hex=int_to_hex(hex_to_int(receipt.x, field="x")),
                    y_hex=int_to_hex(hex_to_int(receipt.y, field="y")),
                    n_ctx=receipt.n_ctx,
                    amount=receipt.amount,
                    merchant_id=receipt.merchant_id,
                    payer_cred_id=receipt.payer_cred.cred_id,
                    timestamp_ms=receipt.timestamp_ms,
                )
            )
            _credit_merchant(
                session, receipt.merchant_id, receipt.amount, receipt.token.currency
            )
            savepoint.commit()
            return ReceiptResult(
                receipt_id=receipt.receipt_id, status=ACCEPTED, detail="settled"
            )
        except IntegrityError:
            savepoint.rollback()
            # The only uniqueness on this table is the `token_id` primary key,
            # so this means a concurrent request settled the same token first.
            # Re-read and fall through to the normal dispositions: the winner's
            # row decides whether this is a DUPLICATE or a double spend.
            session.expire_all()
            prior = session.get(SpentToken, token_id)
            if prior is None:  # pragma: no cover - defensive
                raise

    if prior.receipt_id == receipt.receipt_id:
        # Idempotent: the same receipt uploaded twice is harmless, and must not
        # credit the merchant a second time.
        return ReceiptResult(
            receipt_id=receipt.receipt_id, status=DUPLICATE, detail="already settled"
        )

    return ReceiptResult(
        receipt_id=receipt.receipt_id,
        status=FRAUD,
        detail=_handle_double_spend(session, receipt, prior),
    )


@router.post(
    "/settlement/uploadBatch",
    response_model=UploadBatchResponse,
    summary="Settle a batch of receipts",
)
def upload_batch(
    body: UploadBatchRequest,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> UploadBatchResponse:
    """Settle receipts, detecting double spends.

    An *invalid receipt* is a per-receipt `INVALID` result inside an HTTP 200,
    per the contract, so one bad receipt never discards the good ones around it.
    An *oversized batch* is different: it is a malformed request rather than a
    protocol failure, and it is refused with 413 before any cryptography runs —
    otherwise the rejection would cost exactly the work it exists to avoid.

    `revoked` carries the **full** revocation list, matching `server.py:209` —
    devices use it to refuse anyone on it.
    """
    # Checked first, before the key lookup and before any verification.
    if len(body.receipts) > settings.max_settlement_batch:
        raise HTTPException(
            status_code=413,
            detail=(
                f"batch of {len(body.receipts)} receipts exceeds the maximum of "
                f"{settings.max_settlement_batch}; split it into smaller batches"
            ),
        )

    identity = session.get(MintIdentity, 1)
    mint_pub_hex = identity.public_key_hex if identity else ""

    # Load every key the batch references in one query.
    key_ids = {r.token.key_id for r in body.receipts}
    keys = {
        k.key_id: k
        for k in session.scalars(select(MintKey).where(MintKey.key_id.in_(key_ids))).all()
    }

    results = [
        _settle_one(session, receipt, keys.get(receipt.token.key_id), mint_pub_hex)
        for receipt in body.receipts
    ]

    session.flush()
    return UploadBatchResponse(results=results, revoked=_all_revocations(session))


# ---------------------------------------------------------------------------
# GET /fraud/revocations
# ---------------------------------------------------------------------------


@router.get(
    "/fraud/revocations",
    response_model=RevocationsResponse,
    summary="Revoked credentials",
)
def revocations(session: Session = Depends(get_session)) -> RevocationsResponse:
    """The full revocation list.

    The contract is explicit that this is everything, not a delta (line 93):
    devices cache it and refuse to transact with anyone on it.
    """
    return RevocationsResponse(revoked=_all_revocations(session))
