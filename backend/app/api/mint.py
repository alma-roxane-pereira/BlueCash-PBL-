"""
Mint and audit endpoints.

Implements four of the six in `API_CONTRACT.md`:

* `GET  /mint/keys`           (lines 39-47)
* `POST /mint/registerDevice` (lines 48-53)
* `POST /mint/issue`          (lines 54-63)
* `GET  /audit/root/latest`   (lines 64-66)

Settlement and fraud come later.

# Error style

Errors are raised as FastAPI `HTTPException`, which renders a JSON envelope:

    HTTP 403  {"detail": "device not registered"}

The reference server raises the same `HTTPException`, so its bodies have the
identical shape -- verified by inspection of `server.py:148-166` and by rendering
one here. `API_CONTRACT.md` line 8 describes this loosely as "a short text body
(the app shows it)"; `HttpMintApi.kt:30` does `text.take(200)` on whatever
arrives, so the user sees the raw JSON. That is what the reference produces too,
so matching it is the compatible choice.

Status codes follow the reference: 400 for a bad request, 403 for an unknown or
revoked credential.

# Hex handling

Signature verification uses the client's hex **verbatim**, because that is what
it signed. Storage and comparison use the canonical form from `codec`, so
`"0a"`, `"A"` and `"000a"` behave identically. Mixing the two up is the
single easiest way to break interoperability here.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import mint_keys, protocol
from ..codec import CodecError, hex_to_int, int_to_hex
from ..db.models import AuditLeaf, Device, MintIdentity, MintKey, Revocation
from ..db.session import get_session
from ..schemas import (
    AuditRootResponse,
    CredentialModel,
    IssueRequest,
    IssueResponse,
    MintKeyModel,
    MintKeysResponse,
    RegisterDeviceRequest,
    RegisterDeviceResponse,
)

router = APIRouter(tags=["mint"])

#: How many times to retry an audit append that lost a race for a leaf index.
MAX_APPEND_RETRIES = 5


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=403, detail=detail)


def _identity(session: Session) -> MintIdentity:
    identity = session.get(MintIdentity, 1)
    if identity is None:
        # Startup runs bootstrap, so this means the database was not initialised.
        raise HTTPException(status_code=503, detail="mint is not initialised")
    return identity


def _canonical(value: str, field: str) -> str:
    """Canonical hex for storage and comparison, or a 400."""
    try:
        return int_to_hex(hex_to_int(value, field=field))
    except CodecError as exc:
        raise _bad_request(str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /mint/keys
# ---------------------------------------------------------------------------


@router.get("/mint/keys", response_model=MintKeysResponse, summary="Mint public keys")
def mint_keys_endpoint(session: Session = Depends(get_session)) -> MintKeysResponse:
    """Public mint parameters.

    The client pins `mint_pub` on first contact and refuses a mint whose key
    later changes, so this value must be stable across restarts.

    The private exponent `d` is never included — `MintKeyModel` has no such
    field, so it cannot leak by accident the way a dict-based response could.
    """
    identity = _identity(session)
    keys = session.scalars(
        select(MintKey).where(MintKey.active.is_(True)).order_by(MintKey.amount)
    ).all()

    return MintKeysResponse(
        mint_pub=identity.public_key_hex,
        keys=[
            MintKeyModel(
                key_id=k.key_id,
                amount=k.amount,
                currency=k.currency,
                expiry_ms=k.expiry_ms,
                n=k.n_hex,
                e=k.e_hex,
            )
            for k in keys
        ],
    )


# ---------------------------------------------------------------------------
# POST /mint/registerDevice
# ---------------------------------------------------------------------------


@router.post(
    "/mint/registerDevice",
    response_model=RegisterDeviceResponse,
    summary="Register a device and issue its credential",
)
def register_device(
    body: RegisterDeviceRequest, session: Session = Depends(get_session)
) -> RegisterDeviceResponse:
    """Register a device and return a mint-signed credential.

    Validates, in the contract's order (line 50):

    1. the Ed25519 signature over `BCREG|v1|{device_pub}|{c0}|{ts}`
    2. that `c0` is a quadratic residue mod P with `2 <= c0 <= P-2`

    The Play Integrity token is stored if present but **not verified** — real
    verification needs Google's API, so `integrity_verified` stays false. Saying
    otherwise would be a security claim the code does not support.
    """
    message = protocol.msg_register(body.device_pub, body.c0, body.ts)
    if not protocol.verify_device_signature(body.device_pub, message, body.sig):
        raise _bad_request("registration signature invalid")

    if not protocol.is_subgroup_element(body.c0):
        raise _bad_request("invalid identity commitment")

    cred_id = uuid.uuid4().hex
    expiry_ms = mint_keys.now_ms() + mint_keys.CREDENTIAL_LIFETIME_MS

    # The mint signs the credential using the client's own `c0` spelling, and
    # echoes that spelling back, so the client can reproduce the signed bytes.
    identity = _identity(session)
    cred_message = protocol.msg_credential(cred_id, body.device_pub, body.c0, expiry_ms)
    mint_sig = protocol.mint_sign(identity.ed25519_seed_hex, cred_message)

    session.add(
        Device(
            cred_id=cred_id,
            device_pub=body.device_pub,
            c0_hex=_canonical(body.c0, "c0"),
            expiry_ms=expiry_ms,
            mint_sig=mint_sig,
            integrity_token=body.integrity_token,
            integrity_verified=False,
        )
    )

    return RegisterDeviceResponse(
        credential=CredentialModel(
            cred_id=cred_id,
            device_pub=body.device_pub,
            c0=body.c0,
            expiry_ms=expiry_ms,
            mint_sig=mint_sig,
        )
    )


# ---------------------------------------------------------------------------
# POST /mint/issue
# ---------------------------------------------------------------------------


def _append_audit_leaf(session: Session, leaf_hash: str, cred_id: str, key_id: str) -> int:
    """Append a leaf and return its index.

    `leaf_index` is a position in the Merkle tree, so it must be dense and
    gapless. Two concurrent issuances can read the same `MAX(leaf_index)`; the
    primary key then rejects the loser, and we retry with a fresh index rather
    than writing a duplicate or leaving a hole.
    """
    for _ in range(MAX_APPEND_RETRIES):
        next_index = session.scalar(select(func.coalesce(func.max(AuditLeaf.leaf_index) + 1, 0)))
        savepoint = session.begin_nested()
        try:
            session.add(
                AuditLeaf(
                    leaf_index=next_index,
                    leaf_hash=leaf_hash,
                    cred_id=cred_id,
                    key_id=key_id,
                )
            )
            savepoint.commit()
            return next_index
        except IntegrityError:
            savepoint.rollback()
            # Another issuance took this index (or this exact leaf already
            # exists). Re-read and try again.
            continue

    raise HTTPException(status_code=503, detail="could not append to the audit log")


@router.post("/mint/issue", response_model=IssueResponse, summary="Blind-sign a token")
def issue(body: IssueRequest, session: Session = Depends(get_session)) -> IssueResponse:
    """Blind-sign a token request and append it to the public audit log.

    Validates, per the contract (line 56):

    * the credential exists and is not revoked -> 403
    * the signature over `BCISSUE|v1|{cred_id}|{key_id}|{blinded}|{c0}|{ts}`
    * `c0` equals the registered one, compared **numerically** (line 35)
    * `0 < blinded < n`

    Then computes `blinded^d mod n`, appends the leaf
    `SHA256(blinded || blind_sig)`, and returns the inclusion proof. The client
    verifies that proof and refuses the token if it does not check out
    (line 61).

    PRIVACY: nothing about the token itself is stored. The mint never learns
    `token_id` or `c1` (line 62) — that is what makes issuance unlinkable from
    the later spend.
    """
    device = session.get(Device, body.cred_id)
    if device is None:
        raise _forbidden("device not registered")
    if session.get(Revocation, body.cred_id) is not None:
        raise _forbidden("device revoked")

    message = protocol.msg_issue(body.cred_id, body.key_id, body.blinded, body.c0, body.ts)
    if not protocol.verify_device_signature(device.device_pub, message, body.sig):
        raise _bad_request("issue request signature invalid")

    if _canonical(body.c0, "c0") != device.c0_hex:
        raise _bad_request("identity commitment mismatch")

    key = session.get(MintKey, body.key_id)
    if key is None or not key.active:
        raise _bad_request("unknown key")

    try:
        blind_sig_hex = protocol.blind_sign(body.blinded, key.n_hex, key.d_hex)
    except CodecError as exc:
        raise _bad_request(str(exc)) from exc
    except ValueError as exc:
        # The crate rejects a blinded value outside (0, n).
        raise _bad_request("blinded value out of range") from exc

    leaf_hash = protocol.audit_leaf(body.blinded, blind_sig_hex)
    leaf_index = _append_audit_leaf(session, leaf_hash, body.cred_id, body.key_id)

    leaves = _all_leaves(session)
    return IssueResponse(
        blind_sig=blind_sig_hex,
        leaf_index=leaf_index,
        tree_size=len(leaves),
        proof=protocol.merkle_proof_hex(leaves, leaf_index),
        root=protocol.merkle_root_hex(leaves),
    )


# ---------------------------------------------------------------------------
# GET /audit/root/latest
# ---------------------------------------------------------------------------


def _all_leaves(session: Session) -> list[str]:
    """Every audit leaf, in tree order. Order defines the proof, so it matters."""
    return list(
        session.scalars(select(AuditLeaf.leaf_hash).order_by(AuditLeaf.leaf_index)).all()
    )


@router.get(
    "/audit/root/latest", response_model=AuditRootResponse, summary="Latest audit root"
)
def audit_root_latest(
    request: Request, session: Session = Depends(get_session)
) -> AuditRootResponse:
    """The current Merkle root of the issuance log.

    An empty log returns `root: ""`, matching `server.py:176`. The client reads
    it with `getString("root")`, so an empty string parses while a missing key
    would throw.
    """
    leaves = _all_leaves(session)
    return AuditRootResponse(
        root=protocol.merkle_root_hex(leaves),
        tree_size=len(leaves),
        ts=mint_keys.now_ms(),
    )
