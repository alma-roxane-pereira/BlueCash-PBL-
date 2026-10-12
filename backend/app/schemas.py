"""
Request and response bodies for the mint API.

Shapes come straight from `API_CONTRACT.md` and are cross-checked against what
the Android client actually sends and reads in `HttpMintApi.kt`.

Two deliberate choices:

* **Hex stays a string.** The contract's wire format is hex; converting to `int`
  here would lose the exact spelling the client signed, and the signed strings
  embed that spelling verbatim. Conversion happens in the endpoint, after the
  signature has been checked.
* **No private fields exist on any response model.** `MintKeyModel` has no `d`,
  so the private exponent cannot leak through `GET /mint/keys` even if the
  underlying row is passed around carelessly.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    """Reject unknown fields, so a typo in a client request is visible."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# GET /mint/keys
# ---------------------------------------------------------------------------


class MintKeyModel(BaseModel):
    """One denomination key. Public parameters only."""

    key_id: str
    amount: int
    currency: str
    expiry_ms: int
    n: str = Field(description="RSA modulus, big-endian hex")
    e: str = Field(description="RSA public exponent, big-endian hex")


class MintKeysResponse(BaseModel):
    mint_pub: str = Field(description="Ed25519 public key, hex; the client pins this")
    keys: list[MintKeyModel]


# ---------------------------------------------------------------------------
# POST /mint/registerDevice
# ---------------------------------------------------------------------------


class RegisterDeviceRequest(_Strict):
    device_pub: str
    c0: str
    ts: int
    sig: str
    integrity_token: str | None = Field(
        default=None,
        description="Play Integrity token. Stored, never treated as verified.",
    )


class CredentialModel(BaseModel):
    cred_id: str
    device_pub: str
    c0: str
    expiry_ms: int
    mint_sig: str


class RegisterDeviceResponse(BaseModel):
    credential: CredentialModel


# ---------------------------------------------------------------------------
# POST /mint/issue
# ---------------------------------------------------------------------------


class IssueRequest(_Strict):
    cred_id: str
    key_id: str
    blinded: str
    c0: str
    ts: int
    sig: str


class IssueResponse(BaseModel):
    blind_sig: str
    leaf_index: int
    tree_size: int
    proof: list[str]
    root: str


# ---------------------------------------------------------------------------
# GET /audit/root/latest
# ---------------------------------------------------------------------------


class AuditRootResponse(BaseModel):
    root: str = Field(description='Merkle root hex, or "" when the log is empty')
    tree_size: int
    ts: int


# ---------------------------------------------------------------------------
# POST /settlement/uploadBatch
# ---------------------------------------------------------------------------


class TokenModel(_Strict):
    """A minted token, as the payer presents it at settlement."""

    token_id: str
    key_id: str
    amount: int
    currency: str
    expiry_ms: int
    c0: str
    c1: str
    sig: str = Field(description="RSA blind signature, unblinded, big-endian hex")


class ReceiptModel(_Strict):
    """One token spent at one merchant."""

    receipt_id: str
    token: TokenModel
    n_ctx: str
    x: str = Field(description="share coordinate, bound to token and context")
    y: str = Field(description="share value on the committed line")
    amount: int
    payer_cred: CredentialModel
    payer_sig: str
    merchant_id: str
    merchant_cred: CredentialModel
    merchant_sig: str
    timestamp_ms: int


class UploadBatchRequest(_Strict):
    receipts: list[ReceiptModel]


class ReceiptResult(BaseModel):
    """Per-receipt outcome. Statuses are fixed by the contract."""

    receipt_id: str
    status: str = Field(description="ACCEPTED | DUPLICATE | FRAUD | INVALID")
    detail: str


class RevocationModel(BaseModel):
    cred_id: str
    reason: str
    ts: int


class UploadBatchResponse(BaseModel):
    results: list[ReceiptResult]
    revoked: list[RevocationModel] = Field(
        description="the full revocation list, as the reference returns"
    )


# ---------------------------------------------------------------------------
# GET /fraud/revocations
# ---------------------------------------------------------------------------


class RevocationsResponse(BaseModel):
    revoked: list[RevocationModel]
