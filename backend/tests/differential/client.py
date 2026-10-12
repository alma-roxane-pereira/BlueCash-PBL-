"""
A protocol client that drives both servers with identical inputs.

Built from `API_CONTRACT.md` rather than from backend helpers, so the harness
exercises the contract rather than agreeing with one implementation by
construction. All key material here is generated per test.

Every value the client chooses -- `token_id`, `c1`, the blinding factor `r`,
`n_ctx`, `receipt_id`, timestamps -- is generated **once** and sent to both
servers, so any difference in the responses comes from the servers.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519

import bluecash_crypto as bc


def hexint(value: int) -> str:
    """Even-length lowercase hex, as the contract requires."""
    h = format(value, "x")
    return h if len(h) % 2 == 0 else "0" + h


@dataclass
class Pair:
    """The two servers, addressed together."""

    reference: httpx.Client
    backend: httpx.Client

    def get(self, path: str):
        return self.reference.get(path), self.backend.get(path)

    def post(self, path: str, json: dict):
        return self.reference.post(path, json=json), self.backend.post(path, json=json)

    def post_each(self, path: str, reference_json: dict, backend_json: dict):
        """Send *different* bodies, for requests that must carry each server's
        own `cred_id`."""
        return (
            self.reference.post(path, json=reference_json),
            self.backend.post(path, json=backend_json),
        )


@dataclass
class Device:
    """A test device: an Ed25519 identity plus a Feldman identity secret."""

    sk: ed25519.Ed25519PrivateKey = field(
        default_factory=ed25519.Ed25519PrivateKey.generate
    )
    a0: int = field(default=0)
    #: Each server issues its own credential id, so both are kept.
    credentials: dict[str, dict] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.a0:
            self.a0 = secrets.randbelow(bc.group_q() - 2) + 1

    @property
    def device_pub(self) -> str:
        return self.sk.public_key().public_bytes_raw().hex()

    @property
    def c0(self) -> str:
        return hexint(bc.commit(self.a0))

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

    def cred_id(self, side: str) -> str:
        return self.credentials[side]["cred_id"]


@dataclass
class BlindedRequest:
    """One token request, blinded once and reused for both servers.

    `blinded` does not depend on `cred_id`, so both servers receive the same
    value and must produce the same `blind_sig`, audit leaf and root.
    """

    token_id: str
    a1: int
    c1: str
    r: int
    n: int
    e: int
    message: bytes
    blinded_hex: str

    def issue_body(self, device: Device, side: str, key: dict, ts: int, **overrides) -> dict:
        cred_id = device.cred_id(side)
        body = {
            "cred_id": cred_id,
            "key_id": key["key_id"],
            "blinded": self.blinded_hex,
            "c0": device.c0,
            "ts": ts,
            "sig": device.sign(
                f"BCISSUE|v1|{cred_id}|{key['key_id']}|{self.blinded_hex}|{device.c0}|{ts}"
            ),
        }
        body.update(overrides)
        return body


def blind_token(device: Device, key: dict) -> BlindedRequest:
    """Blind a fresh token request under `key`."""
    n, e = int(key["n"], 16), int(key["e"], 16)
    token_id = secrets.token_hex(16)
    a1 = secrets.randbelow(bc.group_q() - 2) + 1
    c1 = hexint(bc.commit(a1))
    message = f"BCTOKEN|v1|{key['key_id']}|{token_id}|{device.c0}|{c1}".encode()
    blinded, r = bc.blind(message, n, e)
    return BlindedRequest(
        token_id=token_id,
        a1=a1,
        c1=c1,
        r=r,
        n=n,
        e=e,
        message=message,
        blinded_hex=hexint(blinded),
    )


def unblind_token(request: BlindedRequest, blind_sig_hex: str, key: dict) -> dict:
    """Unblind an issuance response into a spendable token."""
    sig = bc.unblind(int(blind_sig_hex, 16), request.r, request.n)
    if not bc.blind_verify(request.message, sig, request.n, request.e):
        raise AssertionError("unblinded signature does not verify")
    return {
        "token_id": request.token_id,
        "key_id": key["key_id"],
        "amount": key["amount"],
        "currency": key["currency"],
        "expiry_ms": key["expiry_ms"],
        "c0": request.c1 and _c0_of(request),
        "c1": request.c1,
        "sig": hexint(sig),
    }


def _c0_of(request: BlindedRequest) -> str:
    """`c0` is embedded in the signed token message; recover it from there."""
    return request.message.decode().split("|")[4]


def build_receipt(
    payer: Device,
    merchant: Device,
    token: dict,
    a1: int,
    n_ctx: str,
    side: str,
    *,
    receipt_id: str,
    timestamp_ms: int = 1_700_000_000_000,
    amount: int | None = None,
) -> dict:
    """Assemble a signed receipt for one server.

    `side` selects which server's credentials to embed; everything else is
    identical across the two.
    """
    amount = token["amount"] if amount is None else amount
    x = bc.challenge_x(token["token_id"], n_ctx)
    y = bc.eval_share(payer.a0, a1, x)
    x_hex, y_hex = hexint(x), hexint(y)

    merchant_id = merchant.cred_id(side)
    return {
        "receipt_id": receipt_id,
        "token": token,
        "n_ctx": n_ctx,
        "x": x_hex,
        "y": y_hex,
        "amount": amount,
        "payer_cred": payer.credentials[side],
        "payer_sig": payer.sign(
            f"BCSPEND|v1|{token['token_id']}|{n_ctx}|{token['amount']}"
        ),
        "merchant_id": merchant_id,
        "merchant_cred": merchant.credentials[side],
        "merchant_sig": merchant.sign(
            f"BCRECEIPT|v1|{receipt_id}|{token['token_id']}|{n_ctx}|{x_hex}|{y_hex}"
            f"|{amount}|{merchant_id}|{timestamp_ms}"
        ),
        "timestamp_ms": timestamp_ms,
    }


def new_receipt_id() -> str:
    return secrets.token_hex(12)
