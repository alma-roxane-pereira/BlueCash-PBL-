"""
One shared, test-only key set for both servers.

Independently generated keys would make `blind_sig`, audit leaves and Merkle
roots differ for entirely legitimate reasons, leaving only structural
comparison. Handing both servers the same key material makes those fields
byte-comparable, which is the point of the harness.

Each server is seeded through a mechanism it already supports -- no production
code is modified:

* the reference server reads `BLUECASH_KEYS` if the file exists
  (`server.py:77-78`) and only generates when it does not;
* the backend's `bootstrap()` returns existing rows, so inserting
  `MintIdentity` and `MintKey` first means it generates nothing
  (`mint_keys.py:get_or_create_identity` / `get_or_create_denominations`).

The keys here are generated per run and never written into the repository.
They are test material and must never be reused anywhere real.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

#: Matches the reference server's DENOMS (`server.py:74`).
DENOMINATIONS = (10, 50, 100, 500)
CURRENCY = "INR"

#: Fixed rather than `now + 365d`, so a run is reproducible and the expiry is
#: far enough out that no test trips over it.
EXPIRY_MS = 1_900_000_000_000

#: Smaller than the protocol's 2048 bits: generating eight 2048-bit keys per
#: run makes the suite unpleasant to run, and key *size* is not what this
#: harness compares -- both servers use whatever the shared file contains.
#: Overridable for a slower, fully protocol-faithful run.
RSA_BITS = 1024
RSA_E = 65537


def _int_hex(value: int) -> str:
    """Even-length lowercase hex, matching the reference's `int_hex`."""
    h = format(value, "x")
    return h if len(h) % 2 == 0 else "0" + h


@dataclass(frozen=True)
class SharedKeys:
    """The key material both servers run on."""

    ed_seed_hex: str
    mint_pub_hex: str
    rsa: tuple[dict, ...]

    def as_reference_file(self) -> dict:
        """The exact shape `_load_keys()` expects (`server.py:80-86`)."""
        return {"ed_seed": self.ed_seed_hex, "rsa": [dict(k) for k in self.rsa]}

    def write_reference_file(self, path: Path) -> Path:
        path.write_text(json.dumps(self.as_reference_file()), encoding="utf-8")
        return path


def generate(bits: int = RSA_BITS) -> SharedKeys:
    """Generate a fresh test-only key set."""
    seed = secrets.token_bytes(32)
    public = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key()

    keys = []
    for amount in DENOMINATIONS:
        private = rsa.generate_private_key(public_exponent=RSA_E, key_size=bits)
        numbers = private.private_numbers()
        keys.append(
            {
                # The reference names its keys `d{amount}-ref`; using the same
                # ids means `key_id` matches on both sides.
                "key_id": f"d{amount}-ref",
                "amount": amount,
                "currency": CURRENCY,
                "expiry_ms": EXPIRY_MS,
                "n": _int_hex(numbers.public_numbers.n),
                "e": _int_hex(numbers.public_numbers.e),
                "d": _int_hex(numbers.d),
            }
        )

    return SharedKeys(
        ed_seed_hex=seed.hex(),
        mint_pub_hex=public.public_bytes_raw().hex(),
        rsa=tuple(keys),
    )


def seed_backend_database(database_url: str, keys: SharedKeys) -> None:
    """Insert the shared keys into a backend database before it starts.

    Uses the ordinary models, so this exercises the same schema the application
    does. It must run *before* the backend's lifespan bootstrap, which then
    finds the rows and generates nothing.
    """
    # Imported here so this module stays importable without the app package.
    from app.config import Settings
    from app.db.models import MintIdentity, MintKey
    from app.db.session import create_all, create_db_engine, session_scope

    engine = create_db_engine(Settings(database_url=database_url))
    try:
        create_all(engine)
        with session_scope(engine) as session:
            session.add(
                MintIdentity(
                    id=1,
                    public_key_hex=keys.mint_pub_hex,
                    ed25519_seed_hex=keys.ed_seed_hex,
                )
            )
            for key in keys.rsa:
                session.add(
                    MintKey(
                        key_id=key["key_id"],
                        amount=key["amount"],
                        currency=key["currency"],
                        expiry_ms=key["expiry_ms"],
                        n_hex=key["n"],
                        e_hex=key["e"],
                        d_hex=key["d"],
                        active=True,
                    )
                )
    finally:
        engine.dispose()
