"""
Hex/integer codec for the HTTP edge.

`API_CONTRACT.md` fixes the wire encoding:

> All bodies are JSON; all binary values are **lowercase hex**; big integers are
> big-endian hex.

> `c0`, `c1` are hex of the big-endian integers (even length, lowercase).
> Compare them as integers, not strings.

Hex is the *wire* format, not an internal one. Everything inside the backend
works with `int` and `bytes`; this module is the only place that converts, so
padding and case bugs cannot leak into the protocol logic or the crypto core.

# Compatibility with the reference server

Encoding matches `int_hex` in `reference-server/server.py` exactly, including
the two cases that bite:

* `int_to_hex(0) == "00"`, not `""` or `"0"`
* odd-length output is left-padded with one `0`, so `15 -> "0f"`, `256 -> "0100"`

Decoding is deliberately **stricter** than the reference's `int(s, 16)`. That
function also accepts `0x` prefixes, `+`/`-` signs, surrounding whitespace and
underscores (`int("0x_1f", 16) == 31`). The Android client never sends any of
those — see `HttpMintApi.kt` and `Models.kt`, which emit plain lowercase hex —
so rejecting them turns a silently-coerced malformed field into a clear 400.
This diverges from the reference only on input that is already invalid.

Byte decoding mirrors the reference's one odd-length accommodation: at
`server.py:168` the audit leaf pads an odd-length `blinded` with a leading `0`
before hashing. `hex_to_bytes(..., pad_odd=True)` reproduces that; the default
rejects odd-length input, as `bytes.fromhex` does.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "CodecError",
    "int_to_hex",
    "hex_to_int",
    "bytes_to_hex",
    "hex_to_bytes",
    "hex_to_fixed_bytes",
    "hex_ints_equal",
    "is_canonical_hex",
]

# Plain hex only: no 0x prefix, no sign, no whitespace, no underscores, non-empty.
_HEX_RE: Final = re.compile(r"\A[0-9a-fA-F]+\Z")

# Longest field the protocol defines is a 2048-bit integer (512 hex chars).
# A generous cap keeps a hostile body from turning into a huge BigInt.
MAX_HEX_LEN: Final = 4096


class CodecError(ValueError):
    """A protocol field could not be decoded.

    Carries the field name so the caller can build a precise error response
    without string-matching the message.
    """

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"{field}: {reason}")


# ---------------------------------------------------------------------------
# encoding
# ---------------------------------------------------------------------------


def int_to_hex(value: int) -> str:
    """Encode a non-negative integer as even-length lowercase big-endian hex.

    Matches `int_hex` in the reference server:

    >>> int_to_hex(0), int_to_hex(15), int_to_hex(256), int_to_hex(65537)
    ('00', '0f', '0100', '010001')

    Raises:
        CodecError: if `value` is negative. The protocol has no negative fields.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise CodecError("value", f"expected int, got {type(value).__name__}")
    if value < 0:
        raise CodecError("value", "must be non-negative")
    h = format(value, "x")
    return h if len(h) % 2 == 0 else "0" + h


def bytes_to_hex(data: bytes) -> str:
    """Encode bytes as lowercase hex. Always even-length by construction."""
    return data.hex()


# ---------------------------------------------------------------------------
# decoding
# ---------------------------------------------------------------------------


def _validate_hex(value: object, field: str) -> str:
    """Shared gate for every decode path."""
    if not isinstance(value, str):
        raise CodecError(field, f"expected a hex string, got {type(value).__name__}")
    if value == "":
        raise CodecError(field, "must not be empty")
    if len(value) > MAX_HEX_LEN:
        raise CodecError(field, f"longer than {MAX_HEX_LEN} hex characters")
    if not _HEX_RE.match(value):
        raise CodecError(field, "is not plain hexadecimal")
    return value


def hex_to_int(value: object, *, field: str = "value") -> int:
    """Decode big-endian hex to an integer.

    Accepts uppercase and leading zeros, since both denote the same number and
    the contract says to compare numerically. Rejects empty strings, `0x`
    prefixes, signs and whitespace.

    >>> hex_to_int("0a"), hex_to_int("A"), hex_to_int("000a")
    (10, 10, 10)
    """
    return int(_validate_hex(value, field), 16)


def hex_to_bytes(value: object, *, field: str = "value", pad_odd: bool = False) -> bytes:
    """Decode hex to bytes.

    Args:
        pad_odd: when true, an odd-length string is left-padded with one `0`
            before decoding, reproducing the audit-leaf behaviour at
            `server.py:168`. When false (the default) odd length is an error,
            matching `bytes.fromhex`.
    """
    text = _validate_hex(value, field)
    if len(text) % 2:
        if not pad_odd:
            raise CodecError(field, "has an odd number of hex characters")
        text = "0" + text
    return bytes.fromhex(text)


def hex_to_fixed_bytes(value: object, length: int, *, field: str = "value") -> bytes:
    """Decode hex to exactly `length` bytes.

    For the protocol's fixed-width fields: 32-byte Ed25519 public keys and
    Merkle hashes, 64-byte signatures.
    """
    data = hex_to_bytes(value, field=field)
    if len(data) != length:
        raise CodecError(
            field, f"must be exactly {length} bytes ({length * 2} hex chars), got {len(data)}"
        )
    return data


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------


def hex_ints_equal(left: object, right: object, *, field: str = "value") -> bool:
    """Compare two hex integers **numerically**, per `API_CONTRACT.md` line 35.

    `"0a"`, `"A"` and `"000a"` all denote 10 and must compare equal. A string
    comparison here would reject a legitimate client over formatting — this is
    the check that decides whether a token belongs to the payer presenting it.

    >>> hex_ints_equal("0a", "000A")
    True
    """
    return hex_to_int(left, field=field) == hex_to_int(right, field=field)


def is_canonical_hex(value: object) -> bool:
    """Is this the exact form `int_to_hex` would produce?

    Lowercase, even-length, and without redundant leading zero bytes (except the
    single `"00"` that encodes zero). Useful for warning about a non-canonical
    but still acceptable field; it is **not** a validation gate, since the
    contract requires numeric comparison rather than textual equality.
    """
    if not isinstance(value, str) or not _HEX_RE.match(value or ""):
        return False
    if len(value) % 2 or value != value.lower():
        return False
    return value == int_to_hex(int(value, 16))
