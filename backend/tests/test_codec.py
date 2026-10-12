"""
Tests for the HTTP-edge hex/integer codec.

Two kinds of coverage here:

* unit tests pinning the documented behaviour, and
* a differential test that executes the *reference server's own* `int_hex`,
  `hex_int` and `unhex` and asserts our encoder agrees with it. That one is the
  reason to trust the rest: the encoding is only correct if it matches what the
  Android client was built against.
"""

from __future__ import annotations

import hashlib
import io
import os

import pytest

from app.codec import (
    MAX_HEX_LEN,
    CodecError,
    bytes_to_hex,
    hex_ints_equal,
    hex_to_bytes,
    hex_to_fixed_bytes,
    hex_to_int,
    int_to_hex,
    is_canonical_hex,
)

# ---------------------------------------------------------------------------
# reference helpers, loaded from the reference server itself
# ---------------------------------------------------------------------------

_SERVER_PY = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..",
        "bluecash-mobile-week1", "bluecash-mobile", "reference-server", "server.py",
    )
)


def _load_reference():
    """Execute only the pure-stdlib helper block of server.py (no fastapi import)."""
    src = io.open(_SERVER_PY, encoding="utf-8").read().splitlines()
    start = next(i for i, line in enumerate(src) if line.startswith("def sha256("))
    end = next(i for i, line in enumerate(src) if line.startswith("# ---- keys & state"))
    namespace = {"hashlib": hashlib}
    exec("\n".join(src[start:end]), namespace)
    return namespace


REF = pytest.importorskip("hashlib") and (
    _load_reference() if os.path.exists(_SERVER_PY) else None
)
needs_reference = pytest.mark.skipif(REF is None, reason="reference server not present")


# ---------------------------------------------------------------------------
# int_to_hex
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "00"),          # not "" and not "0"
        (1, "01"),
        (10, "0a"),
        (15, "0f"),
        (16, "10"),
        (255, "ff"),
        (256, "0100"),
        (65537, "010001"),  # the RSA public exponent, as the contract shows it
        (2**2048 - 1, "f" * 512),
    ],
)
def test_int_to_hex(value, expected):
    assert int_to_hex(value) == expected


def test_int_to_hex_is_always_even_length_and_lowercase():
    for value in [0, 1, 7, 161, 4095, 65535, 1 << 100, 2**2047]:
        encoded = int_to_hex(value)
        assert len(encoded) % 2 == 0, f"{value} -> {encoded}"
        assert encoded == encoded.lower()


def test_int_to_hex_rejects_negative_and_non_int():
    with pytest.raises(CodecError, match="non-negative"):
        int_to_hex(-1)
    with pytest.raises(CodecError, match="expected int"):
        int_to_hex("10")  # type: ignore[arg-type]
    with pytest.raises(CodecError, match="expected int"):
        int_to_hex(True)  # bool is an int subclass; reject it explicitly


@needs_reference
@pytest.mark.parametrize(
    "value",
    [0, 1, 10, 15, 16, 255, 256, 65537, 4095, 2**64, 2**2047, 2**2048 - 1],
)
def test_int_to_hex_matches_reference_server(value):
    assert int_to_hex(value) == REF["int_hex"](value)


@needs_reference
def test_int_to_hex_matches_reference_on_random_values():
    import random

    rng = random.Random(20261012)
    for _ in range(200):
        value = rng.getrandbits(rng.choice([1, 8, 9, 63, 256, 2048]))
        assert int_to_hex(value) == REF["int_hex"](value)


# ---------------------------------------------------------------------------
# hex_to_int
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("00", 0),
        ("0", 0),            # odd length is fine for an integer
        ("01", 1),
        ("0a", 10),
        ("a", 10),           # odd length
        ("A", 10),           # uppercase
        ("0A", 10),
        ("000a", 10),        # leading zeros
        ("0000000000", 0),
        ("ff", 255),
        ("0100", 256),
        ("010001", 65537),
        ("f" * 512, 2**2048 - 1),
    ],
)
def test_hex_to_int(text, expected):
    assert hex_to_int(text) == expected


def test_hex_to_int_round_trips_with_int_to_hex():
    for value in [0, 1, 15, 255, 256, 65537, 2**1024, 2**2048 - 1]:
        assert hex_to_int(int_to_hex(value)) == value


@pytest.mark.parametrize(
    "bad",
    [
        "",         # empty
        "0x0a",     # prefix
        "+0a",      # sign
        "-0a",
        " 0a",      # whitespace
        "0a ",
        "0a\n",
        "0_a",      # underscore (int() accepts this; we do not)
        "zz",       # invalid characters
        "0g",
        "0a0b0c!",
        "٠١",       # non-ascii digits
    ],
)
def test_hex_to_int_rejects_malformed(bad):
    with pytest.raises(CodecError):
        hex_to_int(bad, field="c0")


def test_hex_to_int_rejects_non_strings():
    for bad in (None, 10, b"0a", ["0a"], 1.5):
        with pytest.raises(CodecError, match="expected a hex string"):
            hex_to_int(bad, field="c0")


def test_hex_to_int_rejects_oversized_input():
    with pytest.raises(CodecError, match="longer than"):
        hex_to_int("a" * (MAX_HEX_LEN + 1), field="blinded")
    # The boundary itself is accepted.
    assert hex_to_int("a" * MAX_HEX_LEN) > 0


def test_codec_error_carries_the_field_name():
    with pytest.raises(CodecError) as excinfo:
        hex_to_int("zz", field="payer_sig")
    assert excinfo.value.field == "payer_sig"
    assert "payer_sig" in str(excinfo.value)


@needs_reference
@pytest.mark.parametrize("text", ["00", "0", "0a", "A", "000a", "ff", "0100", "010001"])
def test_hex_to_int_matches_reference_server(text):
    assert hex_to_int(text) == REF["hex_int"](text)


def test_stricter_than_reference_only_on_invalid_input():
    """Document the deliberate divergence: int(s, 16) coerces these; we reject."""
    for coerced in ("0x1f", " 1f ", "+1f", "1_f"):
        assert int(coerced, 16) == 31, "python would accept this"
        with pytest.raises(CodecError):
            hex_to_int(coerced, field="c0")


# ---------------------------------------------------------------------------
# bytes
# ---------------------------------------------------------------------------


def test_bytes_to_hex_is_lowercase_and_even():
    assert bytes_to_hex(b"") == ""
    assert bytes_to_hex(b"\x00") == "00"
    assert bytes_to_hex(b"\xde\xad\xbe\xef") == "deadbeef"
    assert bytes_to_hex(bytes(range(256))) == bytes(range(256)).hex()


def test_hex_to_bytes_round_trip():
    for data in [b"\x00", b"\xff", b"\xde\xad\xbe\xef", os.urandom(32)]:
        assert hex_to_bytes(bytes_to_hex(data)) == data


def test_hex_to_bytes_accepts_uppercase():
    assert hex_to_bytes("DEADBEEF") == b"\xde\xad\xbe\xef"


def test_hex_to_bytes_rejects_odd_length_by_default():
    with pytest.raises(CodecError, match="odd number"):
        hex_to_bytes("abc", field="blinded")


def test_hex_to_bytes_pads_odd_length_when_asked():
    """Reproduces the audit-leaf case at server.py:168."""
    assert hex_to_bytes("abc", pad_odd=True) == bytes.fromhex("0abc")
    assert hex_to_bytes("f", pad_odd=True) == b"\x0f"
    # Even-length input is unaffected by the flag.
    assert hex_to_bytes("0abc", pad_odd=True) == hex_to_bytes("0abc")


@needs_reference
def test_odd_length_padding_matches_the_reference_leaf_construction():
    """server.py:168: unhex(b) if len(b)%2==0 else unhex("0"+b)."""
    for blinded in ["abc", "f", "0abc", "ff", "1", "123456789"]:
        expected = (
            REF["unhex"](blinded) if len(blinded) % 2 == 0 else REF["unhex"]("0" + blinded)
        )
        assert hex_to_bytes(blinded, pad_odd=True) == expected


def test_hex_to_bytes_rejects_empty_and_malformed():
    with pytest.raises(CodecError, match="empty"):
        hex_to_bytes("", field="root")
    with pytest.raises(CodecError, match="not plain hexadecimal"):
        hex_to_bytes("zz", field="root")


# ---------------------------------------------------------------------------
# fixed-width fields
# ---------------------------------------------------------------------------


def test_hex_to_fixed_bytes_accepts_exact_length():
    assert len(hex_to_fixed_bytes("ab" * 32, 32, field="device_pub")) == 32
    assert len(hex_to_fixed_bytes("cd" * 64, 64, field="sig")) == 64


@pytest.mark.parametrize(("text", "length"), [("ab" * 31, 32), ("ab" * 33, 32), ("ab", 32)])
def test_hex_to_fixed_bytes_rejects_wrong_length(text, length):
    with pytest.raises(CodecError, match="exactly 32 bytes"):
        hex_to_fixed_bytes(text, length, field="device_pub")


def test_hex_to_fixed_bytes_error_names_the_field():
    with pytest.raises(CodecError) as excinfo:
        hex_to_fixed_bytes("ab", 32, field="mint_sig")
    assert excinfo.value.field == "mint_sig"


# ---------------------------------------------------------------------------
# numeric comparison  (API_CONTRACT.md line 35)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("0a", "0a"),
        ("0a", "a"),        # odd vs even
        ("0a", "0A"),       # case
        ("0a", "000a"),     # leading zeros
        ("00", "0000"),
        ("0", "00"),
        ("010001", "10001"),
        ("f" * 512, "0" * 8 + "f" * 512),
    ],
)
def test_equivalent_numeric_strings_compare_equal(left, right):
    assert hex_ints_equal(left, right) is True
    # Equality must not depend on argument order.
    assert hex_ints_equal(right, left) is True


@pytest.mark.parametrize(("left", "right"), [("0a", "0b"), ("00", "01"), ("0100", "1000")])
def test_different_numbers_compare_unequal(left, right):
    assert hex_ints_equal(left, right) is False


def test_naive_string_comparison_would_be_wrong():
    """The bug this function exists to prevent."""
    registered, presented = "0a", "000A"
    assert registered != presented, "string comparison rejects a valid payer"
    assert hex_ints_equal(registered, presented) is True


def test_hex_ints_equal_propagates_malformed_input():
    with pytest.raises(CodecError, match="c0"):
        hex_ints_equal("0a", "zz", field="c0")


# ---------------------------------------------------------------------------
# canonical form
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["00", "01", "0a", "ff", "0100", "010001"])
def test_canonical_hex_accepts_encoder_output(text):
    assert is_canonical_hex(text) is True


@pytest.mark.parametrize(
    "text",
    ["0A", "a", "000a", "0000", "", "0x0a", "zz", "0", "00ff"],
)
def test_canonical_hex_rejects_non_canonical(text):
    assert is_canonical_hex(text) is False


def test_canonical_hex_agrees_with_the_encoder():
    for value in [0, 1, 10, 255, 256, 65537, 2**1024]:
        assert is_canonical_hex(int_to_hex(value)) is True


def test_canonical_hex_is_not_a_validation_gate():
    """Non-canonical input is still *acceptable*; it just is not canonical."""
    assert is_canonical_hex("000a") is False
    assert hex_to_int("000a") == 10
    assert hex_ints_equal("000a", "0a") is True
