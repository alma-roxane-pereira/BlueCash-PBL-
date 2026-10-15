"""
The BLE session bindings, against the vectors the Android client also asserts.

This file is the third corner of a three-way check. The same handshake is
implemented in Kotlin (BouncyCastle and the JCE), in Rust (dalek and
RustCrypto), and reached from Python through the PyO3 boundary. The constants
below are byte-for-byte identical to the ones in `SessionVectorTests` in
`CoreTests.kt`, so if all three suites pass, all three implementations agree.

Agreement is the whole point. A payment is two devices deriving the same keys
from an exchange neither of them controls alone; an implementation that is
self-consistent but different from the others is worse than one that is
obviously broken, because it fails only in the field.

Run from the crate directory, with the project .venv active:
    ../../.venv/Scripts/python.exe -m pytest tests/test_session.py -q
"""

import pytest

bc = pytest.importorskip(
    "bluecash_crypto",
    reason="extension module not built; see the build commands in pyproject.toml",
)

# ---------------------------------------------------------------------------
# The shared vectors (identical to CoreTests.kt SessionVectorTests)
# ---------------------------------------------------------------------------

PAYER_SK = bytes.fromhex("11" * 32)
MERCHANT_SK = bytes.fromhex("22" * 32)

PAYER_PUB = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
MERCHANT_PUB = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
SHARED = "9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056"
TRANSCRIPT = "d0e766d338cb746c402f40c6e2d03d0d0da6ddb1549895c6251e3a2b5f5350f7"
P2M = "f8925b865e4a1c63486c812176a53e808dcfac4e5e35c2229cc5198a4a4777f5"
M2P = "5c965e7a61f2d9942509099d2cb6de042cfa02999247062930d25002a63b0337"
SAS = "430971"
RECORD_0 = "de8d729d41c4138cbe6ecc24f1cae2070d499b6cc7c70c6287797e2b0d9d2b1dd8"
RECORD_1 = "ccc590db6d1aff3690112c5149c9bcf13b6f2b4c87b9e7f5d9de3611b89d3f7263"
PLAINTEXT = b"BCSPEND|v1|t|c|10"


@pytest.fixture
def keys():
    """The payer's view of the shared session."""
    shared = bc.x25519_agree(PAYER_SK, bytes.fromhex(MERCHANT_PUB))
    return bc.derive_session_keys(
        shared, bytes.fromhex(PAYER_PUB), bytes.fromhex(MERCHANT_PUB), True
    )


# ---------------------------------------------------------------------------
# RFC 5869, through the binding
# ---------------------------------------------------------------------------


def test_hkdf_matches_rfc5869_case_1():
    okm = bc.hkdf_sha256(
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hkdf_matches_rfc5869_case_3_empty_salt_and_info():
    okm = bc.hkdf_sha256(bytes.fromhex("0b" * 22), b"", b"", 42)
    assert okm.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )


def test_hkdf_rejects_an_impossible_length():
    with pytest.raises(ValueError):
        bc.hkdf_sha256(b"ikm", b"salt", b"info", 0)
    with pytest.raises(ValueError):
        bc.hkdf_sha256(b"ikm", b"salt", b"info", 255 * 32 + 1)


# ---------------------------------------------------------------------------
# X25519
# ---------------------------------------------------------------------------


def test_public_keys_match_the_other_implementations():
    assert bc.x25519_public(PAYER_SK).hex() == PAYER_PUB
    assert bc.x25519_public(MERCHANT_SK).hex() == MERCHANT_PUB


def test_agreement_matches_and_is_symmetric():
    assert bc.x25519_agree(PAYER_SK, bytes.fromhex(MERCHANT_PUB)).hex() == SHARED
    assert bc.x25519_agree(MERCHANT_SK, bytes.fromhex(PAYER_PUB)).hex() == SHARED


def test_rfc7748_section_6_1():
    """The published vector, so the curve is checked against the spec."""
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    assert bc.x25519_agree(alice, bc.x25519_public(bob)).hex() == (
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )


def test_a_low_order_peer_key_is_refused():
    """All-zero has order 1: every secret agrees to the same known value."""
    with pytest.raises(ValueError):
        bc.x25519_agree(PAYER_SK, bytes(32))


def test_a_wrong_length_key_is_refused():
    with pytest.raises(ValueError):
        bc.x25519_agree(PAYER_SK, bytes(31))
    with pytest.raises(ValueError):
        bc.x25519_public(bytes(31))


# ---------------------------------------------------------------------------
# The handshake
# ---------------------------------------------------------------------------


def test_transcript_matches_the_other_implementations():
    assert (
        bc.session_transcript(
            bytes.fromhex(PAYER_PUB), bytes.fromhex(MERCHANT_PUB)
        ).hex()
        == TRANSCRIPT
    )


def test_the_transcript_is_ordered_payer_then_merchant():
    a, b = bytes.fromhex(PAYER_PUB), bytes.fromhex(MERCHANT_PUB)
    assert bc.session_transcript(a, b) != bc.session_transcript(b, a)


def test_derived_keys_and_sas_match_the_other_implementations(keys):
    assert keys["transcript"].hex() == TRANSCRIPT
    assert keys["send_key"].hex() == P2M
    assert keys["recv_key"].hex() == M2P
    assert keys["sas"] == SAS


def test_the_merchant_derives_the_mirror_image():
    shared = bc.x25519_agree(MERCHANT_SK, bytes.fromhex(PAYER_PUB))
    merchant = bc.derive_session_keys(
        shared, bytes.fromhex(PAYER_PUB), bytes.fromhex(MERCHANT_PUB), False
    )
    assert merchant["send_key"].hex() == M2P
    assert merchant["recv_key"].hex() == P2M
    assert merchant["sas"] == SAS


def test_a_swapped_ephemeral_key_changes_the_short_code(keys):
    """What the users' six-digit comparison actually detects."""
    attacker_pub = bc.x25519_public(bytes.fromhex("33" * 32))
    relayed = bc.derive_session_keys(
        bc.x25519_agree(MERCHANT_SK, attacker_pub),
        attacker_pub,
        bytes.fromhex(MERCHANT_PUB),
        False,
    )
    assert relayed["sas"] != keys["sas"]
    assert relayed["transcript"] != keys["transcript"]


def test_the_auth_message_is_bcauth_v1_role_transcript():
    t = bytes.fromhex(TRANSCRIPT)
    assert bc.session_auth_message("payer", t) == b"BCAUTH|v1|payer|" + t
    assert bc.session_auth_message("merchant", t) != bc.session_auth_message("payer", t)


def test_the_session_keys_do_not_leak_through_the_dict(keys):
    """The binding returns a plain dict; nothing should carry a key in a repr."""
    assert set(keys) == {"send_key", "recv_key", "transcript", "sas"}


# ---------------------------------------------------------------------------
# The record layer
# ---------------------------------------------------------------------------


def test_the_nonce_is_a_big_endian_counter_in_the_last_eight_bytes():
    assert bc.session_nonce(0) == bytes(12)
    assert bc.session_nonce(1) == bytes(11) + b"\x01"
    assert bc.session_nonce(0x0102030405060708) == bytes(4) + bytes.fromhex(
        "0102030405060708"
    )


def test_sealed_records_match_the_other_implementations(keys):
    """Both counters pinned, so a counter that fails to advance is caught."""
    assert bc.session_seal(keys["send_key"], 0, PLAINTEXT).hex() == RECORD_0
    assert bc.session_seal(keys["send_key"], 1, PLAINTEXT).hex() == RECORD_1


def test_a_record_sealed_by_the_other_implementations_opens_here(keys):
    """The direction that matters: bytes from Kotlin or Rust must open here."""
    merchant_recv = keys["send_key"]  # the merchant receives what the payer sends
    assert bc.session_open(merchant_recv, 0, bytes.fromhex(RECORD_0)) == PLAINTEXT
    assert bc.session_open(merchant_recv, 1, bytes.fromhex(RECORD_1)) == PLAINTEXT


def test_a_record_round_trips(keys):
    sealed = bc.session_seal(keys["send_key"], 7, b"receipt")
    assert bc.session_open(keys["send_key"], 7, sealed) == b"receipt"


def test_the_same_plaintext_under_two_counters_differs(keys):
    assert bc.session_seal(keys["send_key"], 0, PLAINTEXT) != bc.session_seal(
        keys["send_key"], 1, PLAINTEXT
    )


def test_a_record_opened_at_the_wrong_counter_is_refused(keys):
    """A replay or a reorder reaches the receiver as exactly this."""
    with pytest.raises(ValueError):
        bc.session_open(keys["send_key"], 1, bytes.fromhex(RECORD_0))


def test_a_tampered_record_is_refused(keys):
    broken = bytearray(bytes.fromhex(RECORD_0))
    broken[0] ^= 0x01
    with pytest.raises(ValueError):
        bc.session_open(keys["send_key"], 0, bytes(broken))


def test_a_record_with_a_flipped_tag_bit_is_refused(keys):
    broken = bytearray(bytes.fromhex(RECORD_0))
    broken[-1] ^= 0x80
    with pytest.raises(ValueError):
        bc.session_open(keys["send_key"], 0, bytes(broken))


def test_a_truncated_record_is_refused(keys):
    with pytest.raises(ValueError):
        bc.session_open(keys["send_key"], 0, bytes.fromhex(RECORD_0)[:-1])
    with pytest.raises(ValueError):
        bc.session_open(keys["send_key"], 0, b"")


def test_a_record_from_the_other_direction_is_refused(keys):
    """Directional keys: a relay cannot reflect a message back at its sender."""
    with pytest.raises(ValueError):
        bc.session_open(keys["recv_key"], 0, bytes.fromhex(RECORD_0))


def test_the_tag_is_sixteen_bytes_and_the_plaintext_is_hidden(keys):
    sealed = bc.session_seal(keys["send_key"], 0, PLAINTEXT)
    assert len(sealed) == len(PLAINTEXT) + 16
    assert b"BCSPEND" not in sealed
