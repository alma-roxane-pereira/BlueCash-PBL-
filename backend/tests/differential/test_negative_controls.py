"""
Negative controls for the comparison machinery.

A green differential suite proves nothing unless the comparator can fail. These
tests corrupt payloads deliberately and assert that it does -- and that
normalization, which must hide `cred_id` and wall-clock differences, does not
also hide anything meaningful.

These run in the **normal** suite: they start no servers and are fast.
"""

from __future__ import annotations

import pytest

from .compare import (
    CredentialAliases,
    Mismatch,
    assert_close_in_time,
    assert_json_equal,
    normalize,
)


class _Response:
    """Minimal stand-in for an httpx response."""

    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    @property
    def text(self) -> str:
        import json

        return json.dumps(self._payload)


ISSUE = {
    "blind_sig": "0a1b2c",
    "leaf_index": 3,
    "tree_size": 4,
    "proof": ["aa" * 32, "bb" * 32],
    "root": "cc" * 32,
}


# ---------------------------------------------------------------------------
# the comparator must detect corruption
# ---------------------------------------------------------------------------


def test_identical_payloads_pass():
    assert_json_equal(ISSUE, dict(ISSUE), "sanity")


def test_corrupted_root_is_detected():
    corrupted = dict(ISSUE, root="dd" * 32)
    with pytest.raises(Mismatch, match="root"):
        assert_json_equal(ISSUE, corrupted, "issue")


def test_single_flipped_byte_in_root_is_detected():
    flipped = dict(ISSUE, root="cc" * 31 + "cd")
    with pytest.raises(Mismatch, match="root"):
        assert_json_equal(ISSUE, flipped)


def test_corrupted_blind_sig_is_detected():
    with pytest.raises(Mismatch, match="blind_sig"):
        assert_json_equal(ISSUE, dict(ISSUE, blind_sig="ffffff"))


def test_corrupted_proof_element_is_detected():
    corrupted = dict(ISSUE, proof=["aa" * 32, "cc" * 32])
    with pytest.raises(Mismatch, match=r"proof\[1\]"):
        assert_json_equal(ISSUE, corrupted)


def test_proof_length_change_is_detected():
    with pytest.raises(Mismatch, match="length"):
        assert_json_equal(ISSUE, dict(ISSUE, proof=["aa" * 32]))


def test_missing_field_is_detected():
    short = {k: v for k, v in ISSUE.items() if k != "root"}
    with pytest.raises(Mismatch, match="missing"):
        assert_json_equal(ISSUE, short)


def test_extra_field_is_detected():
    with pytest.raises(Mismatch, match="missing from reference"):
        assert_json_equal(ISSUE, dict(ISSUE, surprise=1))


def test_changed_detail_string_is_detected():
    left = {"results": [{"receipt_id": "r1", "status": "ACCEPTED", "detail": "settled"}]}
    right = {"results": [{"receipt_id": "r1", "status": "ACCEPTED", "detail": "ok"}]}
    with pytest.raises(Mismatch, match="detail"):
        assert_json_equal(left, right)


def test_changed_status_value_is_detected():
    left = {"status": "ACCEPTED"}
    right = {"status": "DUPLICATE"}
    with pytest.raises(Mismatch, match="status"):
        assert_json_equal(left, right)


def test_type_change_is_detected():
    with pytest.raises(Mismatch, match="type"):
        assert_json_equal({"tree_size": 4}, {"tree_size": "4"})


def test_nested_difference_is_reported_with_a_path():
    left = {"credential": {"c0": "0a", "expiry_ms": 1}}
    right = {"credential": {"c0": "0b", "expiry_ms": 1}}
    with pytest.raises(Mismatch, match=r"credential\.c0"):
        assert_json_equal(left, right)


# ---------------------------------------------------------------------------
# normalization must not hide meaningful differences
# ---------------------------------------------------------------------------


def _aliases() -> CredentialAliases:
    aliases = CredentialAliases()
    aliases.pair("a" * 32, "b" * 32)
    return aliases


def test_normalization_aligns_credential_ids():
    aliases = _aliases()
    left = normalize({"cred_id": "a" * 32}, "reference", aliases)
    right = normalize({"cred_id": "b" * 32}, "backend", aliases)
    assert_json_equal(left, right, "aliased credential")


def test_normalization_rewrites_ids_inside_detail_text():
    """`"...credential {cred_id} revoked"` must still compare equal."""
    aliases = _aliases()
    left = normalize({"detail": f"credential {'a' * 32} revoked"}, "reference", aliases)
    right = normalize({"detail": f"credential {'b' * 32} revoked"}, "backend", aliases)
    assert_json_equal(left, right, "revocation detail")


def test_normalization_does_not_hide_a_different_c0():
    aliases = _aliases()
    left = normalize({"cred_id": "a" * 32, "c0": "0a"}, "reference", aliases)
    right = normalize({"cred_id": "b" * 32, "c0": "0b"}, "backend", aliases)
    with pytest.raises(Mismatch, match="c0"):
        assert_json_equal(left, right)


def test_normalization_does_not_hide_a_different_root():
    aliases = _aliases()
    left = normalize({"cred_id": "a" * 32, "root": "cc" * 32}, "reference", aliases)
    right = normalize({"cred_id": "b" * 32, "root": "dd" * 32}, "backend", aliases)
    with pytest.raises(Mismatch, match="root"):
        assert_json_equal(left, right)


def test_normalization_does_not_hide_a_different_status():
    aliases = _aliases()
    left = normalize({"detail": f"credential {'a' * 32} revoked"}, "reference", aliases)
    right = normalize({"detail": f"credential {'b' * 32} suspended"}, "backend", aliases)
    with pytest.raises(Mismatch, match="detail"):
        assert_json_equal(left, right)


def test_unaliased_credential_id_is_not_rewritten():
    """An id the harness never saw must still be compared literally."""
    aliases = _aliases()
    left = normalize({"cred_id": "c" * 32}, "reference", aliases)
    right = normalize({"cred_id": "d" * 32}, "backend", aliases)
    with pytest.raises(Mismatch, match="cred_id"):
        assert_json_equal(left, right)


def test_dropping_volatile_fields_keeps_the_rest():
    left = normalize({"root": "aa", "ts": 1}, "reference", drop=("ts",))
    right = normalize({"root": "aa", "ts": 999}, "backend", drop=("ts",))
    assert_json_equal(left, right, "audit root")

    left = normalize({"root": "aa", "ts": 1}, "reference", drop=("ts",))
    right = normalize({"root": "bb", "ts": 1}, "backend", drop=("ts",))
    with pytest.raises(Mismatch, match="root"):
        assert_json_equal(left, right)


# ---------------------------------------------------------------------------
# status codes and timestamps
# ---------------------------------------------------------------------------


def test_status_code_difference_is_detected():
    from .compare import assert_responses_equal

    with pytest.raises(Mismatch, match="status differs"):
        assert_responses_equal(
            _Response(400, {"detail": "bad"}), _Response(403, {"detail": "bad"}), "issue"
        )


def test_error_detail_difference_is_detected():
    from .compare import assert_responses_equal

    with pytest.raises(Mismatch, match="detail"):
        assert_responses_equal(
            _Response(400, {"detail": "unknown key"}),
            _Response(400, {"detail": "bad key"}),
            "issue",
        )


def test_close_timestamps_pass_and_distant_ones_fail():
    assert_close_in_time(1_700_000_000_000, 1_700_000_000_050, "audit ts")
    with pytest.raises(Mismatch, match="timestamps differ"):
        assert_close_in_time(1_700_000_000_000, 1_700_000_900_000, "audit ts")
