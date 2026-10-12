"""
Validate the PyO3 bindings against the same vectors the Rust tests use.

The expected values in vectors.json / vectors_b.json were generated from the
reference implementations (reference-server/server.py, the client's
DemoMintKeys.kt, and `cryptography`) -- not from this crate. So a pass here
means the compiled extension module agrees with the protocol as implemented by
the server and the Android client, reached through the Python boundary.

Run from the crate directory, with the project .venv active:
    ../../.venv/Scripts/python.exe -m pytest tests/test_bindings.py -q
"""
import json
import os

import pytest

bc = pytest.importorskip(
    "bluecash_crypto",
    reason="extension module not built; see the build commands in pyproject.toml",
)

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


V = _load("vectors.json")
VB = _load("vectors_b.json")


def h2i(s):
    """Hex string -> int, matching the generators' int_hex encoding."""
    return int(s, 16)


def h2b(s):
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# module surface
# ---------------------------------------------------------------------------

def test_module_exposes_the_expected_functions():
    expected = {
        "fdh",
        "blind", "blind_with", "sign_blinded", "unblind", "blind_verify",
        "ed25519_generate_seed", "ed25519_public_key", "ed25519_sign",
        "ed25519_verify",
        "group_p", "group_q", "group_g", "commit", "is_element",
        "random_scalar", "challenge_x", "eval_share", "verify_share",
        "recover_secret",
        "merkle_leaf_hash", "merkle_node_hash", "merkle_root", "merkle_proof",
        "merkle_verify_inclusion",
        "random_bytes",
    }
    assert expected <= {n for n in dir(bc) if not n.startswith("_")}
    assert bc.__version__ == "0.1.0"


# ---------------------------------------------------------------------------
# FDH
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", V["fdh"], ids=lambda c: c["label"])
def test_fdh_matches_reference(case):
    got = bc.fdh(h2b(case["message_hex"]), h2i(case["n_hex"]))
    assert got == h2i(case["expected_hex"])
    assert got < h2i(case["n_hex"]), "result must be reduced"


def test_fdh_returns_a_python_int():
    assert isinstance(bc.fdh(b"abc", h2i(V["fdh"][0]["n_hex"])), int)


def test_fdh_rejects_zero_modulus():
    with pytest.raises(ValueError, match="non-zero"):
        bc.fdh(b"abc", 0)


def test_fdh_rejects_wrong_types():
    with pytest.raises(TypeError):
        bc.fdh("not bytes", 3233)
    with pytest.raises(TypeError):
        bc.fdh(b"abc", "not an int")


# ---------------------------------------------------------------------------
# RSA blind signatures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", VB["blind"], ids=lambda c: c["label"])
def test_blind_signature_matches_reference(case):
    n, e, d = h2i(case["n_hex"]), h2i(case["e_hex"]), h2i(case["d_hex"])
    msg, r = h2b(case["message_hex"]), h2i(case["r_hex"])

    blinded, r_out = bc.blind_with(msg, n, e, r)
    assert blinded == h2i(case["blinded_hex"])
    assert r_out == r

    blind_sig = bc.sign_blinded(blinded, n, d)
    assert blind_sig == h2i(case["blind_sig_hex"])

    sig = bc.unblind(blind_sig, r, n)
    assert sig == h2i(case["sig_hex"])

    assert bc.blind_verify(msg, sig, n, e) is True


@pytest.mark.parametrize("case", VB["blind"], ids=lambda c: c["label"])
def test_blind_verify_rejects_tampering(case):
    n, e = h2i(case["n_hex"]), h2i(case["e_hex"])
    msg, sig = h2b(case["message_hex"]), h2i(case["sig_hex"])

    assert bc.blind_verify(msg, sig, n, e) is True
    assert bc.blind_verify(msg, sig + 1, n, e) is False
    assert bc.blind_verify(msg + b"x", sig, n, e) is False
    # Out-of-range signatures are refused, not raised on.
    assert bc.blind_verify(msg, 0, n, e) is False
    assert bc.blind_verify(msg, n, n, e) is False


def test_blind_round_trip_with_random_factor():
    case = VB["blind"][0]
    n, e, d = h2i(case["n_hex"]), h2i(case["e_hex"]), h2i(case["d_hex"])
    msg = b"BCTOKEN|v1|d10-2027|random-r|0a|0b"

    blinded, r = bc.blind(msg, n, e)
    assert 0 < blinded < n
    assert 2 <= r < n
    sig = bc.unblind(bc.sign_blinded(blinded, n, d), r, n)
    assert bc.blind_verify(msg, sig, n, e) is True


def test_blind_uses_a_fresh_factor_each_call():
    case = VB["blind"][0]
    n, e = h2i(case["n_hex"]), h2i(case["e_hex"])
    first = bc.blind(b"same message", n, e)
    second = bc.blind(b"same message", n, e)
    assert first != second, "blinding factor must not repeat"


def test_blind_errors_are_value_errors():
    case = VB["blind"][0]
    n, e = h2i(case["n_hex"]), h2i(case["e_hex"])
    with pytest.raises(ValueError, match="out of range"):
        bc.blind_with(b"m", n, e, 1)
    with pytest.raises(ValueError, match="out of range"):
        bc.blind_with(b"m", n, e, n)
    with pytest.raises(ValueError, match="too small"):
        bc.blind(b"m", 3, e)
    with pytest.raises(ValueError, match="out of range"):
        bc.sign_blinded(0, n, e)
    with pytest.raises(ValueError, match="out of range"):
        bc.sign_blinded(n, n, e)


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case", VB["ed25519"], ids=lambda c: f"{c['seed_hex'][:8]}-{c['message_hex'][:8] or 'empty'}"
)
def test_ed25519_matches_reference(case):
    seed = h2b(case["seed_hex"])
    msg = h2b(case["message_hex"])
    pub = h2b(case["public_hex"])
    sig = h2b(case["signature_hex"])

    assert bc.ed25519_public_key(seed) == pub
    assert bc.ed25519_sign(seed, msg) == sig
    assert bc.ed25519_verify(pub, msg, sig) is True


def test_ed25519_returns_bytes():
    seed = bc.ed25519_generate_seed()
    assert isinstance(seed, bytes) and len(seed) == 32
    assert isinstance(bc.ed25519_public_key(seed), bytes)
    assert len(bc.ed25519_sign(seed, b"m")) == 64


def test_ed25519_verify_rejects_bad_input():
    case = VB["ed25519"][0]
    pub, msg, sig = (h2b(case["public_hex"]), h2b(case["message_hex"]),
                     h2b(case["signature_hex"]))

    assert bc.ed25519_verify(pub, msg, sig) is True
    assert bc.ed25519_verify(pub, msg + b"x", sig) is False
    assert bc.ed25519_verify(pub, msg, bytes(64)) is False
    # Malformed lengths return False rather than raising.
    assert bc.ed25519_verify(b"", msg, sig) is False
    assert bc.ed25519_verify(pub, msg, b"short") is False
    assert bc.ed25519_verify(bytes(31), msg, sig) is False


def test_ed25519_rejects_wrong_seed_length():
    for bad in (b"", bytes(31), bytes(33)):
        with pytest.raises(ValueError, match="32 bytes"):
            bc.ed25519_public_key(bad)
        with pytest.raises(ValueError, match="32 bytes"):
            bc.ed25519_sign(bad, b"m")


def test_generated_seeds_differ():
    assert bc.ed25519_generate_seed() != bc.ed25519_generate_seed()


# ---------------------------------------------------------------------------
# Feldman shares
# ---------------------------------------------------------------------------

def test_group_parameters_match_reference():
    assert bc.group_p() == h2i(VB["group"]["p_hex"])
    assert bc.group_q() == h2i(VB["group"]["q_hex"])
    assert bc.group_g() == VB["group"]["g"]
    assert bc.group_p().bit_length() == 2048


@pytest.mark.parametrize("case", VB["challenge_x"],
                         ids=lambda c: f"{c['token_id'] or 'empty'}|{c['n_ctx'] or 'empty'}")
def test_challenge_x_matches_reference(case):
    assert bc.challenge_x(case["token_id"], case["n_ctx"]) == h2i(case["x_hex"])


@pytest.mark.parametrize("case", VB["is_element"], ids=lambda c: c["v_hex"][:10])
def test_is_element_matches_reference(case):
    assert bc.is_element(h2i(case["v_hex"])) is case["expected"]


@pytest.mark.parametrize("case", VB["shares"], ids=lambda c: c["a0_hex"][:10])
def test_shares_match_reference(case):
    a0, a1 = h2i(case["a0_hex"]), h2i(case["a1_hex"])
    c0, c1 = h2i(case["c0_hex"]), h2i(case["c1_hex"])
    x1, y1 = h2i(case["x1_hex"]), h2i(case["y1_hex"])
    x2, y2 = h2i(case["x2_hex"]), h2i(case["y2_hex"])

    assert bc.commit(a0) == c0
    assert bc.commit(a1) == c1
    assert bc.eval_share(a0, a1, x1) == y1
    assert bc.eval_share(a0, a1, x2) == y2
    assert bc.verify_share(c0, c1, x1, y1) is True
    assert bc.verify_share(c0, c1, x2, y2) is True

    recovered = bc.recover_secret(x1, y1, x2, y2)
    assert recovered == h2i(case["recovered_a0_hex"])
    assert bc.commit(recovered) == c0


@pytest.mark.parametrize("case", VB["shares"], ids=lambda c: c["a0_hex"][:10])
def test_verify_share_rejects_bad_points(case):
    c0, c1 = h2i(case["c0_hex"]), h2i(case["c1_hex"])
    x1, y1 = h2i(case["x1_hex"]), h2i(case["y1_hex"])
    q = bc.group_q()

    assert bc.verify_share(c0, c1, x1, y1) is True
    assert bc.verify_share(c0, c1, x1, (y1 + 1) % q) is False
    assert bc.verify_share(c1, c0, x1, y1) is False, "swapped commitments"
    assert bc.verify_share(c0, c1, x1, q) is False, "y out of range"
    assert bc.verify_share(c0, c1, 0, y1) is False, "x must be non-zero"
    assert bc.verify_share(1, c1, x1, y1) is False, "c0 outside subgroup"


def test_same_context_reveals_nothing():
    """Replaying one context gives one point, so recovery must return None."""
    case = VB["shares"][0]
    x1, y1 = h2i(case["x1_hex"]), h2i(case["y1_hex"])
    assert bc.recover_secret(x1, y1, x1, y1) is None


def test_recovery_is_order_independent():
    for case in VB["shares"]:
        x1, y1 = h2i(case["x1_hex"]), h2i(case["y1_hex"])
        x2, y2 = h2i(case["x2_hex"]), h2i(case["y2_hex"])
        assert bc.recover_secret(x1, y1, x2, y2) == bc.recover_secret(x2, y2, x1, y1)


def test_random_scalar_is_in_range():
    q = bc.group_q()
    for _ in range(5):
        s = bc.random_scalar()
        assert 0 < s < q


# ---------------------------------------------------------------------------
# Merkle
# ---------------------------------------------------------------------------

def test_merkle_primitives_match_reference():
    prims = V["primitives"]
    assert bc.merkle_leaf_hash(b"") == h2b(prims["leaf_hash_empty"])
    assert bc.merkle_leaf_hash(b"abc") == h2b(prims["leaf_hash_abc"])
    assert bc.merkle_node_hash(
        bc.merkle_leaf_hash(b"a"), bc.merkle_leaf_hash(b"b")
    ) == h2b(prims["node_hash_leafa_leafb"])


@pytest.mark.parametrize("tree", V["merkle"], ids=lambda t: f"size{t['size']}")
def test_merkle_roots_and_proofs_match_reference(tree):
    leaves = [h2b(x) for x in tree["leaves_hex"]]
    root = h2b(tree["root_hex"])

    assert bc.merkle_root(leaves) == root
    for i, leaf_hash_hex in enumerate(tree["leaf_hashes_hex"]):
        assert bc.merkle_leaf_hash(leaves[i]) == h2b(leaf_hash_hex)

    for index, expected_proof in enumerate(tree["proofs"]):
        proof = bc.merkle_proof(leaves, index)
        assert [p.hex() for p in proof] == expected_proof
        assert bc.merkle_verify_inclusion(
            leaves[index], index, tree["size"], proof, root
        ) is True


def test_merkle_verify_rejects_tampering():
    tree = V["merkle"][10]  # size 11
    leaves = [h2b(x) for x in tree["leaves_hex"]]
    root = h2b(tree["root_hex"])
    size = tree["size"]
    proof = bc.merkle_proof(leaves, 5)

    assert bc.merkle_verify_inclusion(leaves[5], 5, size, proof, root) is True
    assert bc.merkle_verify_inclusion(b"not-a-leaf", 5, size, proof, root) is False
    assert bc.merkle_verify_inclusion(leaves[5], 6, size, proof, root) is False
    assert bc.merkle_verify_inclusion(leaves[5], size, size, proof, root) is False
    assert bc.merkle_verify_inclusion(leaves[5], 5, size, proof[:-1], root) is False
    assert bc.merkle_verify_inclusion(
        leaves[5], 5, size, proof + [bytes(32)], root
    ) is False
    assert bc.merkle_verify_inclusion(leaves[5], 5, 0, proof, root) is False
    bad_root = bytearray(root)
    bad_root[0] ^= 1
    assert bc.merkle_verify_inclusion(leaves[5], 5, size, proof, bytes(bad_root)) is False


def test_merkle_verify_rejects_malformed_hashes():
    tree = V["merkle"][3]
    leaves = [h2b(x) for x in tree["leaves_hex"]]
    root = h2b(tree["root_hex"])
    proof = bc.merkle_proof(leaves, 0)
    # Wrong-length root or proof element returns False, never raises.
    assert bc.merkle_verify_inclusion(leaves[0], 0, tree["size"], proof, b"short") is False
    assert bc.merkle_verify_inclusion(
        leaves[0], 0, tree["size"], [b"short"] * len(proof), root
    ) is False


def test_merkle_empty_tree_and_bad_index_raise():
    with pytest.raises(ValueError, match="no leaves"):
        bc.merkle_root([])
    with pytest.raises(ValueError, match="no leaves"):
        bc.merkle_proof([], 0)
    with pytest.raises(ValueError, match="out of range"):
        bc.merkle_proof([b"a", b"b"], 2)


def test_merkle_node_hash_rejects_wrong_lengths():
    with pytest.raises(ValueError, match="32 bytes"):
        bc.merkle_node_hash(b"short", bytes(32))
    with pytest.raises(ValueError, match="32 bytes"):
        bc.merkle_node_hash(bytes(32), b"short")


def test_merkle_returns_bytes_not_bytearray():
    assert isinstance(bc.merkle_leaf_hash(b"x"), bytes)
    assert isinstance(bc.merkle_root([b"x"]), bytes)
    assert all(isinstance(p, bytes) for p in bc.merkle_proof([b"a", b"b"], 0))


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------

def test_random_bytes():
    assert len(bc.random_bytes(0)) == 0
    assert len(bc.random_bytes(32)) == 32
    assert bc.random_bytes(32) != bc.random_bytes(32)


def test_no_secret_material_in_repr():
    """A traceback or log line must not be able to print a seed."""
    seed = bc.ed25519_generate_seed()
    assert seed.hex() not in repr(bc)
    assert "seed" not in repr(bc).lower()
