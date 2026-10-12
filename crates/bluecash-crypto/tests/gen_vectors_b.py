"""
Generate expected values for the Task B primitives: RSA blind signatures,
Ed25519, and the Feldman-committed share scheme.

As with gen_vectors.py, nothing here reimplements the protocol:

* the group parameters, `challenge_x`, `is_element`, `fdh` and `int_hex` come
  from reference-server/server.py's own function definitions;
* the RSA keys come from the Android client's DemoMintKeys.kt, parsed out of the
  file, so the blind-signature vectors are computed with the very keys the
  client's SimulatedMint uses;
* Ed25519 signatures are produced by `cryptography`, the same library
  server.py signs with.

Neither source file is modified. Requires the project .venv (for `cryptography`).

Run from the crate directory:
    ../../.venv/Scripts/python.exe tests/gen_vectors_b.py > tests/vectors_b.json
"""
import hashlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
SERVER = os.path.join(ROOT, "bluecash-mobile-week1", "bluecash-mobile",
                      "reference-server", "server.py")
DEMO_KEYS = os.path.join(ROOT, "bluecash-mobile-week1", "bluecash-mobile", "app",
                         "src", "main", "java", "com", "bluecash", "wallet",
                         "core", "DemoMintKeys.kt")

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402


def load_reference():
    """Execute server.py's pure-stdlib helper blocks (group params + hashes)."""
    src = io.open(SERVER, encoding="utf-8").read().splitlines()
    start = next(i for i, l in enumerate(src) if l.startswith("def _modp14"))
    end = next(i for i, l in enumerate(src) if l.startswith("# ---- keys & state"))
    block = "\n".join(src[start:end])
    if re.search(r"^\s*(import |open\(|eval\()", block, re.M):
        raise SystemExit("refusing to exec a block containing imports or IO")
    ns = {"hashlib": hashlib}
    exec(block, ns)
    return ns


def load_demo_rsa_key(amount: int):
    """Parse one denomination's n/e/d out of DemoMintKeys.kt."""
    src = io.open(DEMO_KEYS, encoding="utf-8").read()

    def const(name):
        m = re.search(rf'val\s+{name}\b[^"]*"([0-9a-fA-F]+)"', src) or \
            re.search(rf'{name}\s*=\s*"([0-9a-fA-F]+)"', src)
        if not m:
            raise SystemExit(f"could not find {name} in DemoMintKeys.kt")
        return int(m.group(1), 16)

    return const(f"N{amount}"), const(f"E{amount}"), const(f"D{amount}")


R = load_reference()
P = R["_modp14"]()
Q = (P - 1) // 2
G = 2
int_hex, fdh, challenge_x = R["int_hex"], R["fdh"], R["challenge_x"]

out = {
    "source": "reference-server/server.py + app DemoMintKeys.kt + cryptography",
    "group": {"p_hex": int_hex(P), "q_hex": int_hex(Q), "g": G},
}

# --- RSA blind signatures, using the client's own demo keys ----------------
# Deterministic r values so the Rust side can reproduce the exact blinding.
out["blind"] = []
for amount in (10, 100, 500):
    n, e, d = load_demo_rsa_key(amount)
    for label, msg, r in [
        ("token string", f"BCTOKEN|v1|d{amount}-2027|tok-{amount}|0a|0b".encode(), 3),
        ("empty message", b"", 65537),
        ("large r", b"payload", n - 2),
    ]:
        m = fdh(msg, n)
        blinded = (m * pow(r, e, n)) % n
        blind_sig = pow(blinded, d, n)
        sig = (blind_sig * pow(r, -1, n)) % n
        assert pow(sig, e, n) == m, "reference blind signature must verify"
        out["blind"].append({
            "label": f"d{amount} / {label}",
            "n_hex": int_hex(n), "e_hex": int_hex(e), "d_hex": int_hex(d),
            "message_hex": msg.hex(),
            "r_hex": int_hex(r),
            "blinded_hex": int_hex(blinded),
            "blind_sig_hex": int_hex(blind_sig),
            "sig_hex": int_hex(sig),
        })

# --- Ed25519, signed with the same library the server uses ----------------
out["ed25519"] = []
_seeds = [
    bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
    bytes(range(32)),
]
_messages = [
    b"",
    b"\x72",
    "BCREG|v1|aabbcc|0f|1700000000000".encode(),
    "BCSPEND|v1|tok1|ctx-shop-a|100".encode(),
    "BCCRED|v1|cred1|aabb|0c|1800000000000".encode(),
    "héllo ∑".encode(),
]
for seed in _seeds:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes_raw()
    for msg in _messages:
        out["ed25519"].append({
            "seed_hex": seed.hex(),
            "public_hex": pub.hex(),
            "message_hex": msg.hex(),
            "signature_hex": sk.sign(msg).hex(),
        })

# --- Feldman share scheme -------------------------------------------------
out["shares"] = []
_pairs = [
    (12345, 67890),
    (Q - 1, 2),
    (1, Q - 2),
    (0x1234567890ABCDEF, 0xFEDCBA0987654321),
]
for a0, a1 in _pairs:
    c0, c1 = pow(G, a0, P), pow(G, a1, P)
    x1 = challenge_x("tok-A", "ctx-shop-a")
    x2 = challenge_x("tok-A", "ctx-shop-b")
    y1 = (a0 + a1 * x1) % Q
    y2 = (a0 + a1 * x2) % Q
    # Reference recovery, exactly as /settlement/uploadBatch does it.
    rec_a1 = (y2 - y1) * pow(x2 - x1, -1, Q) % Q
    rec_a0 = (y1 - rec_a1 * x1) % Q
    assert rec_a0 == a0 % Q, "reference recovery must return a0"
    assert pow(G, y1, P) == c0 * pow(c1, x1, P) % P, "reference share must verify"
    out["shares"].append({
        "a0_hex": int_hex(a0), "a1_hex": int_hex(a1),
        "c0_hex": int_hex(c0), "c1_hex": int_hex(c1),
        "x1_hex": int_hex(x1), "y1_hex": int_hex(y1),
        "x2_hex": int_hex(x2), "y2_hex": int_hex(y2),
        "recovered_a0_hex": int_hex(rec_a0),
    })

# challenge_x vectors, independent of any key material
out["challenge_x"] = [
    {"token_id": t, "n_ctx": c, "x_hex": int_hex(challenge_x(t, c))}
    for t, c in [("tok1", "ctx-a"), ("tok1", "ctx-b"), ("tok2", "ctx-a"),
                 ("", ""), ("tokenA", "ctxB"), ("t|pipe", "c|pipe")]
]

# Subgroup membership, per server.py's Euler test.
out["is_element"] = [
    {"v_hex": int_hex(v), "expected": bool(R["is_element"](v))}
    for v in [1, 2, 3, 4, P - 1, P - 2, pow(G, 12345, P), pow(G, Q - 1, P)]
]

json.dump(out, sys.stdout, indent=1, sort_keys=True)
