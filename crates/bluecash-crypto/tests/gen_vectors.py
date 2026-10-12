"""
Generate expected FDH / Merkle values for the Rust differential tests.

This does NOT reimplement anything. It loads the reference server's own function
definitions straight out of reference-server/server.py and calls them, so the
expected values are independently derived from the compatibility reference rather
than from the Rust code under test.

server.py is never modified, and it is not imported as a module (that would pull in
fastapi); only the pure-stdlib block holding sha256/fdh/merkle is executed.

Run from the crate directory:
    python -I tests/gen_vectors.py > tests/vectors.json
"""
import hashlib, io, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.normpath(os.path.join(
    HERE, "..", "..", "..",
    "bluecash-mobile-week1", "bluecash-mobile", "reference-server", "server.py"))


def load_reference():
    """Execute only the pure-stdlib helper block from server.py."""
    src = io.open(SERVER, encoding="utf-8").read().splitlines()
    # Bound the block by its own markers so line drift cannot silently change it.
    start = next(i for i, l in enumerate(src) if l.startswith("def sha256("))
    end = next(i for i, l in enumerate(src) if l.startswith("# ---- keys & state"))
    block = "\n".join(src[start:end])
    for forbidden in ("import ", "open(", "eval("):
        if re.search(r"^\s*" + re.escape(forbidden), block, re.M):
            raise SystemExit(f"refusing to exec block containing {forbidden!r}")
    ns = {"hashlib": hashlib}
    exec(block, ns)
    return ns


R = load_reference()

# A 2048-bit modulus with a known bit length, so k = ceil(2048/8) + 16 = 272.
N_2048 = int(
    "ce997871d7f27e74e51ba7051186e15bc647a032a421033f8d494f5ffdcd55ab"
    "a9a792f58b5261d9066cfed6b0a463bc25dc3869b932c9edf1f529efbe717d29"
    "d73ed21121bd4d971fe0faaf297458db02ca68c0328758029b863a2d88412c88"
    "96b50fce1b9f03697e9d70b2221a2f9135d7e6ae831452678f1ab25107bafdf7"
    "c3d5554399204f7d12d5cae56dcc92dc554d9ee8b60f397d7ebf329960dc4423"
    "2ab4417f17fc19e0447b42822bb472ec9c4f7fd734c614fc6275521207f74788"
    "31cc799ff3da5103cc29ddb238c2b5f12a9b14f01ad922173a3be69815f29858"
    "d4fcbe527e1ac24e406e4b733755cc53d2ac6a11773c4f72785ebe6d5b909091", 16)

out = {"source": "reference-server/server.py", "fdh": [], "merkle": []}

# --- FDH: vary message, and vary modulus size to exercise k and the reduction ---
fdh_cases = [
    ("empty message", b"", N_2048),
    ("short", b"abc", N_2048),
    ("contract token string",
     "BCTOKEN|v1|d100-2027|t0001|0a|0b".encode(), N_2048),
    ("non-ascii utf8", "héllo wörld ∑".encode(), N_2048),
    ("block boundary 32B", b"x" * 32, N_2048),
    ("long 1000B", b"y" * 1000, N_2048),
    # Small moduli: k is small, so the reduction actually bites.
    ("tiny modulus 3", b"abc", 3),
    ("small modulus 257", b"abc", 257),
    ("17-bit modulus", b"abc", 0x1FFFF),
    ("512-bit modulus", b"abc", (1 << 512) - 1),
]
for label, msg, n in fdh_cases:
    out["fdh"].append({
        "label": label,
        "message_hex": msg.hex(),
        "n_hex": R["int_hex"](n),
        "k": (n.bit_length() + 7) // 8 + 16,
        "expected_hex": R["int_hex"](R["fdh"](msg, n)),
    })

# --- Merkle: sizes 1..17, every leaf proved ---
for size in range(1, 18):
    leaves = [f"leaf-{i}".encode() for i in range(size)]
    hs = [R["leaf_hash"](d) for d in leaves]
    out["merkle"].append({
        "size": size,
        "split": R["_split"](size) if size >= 2 else None,
        "leaves_hex": [d.hex() for d in leaves],
        "leaf_hashes_hex": [h.hex() for h in hs],
        "root_hex": R["mth"](hs).hex(),
        "proofs": [[p.hex() for p in R["audit_path"](m, hs)] for m in range(size)],
    })

# --- Primitive spot-checks ---
out["primitives"] = {
    "leaf_hash_empty": R["leaf_hash"](b"").hex(),
    "leaf_hash_abc": R["leaf_hash"](b"abc").hex(),
    "node_hash_empty_empty": R["node_hash"](b"", b"").hex(),
    "node_hash_leafa_leafb": R["node_hash"](
        R["leaf_hash"](b"a"), R["leaf_hash"](b"b")).hex(),
}

json.dump(out, sys.stdout, indent=1, sort_keys=True)
