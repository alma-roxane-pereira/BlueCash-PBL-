"""
BlueCash reference backend (mint + settlement + fraud + audit) in ~250 lines.

Written from API_CONTRACT.md as an independent implementation, so the Android client can be
tested against something that isn't its own simulated mint. It is a TEACHING/TEST server:
state is in memory (optionally saved to state.json), keys live in a plain file, and there is
no authentication. Person A's real server should replace it.

Run:   pip install fastapi uvicorn cryptography
       uvicorn server:app --host 0.0.0.0 --port 8000
"""
import hashlib, json, os, time, uuid
from fastapi import FastAPI, HTTPException, Request
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# ---- group parameters: RFC 3526 group 14 ------------------------------------------------
def _modp14():
    # P = 2^2048 - 2^1984 - 1 + 2^64 * ( floor(2^1918 * pi) + 124476 ), pi via Machin's formula
    def arctan_inv(x, prec):
        one = 1 << prec; term = one // x; total = term; x2 = x * x; n = 1; sign = -1
        while term:
            term //= x2; n += 2; total += sign * (term // n); sign = -sign
        return total
    prec = 2200
    pi = 4 * (4 * arctan_inv(5, prec) - arctan_inv(239, prec))
    return 2**2048 - 2**1984 - 1 + 2**64 * ((pi >> (prec - 1918)) + 124476)

P = _modp14(); Q = (P - 1) // 2; G = 2

def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts: h.update(p)
    return h.digest()

def unhex(s: str) -> bytes: return bytes.fromhex(s)
def hex_int(s: str) -> int: return int(s, 16)
def int_hex(i: int) -> str:
    h = format(i, "x"); return h if len(h) % 2 == 0 else "0" + h

def is_element(v: int) -> bool:
    return 1 < v < P - 1 and pow(v, Q, P) == 1

def fdh(message: bytes, n: int) -> int:
    k = (n.bit_length() + 7) // 8 + 16
    out = b""; ctr = 0
    while len(out) < k:
        out += sha256(b"BCFDH|v1|", message, ctr.to_bytes(2, "big")); ctr += 1
    return int.from_bytes(out[:k], "big") % n

def challenge_x(token_id: str, n_ctx: str) -> int:
    x = int.from_bytes(sha256(f"BCSHARE|v1|{token_id}|{n_ctx}".encode()), "big")
    return x or 1

# ---- Merkle (RFC 6962) -------------------------------------------------------------------
def leaf_hash(d: bytes) -> bytes: return sha256(b"\x00", d)
def node_hash(l: bytes, r: bytes) -> bytes: return sha256(b"\x01", l, r)
def _split(n: int) -> int:
    k = 1
    while k * 2 < n: k *= 2
    return k
def mth(hs):
    if len(hs) == 1: return hs[0]
    k = _split(len(hs)); return node_hash(mth(hs[:k]), mth(hs[k:]))
def audit_path(m, hs):
    if len(hs) == 1: return []
    k = _split(len(hs))
    return audit_path(m, hs[:k]) + [mth(hs[k:])] if m < k else audit_path(m - k, hs[k:]) + [mth(hs[:k])]

# ---- keys & state ------------------------------------------------------------------------
KEYS_FILE = os.environ.get("BLUECASH_KEYS", "mint_keys.json")
STATE_FILE = os.environ.get("BLUECASH_STATE", "")
DENOMS = [10, 50, 100, 500]

def _load_keys():
    if os.path.exists(KEYS_FILE):
        return json.load(open(KEYS_FILE))
    seed = os.urandom(32); expiry = int((time.time() + 365 * 86400) * 1000)
    k = {"ed_seed": seed.hex(), "rsa": []}
    for d in DENOMS:
        pk = rsa.generate_private_key(65537, 2048); nums = pk.private_numbers()
        k["rsa"].append({"key_id": f"d{d}-ref", "amount": d, "currency": "INR", "expiry_ms": expiry,
                         "n": int_hex(nums.public_numbers.n), "e": int_hex(nums.public_numbers.e), "d": int_hex(nums.d)})
    json.dump(k, open(KEYS_FILE, "w"))
    return k

KEYS = _load_keys()
ED = ed25519.Ed25519PrivateKey.from_private_bytes(unhex(KEYS["ed_seed"]))
ED_PUB = ED.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
RSA = {k["key_id"]: k for k in KEYS["rsa"]}

S = {"devices": {}, "leaves": [], "spent": {}, "revoked": {}}
if STATE_FILE and os.path.exists(STATE_FILE): S = json.load(open(STATE_FILE))
def save():
    if STATE_FILE: json.dump(S, open(STATE_FILE, "w"))

def ed_verify(pub_hex, msg: bytes, sig_hex) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(unhex(pub_hex)).verify(unhex(sig_hex), msg); return True
    except (InvalidSignature, ValueError): return False

def now_ms(): return int(time.time() * 1000)

def verify_cred(c, at_ms) -> bool:
    msg = f"BCCRED|v1|{c['cred_id']}|{c['device_pub']}|{c['c0']}|{c['expiry_ms']}".encode()
    return c["expiry_ms"] > at_ms and ed_verify(ED_PUB.hex(), msg, c["mint_sig"])

def verify_token(t, at_ms):
    if t["expiry_ms"] <= at_ms: return "token expired"
    k = RSA.get(t["key_id"])
    if not k: return "unknown mint key"
    if (k["amount"], k["expiry_ms"], k["currency"]) != (t["amount"], t["expiry_ms"], t["currency"]): return "token does not match its mint key"
    msg = f"BCTOKEN|v1|{t['key_id']}|{t['token_id']}|{t['c0']}|{t['c1']}".encode()
    n, e = hex_int(k["n"]), hex_int(k["e"]); s = hex_int(t["sig"])
    if not (0 < s < n) or pow(s, e, n) != fdh(msg, n): return "invalid mint signature"
    if not is_element(hex_int(t["c0"])) or not is_element(hex_int(t["c1"])): return "invalid commitments"
    return None

def verify_receipt(r):
    at = r["timestamp_ms"]
    if not verify_cred(r["payer_cred"], at): return "payer credential invalid"
    if not verify_cred(r["merchant_cred"], at): return "merchant credential invalid"
    t = r["token"]
    if (e := verify_token(t, at)): return e
    if hex_int(t["c0"]) != hex_int(r["payer_cred"]["c0"]): return "token does not belong to this payer"
    x = challenge_x(t["token_id"], r["n_ctx"])
    if hex_int(r["x"]) != x: return "wrong share coordinate for this context"
    y = hex_int(r["y"])
    if not (0 <= y < Q) or pow(G, y, P) != hex_int(t["c0"]) * pow(hex_int(t["c1"]), x, P) % P: return "share is not on the committed line"
    if not ed_verify(r["payer_cred"]["device_pub"], f"BCSPEND|v1|{t['token_id']}|{r['n_ctx']}|{t['amount']}".encode(), r["payer_sig"]): return "bad payer signature"
    if r["amount"] != t["amount"]: return "amount mismatch"
    msg = f"BCRECEIPT|v1|{r['receipt_id']}|{t['token_id']}|{r['n_ctx']}|{r['x']}|{r['y']}|{r['amount']}|{r['merchant_id']}|{r['timestamp_ms']}".encode()
    if not ed_verify(r["merchant_cred"]["device_pub"], msg, r["merchant_sig"]): return "bad merchant signature"
    return None

# ---- API ---------------------------------------------------------------------------------
app = FastAPI(title="BlueCash reference mint")

@app.get("/mint/keys")
def keys():
    return {"mint_pub": ED_PUB.hex(),
            "keys": [{k: v for k, v in rk.items() if k != "d"} | {"expiry_ms": rk["expiry_ms"]} for rk in KEYS["rsa"]]}

@app.post("/mint/registerDevice")
async def register(req: Request):
    b = await req.json()
    if not ed_verify(b["device_pub"], f"BCREG|v1|{b['device_pub']}|{b['c0']}|{b['ts']}".encode(), b["sig"]): raise HTTPException(400, "registration signature invalid")
    if not is_element(hex_int(b["c0"])): raise HTTPException(400, "invalid identity commitment")
    cred_id = uuid.uuid4().hex; expiry = now_ms() + 180 * 86400 * 1000
    msg = f"BCCRED|v1|{cred_id}|{b['device_pub']}|{b['c0']}|{expiry}".encode()
    S["devices"][cred_id] = {"pub": b["device_pub"], "c0": b["c0"]}; save()
    return {"credential": {"cred_id": cred_id, "device_pub": b["device_pub"], "c0": b["c0"], "expiry_ms": expiry, "mint_sig": ED.sign(msg).hex()}}

@app.post("/mint/issue")
async def issue(req: Request):
    b = await req.json()
    dev = S["devices"].get(b["cred_id"])
    if not dev: raise HTTPException(403, "device not registered")
    if b["cred_id"] in S["revoked"]: raise HTTPException(403, "device revoked")
    if not ed_verify(dev["pub"], f"BCISSUE|v1|{b['cred_id']}|{b['key_id']}|{b['blinded']}|{b['c0']}|{b['ts']}".encode(), b["sig"]): raise HTTPException(400, "issue request signature invalid")
    if hex_int(b["c0"]) != hex_int(dev["c0"]): raise HTTPException(400, "identity commitment mismatch")
    k = RSA.get(b["key_id"])
    if not k: raise HTTPException(400, "unknown key")
    n, d = hex_int(k["n"]), hex_int(k["d"]); m = hex_int(b["blinded"])
    if not (0 < m < n): raise HTTPException(400, "blinded value out of range")
    blind_sig = int_hex(pow(m, d, n))
    S["leaves"].append(sha256(unhex(b["blinded"]) if len(b["blinded"]) % 2 == 0 else unhex("0" + b["blinded"]), unhex(blind_sig)).hex()); save()
    hs = [leaf_hash(unhex(l)) for l in S["leaves"]]; idx = len(hs) - 1
    return {"blind_sig": blind_sig, "leaf_index": idx, "tree_size": len(hs),
            "proof": [p.hex() for p in audit_path(idx, hs)], "root": mth(hs).hex()}

@app.get("/audit/root/latest")
def root():
    hs = [leaf_hash(unhex(l)) for l in S["leaves"]]
    return {"root": mth(hs).hex() if hs else "", "tree_size": len(hs), "ts": now_ms()}

def revocations(): return [{"cred_id": c, "reason": v["reason"], "ts": v["ts"]} for c, v in S["revoked"].items()]

@app.get("/fraud/revocations")
def get_revocations(): return {"revoked": revocations()}

@app.post("/settlement/uploadBatch")
async def upload(req: Request):
    results = []
    for r in (await req.json())["receipts"]:
        rid, t = r["receipt_id"], r["token"]
        err = verify_receipt(r)
        if err: results.append({"receipt_id": rid, "status": "INVALID", "detail": err}); continue
        prev = S["spent"].get(t["token_id"])
        if prev is None:
            S["spent"][t["token_id"]] = {"receipt_id": rid, "x": r["x"], "y": r["y"]}
            results.append({"receipt_id": rid, "status": "ACCEPTED", "detail": "settled"})
        elif prev["receipt_id"] == rid:
            results.append({"receipt_id": rid, "status": "DUPLICATE", "detail": "already settled"})
        else:
            x1, y1, x2, y2 = hex_int(prev["x"]), hex_int(prev["y"]), hex_int(r["x"]), hex_int(r["y"])
            detail = "double-spend detected"
            if (x2 - x1) % Q:
                a1 = (y2 - y1) * pow(x2 - x1, -1, Q) % Q; a0 = (y1 - a1 * x1) % Q
                c0 = hex_int(t["c0"])
                if pow(G, a0, P) == c0:
                    cid = next((c for c, d in S["devices"].items() if hex_int(d["c0"]) == c0), None)
                    if cid:
                        S["revoked"][cid] = {"reason": f"double-spend of token {t['token_id'][:12]}", "ts": now_ms()}
                        detail = f"double-spend: identity secret recovered, credential {cid} revoked"
            results.append({"receipt_id": rid, "status": "FRAUD", "detail": detail})
    save()
    return {"results": results, "revoked": revocations()}
