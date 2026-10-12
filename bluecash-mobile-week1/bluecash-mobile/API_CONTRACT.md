# BlueCash backend contract (for Person A)

The Android app talks to the backend through `core/HttpMintApi.kt`. The simulated mint in
`core/SimulatedMint.kt` is an **executable reference implementation** of everything below —
if in doubt, read it. Set the server URL in the app under **Settings → Backend**.

All bodies are JSON; all binary values are **lowercase hex**; big integers are big-endian hex.
Errors: any non-2xx status with a short text body (the app shows it).

## Cryptographic parameters (must match exactly)

| Thing | Definition |
|---|---|
| Device signatures | Ed25519 (32-byte public keys, 64-byte signatures) |
| Mint token signature | RSA blind signature, 2048-bit, e = 65537, **full-domain hash** (below) |
| Share group | RFC 3526 group 14 (2048-bit safe prime P), Q = (P-1)/2, g = 2. Work in the order-Q subgroup. |
| Hash | SHA-256 |
| Merkle tree | RFC 6962/9162: leaf = SHA256(0x00‖data), node = SHA256(0x01‖left‖right), split at the largest power of two < n |

**FDH(message, n)**: `k = ceil(bitlen(n)/8) + 16` bytes; output = concatenation of
`SHA256("BCFDH|v1|" ‖ message ‖ ctr)` for `ctr = 0,1,2…` (ctr as 2-byte big-endian), truncated to `k` bytes,
read as a big-endian integer, `mod n`. A token signature `s` is valid iff `s^e mod n == FDH(message, n)`.

**Signed strings** (UTF-8, `|`-separated, exact):

| Purpose | String |
|---|---|
| Token (mint signs, blinded) | `BCTOKEN|v1|{key_id}|{token_id}|{c0}|{c1}` |
| Credential (mint signs, Ed25519) | `BCCRED|v1|{cred_id}|{device_pub}|{c0}|{expiry_ms}` |
| Register request (device signs) | `BCREG|v1|{device_pub}|{c0}|{ts}` |
| Issue request (device signs) | `BCISSUE|v1|{cred_id}|{key_id}|{blinded}|{c0}|{ts}` |
| Spend (payer signs) | `BCSPEND|v1|{token_id}|{n_ctx}|{amount}` |
| Receipt (merchant signs) | `BCRECEIPT|v1|{receipt_id}|{token_id}|{n_ctx}|{x}|{y}|{amount}|{merchant_id}|{timestamp_ms}` |

`c0`, `c1` are hex of the big-endian integers (even length, lowercase). Compare them as integers, not strings.

## Endpoints

### `GET /mint/keys`
```json
{ "mint_pub": "<ed25519 pub hex>",
  "keys": [ { "key_id": "d100-2027", "amount": 100, "currency": "INR",
              "expiry_ms": 1830211200000, "n": "<hex>", "e": "010001" } ] }
```
One RSA key per denomination; the key id fixes amount and expiry. The app **pins** `mint_pub`
on first contact and refuses a mint whose key later changes.

### `POST /mint/registerDevice`
Request: `{ "device_pub", "c0", "ts", "sig", "integrity_token"? }` where `sig` signs the *Register* string.
Verify the signature, that `c0` is a quadratic residue mod P (`2 ≤ c0 ≤ P-2`, Jacobi symbol 1), and (when configured) the Play Integrity token.
Response: `{ "credential": { "cred_id", "device_pub", "c0", "expiry_ms", "mint_sig" } }`
(`cred_id` any unique string; `mint_sig` signs the *Credential* string.) Remember `cred_id → (device_pub, c0)`: this is how a recovered secret is mapped to a person.

### `POST /mint/issue`
Request: `{ "cred_id", "key_id", "blinded", "c0", "ts", "sig" }`.
Check: credential exists and is not revoked; `sig` valid (*Issue* string, with the registered device key); `c0` equals the registered one; `0 < blinded < n`.
Compute `blind_sig = blinded^d mod n` with that key's private exponent, debit the account, then **append to the audit log** the leaf `SHA256(blinded_bytes ‖ blind_sig_bytes)` and return:
```json
{ "blind_sig": "<hex>", "leaf_index": 7, "tree_size": 8, "proof": ["<hex>", "..."], "root": "<hex>" }
```
The app verifies the inclusion proof against `root` and refuses the token otherwise.
(The mint never sees `token_id` or `c1` — that is the point of the blinding.)

### `GET /audit/root/latest`
`{ "root": "<hex>", "tree_size": 8, "ts": 1790000000000 }`

### `POST /settlement/uploadBatch`
Request: `{ "receipts": [ { "receipt_id", "token": {token_id,key_id,amount,currency,expiry_ms,c0,c1,sig},
"n_ctx", "x", "y", "amount", "payer_cred": {…}, "payer_sig", "merchant_id", "merchant_cred": {…}, "merchant_sig", "timestamp_ms" } ] }`

For each receipt, validate **all** of (see `Verify.receipt` in `core/MintApi.kt`):
1. both credentials: mint signature valid and not expired at `timestamp_ms`;
2. token: not expired, `key_id` known, amount/expiry match the key, RSA signature valid, `c0`,`c1` are subgroup elements;
3. `token.c0 == payer_cred.c0`;
4. `x == SHA256("BCSHARE|v1|{token_id}|{n_ctx}")` as a big-endian integer;
5. `g^y ≡ c0 · c1^x (mod P)` and `0 ≤ y < Q`;
6. `payer_sig` valid for the *Spend* string under `payer_cred.device_pub`; `merchant_sig` valid for the *Receipt* string under `merchant_cred.device_pub`.

Then per `token_id`:
* first time → `ACCEPTED` (credit the merchant), remember `(receipt_id, x, y)`;
* same `receipt_id` again → `DUPLICATE` (idempotent, harmless);
* different `receipt_id` → **double-spend**: with the two points `(x1,y1)`, `(x2,y2)`:
  `a1 = (y2−y1)·(x2−x1)⁻¹ mod Q`, `a0 = y1 − a1·x1 mod Q`. If `g^a0 == c0`, look up the credential whose `c0` matches and **revoke** it. Respond `FRAUD`.
* any validation failure → `INVALID` with a `detail`.

Response:
```json
{ "results": [ { "receipt_id": "…", "status": "ACCEPTED|DUPLICATE|FRAUD|INVALID", "detail": "…" } ],
  "revoked": [ { "cred_id": "…", "reason": "…", "ts": 1790000000000 } ] }
```

### `GET /fraud/revocations`
`{ "revoked": [ { "cred_id", "reason", "ts" } ] }` — the full list; devices cache it and refuse to transact with anyone on it.

## What the app does NOT need
No per-spend Merkle proof (it can't coexist with blind signatures — see README), no push channel
(the app polls revocations whenever it syncs).
