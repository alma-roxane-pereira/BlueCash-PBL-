# BlueCash mint backend

FastAPI backend for the BlueCash Protocol: the mint, settlement, audit and
fraud endpoints defined in
[`API_CONTRACT.md`](../bluecash-mobile-week1/bluecash-mobile/API_CONTRACT.md).

Cryptographic operations are performed by the shared Rust core
(`crates/bluecash-crypto`) through its PyO3 bindings, so this backend and the
Android client run the same implementation of the protocol maths rather than
two that can drift apart. The one exception is RSA **key generation**, which the
bindings do not expose and which uses `cryptography` — the same library the
reference server uses for it.

> **Prototype. Not production software.** See
> [Security limitations](#security-limitations) before running this anywhere
> that matters.

## Status

All six contract endpoints are implemented and covered by tests.

**Compatibility with the Android client has not been demonstrated.** The tests
assert behaviour against the contract and reproduce the reference server's
status values and detail strings, but no differential run against
[`reference-server/`](../bluecash-mobile-week1/bluecash-mobile/reference-server/)
has happened yet, and the Android client has never been pointed at this backend.
Until that exists, treat compatibility as intended rather than proven.

Not implemented:

- Play Integrity verification (tokens are stored, never checked)
- BBS+ anonymous credentials
- any endpoint beyond the six in the contract

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness. Touches no database, keys or crypto. |
| `GET` | `/mint/keys` | Mint public key and denomination keys. Clients **pin** `mint_pub`. |
| `POST` | `/mint/registerDevice` | Verify a device signature and `c0`, return a mint-signed credential. |
| `POST` | `/mint/issue` | Blind-sign a token, append an audit leaf, return the inclusion proof. |
| `GET` | `/audit/root/latest` | Current Merkle root. `""` when the log is empty. |
| `POST` | `/settlement/uploadBatch` | Settle receipts; detect double spends and revoke. |
| `GET` | `/fraud/revocations` | The full revocation list. |

Errors are FastAPI's JSON envelope, e.g. `HTTP 403 {"detail": "device revoked"}`
— the same shape the reference server produces. Settlement is the exception: an
invalid receipt is a per-receipt `INVALID` result inside an HTTP 200, never a
batch-level error.

## Setup

Uses the project virtual environment at `../.venv`. On macOS or Linux the
interpreter is `../.venv/bin/python` instead of `../.venv/Scripts/python.exe`.

```bash
cd backend
../.venv/Scripts/python.exe -m alembic upgrade head
../.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```bash
curl http://127.0.0.1:8000/health
# {"status":"ok","service":"bluecash-mint","version":"0.1.0"}
```

Interactive docs are at `/docs` (disabled when `BLUECASH_ENV=production`).

### First run generates keys — keep the database

On first start the mint generates an Ed25519 identity and four 2048-bit RSA
denomination keys. That takes a few seconds, and the keys are written to the
database.

**The database must persist.** Clients pin `mint_pub` on first contact and
refuse a mint whose key later changes, so deleting `bluecash.db` does not reset
the mint — it orphans every wallet that has already registered, and invalidates
every token in circulation. Back it up accordingly.

Startup calls `create_all` for convenience in development. For anything you care
about, run `alembic upgrade head` instead so the schema is versioned.

### Pointing the Android app at a local backend

For **local development only**: an Android emulator reaches the host at
`10.0.2.2`, so in the app under Settings → Backend use `http://10.0.2.2:8000`.
This is a development convenience over cleartext HTTP, not a deployment address.

## Configuration

Settings live in `app/config.py`, read from the environment with the
`BLUECASH_` prefix or from a `.env` file (`.env` is gitignored).

| Variable | Default | Meaning |
|---|---|---|
| `BLUECASH_ENV` | `development` | `development`, `test` or `production` |
| `BLUECASH_LOG_LEVEL` | `INFO` | root log level |
| `BLUECASH_HOST` | `127.0.0.1` | bind address; exposing the mint is a deliberate choice |
| `BLUECASH_PORT` | `8000` | bind port |
| `BLUECASH_DATABASE_URL` | `sqlite:///./bluecash.db` | synchronous SQLite via the stdlib driver |
| `BLUECASH_DATABASE_ECHO` | `false` | log every SQL statement |
| `BLUECASH_SERVICE_NAME` | `bluecash-mint` | reported by `/health` |
| `BLUECASH_VERIFY_PLAY_INTEGRITY` | `false` | **no effect** — verification is not implemented |

## Database

Synchronous SQLAlchemy over Python's built-in `sqlite3`. The schema is written
to stay PostgreSQL-compatible, so moving later is a URL change plus a driver.

| Table | Holds | Contract reference |
|---|---|---|
| `mint_identity` | the mint's Ed25519 signing key (single row) | `mint_pub`, lines 39-47 |
| `mint_keys` | one RSA key per denomination | `GET /mint/keys` |
| `devices` | registered credentials, `cred_id -> (device_pub, c0)` | line 52 |
| `audit_leaves` | append-only Merkle log, `SHA256(blinded‖blind_sig)` | lines 57-60 |
| `spent_tokens` | first settled spend per token, with `(receipt_id, x, y)` | lines 79-85 |
| `revocations` | revoked credentials | `GET /fraud/revocations` |
| `balances` | account and merchant bookkeeping | lines 59, 80 |

Two deliberate absences:

- `audit_leaves` has no `token_id` and no `c1`. The mint never sees them — that
  is what makes issuance unlinkable from settlement (line 62).
- `devices` is deliberately linkable, because mapping a recovered secret back to
  a person is how double-spend detection works. It is also why honest spends are
  not anonymous here: BBS+ is not implemented.

Spent state is keyed by `token_id` alone. `receipt_id` is indexed but **not
unique**, matching both reference implementations: the same receipt id on two
different tokens is accepted.

### SQLite transaction handling

`app/db/session.py` configures three things that SQLite needs and PostgreSQL
does not:

- `PRAGMA foreign_keys=ON` — SQLite ignores foreign keys otherwise.
- `isolation_level = None` plus an explicit `BEGIN IMMEDIATE` — pysqlite does
  not emit `BEGIN` on its own and commits implicitly around `SAVEPOINT`, which
  made a released savepoint durable and meant a failed settlement batch could
  leave earlier receipts committed. `IMMEDIATE` also takes the write lock up
  front, avoiding the lock-upgrade failure that read-then-write requests hit.
- `PRAGMA busy_timeout=5000` — a competing writer waits rather than failing.

The cost is that transactions serialise. That is the right trade for a prototype
and is specific to SQLite.

### Migrations

Migrations are the source of truth for a real database; `create_all` is for
tests. `migrations/env.py` reads the URL from application settings, so a
migration cannot be applied to a different database than the app uses.

```bash
cd backend
../.venv/Scripts/python.exe -m alembic upgrade head        # apply
../.venv/Scripts/python.exe -m alembic current             # applied revision
../.venv/Scripts/python.exe -m alembic history             # all revisions
../.venv/Scripts/python.exe -m alembic downgrade -1        # undo one
../.venv/Scripts/python.exe -m alembic upgrade head --sql  # print SQL, apply nothing
```

After changing `app/db/models.py`:

```bash
../.venv/Scripts/python.exe -m alembic revision --autogenerate -m "what changed"
```

Always read the generated file before committing it — autogenerate does not
detect every change, notably `CHECK` constraints and some type changes.

To target a different database for one command:

```bash
BLUECASH_DATABASE_URL="sqlite:///./scratch.db" ../.venv/Scripts/python.exe -m alembic upgrade head
```

`test_migration_matches_the_models` builds one database by migration and another
by `create_all` and diffs them, so the two cannot drift apart unnoticed.

## Tests

```bash
cd backend
../.venv/Scripts/python.exe -m pytest           # whole suite
../.venv/Scripts/python.exe -m pytest tests/test_settlement_api.py -q
../.venv/Scripts/python.exe -m pytest -k double_spend -v
```

Every test uses a temporary database under pytest's `tmp_path` and keys
generated for that test. The suite creates no real database; a test asserts
this, and it caught a leak once already.

The Rust core and its Python bindings have their own suites:

```bash
cd crates/bluecash-crypto
cargo test --offline
../../.venv/Scripts/python.exe -m pytest tests/test_bindings.py -q
```

## Layout

```
backend/
├── alembic.ini
├── app/
│   ├── config.py        # settings
│   ├── codec.py         # hex/int conversions at the HTTP edge
│   ├── protocol.py      # signed-string formats, crypto via the Rust core
│   ├── mint_keys.py     # first-run key generation
│   ├── schemas.py       # request/response models
│   ├── main.py          # app factory and `app`
│   ├── api/
│   │   ├── health.py
│   │   ├── mint.py       # /mint/*, /audit/root/latest
│   │   └── settlement.py # /settlement/uploadBatch, /fraud/revocations
│   └── db/
│       ├── models.py
│       └── session.py
├── migrations/
│   └── versions/0001_initial_mint_schema.py
├── tests/
└── pyproject.toml
```

## Security limitations

This is a prototype built against a course deadline. It has **not** had an
independent security review, and the following are known and unaddressed:

- **Mint private keys are stored in the database.**
  `mint_identity.ed25519_seed_hex` and `mint_keys.d_hex` are private keys held
  in plaintext rows. They belong in an HSM or KMS; anyone with the database file
  can mint money.
- **Expiry is checked against a client-supplied timestamp.** Settlement uses
  `timestamp_ms` from the receipt to decide whether credentials and tokens have
  expired, so a merchant can backdate to use expired material. The reference
  behaves the same way.
- **Register and issue requests are replayable.** `ts` is carried in the signed
  string but never checked for freshness, so a captured request can be resent.
  Matches the reference; tightening it unilaterally would risk rejecting a valid
  client.
- **No authentication or rate limiting.** Any party that can reach the mint can
  register devices and request issuance.
- **No batch size limit.** A single `/settlement/uploadBatch` call can contain
  arbitrarily many receipts, each requiring several modular exponentiations.
- **Play Integrity is not verified.** The token is stored and
  `integrity_verified` stays false. `BLUECASH_VERIFY_PLAY_INTEGRITY` does
  nothing.
- **BBS+ anonymous credentials are not implemented.** The proposal describes
  this gap as closed; it is not. Credentials are plain Ed25519 and are sent with
  every receipt, so honest spends are **linkable** by the mint and by merchants.
  The anonymity property the proposal claims is not provided.
- **Cleartext HTTP.** There is no TLS, and the Android client ships
  `usesCleartextTraffic="true"` for development. Both must change before any
  real deployment.
- **No independent audit** of the protocol or its implementation.

Separately, the signed strings are `|`-separated while `n_ctx` itself contains
`|` characters (`Sessions.kt:232`), so they are not uniquely decodable. Both
sides build them identically so signatures verify, but it is worth noting.
