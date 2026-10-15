# Deploying the mint

The point of hosting is a stable address. The phones currently hold the
laptop's LAN IP, which changes with every Wi-Fi network and hotspot, and the
app has to be reconfigured each time. A deployed mint has one URL that works
anywhere there is internet.

What this does not change is the trust model. A hosted mint is a convenience
for demonstrating the protocol; it is not the architecture the design argues
for. Offline payment between two phones still happens over BLE with no server
involved — the mint is only needed to issue tokens and to settle receipts
afterwards. Say so when presenting it.

## The one thing to understand first

**The mint's identity lives in the database.**

Its Ed25519 signing key and its four RSA denomination keys are rows in
`mint_identity` and `mint_keys`. Every wallet pins `mint_pub` the first time it
talks to a mint and refuses to talk to a different one — that is deliberate,
and it is what stops a substituted server from issuing tokens in the mint's
name.

The consequence for deployment: **if the database is lost, the mint is gone.**
Not reset — gone. Every wallet that registered will refuse the replacement with
"the mint's signing key changed", and the only recovery is resetting every
wallet.

This is why the deployment uses managed PostgreSQL and not SQLite on disk.
Render's filesystem is ephemeral: it is wiped on every deploy and on restart
after the free instance idles. A SQLite file there would mean a new mint
identity several times a day.

## Deploying to Render

1. Push this branch and merge it to `main`.

2. Sign in at <https://dashboard.render.com> with GitHub.

3. **New → Blueprint**, pick the `BlueCash-PBL-` repository. Render reads
   [`render.yaml`](../render.yaml) and offers to create two things: the
   `bluecash-mint` web service and the `bluecash-mint-db` PostgreSQL database.
   Approve both. The database connection string is wired into the service
   automatically — do not paste it anywhere yourself.

4. The first build takes **10–15 minutes**, because it compiles the Rust core.
   Later builds are faster: the dependency layer is cached.

5. When it finishes, check it from anywhere:

   ```bash
   curl https://bluecash-mint.onrender.com/health
   # {"status":"ok","service":"bluecash-mint","version":"0.1.0"}

   # The status page: mint fingerprint, denominations, audit root.
   curl -s -o /dev/null -w '%{http_code}\n' https://bluecash-mint.onrender.com/
   # 200
   ```

   `/docs`, `/redoc` and `/openapi.json` all return 404, and that is deliberate.
   `BLUECASH_ENV=production` withholds the schema as well as the browser that
   renders it: hiding only `/docs` would leave every route and field listed for
   anyone who asked for the JSON. Set `BLUECASH_ENV=development` in the Render
   dashboard if you want the API browser during a demo.

6. Record the mint fingerprint immediately, so you can prove later whether the
   identity has changed:

   ```bash
   curl -s https://bluecash-mint.onrender.com/mint/keys \
     | python -c "import sys,json,hashlib; print(hashlib.sha256(json.load(sys.stdin)['mint_pub'].encode()).hexdigest()[:16])"
   ```

7. In the app: **Settings → Backend**, replace the IP with the HTTPS URL.

   A wallet already registered against the laptop mint will refuse the new one,
   correctly — it is a different mint. Those wallets need resetting, so **back
   them up first** if their history is evidence you intend to keep.

## Two things that will catch you out

**The free instance sleeps.** After 15 minutes idle it stops, and the next
request takes 30–60 seconds while it wakes. In a demo that reads as a broken
app. Hit `/health` a minute before you present.

**The free database expires 30 days after creation.** When it goes, the mint
identity goes with it. Note the date. If the project needs to outlive it,
either upgrade the plan or export `mint_identity` and `mint_keys` beforehand —
they are two small tables, and they are the whole mint.

## Running the container locally

Worth doing once before deploying, because it is the same image Render builds.

Everything below is disposable: a dedicated network, a database whose port is
never published, and the mint bound to loopback on a port that collides with
nothing. `--rm` on both containers means no storage survives them.

```bash
docker build -t bluecash-mint:local .

docker network create bc-smoke-net

# No host mount, no named volume, and no -p: nothing outside the network can
# reach the database.
docker run -d --rm --name bc-smoke-db --network bc-smoke-net \
  -e POSTGRES_PASSWORD=smoketest \
  -e POSTGRES_USER=bluecash \
  -e POSTGRES_DB=bluecash \
  postgres:16-alpine

docker exec bc-smoke-db pg_isready -U bluecash -d bluecash

# 127.0.0.1:18082 -- loopback only, and clear of the development ports.
docker run -d --rm --name bc-smoke-mint --network bc-smoke-net \
  -e BLUECASH_DATABASE_URL="postgresql://bluecash:smoketest@bc-smoke-db:5432/bluecash" \
  -p 127.0.0.1:18082:8000 \
  bluecash-mint:local

docker logs bc-smoke-mint
curl -s http://127.0.0.1:18082/health
```

Tear it down with `docker stop bc-smoke-mint bc-smoke-db && docker network rm
bc-smoke-net`. Nothing persists: neither container has a volume.

`postgresql://` is rewritten to `postgresql+psycopg://` by `Settings`, so the
URL a host hands you works unchanged. This run is what exercises that rewrite:
without it the mint fails at startup with `ModuleNotFoundError: psycopg2`,
because psycopg2 is not a dependency of this project.

### What the local run established

Running exactly the above against `postgres:16-alpine`:

* Migrations applied under `PostgresqlImpl` -- the first time the schema had
  been built anywhere but SQLite.
* Bootstrap produced one Ed25519 identity and four RSA denomination keys
  (10, 50, 100 and 500 INR), with an empty audit log.
* `GET /health` and `GET /` both returned 200.
* Startup took about two seconds, and the container settled at roughly 64 MB
  -- well inside a free instance's 512 MB.

Two seconds is a laptop figure, and the first boot against an *empty* database
is the slow one: it generates four RSA-2048 keys before the port opens. On a
shared-CPU host that can take appreciably longer, and a health check impatient
enough to give up will mark the deploy failed when nothing is wrong. Watch the
first deploy's logs. Later boots reuse the stored keys and start quickly.

## Configuration

| Variable | Purpose |
| --- | --- |
| `BLUECASH_DATABASE_URL` | **Required.** The container refuses to start without it. |
| `BLUECASH_ENV` | `production` disables `/docs`. Set `development` to expose the API browser during a demo. |
| `BLUECASH_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `BLUECASH_MAX_SETTLEMENT_BATCH` | Largest accepted settlement batch. Default 500. |
| `PORT` | Set by the host. |
