# BlueCash reference server

A small, independent implementation of `../API_CONTRACT.md` (mint, settlement, fraud, audit).
It exists so the Android app can be tested against something other than its own built-in
simulated mint, and so Person A can diff her server's behaviour against a working one.

**Test/teaching only**: in-memory state, keys in a plain file (`mint_keys.json`, created on first
run), no authentication.

## Run

```
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8000
```
(The first start generates four 2048-bit RSA keys, which takes a few seconds.)

## Point the app at it

* Android **emulator**: Settings → Backend → `http://10.0.2.2:8000` → Apply.
* **Real phones** on the same Wi-Fi: use your computer's LAN address, e.g. `http://192.168.1.20:8000`
  (allow port 8000 through the computer's firewall).

Then register and mint on each phone. Because both phones now use the SAME server, a token
spent at two different merchants is caught when both upload their receipts, and the cheater's
credential is revoked for everyone.

## Check a server against the client (automated)

```
uvicorn server:app --port 8765 &
BLUECASH_TEST_URL=http://localhost:8765 ./gradlew test     # runs HttpIntegrationTest too
```
That test drives register → blind mint (with audit-proof check) → pay → settle → double-spend →
revocation through real HTTP. It was verified against this server, and was confirmed to fail
if the server disagrees with the client on even one hash label.
