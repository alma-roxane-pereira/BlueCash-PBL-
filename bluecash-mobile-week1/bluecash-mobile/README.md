# BlueCash Wallet — Android client

Kotlin + Jetpack Compose wallet for the BlueCash Protocol: offline peer-to-peer
payments over BLE, with tokens minted and settled through the backend defined in
[`API_CONTRACT.md`](API_CONTRACT.md).

## What is implemented

Four screens, all functional, wired through a bottom navigation bar
(`navigation/BlueCashNavHost.kt`, `navigation/Destinations.kt`):

| Route | Screen | What it does |
|---|---|---|
| `wallet_home` | `WalletHomeScreen.kt` | Balance, onboarding checklist, add money |
| `pay` | `PayScreen.kt` | BLE permissions, QR scan of the merchant, pay flow |
| `receive` | `ReceiveScreen.kt` | Amount and shop name, BLE advertise, receive |
| `settings` | `SettingsScreen.kt` | Generate device identity, register with mint, backend URL |

`ui/screens/PlaceholderScreen.kt` still exists but is **not routed** — no screen
is a placeholder any more.

Also implemented: BLE payer and merchant roles (`ble/`), the Chaum/RSA blind
signature and Feldman share maths (`core/`), a hash-chained local ledger
(`core/HashChainLedger.kt`), encrypted key storage
(`crypto/DeviceIdentityStore.kt`), background settlement sync
(`SettlementSyncWorker.kt`), QR scanning (`QrUtil.kt`) and a Play Integrity
check (`IntegrityChecker.kt`).

**Cryptography runs on BouncyCastle, not the Rust core.** `crypto/CryptoModule.kt`
returns `BouncyCastleProtocolKeyProvider`; the UniFFI bindings to
`crates/bluecash-crypto` are not generated and not wired in. The seam for
swapping them is `crypto/ProtocolKeyProvider.kt`.

## Prerequisites

| Requirement | Needed | Verified locally |
|---|---|---|
| JDK | 17 or newer (the build targets Java 17) | JBR 21.0.6, bundled with Android Studio |
| Android SDK platform | **android-35** (`compileSdk = 35`, `targetSdk = 35`) | present |
| Build tools | 35.0.0 | present |
| Device/emulator | **API 26+** (`minSdk = 26`) | — |
| Gradle | **8.10.2**, supplied by the wrapper | **8.10.2 via `./gradlew`, verified** |
| AGP / Kotlin | 8.7.2 / 2.1.0 (`gradle/libs.versions.toml`) | resolved and built |

Android Studio supplies a compatible JDK and Gradle, so it is the simplest route.

## The Gradle wrapper

`gradlew`, `gradlew.bat` and `gradle/wrapper/gradle-wrapper.jar` are committed,
so the project builds with the **Gradle 8.10.2** that
`gradle/wrapper/gradle-wrapper.properties` pins. No local Gradle installation is
needed and no one has to guess a version.

```bash
./gradlew <task>      # macOS, Linux, Git Bash, WSL
gradlew.bat <task>    # Windows cmd.exe or PowerShell
```

The **first run downloads the pinned 8.10.2 distribution** into
`~/.gradle/wrapper/dists/`; later runs reuse it. `validateDistributionUrl=true`
is set in the properties file, so the wrapper checks the distribution URL before
fetching.

> **The first build also re-downloads dependency metadata**, even on a machine
> where another Gradle version already built this project. Gradle stores module
> descriptors per cache format: 8.10.2 reads `metadata-2.106`, Gradle 8.13 writes
> `metadata-2.107`. The jars themselves are shared in `files-2.1/`, but until
> 8.10.2 has resolved online once, `--offline` fails with "No cached version of
> … available for offline mode" even though the artifacts are on disk.

## Opening the project

Open the **`bluecash-mobile`** folder — the one containing `settings.gradle.kts`
— in Android Studio (**File → Open**). The project is `BlueCashWallet` with a
single module, `:app`.

Note there is a stray `app/app/` directory containing a byte-identical copy of
`app/src`. `settings.gradle.kts` includes only `:app`, so Gradle never reads it;
editing files there has no effect.

## Configuring the SDK path

`local.properties` is **gitignored** and must not be committed — it contains an
absolute path specific to one machine. Two ways to supply it:

**1. Let Android Studio create it.** Opening the project generates
`local.properties` with the correct `sdk.dir` for your machine. Nothing to do.

**2. Use an environment variable**, which needs no file at all:

```bash
# Windows (Git Bash / WSL)
export ANDROID_HOME="C:\Users\<you>\AppData\Local\Android\Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"

# macOS / Linux
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
```

This is **verified working**: it is how the integration tests below were run.

> If a `local.properties` you inherited points at someone else's home directory,
> the build fails with `SDK location not found`. Either delete it and let
> Android Studio regenerate it, or set `ANDROID_HOME` — which takes effect
> without editing any file.

## Building and testing

```bash
cd bluecash-mobile
export JAVA_HOME="C:/Program Files/Android/Android Studio/jbr"
export ANDROID_HOME="C:/Users/<you>/AppData/Local/Android/Sdk"

# Unit tests
./gradlew :app:testDebugUnitTest

# A debug APK
./gradlew :app:assembleDebug
```

`:app:testDebugUnitTest` is **verified through the wrapper** (2026-10-12): the
task compiled and executed, and **31 tests completed — 29 passed, 0 failed,
2 skipped**. The two skips are the HTTP tests, which skip themselves without
`BLUECASH_TEST_URL`; they are run separately, below.

`:app:assembleDebug` is the standard task but **has not been run here** — treat
it as untested on this setup.

Stop the daemon when finished — it can outlive the build:

```bash
./gradlew --stop
```

### Tests that exist

| File | Tests | Needs |
|---|---|---|
| `app/src/test/.../CoreTests.kt` | 29 | nothing — pure JVM, offline |
| `app/src/test/.../HttpIntegrationTest.kt` | 2 | a running backend |

There is **no `app/src/androidTest/` directory**, so there are no instrumented
tests despite `androidTest` dependencies being declared in `app/build.gradle.kts`.

### A fixed flakiness, worth knowing about

`EndToEndTests.tamperedTokenIsRejectedByMerchant` used to fail intermittently
— one pass in five runs — with `expected:<REJECTED> but was:<SUCCESS>`.

The test, not the protocol, was unsound. It tampers a 10-token so it claims
`amount = 100`, then spends 100 from a wallet that also held a *genuine*
100-token. `selectExact` sorts `sortedByDescending { it.token.amount }`
(`core/Wallet.kt:161`), so the forged and genuine tokens tied, and the tiebreak
fell to the order of `kv.keys("token:")` — which follows randomly generated
token ids. Whenever the genuine token was selected, the payment legitimately
succeeded and the assertion failed.

The fixture now funds that wallet with 60 (a 50 and a 10) instead of 160, so no
genuine 100 exists and the forgery is the only token that can fund the payment.
The assertion is unchanged, and no production code was touched. Verified
deterministic: **10 consecutive passes**.

The same tie-break nondeterminism applies to any future test that puts two
equal-amount tokens in one wallet and expects a particular one to be spent.

### Running the HTTP integration tests

These are JVM unit tests, not instrumented — **no emulator required**. They skip
themselves unless `BLUECASH_TEST_URL` is set (`HttpIntegrationTest.kt:19-20`).

The mint stores its keys in its database, so pointing the backend at a throwaway
database file outside the repository keeps test keys out of any real one.

```bash
# Terminal 1 — the FastAPI backend (see ../../backend/README.md)
cd backend
BLUECASH_DATABASE_URL="sqlite:///<a path outside the repo>/test-mint.db" \
BLUECASH_ENV=test \
  ../.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2
cd bluecash-mobile
BLUECASH_TEST_URL=http://127.0.0.1:8000 \
  ./gradlew :app:testDebugUnitTest --tests "*HttpIntegrationTest*" --rerun
```

`--rerun` matters: Gradle does not treat an environment-variable change as
invalidating the test task, so without it the tests are reported as up to date
and never execute.

Both tests are **verified passing** (2026-10-12) against a loopback backend on a
temporary database: `tests="2" skipped="0" failures="0" errors="0"`,
`fullStoryAgainstRealServer` in 0.283 s and `serverRejectsForgedReceipt` in
0.304 s. The run exercised all six contract endpoints — `/mint/keys`,
`/mint/registerDevice`, `/mint/issue`, `/audit/root/latest`,
`/settlement/uploadBatch` and `/fraud/revocations`.

The two tests drive the whole protocol — register three devices, blind-mint 160
across denominations with audit-proof verification, pay, replay the same token
offline at a second shop, settle both, confirm the double-spender is revoked and
can no longer mint, and check a forged receipt is rejected.

The reference implementation at `reference-server/` works as a backend too, and
is useful for isolating whether a failure is in the client or the server.


## Pointing the app at a backend

In the app: **Settings → Backend**, enter the URL, tap **Apply**.

| Running on | URL |
|---|---|
| **Emulator** | `http://10.0.2.2:8000` — the emulator's alias for your computer's loopback |
| **Physical device** | `http://<your-computer-LAN-IP>:8000`, e.g. `http://192.168.1.20:8000` |

For a physical device both must be on the same Wi-Fi, the backend must bind
`0.0.0.0` rather than `127.0.0.1`, and your firewall must allow the port. Binding
beyond loopback exposes the mint to your network — do it deliberately.

Plain HTTP works because `AndroidManifest.xml:49` sets
`usesCleartextTraffic="true"`. That is **development only** and must be removed,
with the backend served over TLS, before any real deployment.

## Known setup limitations

- **The first build must be online** — it fetches the pinned Gradle 8.10.2
  distribution and re-resolves dependency metadata for the 8.10.2 cache format
  (see [The Gradle wrapper](#the-gradle-wrapper)). `--offline` only works after
  one successful online build.
- **`selectExact` does not break amount ties deterministically** (above) —
  harmless in production, but a trap when writing tests.
- **No instrumented tests**, so nothing automatically exercises BLE, the
  Keystore, or the Compose UI. BLE in particular needs two real devices and has
  never been verified in this setup.
- **Play Integrity is not verified by the backend**; the token is stored and
  ignored.
- **The app has not been run on an emulator or device here** — only built, and
  its JVM tests executed. Screenshots and UI behaviour are unverified.
