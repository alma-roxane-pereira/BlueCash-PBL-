# BlueCash Wallet — Android Client (Person B)

Week 1 scaffold: Kotlin + Jetpack Compose project, BLE permissions, and the
four-screen navigation shell (Wallet, Pay, Receive, Settings).

## Opening this project

1. Unzip this folder somewhere convenient.
2. Open **Android Studio** → **File → Open** → select the `bluecash-mobile`
   folder (the one containing `settings.gradle.kts`).
3. Android Studio will notice there's no Gradle wrapper (`gradlew`) checked
   in and offer to generate one — accept it. If it doesn't prompt
   automatically, run **File → New → Import Project** on the same folder,
   or from a terminal with Gradle installed:
   ```
   gradle wrapper --gradle-version 8.10.2
   ```
4. Let Gradle sync. Android Studio may suggest upgrading the Android
   Gradle Plugin / Kotlin version shown in `gradle/libs.versions.toml` —
   that's expected and fine to accept; these version numbers will drift
   over the life of the project.
5. Run on an emulator or device with **API 26+** (min SDK is 26, since
   StrongBox and several BLE APIs we'll use from Week 2 onward assume it).

## What's implemented (Week 1)

- Project scaffold: Gradle Kotlin DSL, version catalog, Compose enabled.
- `AndroidManifest.xml`: full BLE permission set for both pre- and
  post-Android 12 (API 31 split), plus the camera permission reserved for
  the Week 4 QR fallback.
- `permissions/BlePermissions.kt`: a `rememberBlePermissionsState()`
  composable that checks current grant status and exposes a `request()`
  callback — no extra permissions library needed.
- `navigation/`: bottom-nav shell wiring four screens (Wallet, Pay,
  Receive, Settings).
- `ui/screens/WalletHomeScreen.kt`: the only screen with real logic so
  far — it shows BLE permission status and lets you grant it. Run the app
  and tap **Grant Bluetooth Access** to see the flow end to end.
- The other three screens are intentional placeholders; each one's body
  text says which week fills it in, so nothing here needs to be
  rediscovered later.

## Not yet included (comes with later weeks)

- UniFFI-generated bindings to the shared `bluecash-crypto` Rust core
  (Week 2) — there's a reserved package for them once Person A's crate
  interface is frozen.
- Native BLE scan/advertise code, CameraX + ZXing for QR (Week 4).
- Room + SQLCipher-for-Android local encrypted ledger (Week 6).
- WorkManager background sync (Week 8).

These aren't stubbed out yet on purpose — adding empty dependencies now
would just be version-pinning risk for libraries we don't need for another
few weeks.

## Next step

Once Person A circulates the frozen `bluecash-crypto` UniFFI interface
(end of Week 1), Week 2 starts with:
```
cargo ndk -t arm64-v8a -t x86_64 -o app/src/main/jniLibs build --release
uniffi-bindgen generate --language kotlin --out-dir app/src/main/java/com/bluecash/wallet/crypto/generated
```
