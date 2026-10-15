package com.bluecash.wallet.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.bluecash.wallet.AppConfig
import com.bluecash.wallet.AppContainer
import com.bluecash.wallet.IntegrityChecker
import com.bluecash.wallet.IntegrityState
import com.bluecash.wallet.SyncScheduler
import com.bluecash.wallet.core.SelfTest
import com.bluecash.wallet.crypto.CryptoModule
import com.bluecash.wallet.crypto.DeviceIdentityStore
import com.bluecash.wallet.crypto.ProtocolIdentity
import com.bluecash.wallet.ui.components.ScreenColumn
import com.bluecash.wallet.ui.components.SectionCard
import kotlin.concurrent.thread
import com.bluecash.wallet.ui.FriendlyError

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val keyProvider = remember { CryptoModule.provideProtocolKeyProvider(context) }
    LaunchedEffect(Unit) { AppContainer.refreshAsync() }

    var identity by remember {
        mutableStateOf<ProtocolIdentity?>(if (keyProvider.hasIdentity()) keyProvider.getOrCreateIdentity() else null)
    }
    var busy by remember { mutableStateOf(false) }
    var regMessage by remember { mutableStateOf<String?>(null) }
    var syncMessage by remember { mutableStateOf<String?>(null) }
    var urlText by remember { mutableStateOf(AppContainer.serverUrl) }
    var testLog by remember { mutableStateOf<List<String>>(emptyList()) }
    var testRunning by remember { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf(false) }
    var releaseMessage by remember { mutableStateOf<String?>(null) }

    ScreenColumn {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)

        // ---- Week 2: device identity ----
        SectionCard("Device identity") {
            val current = identity
            if (current == null) {
                Text("No identity generated yet.", style = MaterialTheme.typography.bodyMedium)
                Button(onClick = {
                    identity = keyProvider.getOrCreateIdentity()
                    AppContainer.refreshAsync()
                }) { Text("Generate Device Identity") }
            } else {
                IdentityRow("Device ID", current.deviceId)
                IdentityRow("Public key", current.publicKeyHex.take(16) + "…")
                IdentityRow("Key storage", backingLabel(current.keystoreBacking))
            }
        }

        // ---- Week 3: registration with the mint ----
        SectionCard("Mint registration") {
            Text(
                if (AppContainer.registered) "Registered ✓ — this device holds a mint-issued credential."
                else "Not registered. Registering gives you a credential other phones will trust.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(enabled = identity != null && !busy && !AppContainer.registered, onClick = {
                busy = true
                regMessage = "Registering…"
                thread(name = "register") {
                    regMessage = try {
                        AppContainer.integrityBlocks()?.let { throw IllegalStateException(it) }
                        val token = IntegrityChecker.checkBlocking(context)
                        AppContainer.wallet.register(AppContainer.mintApi(), token)
                        "Registered ✓"
                    } catch (e: Exception) {
                        FriendlyError.of(e.message)
                    }
                    busy = false
                    AppContainer.refreshState()
                }
            }) { Text("Register with Mint") }
            regMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }

        // ---- backend selection ----
        SectionCard("Backend") {
            Text(
                if (AppContainer.usingSimulatedMint()) "Using the simulated mint inside the app (works with no server)."
                else "Using ${AppContainer.serverUrl}",
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedTextField(
                value = urlText,
                onValueChange = { urlText = it },
                label = { Text("Server URL (blank = simulated)") },
                placeholder = { Text("http://10.0.2.2:8000") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = { AppContainer.saveServerUrl(urlText); SyncScheduler.schedulePeriodic(context) }) { Text("Apply") }
            Text(
                "10.0.2.2 reaches your computer from the Android emulator. A phone on Wi-Fi needs your computer's LAN address.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        // ---- Week 8/9: settlement, fraud and audit status ----
        SectionCard("Settlement, fraud & audit") {
            Text("Receipts waiting to upload: ${AppContainer.pendingReceipts}", style = MaterialTheme.typography.bodyMedium)
            Text("Revoked devices known: ${AppContainer.revokedCount}", style = MaterialTheme.typography.bodyMedium)
            Text(
                "Audit root: " + if (AppContainer.auditRoot.isBlank()) "none yet" else AppContainer.auditRoot.take(16) + "…",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(enabled = !busy && AppContainer.registered, onClick = {
                busy = true
                syncMessage = "Syncing…"
                thread(name = "sync") {
                    syncMessage = try {
                        val r = AppContainer.wallet.sync(AppContainer.mintApi())
                        "Uploaded ${r.uploaded}, settled ${r.accepted}, alerts ${r.alerts.size}"
                    } catch (e: Exception) {
                        "Sync failed. " + FriendlyError.of(e.message)
                    }
                    busy = false
                    AppContainer.refreshState()
                }
            }) { Text("Sync now") }
            syncMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            if (AppContainer.alerts.isNotEmpty()) {
                Text("Fraud alerts", style = MaterialTheme.typography.titleSmall)
                AppContainer.alerts.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        }

        // ---- Week 10: device integrity ----
        SectionCard("Device integrity (Play Integrity)") {
            Text(integrityLabel(AppContainer.integrity), style = MaterialTheme.typography.bodyMedium)
            if (AppConfig.PLAY_INTEGRITY_CLOUD_PROJECT == 0L) {
                Text(
                    "Set PLAY_INTEGRITY_CLOUD_PROJECT in AppConfig.kt once you have a Google Cloud project. The mint must verify the token — the phone can't judge it itself.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            OutlinedButton(onClick = { IntegrityChecker.check(context) { s, _ -> AppContainer.integrity = s } }) { Text("Check now") }
        }

        // ---- developer tools ----
        SectionCard("Developer tools") {
            Text("Self-test runs mint → pay → deliberate double-spend → fraud detection on this phone, with no Bluetooth or server.", style = MaterialTheme.typography.bodySmall)
            Button(enabled = !testRunning, onClick = {
                testRunning = true
                testLog = listOf("Running…")
                thread(name = "selftest") {
                    SelfTest.run { line -> testLog = testLog + line }
                    testRunning = false
                }
            }) { Text(if (testRunning) "Running…" else "Run protocol self-test") }
            testLog.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }

            if (AppContainer.pendingAmount > 0) {
                Text(
                    "₹${AppContainer.pendingAmount} is locked from a payment that didn't confirm. Only release it if you're SURE the merchant did not receive it — otherwise you risk double-spending your own tokens.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedButton(onClick = {
                    thread { val n = AppContainer.wallet.releasePending(); releaseMessage = if (n == 1) "Released 1 token" else "Released $n tokens"; AppContainer.refreshState() }
                }) { Text("Release locked tokens") }
                releaseMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }

            OutlinedButton(onClick = {
                if (!confirmReset) { confirmReset = true } else {
                    confirmReset = false
                    thread { AppContainer.resetWallet() }
                }
            }) { Text(if (confirmReset) "Tap again: erase tokens & history" else "Reset wallet data") }
        }
    }
}

@Composable
private fun IdentityRow(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

private fun integrityLabel(s: IntegrityState): String = when (s) {
    IntegrityState.NotChecked -> "Not checked yet."
    IntegrityState.NotConfigured -> "Not configured — checks are skipped."
    IntegrityState.Checking -> "Checking…"
    is IntegrityState.TokenIssued -> "Token issued (${s.preview}). The mint verifies it at registration."
    is IntegrityState.Failed -> "Failed: ${s.reason} — minting and payments are blocked."
}

private fun backingLabel(backing: DeviceIdentityStore.KeystoreBacking): String = when (backing) {
    DeviceIdentityStore.KeystoreBacking.STRONGBOX -> "StrongBox (dedicated secure chip)"
    DeviceIdentityStore.KeystoreBacking.TEE -> "TEE (Trusted Execution Environment)"
    DeviceIdentityStore.KeystoreBacking.SOFTWARE_FALLBACK -> "Software fallback (dev/emulator only)"
}
