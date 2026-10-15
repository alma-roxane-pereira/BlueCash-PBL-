package com.bluecash.wallet.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
import com.bluecash.wallet.permissions.rememberBlePermissionsState
import com.bluecash.wallet.ui.FriendlyError
import com.bluecash.wallet.ui.components.ScreenColumn
import com.bluecash.wallet.ui.components.SectionCard
import kotlin.concurrent.thread

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val keyProvider = remember { CryptoModule.provideProtocolKeyProvider(context) }
    val perms = rememberBlePermissionsState()
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

    // Read from the installed package rather than BuildConfig, which this module
    // does not generate.
    val appVersion = remember {
        runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull().orEmpty()
    }

    ScreenColumn {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)

        // ---- Account / identity --------------------------------------------
        SectionCard("Your device") {
            val current = identity
            if (current == null) {
                StatusPill("No identity", ok = false)
                Text(
                    "An identity is the keypair that makes this phone itself. Nothing can be minted or paid without one.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(
                    onClick = {
                        identity = keyProvider.getOrCreateIdentity()
                        AppContainer.refreshAsync()
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Generate device identity") }
            } else {
                StatusPill("Identity ready", ok = true)
                SettingRow("Device ID", current.deviceId)
                // A truncated public key only. The private key is never read here,
                // and nothing on this screen can reveal it.
                SettingRow("Public key", current.publicKeyHex.take(16) + "…")
                SettingRow("Key storage", backingLabel(current.keystoreBacking))
            }
        }

        SectionCard("Mint registration") {
            StatusPill(
                if (AppContainer.registered) "Registered" else "Not registered",
                ok = AppContainer.registered,
            )
            Text(
                if (AppContainer.registered) "This device holds a mint-issued credential, so other phones will trust it."
                else "Registering gives you a credential other phones will trust.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                enabled = identity != null && !busy && !AppContainer.registered,
                onClick = {
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
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Register with mint") }
            regMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }

        // ---- Connectivity ---------------------------------------------------
        SectionCard("Mint server") {
            StatusPill(
                if (AppContainer.usingSimulatedMint()) "Simulated" else "Configured",
                ok = !AppContainer.usingSimulatedMint(),
            )
            Text(
                if (AppContainer.usingSimulatedMint()) "Using the simulated mint inside the app, which works with no server."
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
            Button(
                onClick = { AppContainer.saveServerUrl(urlText); SyncScheduler.schedulePeriodic(context) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Apply") }
            Text(
                "10.0.2.2 reaches your computer from the Android emulator. A phone on Wi-Fi needs your computer's LAN address.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SectionCard("Bluetooth") {
            StatusPill(if (perms.allGranted) "Granted" else "Permission needed", ok = perms.allGranted)
            Text(
                if (perms.allGranted) "Ready to discover and pay nearby devices."
                else "Required to find and pay nearby devices.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (!perms.allGranted) {
                Button(onClick = perms.request, modifier = Modifier.fillMaxWidth()) {
                    Text("Grant Bluetooth access")
                }
            }
        }

        // ---- Settlement, fraud and audit ------------------------------------
        SectionCard("Settlement, fraud & audit") {
            SettingRow("Receipts waiting to upload", "${AppContainer.pendingReceipts}")
            SettingRow("Revoked devices known", "${AppContainer.revokedCount}")
            SettingRow(
                "Audit root",
                if (AppContainer.auditRoot.isBlank()) "none yet" else AppContainer.auditRoot.take(16) + "…",
            )
            Button(
                enabled = !busy && AppContainer.registered,
                onClick = {
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
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Sync now") }
            syncMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            if (AppContainer.alerts.isNotEmpty()) {
                Text(
                    "Fraud alerts",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.error,
                )
                AppContainer.alerts.forEach {
                    Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        }

        // ---- Security --------------------------------------------------------
        SectionCard("Device integrity") {
            val configured = AppConfig.PLAY_INTEGRITY_CLOUD_PROJECT != 0L
            StatusPill(if (configured) "Configured" else "Not configured", ok = configured)
            Text(integrityLabel(AppContainer.integrity), style = MaterialTheme.typography.bodyMedium)
            if (!configured) {
                Text(
                    "Set PLAY_INTEGRITY_CLOUD_PROJECT in AppConfig.kt once you have a Google Cloud project. The mint must verify the token — the phone can't judge it itself.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedButton(
                onClick = { IntegrityChecker.check(context) { s, _ -> AppContainer.integrity = s } },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Check now") }
        }

        // ---- Developer tools --------------------------------------------------
        SectionCard("Developer tools") {
            Text(
                "Self-test runs mint → pay → deliberate double-spend → fraud detection on this phone, with no Bluetooth or server.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                enabled = !testRunning,
                onClick = {
                    testRunning = true
                    testLog = listOf("Running…")
                    thread(name = "selftest") {
                        SelfTest.run { line -> testLog = testLog + line }
                        testRunning = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (testRunning) "Running…" else "Run protocol self-test") }
            testLog.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }

            if (AppContainer.pendingAmount > 0) {
                Text(
                    "₹${AppContainer.pendingAmount} is locked from a payment that didn't confirm. Only release it if you're SURE the merchant did not receive it — otherwise you risk double-spending your own tokens.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                OutlinedButton(
                    onClick = {
                        thread {
                            val n = AppContainer.wallet.releasePending()
                            releaseMessage = if (n == 1) "Released 1 token" else "Released $n tokens"
                            AppContainer.refreshState()
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Release locked tokens") }
                releaseMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }

            // Two taps, and the second one says what it destroys. The colour only
            // appears once the action is armed, so the warning matches the risk.
            OutlinedButton(
                onClick = {
                    if (!confirmReset) confirmReset = true else {
                        confirmReset = false
                        thread { AppContainer.resetWallet() }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (confirmReset) "Tap again: erase tokens & history" else "Reset wallet data",
                    color = if (confirmReset) MaterialTheme.colorScheme.error else Color.Unspecified,
                )
            }
        }

        // ---- App information ---------------------------------------------------
        SectionCard("About") {
            SettingRow("App version", if (appVersion.isBlank()) "unknown" else appVersion)
            Text(
                "BlueCash Protocol — offline peer-to-peer digital cash over Bluetooth.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** A label above its value: the shape every read-only fact on this screen takes. */
@Composable
private fun SettingRow(label: String, value: String) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * A small status chip. Deliberately not a switch: everything it reports is a
 * state the app observes, not a setting a tap could change, and a switch that
 * does nothing is worse than a label.
 */
@Composable
private fun StatusPill(text: String, ok: Boolean) {
    Row(horizontalArrangement = Arrangement.Start, modifier = Modifier.fillMaxWidth()) {
        Surface(
            shape = MaterialTheme.shapes.small,
            color = if (ok) MaterialTheme.colorScheme.primaryContainer
            else MaterialTheme.colorScheme.surfaceVariant,
        ) {
            Text(
                text,
                style = MaterialTheme.typography.labelMedium,
                color = if (ok) MaterialTheme.colorScheme.onPrimaryContainer
                else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            )
        }
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
