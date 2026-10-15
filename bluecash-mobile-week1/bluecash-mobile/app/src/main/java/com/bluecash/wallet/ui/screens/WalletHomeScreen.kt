package com.bluecash.wallet.ui.screens


import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.bluecash.wallet.AppContainer
import com.bluecash.wallet.permissions.rememberBlePermissionsState
import com.bluecash.wallet.ui.components.ScreenColumn
import com.bluecash.wallet.ui.components.SectionCard
import kotlin.concurrent.thread
import com.bluecash.wallet.ui.components.BalanceCard
import com.bluecash.wallet.ui.FriendlyError
import com.bluecash.wallet.ui.HistoryText
import androidx.compose.ui.Alignment
import androidx.compose.foundation.layout.width

@Composable
fun WalletHomeScreen() {
    val blePermissions = rememberBlePermissionsState()
    LaunchedEffect(Unit) { AppContainer.refreshAsync() }

    var amountText by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    ScreenColumn {
        Text("BlueCash Wallet", style = MaterialTheme.typography.headlineMedium)
        Text("Offline peer-to-peer payments over Bluetooth.", style = MaterialTheme.typography.bodyMedium)

        BalanceCard {
            Text("₹${AppContainer.balance}", style = MaterialTheme.typography.displayMedium)
            Text(
                "${AppContainer.tokenCount} token(s)" +
                        if (AppContainer.pendingAmount > 0) "  ·  ₹${AppContainer.pendingAmount} locked (unconfirmed payment)" else "",
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        if (!AppContainer.hasIdentity || !AppContainer.registered) {
            SectionCard("Finish setup") {
                Text(if (!AppContainer.hasIdentity) "1. Open Settings and tap “Generate Device Identity”." else "1. Device identity ✓")
                Text("2. In Settings, tap “Register with Mint”.")
                Text("Then come back here to add money.", style = MaterialTheme.typography.bodySmall)
            }
        } else {
            SectionCard("Add money (mint tokens)") {
                Text(
                    if (AppContainer.usingSimulatedMint()) "Using the simulated mint inside the app (demo money)."
                    else "Using server ${AppContainer.serverUrl}",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = amountText,
                    onValueChange = { amountText = it.filter(Char::isDigit).take(6) },
                    label = { Text("Amount (₹, multiples of 10)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    enabled = !busy && (amountText.toIntOrNull() ?: 0) > 0,
                    onClick = {
                        val amount = amountText.toInt()
                        busy = true
                        message = "Starting…"
                        thread(name = "mint") {
                            message = try {
                                AppContainer.integrityBlocks()?.let { throw IllegalStateException(it) }
                                AppContainer.wallet.mint(AppContainer.mintApi(), amount) { message = it }
                                "Minted ₹$amount ✓"
                            } catch (e: Exception) {
                                FriendlyError.of(e.message)
                            }
                            busy = false
                            AppContainer.refreshState()
                        }
                    },
                ) { Text(if (busy) "Working…" else "Mint") }
                message?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }
        }

        SectionCard("Bluetooth permissions") {
            Text(
                if (blePermissions.allGranted) "Granted — ready to discover nearby devices."
                else "Required to find and pay nearby devices.",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (!blePermissions.allGranted) {
                Button(onClick = blePermissions.request) { Text("Grant Bluetooth Access") }
                if (blePermissions.shouldShowRationale) {
                    Text("BlueCash needs Bluetooth to pay nearby devices without internet.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        SectionCard("History") {
            Text(
                if (AppContainer.ledgerOk) "Ledger integrity: intact ✓" else "Ledger integrity: TAMPERING DETECTED ✗",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (AppContainer.recent.isEmpty()) Text("Nothing yet.", style = MaterialTheme.typography.bodySmall)
            AppContainer.recent.forEach { e ->
                val row = HistoryText.format(e)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        row.icon,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.width(28.dp),
                    )
                    Column(Modifier.weight(1f)) {
                        Text(row.title, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            listOf(row.time, row.detail).filter { it.isNotEmpty() }.joinToString("  ·  "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}
