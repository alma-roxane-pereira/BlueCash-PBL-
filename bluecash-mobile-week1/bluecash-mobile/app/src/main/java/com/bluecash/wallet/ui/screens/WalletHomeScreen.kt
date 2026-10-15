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
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Send
import com.bluecash.wallet.navigation.Destination

@Composable
fun WalletHomeScreen(onNavigate: (String) -> Unit = {}) {
    val blePermissions = rememberBlePermissionsState()
    LaunchedEffect(Unit) { AppContainer.refreshAsync() }

    var amountText by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    ScreenColumn {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("BlueCash", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
            IconButton(onClick = { onNavigate(Destination.Settings.route) }) {
                Icon(Icons.Filled.AccountCircle, contentDescription = "Settings")
            }
        }

        BalanceCard(label = "Wallet balance") {
            Text("₹ ${AppContainer.balance}", style = MaterialTheme.typography.displayMedium)
            // The token count sits in a chip rather than a sentence: it is a
            // secondary fact about the same number above it.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.45f),
                ) {
                    Text(
                        if (AppContainer.tokenCount == 1) "1 token" else "${AppContainer.tokenCount} tokens",
                        style = MaterialTheme.typography.labelLarge,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                    )
                }
            }
            if (AppContainer.pendingAmount > 0) {
                Text(
                    "₹${AppContainer.pendingAmount} awaiting confirmation",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        // Pay and Receive are the two things this screen exists to start, so they
        // are buttons here as well as tabs below -- the tab bar is for moving
        // around, these are for acting.
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = { onNavigate(Destination.Pay.route) },
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Filled.Send, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Pay")
            }
            FilledTonalButton(
                onClick = { onNavigate(Destination.Receive.route) },
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Filled.QrCode, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Receive")
            }
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

        // "Recent activity" is a plain section heading rather than a card, so the
        // entries below read as one list instead of a card inside a card.
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(
                "Recent activity",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            val intact = AppContainer.ledgerOk
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier.semantics {
                    contentDescription = if (intact) {
                        "Ledger integrity intact"
                    } else {
                        "Warning: ledger tampering detected"
                    }
                },
            ) {
                Text(
                    if (intact) "✓" else "✕",
                    style = MaterialTheme.typography.labelLarge,
                    color = if (intact) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                )
                Text(
                    if (intact) "Ledger intact" else "Tampering detected",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (intact) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                )
            }
        }

        if (AppContainer.recent.isEmpty()) {
            SectionCard("Nothing yet") {
                Text(
                    "Payments and top-ups will appear here.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        // A plain forEach, not a LazyColumn: ScreenColumn already provides the one
        // vertical scroll, and nesting a second scrollable inside it would give
        // this list an unbounded height and break both.
        AppContainer.recent.forEach { entry ->
            val row = HistoryText.format(entry)
            Card(modifier = Modifier.fillMaxWidth()) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                ) {
                    // Money in, money out and everything else get different
                    // coloured discs, so direction is visible before reading.
                    val tint = when (row.credit) {
                        true -> MaterialTheme.colorScheme.tertiaryContainer
                        false -> MaterialTheme.colorScheme.errorContainer
                        null -> MaterialTheme.colorScheme.surfaceVariant
                    }
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(40.dp)
                            .clip(CircleShape)
                            .background(tint),
                    ) {
                        Text(row.icon, style = MaterialTheme.typography.titleMedium)
                    }
                    Column(Modifier.weight(1f)) {
                        Text(row.title, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            listOf(row.time, row.detail).filter { it.isNotEmpty() }
                                .joinToString("  ·  "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (row.amount.isNotEmpty()) {
                        Text(
                            row.amount,
                            style = MaterialTheme.typography.titleSmall,
                            color = when (row.credit) {
                                true -> MaterialTheme.colorScheme.tertiary
                                false -> MaterialTheme.colorScheme.error
                                null -> MaterialTheme.colorScheme.onSurface
                            },
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))
    }
}
