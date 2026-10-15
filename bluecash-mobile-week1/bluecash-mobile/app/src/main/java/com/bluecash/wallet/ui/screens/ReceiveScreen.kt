package com.bluecash.wallet.ui.screens

import android.bluetooth.BluetoothAdapter
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.bluecash.wallet.AppContainer
import com.bluecash.wallet.QrUtil
import com.bluecash.wallet.permissions.isBluetoothOn
import com.bluecash.wallet.permissions.rememberBlePermissionsState
import com.bluecash.wallet.session.ReceiveController
import com.bluecash.wallet.session.ReceivePhase
import com.bluecash.wallet.ui.components.ResultCard
import com.bluecash.wallet.ui.components.SasCard
import com.bluecash.wallet.ui.components.ScreenColumn
import com.bluecash.wallet.ui.components.SectionCard

@Composable
fun ReceiveScreen() {
    val context = LocalContext.current
    val perms = rememberBlePermissionsState()
    var btOn by remember { mutableStateOf(isBluetoothOn(context)) }
    var amountText by remember { mutableStateOf("") }
    var nameText by remember { mutableStateOf(AppContainer.merchantName) }

    val enableBt = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        btOn = isBluetoothOn(context)
    }

    ScreenColumn {
        Text("Receive", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Ask for an amount, and this phone offers it to a payer standing next to you over Bluetooth.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (!AppContainer.registered && ReceiveController.phase == ReceivePhase.IDLE) {
            SectionCard("Setup needed") {
                Text("Open Settings, generate your device identity and register with the mint first.")
            }
        }

        when (ReceiveController.phase) {
            ReceivePhase.IDLE -> SectionCard("Request a payment") {
                // The amount is the one thing typed on this screen, so it gets the
                // larger type and the currency sign built in rather than only a label.
                OutlinedTextField(
                    value = amountText,
                    onValueChange = { amountText = it.filter(Char::isDigit).take(6) },
                    label = { Text("Amount to receive") },
                    leadingIcon = { Text("₹", style = MaterialTheme.typography.titleLarge) },
                    textStyle = MaterialTheme.typography.headlineSmall,
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = nameText,
                    onValueChange = { nameText = it.take(24) },
                    label = { Text("Shop name (optional)") },
                    supportingText = { Text("Shown to the payer when they confirm.") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                // Name which requirement is unmet. Permission missing, Bluetooth
                // off and not-registered are indistinguishable from the user's
                // side unless the screen says which one it is.
                val ready = perms.allGranted && btOn
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    StatusDisc(ready)
                    Text(
                        when {
                            !perms.allGranted -> "Bluetooth permission needed"
                            !btOn -> "Bluetooth is off"
                            else -> "Bluetooth ready"
                        },
                        style = MaterialTheme.typography.titleSmall,
                        color = if (ready) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurface,
                    )
                }

                if (!perms.allGranted) {
                    Button(onClick = perms.request, modifier = Modifier.fillMaxWidth()) {
                        Text("Grant Bluetooth access")
                    }
                } else if (!btOn) {
                    Button(
                        onClick = { enableBt.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)) },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Turn on Bluetooth") }
                } else {
                    Button(
                        enabled = AppContainer.registered && (amountText.toIntOrNull() ?: 0) > 0,
                        onClick = {
                            AppContainer.saveMerchantName(nameText)
                            ReceiveController.start(context, amountText.toInt())
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Start receiving") }
                }

                Text(
                    "Payments are checked offline; the money is settled when you next go online.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            ReceivePhase.ADVERTISING, ReceivePhase.SESSION -> SectionCard(
                "Receiving ₹${ReceiveController.requestedAmount}"
            ) {
                if (ReceiveController.sas == null) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator(Modifier.padding(4.dp))
                        Column {
                            Text(ReceiveController.status, style = MaterialTheme.typography.bodyMedium)
                            // The merchant is holding the phone out; the useful
                            // instruction is what the *other* person must do.
                            Text(
                                "Ask the customer to open Pay and tap Find nearby devices.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }

                ReceiveController.sas?.let { SasCard(it) { ok -> ReceiveController.answer(ok) } }

                ReceiveController.qrText?.let { qr ->
                    if (ReceiveController.phase == ReceivePhase.ADVERTISING) {
                        val bmp = remember(qr) { QrUtil.bitmap(qr) }
                        Text(
                            "Optional: let the customer scan this to verify it's really you.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        // Centred, because a code to be scanned is the focus of the
                        // screen while it is shown.
                        Row(
                            horizontalArrangement = Arrangement.Center,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Image(
                                bitmap = bmp.asImageBitmap(),
                                contentDescription = "Merchant verification QR code",
                                modifier = Modifier.size(220.dp),
                            )
                        }
                    }
                }

                TextButton(onClick = { ReceiveController.reset() }) { Text("Stop receiving") }
            }

            ReceivePhase.DONE -> ReceiveController.result?.let { ResultCard(it) { ReceiveController.reset() } }
        }

        if (AppContainer.pendingReceipts > 0) {
            SectionCard("Waiting to settle") {
                val n = AppContainer.pendingReceipts
                Text(
                    if (n == 1) "1 receipt will upload automatically when you are online."
                    else "$n receipts will upload automatically when you are online.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

/** A tinted disc behind the Bluetooth glyph: brand-coloured when advertising can start. */
@Composable
private fun StatusDisc(ready: Boolean) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(
                if (ready) MaterialTheme.colorScheme.primaryContainer
                else MaterialTheme.colorScheme.surfaceVariant
            ),
    ) {
        Icon(
            Icons.Filled.Bluetooth,
            contentDescription = null,
            tint = if (ready) MaterialTheme.colorScheme.primary
            else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
