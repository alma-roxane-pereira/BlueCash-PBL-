package com.bluecash.wallet.ui.screens

import android.bluetooth.BluetoothAdapter
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.bluecash.wallet.AppContainer
import com.bluecash.wallet.permissions.isBluetoothOn
import com.bluecash.wallet.permissions.rememberBlePermissionsState
import com.bluecash.wallet.session.PayController
import com.bluecash.wallet.session.PayPhase
import com.bluecash.wallet.ui.components.ResultCard
import com.bluecash.wallet.ui.components.SasCard
import com.bluecash.wallet.ui.components.ScreenColumn
import com.bluecash.wallet.ui.components.SectionCard
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

@Composable
fun PayScreen() {
    val context = LocalContext.current
    val perms = rememberBlePermissionsState()
    var btOn by remember { mutableStateOf(isBluetoothOn(context)) }
    var qrError by remember { mutableStateOf(false) }

    val enableBt = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        btOn = isBluetoothOn(context)
    }
    val scanQr = rememberLauncherForActivityResult(ScanContract()) { r ->
        val text = r.contents
        if (text != null) qrError = !PayController.setQr(text)
    }

    DisposableEffect(Unit) {
        onDispose { if (PayController.phase == PayPhase.SCANNING) PayController.cancel() }
    }

    ScreenColumn {
        Text("Pay", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Pay a merchant standing next to you. This works over Bluetooth, with no internet.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (!AppContainer.registered && PayController.phase == PayPhase.IDLE) {
            SectionCard("Setup needed") {
                Text("Open Settings, generate your device identity and register with the mint first.")
            }
        }

        when (PayController.phase) {
            PayPhase.IDLE -> {
                // One card answers "can I pay right now?" before offering the
                // button. The three things that stop a payment -- no permission,
                // Bluetooth off, not registered -- are indistinguishable from the
                // user's side unless the screen names which one is in the way.
                val ready = perms.allGranted && btOn
                SectionCard("Nearby devices") {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        StatusDisc(ready)
                        Column(Modifier.weight(1f)) {
                            Text(
                                when {
                                    !perms.allGranted -> "Bluetooth permission needed"
                                    !btOn -> "Bluetooth is off"
                                    else -> "Ready to connect"
                                },
                                style = MaterialTheme.typography.titleSmall,
                                color = if (ready) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                "Balance ₹${AppContainer.balance}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
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
                            enabled = AppContainer.registered,
                            onClick = { PayController.startScan(context) },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Find nearby devices") }
                        Text(
                            "Keep both phones close together.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                if (perms.allGranted && btOn) {
                    SectionCard("Extra security (optional)") {
                        Text(
                            "Scanning the merchant's QR code binds this payment to that exact device.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        OutlinedButton(
                            onClick = { qrError = false; scanQr.launch(qrOptions()) },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(
                                if (PayController.qrBound) "Merchant QR scanned ✓ (tap to rescan)"
                                else "Scan merchant's QR"
                            )
                        }
                        if (qrError) {
                            Text(
                                "That QR code isn't from a BlueCash merchant.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                }

                Text(
                    "Offline payments can't give change, so you pay exact amounts using your tokens.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            PayPhase.SCANNING -> SectionCard("Nearby merchants") {
                if (PayController.found.isEmpty()) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator(Modifier.padding(4.dp))
                        Column {
                            Text(PayController.status, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "Ask the merchant to open Receive.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                PayController.found.forEach { f ->
                    OutlinedButton(
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { PayController.connect(f) },
                    ) {
                        Column(Modifier.fillMaxWidth()) {
                            Text(
                                "Merchant …${f.address.takeLast(5)}",
                                style = MaterialTheme.typography.bodyLarge,
                            )
                            // dBm means nothing to most people; the word does, and
                            // the number stays for anyone who wants it.
                            Text(
                                "${signalWord(f.rssi)}  ·  ${f.rssi} dBm",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
                TextButton(onClick = { PayController.reset(keepQr = true) }) { Text("Stop scanning") }
            }

            PayPhase.CONNECTING, PayPhase.SESSION -> SectionCard("Paying") {
                if (PayController.sas == null && PayController.paymentRequest == null) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator(Modifier.padding(4.dp))
                        Column {
                            Text(PayController.status, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "Keep both screens on and the phones close.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                PayController.sas?.let { SasCard(it) { ok -> PayController.answer(ok) } }
                PayController.paymentRequest?.let { (amount, merchant) ->
                    // The merchant sets the amount; this screen's one job here is
                    // to make it unmissable before the payer agrees to it.
                    Text("₹$amount", style = MaterialTheme.typography.displaySmall)
                    Text(
                        "to $merchant",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Button(onClick = { PayController.answer(true) }, modifier = Modifier.weight(1f)) {
                            Text("Pay ₹$amount")
                        }
                        OutlinedButton(onClick = { PayController.answer(false) }, modifier = Modifier.weight(1f)) {
                            Text("Decline")
                        }
                    }
                }
                TextButton(onClick = { PayController.reset() }) { Text("Cancel payment") }
            }

            PayPhase.DONE -> PayController.result?.let { ResultCard(it) { PayController.reset() } }
        }
    }
}

/** A tinted disc behind the Bluetooth glyph: brand-coloured when a payment can start. */
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

/** RSSI as a word. The thresholds are the usual rule of thumb for BLE proximity. */
private fun signalWord(rssi: Int): String = when {
    rssi >= -55 -> "Very close"
    rssi >= -70 -> "Nearby"
    else -> "Far — move closer"
}

private fun qrOptions() = ScanOptions()
    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
    .setPrompt("Scan the QR code shown on the merchant's phone")
    .setBeepEnabled(false)
    .setOrientationLocked(false)
