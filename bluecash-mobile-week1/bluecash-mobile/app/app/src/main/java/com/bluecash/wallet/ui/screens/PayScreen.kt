package com.bluecash.wallet.ui.screens

import android.bluetooth.BluetoothAdapter
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
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

        if (!AppContainer.registered && PayController.phase == PayPhase.IDLE) {
            SectionCard("Setup needed") {
                Text("Open Settings, generate your device identity and register with the mint first.")
            }
        }

        when (PayController.phase) {
            PayPhase.IDLE -> SectionCard("Find a merchant") {
                Text("Balance: ₹${AppContainer.balance}", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "Offline payments can't give change, so you pay exact amounts using your tokens.",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (!perms.allGranted) {
                    Button(onClick = perms.request) { Text("Grant Bluetooth access") }
                } else if (!btOn) {
                    Button(onClick = { enableBt.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)) }) { Text("Turn on Bluetooth") }
                } else {
                    OutlinedButton(onClick = { qrError = false; scanQr.launch(qrOptions()) }) {
                        Text(if (PayController.qrBound) "Merchant QR scanned ✓ (tap to rescan)" else "Scan merchant's QR (extra security)")
                    }
                    if (qrError) Text("That QR code isn't from a BlueCash merchant.", style = MaterialTheme.typography.bodySmall)
                    Button(enabled = AppContainer.registered, onClick = { PayController.startScan(context) }) {
                        Text("Scan for merchants")
                    }
                }
            }

            PayPhase.SCANNING -> SectionCard("Nearby merchants") {
                if (PayController.found.isEmpty()) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        CircularProgressIndicator(Modifier.padding(4.dp))
                        Text(PayController.status)
                    }
                }
                PayController.found.forEach { f ->
                    OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = { PayController.connect(f) }) {
                        Text("Merchant …${f.address.takeLast(5)}   ·   signal ${f.rssi} dBm")
                    }
                }
                TextButton(onClick = { PayController.reset(keepQr = true) }) { Text("Stop scanning") }
            }

            PayPhase.CONNECTING, PayPhase.SESSION -> SectionCard("Paying") {
                if (PayController.sas == null && PayController.paymentRequest == null) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        CircularProgressIndicator(Modifier.padding(4.dp))
                        Text(PayController.status)
                    }
                }
                PayController.sas?.let { SasCard(it) { ok -> PayController.answer(ok) } }
                PayController.paymentRequest?.let { (amount, merchant) ->
                    Text("Pay ₹$amount to $merchant?", style = MaterialTheme.typography.titleLarge)
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Button(onClick = { PayController.answer(true) }) { Text("Pay ₹$amount") }
                        OutlinedButton(onClick = { PayController.answer(false) }) { Text("Cancel") }
                    }
                }
                TextButton(onClick = { PayController.reset() }) { Text("Cancel") }
            }

            PayPhase.DONE -> PayController.result?.let { ResultCard(it) { PayController.reset() } }
        }
    }
}

private fun qrOptions() = ScanOptions()
    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
    .setPrompt("Scan the QR code shown on the merchant's phone")
    .setBeepEnabled(false)
    .setOrientationLocked(false)
