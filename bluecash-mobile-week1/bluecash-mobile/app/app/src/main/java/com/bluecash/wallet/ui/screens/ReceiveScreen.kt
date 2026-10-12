package com.bluecash.wallet.ui.screens

import android.bluetooth.BluetoothAdapter
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
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

        if (!AppContainer.registered && ReceiveController.phase == ReceivePhase.IDLE) {
            SectionCard("Setup needed") {
                Text("Open Settings, generate your device identity and register with the mint first.")
            }
        }

        when (ReceiveController.phase) {
            ReceivePhase.IDLE -> SectionCard("Request a payment") {
                OutlinedTextField(
                    value = amountText,
                    onValueChange = { amountText = it.filter(Char::isDigit).take(6) },
                    label = { Text("Amount to receive (₹)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = nameText,
                    onValueChange = { nameText = it.take(24) },
                    label = { Text("Shop name (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (!perms.allGranted) {
                    Button(onClick = perms.request) { Text("Grant Bluetooth access") }
                } else if (!btOn) {
                    Button(onClick = { enableBt.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)) }) { Text("Turn on Bluetooth") }
                } else {
                    Button(
                        enabled = AppContainer.registered && (amountText.toIntOrNull() ?: 0) > 0,
                        onClick = {
                            AppContainer.saveMerchantName(nameText)
                            ReceiveController.start(context, amountText.toInt())
                        },
                    ) { Text("Start receiving") }
                }
                Text(
                    "Payments are checked offline; the money is settled when you next go online.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            ReceivePhase.ADVERTISING, ReceivePhase.SESSION -> SectionCard("Receiving ₹${ReceiveController.requestedAmount}") {
                if (ReceiveController.sas == null) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        CircularProgressIndicator(Modifier.padding(4.dp))
                        Text(ReceiveController.status)
                    }
                }
                ReceiveController.sas?.let { SasCard(it) { ok -> ReceiveController.answer(ok) } }
                ReceiveController.qrText?.let { qr ->
                    if (ReceiveController.phase == ReceivePhase.ADVERTISING) {
                        val bmp = remember(qr) { QrUtil.bitmap(qr) }
                        Text("Optional: let the customer scan this to verify it's really you.", style = MaterialTheme.typography.bodySmall)
                        Image(bitmap = bmp.asImageBitmap(), contentDescription = "Merchant verification QR code", modifier = Modifier.size(220.dp))
                    }
                }
                TextButton(onClick = { ReceiveController.reset() }) { Text("Stop") }
            }

            ReceivePhase.DONE -> ReceiveController.result?.let { ResultCard(it) { ReceiveController.reset() } }
        }

        if (AppContainer.pendingReceipts > 0) {
            SectionCard("Waiting to settle") {
                Text("${AppContainer.pendingReceipts} receipt(s) will upload automatically when you're online.", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
