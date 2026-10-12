package com.bluecash.wallet.permissions

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat

/**
 * The permission set BlueCash needs to act as both a BLE central (payer,
 * scanning for merchants) and a BLE peripheral (merchant, advertising a
 * service), across API levels. See AndroidManifest.xml for the matching
 * <uses-permission> declarations.
 */
fun blePermissions(): Array<String> =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
    } else {
        arrayOf(
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    }

data class BlePermissionsState(
    val allGranted: Boolean,
    val shouldShowRationale: Boolean,
    val request: () -> Unit,
)

/**
 * Tracks BLE permission status and exposes a `request()` callback that
 * launches the system permission dialog. Used from WalletHomeScreen for
 * now; the actual scan/advertise code (Week 4) will call blePermissions()
 * again before touching BluetoothGatt.
 */
@Composable
fun rememberBlePermissionsState(): BlePermissionsState {
    val context = LocalContext.current
    val permissions = remember { blePermissions() }

    fun currentlyGranted() = permissions.all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }

    var allGranted by remember { mutableStateOf(currentlyGranted()) }
    var shouldShowRationale by remember { mutableStateOf(false) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        allGranted = results.values.all { it }
        shouldShowRationale = !allGranted
    }

    return BlePermissionsState(
        allGranted = allGranted,
        shouldShowRationale = shouldShowRationale,
        request = { launcher.launch(permissions) }
    )
}

/** True if the phone's Bluetooth radio is switched on. (Needs no runtime permission.) */
fun isBluetoothOn(context: android.content.Context): Boolean =
    (context.getSystemService(android.content.Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager)
        ?.adapter?.isEnabled == true
