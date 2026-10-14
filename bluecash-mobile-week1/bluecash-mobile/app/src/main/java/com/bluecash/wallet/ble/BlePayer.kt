package com.bluecash.wallet.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import com.bluecash.wallet.core.Framing
import com.bluecash.wallet.core.FrameTransport
import com.bluecash.wallet.core.QueueTransport
import com.bluecash.wallet.core.TransportClosedException
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

/**
 * Payer side of the radio: scans for merchants (filtered by the BlueCash service id) and
 * connects as a GATT *client*. The caller must hold BLUETOOTH_SCAN and BLUETOOTH_CONNECT.
 */
@SuppressLint("MissingPermission")
class BlePayer(private val context: Context) {

    data class Found(val address: String, val device: BluetoothDevice, val rssi: Int)

    interface ScanListener {
        fun onResults(list: List<Found>)
        fun onError(message: String)
    }

    interface ConnectListener {
        fun onReady(transport: FrameTransport)
        fun onFailed(message: String)
    }

    private val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val results = LinkedHashMap<String, Found>()
    private var scanning = false
    private var gatt: BluetoothGatt? = null
    private var transport: ClientTransport? = null
    private var connectListener: ConnectListener? = null
    @Volatile private var ready = false
    @Volatile private var mtu = 23
    private var scanListener: ScanListener? = null

    fun startScan(l: ScanListener) {
        val adapter = manager.adapter
        if (adapter == null || !adapter.isEnabled) { l.onError("Bluetooth is off"); return }
        val scanner = adapter.bluetoothLeScanner ?: run { l.onError("Bluetooth LE scanning unavailable"); return }
        stopScan()
        results.clear()
        scanListener = l
        val filters = listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(BleConstants.SERVICE_UUID)).build())
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanner.startScan(filters, settings, scanCallback)
        scanning = true
    }

    fun stopScan() {
        if (scanning) runCatching { manager.adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
        scanning = false
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val f = Found(result.device.address, result.device, result.rssi)
            synchronized(results) { results[f.address] = f }
            scanListener?.onResults(synchronized(results) { results.values.sortedByDescending { it.rssi } })
        }

        override fun onScanFailed(errorCode: Int) {
            scanning = false
            scanListener?.onError("Scan failed (code $errorCode)")
        }
    }

    fun connect(found: Found, l: ConnectListener) {
        stopScan()
        disconnect()
        ready = false
        mtu = 23
        connectListener = l
        gatt = found.device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        if (gatt == null) l.onFailed("Could not start the Bluetooth connection")
    }

    fun disconnect() {
        transport?.markClosed()
        transport = null
        runCatching { gatt?.disconnect() }
        runCatching { gatt?.close() }
        gatt = null
    }

    @Suppress("DEPRECATION")
    private fun writePacket(g: BluetoothGatt, ch: BluetoothGattCharacteristic, packet: ByteArray): Boolean =
        if (Build.VERSION.SDK_INT >= 33) {
            g.writeCharacteristic(ch, packet, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothStatusCodes.SUCCESS
        } else {
            ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            ch.value = packet
            g.writeCharacteristic(ch)
        }

    private inner class ClientTransport(val g: BluetoothGatt, val rx: BluetoothGattCharacteristic) : QueueTransport() {
        val reassembler = Framing.Reassembler()
        private val written = Semaphore(0)
        @Volatile private var lastOk = true

        fun onWritten(ok: Boolean) { lastOk = ok; written.release() }

        override fun send(msg: ByteArray) {
            if (closed) throw TransportClosedException()
            val maxPacket = Framing.packetSize(mtu)
            for (packet in Framing.chunk(msg, maxPacket)) {
                if (!writePacket(g, rx, packet)) throw TransportClosedException("could not send over Bluetooth")
                if (!written.tryAcquire(BleConstants.IO_TIMEOUT_SEC, TimeUnit.SECONDS)) throw TransportClosedException("Bluetooth send timed out")
                if (!lastOk) throw TransportClosedException("Bluetooth write failed")
            }
        }

        override fun close() {
            markClosed()
            runCatching { g.disconnect() }
        }
    }

    private fun onIncoming(value: ByteArray?) {
        val t = transport ?: return
        if (value == null) return
        t.reassembler.feed(value)?.let { t.deliver(it) }
    }

    private fun fail(msg: String) {
        val l = connectListener
        connectListener = null
        l?.onFailed(msg)
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (!g.requestMtu(BleConstants.REQUESTED_MTU)) g.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                transport?.markClosed()
                if (!ready) fail("Connection failed (status $status)")
                runCatching { g.close() }
            }
        }

        override fun onMtuChanged(g: BluetoothGatt, newMtu: Int, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) mtu = newMtu
            g.discoverServices()
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            val service = g.getService(BleConstants.SERVICE_UUID)
            val rx = service?.getCharacteristic(BleConstants.RX_UUID)
            val tx = service?.getCharacteristic(BleConstants.TX_UUID)
            val cccd = tx?.getDescriptor(BleConstants.CCCD_UUID)
            if (status != BluetoothGatt.GATT_SUCCESS || rx == null || tx == null || cccd == null) {
                fail("That device isn't a BlueCash merchant"); return
            }
            transport = ClientTransport(g, rx)
            g.setCharacteristicNotification(tx, true)
            val started = writeCccd(g, cccd)
            if (!started) fail("Could not subscribe to the merchant")
        }

        override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) { fail("Could not subscribe to the merchant"); return }
            val t = transport ?: return
            ready = true
            val l = connectListener
            connectListener = null
            l?.onReady(t)
        }

        override fun onCharacteristicWrite(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            transport?.onWritten(status == BluetoothGatt.GATT_SUCCESS)
        }

        // Android 13+ delivers the value directly...
        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            onIncoming(value)
        }

        // ...older versions use this one (deprecated, but the only choice below API 33).
        @Deprecated("Used on Android 12 and below")
        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION")
            onIncoming(characteristic.value)
        }
    }

    @Suppress("DEPRECATION")
    private fun writeCccd(g: BluetoothGatt, d: BluetoothGattDescriptor): Boolean =
        if (Build.VERSION.SDK_INT >= 33) {
            g.writeDescriptor(d, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == BluetoothStatusCodes.SUCCESS
        } else {
            d.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            g.writeDescriptor(d)
        }
}
