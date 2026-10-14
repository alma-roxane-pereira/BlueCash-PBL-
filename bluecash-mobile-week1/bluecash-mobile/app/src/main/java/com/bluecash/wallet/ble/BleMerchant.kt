package com.bluecash.wallet.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
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
 * Merchant side of the radio: a GATT *server* that advertises the BlueCash service and
 * accepts ONE payer at a time. The caller must hold the BLUETOOTH_ADVERTISE and
 * BLUETOOTH_CONNECT permissions (the UI checks this before calling [start]).
 */
@SuppressLint("MissingPermission")
class BleMerchant(private val context: Context, private val listener: Listener) {

    interface Listener {
        fun onAdvertising()
        /** The payer has connected and subscribed; run the session on this transport. */
        fun onPayerConnected(transport: FrameTransport)
        fun onError(message: String)
    }

    private val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private var server: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var tx: BluetoothGattCharacteristic? = null
    private var current: ServerTransport? = null
    @Volatile private var stopped = false
    @Volatile private var advertising = false

    fun start() {
        val adapter = manager.adapter
        if (adapter == null || !adapter.isEnabled) { listener.onError("Bluetooth is off"); return }
        advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) { listener.onError("This phone can't advertise over Bluetooth LE"); return }
        stopped = false
        val srv = manager.openGattServer(context, gattCallback)
        if (srv == null) { listener.onError("Could not open the Bluetooth server"); return }
        server = srv

        val service = BluetoothGattService(BleConstants.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val rx = BluetoothGattCharacteristic(
            BleConstants.RX_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val txChar = BluetoothGattCharacteristic(
            BleConstants.TX_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        txChar.addDescriptor(
            BluetoothGattDescriptor(
                BleConstants.CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
            )
        )
        tx = txChar
        service.addCharacteristic(rx)
        service.addCharacteristic(txChar)
        if (!srv.addService(service)) listener.onError("Could not register the Bluetooth service")
        // advertising starts in onServiceAdded
    }

    fun stop() {
        stopped = true
        stopAdvertising()
        current?.close()
        current = null
        runCatching { server?.close() }
        server = null
    }

    private fun startAdvertising() {
        if (stopped || advertising) return
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        // No device name in the advertisement: nothing identifying is broadcast, only the service id.
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(BleConstants.SERVICE_UUID))
            .build()
        advertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    private fun stopAdvertising() {
        if (advertising) runCatching { advertiser?.stopAdvertising(advertiseCallback) }
        advertising = false
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            advertising = true
            listener.onAdvertising()
        }

        override fun onStartFailure(errorCode: Int) {
            advertising = false
            listener.onError("Bluetooth advertising failed (code $errorCode)")
        }
    }

    @Suppress("DEPRECATION")
    private fun notifyPacket(device: BluetoothDevice, packet: ByteArray): Boolean {
        val ch = tx ?: return false
        val srv = server ?: return false
        return if (Build.VERSION.SDK_INT >= 33) {
            srv.notifyCharacteristicChanged(device, ch, false, packet) == BluetoothStatusCodes.SUCCESS
        } else {
            ch.value = packet
            srv.notifyCharacteristicChanged(device, ch, false)
        }
    }

    private inner class ServerTransport(val device: BluetoothDevice) : QueueTransport() {
        @Volatile var mtu = 23
        val reassembler = Framing.Reassembler()
        private val sent = Semaphore(0)
        @Volatile var delivered = false

        fun onNotificationSent() = sent.release()

        override fun send(msg: ByteArray) {
            if (closed) throw TransportClosedException()
            val maxPacket = Framing.packetSize(mtu)
            for (packet in Framing.chunk(msg, maxPacket)) {
                if (!notifyPacket(device, packet)) throw TransportClosedException("could not send over Bluetooth")
                if (!sent.tryAcquire(BleConstants.IO_TIMEOUT_SEC, TimeUnit.SECONDS)) throw TransportClosedException("Bluetooth send timed out")
            }
        }

        override fun close() {
            markClosed()
            runCatching { server?.cancelConnection(device) }
        }
    }

    private val gattCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            if (status == BluetoothGatt.GATT_SUCCESS) startAdvertising()
            else listener.onError("Could not register the Bluetooth service (status $status)")
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (current != null || stopped) {
                    runCatching { server?.cancelConnection(device) } // one payer at a time
                    return
                }
                current = ServerTransport(device)
                stopAdvertising()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                val cur = current
                if (cur != null && cur.device.address == device.address) {
                    cur.markClosed()
                    current = null
                    if (!stopped) startAdvertising()
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            current?.mtu = mtu
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
        ) {
            val cur = current
            if (characteristic.uuid == BleConstants.RX_UUID && cur != null && value != null && cur.device.address == device.address) {
                cur.reassembler.feed(value)?.let { cur.deliver(it) }
            }
            if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
        ) {
            if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            val cur = current
            if (descriptor.uuid == BleConstants.CCCD_UUID && cur != null && !cur.delivered &&
                value != null && value.isNotEmpty() && value[0].toInt() != 0
            ) {
                cur.delivered = true
                listener.onPayerConnected(cur)
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            current?.onNotificationSent()
        }
    }
}
