package com.bluecash.wallet.ble

import java.util.UUID

object BleConstants {
    /** Merchants advertise this service; payers scan for it. */
    val SERVICE_UUID: UUID = UUID.fromString("b1ec45a0-7e4b-4c5a-9b1e-5f0c0de0b1ec")
    /** Payer -> merchant: the payer writes packets here. */
    val RX_UUID: UUID = UUID.fromString("b1ec45a1-7e4b-4c5a-9b1e-5f0c0de0b1ec")
    /** Merchant -> payer: the merchant notifies packets here. */
    val TX_UUID: UUID = UUID.fromString("b1ec45a2-7e4b-4c5a-9b1e-5f0c0de0b1ec")
    /** Standard "enable notifications" descriptor. */
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    const val REQUESTED_MTU = 247
    /** Weaker signal than this (in dBm) is treated as "too far away to be a nearby customer". */
    const val MIN_RSSI = -85
    const val IO_TIMEOUT_SEC = 5L
}
