package com.bluecash.wallet.core

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Small encrypted key-value store. On Android this is backed by EncryptedSharedPreferences. */
interface SecureKV {
    fun get(key: String): String?
    fun put(key: String, value: String)
    fun remove(key: String)
    fun keys(prefix: String): List<String>
}

class MemoryKV : SecureKV {
    private val m = java.util.concurrent.ConcurrentHashMap<String, String>()
    override fun get(key: String) = m[key]
    override fun put(key: String, value: String) { m[key] = value }
    override fun remove(key: String) { m.remove(key) }
    override fun keys(prefix: String) = m.keys.filter { it.startsWith(prefix) }.sorted()
    fun copyFrom(other: MemoryKV) { m.putAll(other.m) }
}

class TransportClosedException(msg: String = "connection closed") : Exception(msg)

/** A message pipe between two phones. BLE implements it; tests use an in-memory version. */
interface FrameTransport {
    /** Blocks until the whole message is handed to the radio. */
    fun send(msg: ByteArray)
    /** Blocks up to [timeoutMs]; throws TimeoutException or TransportClosedException. */
    fun receive(timeoutMs: Long): ByteArray
    fun close()
}

abstract class QueueTransport : FrameTransport {
    private val inbox = LinkedBlockingQueue<ByteArray>()
    private val poison = ByteArray(0)
    @Volatile var closed = false
        private set

    fun deliver(msg: ByteArray) { inbox.put(msg) }

    fun markClosed() {
        closed = true
        inbox.offer(poison)
    }

    override fun receive(timeoutMs: Long): ByteArray {
        val m = inbox.poll(timeoutMs, TimeUnit.MILLISECONDS) ?: throw TimeoutException("timed out waiting for peer")
        if (m === poison) {
            inbox.offer(poison)
            throw TransportClosedException()
        }
        return m
    }
}

/** What the session needs from the screen: status text and the human confirmations. */
interface SessionUi {
    fun status(msg: String)
    /** Show the 6-digit code; true if the user says it matches the other phone. Blocks. */
    fun confirmSas(sas: String): Boolean
    /** Payer only: confirm paying [amount] to [merchantId]. Blocks. */
    fun confirmPayment(amount: Int, merchantId: String): Boolean
}
