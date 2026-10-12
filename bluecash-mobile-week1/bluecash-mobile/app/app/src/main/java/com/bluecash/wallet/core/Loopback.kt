package com.bluecash.wallet.core

/** Two in-memory ends of a pipe, standing in for the BLE link (tests and the in-app self-test). */
class PipeEnd : QueueTransport() {
    lateinit var peer: PipeEnd
    @Volatile var delayMs = 0L

    override fun send(msg: ByteArray) {
        if (closed) throw TransportClosedException()
        if (delayMs > 0) Thread.sleep(delayMs)
        peer.deliver(msg)
    }

    override fun close() {
        markClosed()
        if (::peer.isInitialized) peer.markClosed()
    }
}

fun pipe(): Pair<PipeEnd, PipeEnd> {
    val a = PipeEnd()
    val b = PipeEnd()
    a.peer = b
    b.peer = a
    return a to b
}
