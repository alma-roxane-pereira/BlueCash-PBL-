package com.bluecash.wallet.core

/**
 * A BLE packet carries only ~240 bytes, but our messages are a few KB. Each message is cut
 * into packets of [flag byte][payload]. The flag marks the first and/or last packet so the
 * receiver can put the message back together.
 */
object Framing {
    private const val FIRST = 1
    private const val LAST = 2

    /**
     * GATT refuses any attribute value longer than this, whatever the ATT MTU negotiated to.
     * Modern phones agree an MTU of 517, and 517 - 3 = 514 is over the limit, so the packet
     * size has to be clamped as well as derived from the MTU.
     */
    const val MAX_ATTRIBUTE_LEN = 512

    /**
     * Largest packet that may be notified or written on a link whose ATT MTU is [mtu].
     *
     * Three bytes go to the ATT header, the rest is ours -- but never more than
     * [MAX_ATTRIBUTE_LEN], and never less than the 20 bytes the smallest MTU leaves.
     */
    fun packetSize(mtu: Int): Int = (mtu - 3).coerceIn(20, MAX_ATTRIBUTE_LEN)

    fun chunk(msg: ByteArray, maxPacket: Int): List<ByteArray> {
        require(maxPacket >= 2)
        val payload = maxPacket - 1
        val out = ArrayList<ByteArray>()
        var off = 0
        do {
            val end = minOf(msg.size, off + payload)
            var flag = 0
            if (off == 0) flag = flag or FIRST
            if (end == msg.size) flag = flag or LAST
            out.add(byteArrayOf(flag.toByte()) + msg.copyOfRange(off, end))
            off = end
        } while (off < msg.size)
        return out
    }

    class Reassembler(private val maxSize: Int = 64 * 1024) {
        private var buf = java.io.ByteArrayOutputStream()
        private var active = false

        /** Feed one packet; returns the complete message when the last packet arrives. */
        fun feed(packet: ByteArray): ByteArray? {
            if (packet.isEmpty()) return null
            val flag = packet[0].toInt()
            if (flag and FIRST != 0) {
                buf = java.io.ByteArrayOutputStream()
                active = true
            }
            if (!active) return null
            buf.write(packet, 1, packet.size - 1)
            if (buf.size() > maxSize) {
                active = false
                return null
            }
            if (flag and LAST != 0) {
                active = false
                return buf.toByteArray()
            }
            return null
        }
    }
}
