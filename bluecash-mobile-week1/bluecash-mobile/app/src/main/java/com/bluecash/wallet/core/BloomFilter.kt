package com.bluecash.wallet.core

/**
 * Small Bloom filter used as a fast "have I seen this token?" pre-check on a merchant.
 * A Bloom filter can say "definitely not seen" instantly, but "maybe seen" can be a false
 * alarm, so a "maybe" is always confirmed against the exact set before rejecting anyone.
 */
class BloomFilter(private val bits: Int = 1 shl 18, private val hashes: Int = 7) {
    private val data = ByteArray(bits / 8)

    private fun positions(item: String): IntArray {
        val h = sha256(utf8(item))
        var h1 = 0L
        var h2 = 0L
        for (i in 0 until 8) h1 = (h1 shl 8) or (h[i].toLong() and 0xff)
        for (i in 8 until 16) h2 = (h2 shl 8) or (h[i].toLong() and 0xff)
        return IntArray(hashes) { i -> (((h1 + i * h2) and Long.MAX_VALUE) % bits).toInt() }
    }

    fun add(item: String) {
        for (p in positions(item)) data[p shr 3] = (data[p shr 3].toInt() or (1 shl (p and 7))).toByte()
    }

    fun mightContain(item: String): Boolean =
        positions(item).all { p -> (data[p shr 3].toInt() and (1 shl (p and 7))) != 0 }
}
