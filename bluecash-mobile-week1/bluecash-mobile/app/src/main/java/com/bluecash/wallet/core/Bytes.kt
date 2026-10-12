package com.bluecash.wallet.core

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/** Hex encoding helpers. Everything on the wire and in storage is lowercase hex. */
object Hex {
    private val CHARS = "0123456789abcdef".toCharArray()

    fun enc(b: ByteArray): String {
        val o = CharArray(b.size * 2)
        for (i in b.indices) {
            val v = b[i].toInt() and 0xff
            o[i * 2] = CHARS[v ushr 4]
            o[i * 2 + 1] = CHARS[v and 15]
        }
        return String(o)
    }

    fun dec(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd-length hex" }
        val o = ByteArray(s.length / 2)
        for (i in o.indices) {
            val hi = Character.digit(s[i * 2], 16)
            val lo = Character.digit(s[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "bad hex" }
            o[i] = ((hi shl 4) or lo).toByte()
        }
        return o
    }
}

fun ByteArray.hex(): String = Hex.enc(this)
fun String.unhex(): ByteArray = Hex.dec(this)
fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

fun sha256(vararg parts: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    for (p in parts) md.update(p)
    return md.digest()
}

fun ctEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

fun bigFromHex(s: String): BigInteger = BigInteger(1, Hex.dec(if (s.length % 2 == 0) s else "0$s"))
fun BigInteger.toHexString(): String {
    val h = toString(16)
    return if (h.length % 2 == 0) h else "0$h"
}

object Rand {
    val rnd = SecureRandom()
    fun bytes(n: Int): ByteArray = ByteArray(n).also { rnd.nextBytes(it) }
}
