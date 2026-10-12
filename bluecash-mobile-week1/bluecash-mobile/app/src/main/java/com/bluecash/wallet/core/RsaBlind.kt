package com.bluecash.wallet.core

import java.math.BigInteger

/**
 * Chaum-style RSA blind signatures with a full-domain hash.
 *
 * Flow: the wallet *blinds* a token message so the mint can sign it without seeing it, the
 * mint signs the blinded value, and the wallet *unblinds* to get an ordinary RSA signature
 * on the original message. Later the mint cannot link that signature to the issuance.
 */
object RsaBlind {
    /** Hash a message to a number in [0, n) by expanding SHA-256 in counter mode. */
    fun fdh(message: ByteArray, n: BigInteger): BigInteger {
        val len = (n.bitLength() + 7) / 8 + 16 // extra bytes make the modulo bias negligible
        val out = java.io.ByteArrayOutputStream()
        var ctr = 0
        while (out.size() < len) {
            out.write(sha256(utf8("BCFDH|v1|"), message, byteArrayOf((ctr ushr 8).toByte(), ctr.toByte())))
            ctr++
        }
        return BigInteger(1, out.toByteArray().copyOf(len)).mod(n)
    }

    class Blinded(val blindedMessage: BigInteger, val r: BigInteger)

    fun blind(message: ByteArray, n: BigInteger, e: BigInteger): Blinded {
        var r: BigInteger
        do {
            r = BigInteger(n.bitLength() - 1, Rand.rnd)
        } while (r < BigInteger.valueOf(2) || r.gcd(n) != BigInteger.ONE)
        val m = fdh(message, n)
        return Blinded(m.multiply(r.modPow(e, n)).mod(n), r)
    }

    /** Mint side. */
    fun signBlinded(blinded: BigInteger, n: BigInteger, d: BigInteger): BigInteger {
        require(blinded.signum() > 0 && blinded < n) { "blinded value out of range" }
        return blinded.modPow(d, n)
    }

    fun unblind(blindSig: BigInteger, r: BigInteger, n: BigInteger): BigInteger =
        blindSig.multiply(r.modInverse(n)).mod(n)

    fun verify(message: ByteArray, sig: BigInteger, n: BigInteger, e: BigInteger): Boolean {
        if (sig.signum() <= 0 || sig >= n) return false
        return sig.modPow(e, n) == fdh(message, n)
    }
}
