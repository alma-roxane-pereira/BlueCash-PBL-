package com.bluecash.wallet.core

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SessionKeys(val sendKey: ByteArray, val recvKey: ByteArray, val sas: String, val transcript: ByteArray)

object Handshake {
    /**
     * Derive the session keys. [isPayer] decides which of the two directional keys is "send".
     * The transcript hash binds both ephemeral public keys, so a man in the middle who swaps
     * either key ends up with different keys and a different short code (SAS) on each side.
     */
    fun derive(shared: ByteArray, epkPayer: ByteArray, epkMerchant: ByteArray, isPayer: Boolean): SessionKeys {
        val transcript = sha256(utf8("BCHS|v1|"), epkPayer, epkMerchant)
        val p2m = Hkdf.derive(shared, transcript, utf8("bluecash payer->merchant"), 32)
        val m2p = Hkdf.derive(shared, transcript, utf8("bluecash merchant->payer"), 32)
        val sasBytes = Hkdf.derive(shared, transcript, utf8("bluecash sas"), 4)
        var v = 0L
        for (b in sasBytes) v = (v shl 8) or (b.toLong() and 0xff)
        val sas = (v % 1_000_000L).toString().padStart(6, '0')
        return if (isPayer) SessionKeys(p2m, m2p, sas, transcript) else SessionKeys(m2p, p2m, sas, transcript)
    }

    fun authMessage(role: String, transcript: ByteArray): ByteArray = utf8("BCAUTH|v1|$role|") + transcript
}

/**
 * AES-256-GCM with an implicit message counter as the nonce. Both sides count messages, so a
 * replayed, dropped, reordered or modified message fails authentication and aborts the session.
 */
class SecureChannel(private val sendKey: ByteArray, private val recvKey: ByteArray) {
    private var sendCtr = 0L
    private var recvCtr = 0L

    private fun nonce(c: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) n[11 - i] = (c ushr (8 * i)).toByte()
        return n
    }

    @Synchronized
    fun seal(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sendKey, "AES"), GCMParameterSpec(128, nonce(sendCtr)))
        c.updateAAD(AAD)
        sendCtr++
        return c.doFinal(plain)
    }

    @Synchronized
    fun open(cipherText: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(recvKey, "AES"), GCMParameterSpec(128, nonce(recvCtr)))
        c.updateAAD(AAD)
        val out = c.doFinal(cipherText) // throws if tampered/replayed/out of order
        recvCtr++
        return out
    }

    private companion object {
        val AAD = utf8("bluecash-v1")
    }
}
