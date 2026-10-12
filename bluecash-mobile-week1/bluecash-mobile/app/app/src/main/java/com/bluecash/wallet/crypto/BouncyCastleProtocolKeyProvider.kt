package com.bluecash.wallet.crypto

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom
import java.util.UUID

/**
 * Interim Ed25519 implementation using Bouncy Castle.
 *
 * This is one of the two fallback crypto libraries named in the Final
 * Proposal's tech stack ("Kotlin: BouncyCastle or Google Tink") for exactly
 * this situation: it lets the Android side keep moving before the shared
 * Rust core's UniFFI bindings are ready — or permanently, if that
 * integration doesn't pan out. The private key is generated here in
 * software and immediately handed to [DeviceIdentityStore] for encrypted,
 * Keystore-backed storage; the raw key material is never written to disk
 * unencrypted.
 */
class BouncyCastleProtocolKeyProvider(
    private val store: DeviceIdentityStore,
) : ProtocolKeyProvider {

    override fun hasIdentity(): Boolean =
        store.getPrivateKeyHex() != null && store.getPublicKeyHex() != null

    override fun getOrCreateIdentity(): ProtocolIdentity {
        val existingPrivate = store.getPrivateKeyHex()
        val existingPublic = store.getPublicKeyHex()
        val existingDeviceId = store.getDeviceId()

        if (existingPrivate != null && existingPublic != null && existingDeviceId != null) {
            return ProtocolIdentity(existingDeviceId, existingPublic, store.keystoreBacking)
        }

        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val privateKey = Ed25519PrivateKeyParameters(seed, 0)
        val publicKey = privateKey.generatePublicKey()

        val privateKeyHex = privateKey.encoded.toHex()
        val publicKeyHex = publicKey.encoded.toHex()
        val deviceId = UUID.randomUUID().toString()

        store.savePrivateKeyHex(privateKeyHex)
        store.savePublicIdentity(deviceId, publicKeyHex)

        return ProtocolIdentity(deviceId, publicKeyHex, store.keystoreBacking)
    }

    override fun sign(message: ByteArray): ByteArray {
        val privateKeyHex = store.getPrivateKeyHex()
            ?: error("No identity yet — call getOrCreateIdentity() first")
        val privateKey = Ed25519PrivateKeyParameters(privateKeyHex.fromHex(), 0)

        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.fromHex(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
