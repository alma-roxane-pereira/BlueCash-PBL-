package com.bluecash.wallet.core

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/** Anything that can sign with the device's Ed25519 identity key. */
interface Signer {
    val publicKey: ByteArray
    fun sign(message: ByteArray): ByteArray
}

/** Ed25519 via Bouncy Castle (the interim crypto library until the Rust core's bindings land). */
object Ed25519 {
    fun newSeed(): ByteArray = Rand.bytes(32)

    fun publicKey(seed: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded

    fun sign(seed: ByteArray, msg: ByteArray): ByteArray {
        val s = Ed25519Signer()
        s.init(true, Ed25519PrivateKeyParameters(seed, 0))
        s.update(msg, 0, msg.size)
        return s.generateSignature()
    }

    fun verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = try {
        val s = Ed25519Signer()
        s.init(false, Ed25519PublicKeyParameters(pub, 0))
        s.update(msg, 0, msg.size)
        s.verifySignature(sig)
    } catch (e: Exception) {
        false
    }
}

/** A signer that holds its seed in memory. Used by the simulated mint and in tests. */
class SeedSigner(private val seed: ByteArray) : Signer {
    override val publicKey: ByteArray = Ed25519.publicKey(seed)
    override fun sign(message: ByteArray): ByteArray = Ed25519.sign(seed, message)
}

/** X25519 key agreement: the basis of the forward-secret BLE session key. */
object X25519 {
    class KeyPair(val priv: X25519PrivateKeyParameters, val pub: ByteArray)

    fun generate(): KeyPair {
        val priv = X25519PrivateKeyParameters(Rand.rnd)
        return KeyPair(priv, priv.generatePublicKey().encoded)
    }

    fun agree(priv: X25519PrivateKeyParameters, peerPub: ByteArray): ByteArray {
        require(peerPub.size == 32) { "bad public key length" }
        val out = ByteArray(32)
        priv.generateSecret(X25519PublicKeyParameters(peerPub, 0), out, 0)
        return out
    }
}
