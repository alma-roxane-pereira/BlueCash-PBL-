package com.bluecash.wallet.crypto

/**
 * Everything the app needs from "the crypto layer" for protocol identity:
 * generate a keypair, know the current identity, and sign a message.
 *
 * This interface is shaped to match what Person A's UniFFI-generated
 * bindings to the shared `bluecash-crypto` Rust core will eventually expose
 * (see the Final Proposal, Section 2 — generateEd25519Keypair / sign /
 * verify). [BouncyCastleProtocolKeyProvider] is a temporary, fully
 * functional implementation so the rest of the app — this Settings screen,
 * the Week 3 minting flow — can be built and tested now, without waiting on
 * the crate. Swapping in the real bindings later means changing what
 * [CryptoModule] returns; nothing that calls this interface needs to change.
 */
interface ProtocolKeyProvider {

    /** True once a device identity has been generated and persisted. */
    fun hasIdentity(): Boolean

    /** Returns the existing identity, or generates and persists a new one. */
    fun getOrCreateIdentity(): ProtocolIdentity

    /** Signs [message] with the device's protocol private key. */
    fun sign(message: ByteArray): ByteArray
}

data class ProtocolIdentity(
    val deviceId: String,
    val publicKeyHex: String,
    val keystoreBacking: DeviceIdentityStore.KeystoreBacking,
)
