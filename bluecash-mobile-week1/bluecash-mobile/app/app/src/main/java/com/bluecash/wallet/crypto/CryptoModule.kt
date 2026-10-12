package com.bluecash.wallet.crypto

import android.content.Context

/**
 * Manual dependency access point — no DI framework needed for a project this size.
 * Swap the implementation returned here to move from BouncyCastle to the real Rust/UniFFI
 * bindings once Person A's crate interface lands; nothing that calls these needs to change.
 */
object CryptoModule {
    @Volatile private var store: DeviceIdentityStore? = null
    @Volatile private var provider: ProtocolKeyProvider? = null

    /** The one encrypted store shared by the identity key and the wallet. */
    fun provideStore(context: Context): DeviceIdentityStore =
        store ?: synchronized(this) {
            store ?: DeviceIdentityStore(context).also { store = it }
        }

    fun provideProtocolKeyProvider(context: Context): ProtocolKeyProvider =
        provider ?: synchronized(this) {
            provider ?: BouncyCastleProtocolKeyProvider(provideStore(context)).also { provider = it }
        }
}
