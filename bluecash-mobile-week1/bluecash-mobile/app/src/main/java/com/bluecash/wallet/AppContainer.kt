package com.bluecash.wallet

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.bluecash.wallet.core.HttpMintApi
import com.bluecash.wallet.core.LedgerEntry
import com.bluecash.wallet.core.MintApi
import com.bluecash.wallet.core.SimulatedMint
import com.bluecash.wallet.core.Signer
import com.bluecash.wallet.core.TokenState
import com.bluecash.wallet.core.Wallet
import com.bluecash.wallet.core.hex
import com.bluecash.wallet.core.unhex
import com.bluecash.wallet.crypto.CryptoModule
import com.bluecash.wallet.crypto.DeviceIdentityStore
import com.bluecash.wallet.crypto.ProtocolKeyProvider
import kotlin.concurrent.thread

/** Adapts the Keystore-backed key provider to the [Signer] the protocol code expects. */
class KeyProviderSigner(private val p: ProtocolKeyProvider) : Signer {
    override val publicKey: ByteArray get() = p.getOrCreateIdentity().publicKeyHex.unhex()
    override fun sign(message: ByteArray): ByteArray = p.sign(message)
}

/**
 * Single place that builds the app's long-lived objects, plus the observable state the
 * screens read. Screens never block: they call [refreshAsync] and Compose redraws when the
 * fields below change.
 */
object AppContainer {
    private lateinit var app: Application
    private var initialized = false

    lateinit var store: DeviceIdentityStore
        private set
    lateinit var keyProvider: ProtocolKeyProvider
        private set
    lateinit var signer: Signer
        private set
    lateinit var wallet: Wallet
        private set

    // ---- observable UI state ----
    var hasIdentity by mutableStateOf(false)
    var registered by mutableStateOf(false)
    var balance by mutableStateOf(0)
    var pendingAmount by mutableStateOf(0)
    var tokenCount by mutableStateOf(0)
    var ledgerOk by mutableStateOf(true)
    var recent by mutableStateOf<List<LedgerEntry>>(emptyList())
    var alerts by mutableStateOf<List<String>>(emptyList())
    var pendingReceipts by mutableStateOf(0)
    var revokedCount by mutableStateOf(0)
    var auditRoot by mutableStateOf("")
    var serverUrl by mutableStateOf("")
    var merchantName by mutableStateOf("")
    var integrity by mutableStateOf<IntegrityState>(IntegrityState.NotChecked)

    fun init(application: Application) {
        if (initialized) return
        app = application
        store = CryptoModule.provideStore(app)
        keyProvider = CryptoModule.provideProtocolKeyProvider(app)
        signer = KeyProviderSigner(keyProvider)
        wallet = Wallet(store, signer)
        val prefs = app.getSharedPreferences("bluecash_settings", Context.MODE_PRIVATE)
        serverUrl = prefs.getString("server_url", "") ?: ""
        merchantName = prefs.getString("merchant_name", "") ?: ""
        initialized = true
    }

    fun saveServerUrl(url: String) {
        serverUrl = url.trim()
        app.getSharedPreferences("bluecash_settings", Context.MODE_PRIVATE).edit().putString("server_url", serverUrl).apply()
    }

    fun saveMerchantName(name: String) {
        merchantName = name.trim()
        app.getSharedPreferences("bluecash_settings", Context.MODE_PRIVATE).edit().putString("merchant_name", merchantName).apply()
    }

    /** Blank server URL means "use the simulated mint that runs inside the app". */
    fun mintApi(): MintApi = if (serverUrl.isBlank()) SimulatedMint(store) else HttpMintApi(serverUrl)
    fun usingSimulatedMint(): Boolean = serverUrl.isBlank()

    /** Name shown to payers; defaults to something derived from the device key. */
    fun effectiveMerchantName(): String =
        merchantName.ifBlank { "shop-" + signer.publicKey.hex().take(6) }

    fun refreshState() {
        hasIdentity = keyProvider.hasIdentity()
        registered = wallet.isRegistered()
        val toks = wallet.tokens()
        balance = wallet.balance()
        pendingAmount = wallet.pendingAmount()
        tokenCount = toks.count { it.state == TokenState.UNSPENT }
        ledgerOk = wallet.ledger.verify()
        recent = wallet.ledger.entries().takeLast(8).reversed()
        alerts = wallet.alerts().reversed()
        pendingReceipts = wallet.pendingReceipts().size
        revokedCount = wallet.revokedIds().size
        auditRoot = wallet.auditRoot() ?: ""
    }

    fun refreshAsync() { thread(name = "refresh") { runCatching { refreshState() } } }

    fun resetWallet() {
        wallet.resetData()
        wallet = Wallet(store, signer) // fresh in-memory caches
        refreshState()
    }

    /** If Play Integrity is configured and the last check failed, risky actions are blocked. */
    fun integrityBlocks(): String? =
        (integrity as? IntegrityState.Failed)?.let { "Device integrity check failed: ${it.reason}" }
}
