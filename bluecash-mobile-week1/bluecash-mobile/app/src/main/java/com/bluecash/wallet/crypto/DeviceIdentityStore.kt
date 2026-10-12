package com.bluecash.wallet.crypto

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.security.keystore.StrongBoxUnavailableException
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.bluecash.wallet.core.SecureKV

/**
 * Encrypted-at-rest storage for the device's protocol identity.
 *
 * The private key goes into an EncryptedSharedPreferences file backed by a
 * Keystore master key — StrongBox-backed where the device has a dedicated
 * secure chip, falling back to the TEE otherwise. The public key and device
 * ID aren't secret, so they live in a plain SharedPreferences file.
 *
 * This class is deliberately kept separate from the Ed25519 math in
 * [BouncyCastleProtocolKeyProvider]: when Person A's Rust core lands, only
 * the math implementation changes — this storage layer stays as-is.
 */
class DeviceIdentityStore(context: Context) : SecureKV {

    enum class KeystoreBacking { STRONGBOX, TEE, SOFTWARE_FALLBACK }

    private val appContext = context.applicationContext

    private val plainPrefs: SharedPreferences =
        appContext.getSharedPreferences(PLAIN_PREFS_NAME, Context.MODE_PRIVATE)

    private lateinit var backing: KeystoreBacking

    private val encryptedPrefs: SharedPreferences by lazy { buildEncryptedPrefs() }

    /** Which Keystore tier is actually backing the encrypted store right now. */
    val keystoreBacking: KeystoreBacking
        get() {
            encryptedPrefs // touch the lazy delegate so `backing` is set
            return backing
        }

    private fun buildEncryptedPrefs(): SharedPreferences {
        val strongBoxAvailable = appContext.packageManager
            .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        if (!strongBoxAvailable) return buildTeeBackedPrefs()

        return try {
            val masterKey = MasterKey.Builder(appContext, MASTER_KEY_ALIAS)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setRequestStrongBoxBacked(true)
                .build()
            backing = KeystoreBacking.STRONGBOX
            createEncryptedPrefs(masterKey)
        } catch (e: StrongBoxUnavailableException) {
            buildTeeBackedPrefs()
        } catch (e: Exception) {
            // Some devices advertise the feature but still fail at key
            // creation time; fall back rather than crash the app.
            buildTeeBackedPrefs()
        }
    }

    private fun buildTeeBackedPrefs(): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(appContext, MASTER_KEY_ALIAS)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            backing = KeystoreBacking.TEE
            createEncryptedPrefs(masterKey)
        } catch (e: Exception) {
            // Should only ever happen on a broken/emulated Keystore. This
            // keeps the app usable during early development but must never
            // be hit in a release build — the Settings screen surfaces the
            // backing tier precisely so this doesn't go unnoticed.
            backing = KeystoreBacking.SOFTWARE_FALLBACK
            plainPrefs
        }
    }

    private fun createEncryptedPrefs(masterKey: MasterKey): SharedPreferences =
        EncryptedSharedPreferences.create(
            appContext,
            ENCRYPTED_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

    // ---- SecureKV: the wallet keeps tokens, receipts and its ledger in the same encrypted file.
    // commit() (not apply()) so an accepted payment is on disk before we tell the payer "received".
    override fun get(key: String): String? = encryptedPrefs.getString(key, null)
    override fun put(key: String, value: String) { encryptedPrefs.edit().putString(key, value).commit() }
    override fun remove(key: String) { encryptedPrefs.edit().remove(key).commit() }
    override fun keys(prefix: String): List<String> = encryptedPrefs.all.keys.filter { it.startsWith(prefix) }.sorted()

    fun getPrivateKeyHex(): String? = encryptedPrefs.getString(KEY_PRIVATE_KEY, null)

    fun savePrivateKeyHex(hex: String) {
        encryptedPrefs.edit().putString(KEY_PRIVATE_KEY, hex).apply()
    }

    fun getPublicKeyHex(): String? = plainPrefs.getString(KEY_PUBLIC_KEY, null)

    fun getDeviceId(): String? = plainPrefs.getString(KEY_DEVICE_ID, null)

    fun savePublicIdentity(deviceId: String, publicKeyHex: String) {
        plainPrefs.edit()
            .putString(KEY_DEVICE_ID, deviceId)
            .putString(KEY_PUBLIC_KEY, publicKeyHex)
            .apply()
    }

    /** Wipes the stored identity. Useful for testing the generate-identity flow again. */
    fun clear() {
        plainPrefs.edit().clear().apply()
        encryptedPrefs.edit().clear().apply()
    }

    companion object {
        private const val MASTER_KEY_ALIAS = "bluecash_device_master_key"
        private const val ENCRYPTED_PREFS_NAME = "bluecash_identity_encrypted"
        private const val PLAIN_PREFS_NAME = "bluecash_identity_public"
        private const val KEY_PRIVATE_KEY = "protocol_private_key_hex"
        private const val KEY_PUBLIC_KEY = "protocol_public_key_hex"
        private const val KEY_DEVICE_ID = "device_id"
    }
}
