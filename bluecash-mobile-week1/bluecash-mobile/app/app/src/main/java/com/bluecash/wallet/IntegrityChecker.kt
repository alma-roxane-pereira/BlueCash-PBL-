package com.bluecash.wallet

import android.content.Context
import android.util.Base64
import com.bluecash.wallet.core.Rand
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

sealed class IntegrityState {
    object NotChecked : IntegrityState()
    object NotConfigured : IntegrityState()
    object Checking : IntegrityState()
    data class TokenIssued(val preview: String) : IntegrityState()
    data class Failed(val reason: String) : IntegrityState()
}

/**
 * Asks Google Play whether this app + device look genuine (not tampered, not an emulator,
 * Play-installed). IMPORTANT: the phone only receives an opaque token. Only the backend can
 * decode and judge it, so a client-side "ok" proves nothing by itself; the mint must verify
 * the token we send at registration.
 */
object IntegrityChecker {
    fun check(context: Context, onResult: (IntegrityState, String?) -> Unit) {
        val project = AppConfig.PLAY_INTEGRITY_CLOUD_PROJECT
        if (project == 0L) { onResult(IntegrityState.NotConfigured, null); return }
        onResult(IntegrityState.Checking, null)
        val nonce = Base64.encodeToString(Rand.bytes(32), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        try {
            IntegrityManagerFactory.create(context.applicationContext)
                .requestIntegrityToken(IntegrityTokenRequest.builder().setNonce(nonce).setCloudProjectNumber(project).build())
                .addOnSuccessListener { r -> val t = r.token(); onResult(IntegrityState.TokenIssued(t.take(12) + "…"), t) }
                .addOnFailureListener { e -> onResult(IntegrityState.Failed(e.message ?: "integrity check failed"), null) }
        } catch (e: Exception) {
            onResult(IntegrityState.Failed(e.message ?: "integrity check failed"), null)
        }
    }

    /**
     * Blocking version for use on a worker thread (e.g. just before registering with the mint).
     * Returns the token, or null if integrity isn't configured / the check failed; the
     * outcome is also published to [AppContainer.integrity].
     */
    fun checkBlocking(context: Context): String? {
        val f = java.util.concurrent.CompletableFuture<String?>()
        check(context) { state, token ->
            AppContainer.integrity = state
            if (state !is IntegrityState.Checking) f.complete(token)
        }
        return try { f.get(20, java.util.concurrent.TimeUnit.SECONDS) } catch (e: Exception) { null }
    }
}
