package com.bluecash.wallet.session

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.bluecash.wallet.AppContainer
import com.bluecash.wallet.SyncScheduler
import com.bluecash.wallet.ble.BleMerchant
import com.bluecash.wallet.core.FrameTransport
import com.bluecash.wallet.core.Limits
import com.bluecash.wallet.core.MerchantSession
import com.bluecash.wallet.core.Outcome
import com.bluecash.wallet.core.SessionResult
import com.bluecash.wallet.core.SessionUi
import com.bluecash.wallet.core.X25519
import com.bluecash.wallet.core.hex
import com.bluecash.wallet.core.sha256
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

enum class ReceivePhase { IDLE, ADVERTISING, SESSION, DONE }

/** Drives the receiving side: advertise -> accept one payer -> run [MerchantSession]. */
object ReceiveController : SessionUi {
    var phase by mutableStateOf(ReceivePhase.IDLE)
    var status by mutableStateOf("")
    var sas by mutableStateOf<String?>(null)
    var result by mutableStateOf<SessionResult?>(null)
    var qrText by mutableStateOf<String?>(null)
    var requestedAmount by mutableStateOf(0)

    private var ble: BleMerchant? = null
    private var pending: CompletableFuture<Boolean>? = null

    fun start(context: Context, amount: Int) {
        reset()
        val w = AppContainer.wallet
        val cred = w.credential()
        val mintPub = w.mintPub()
        if (cred == null || mintPub == null) { fail("Register this device with the mint first (Settings)"); return }
        if (w.mintKeys().isEmpty()) { fail("No mint keys cached yet - run Sync in Settings once while online"); return }
        if (amount <= 0) { fail("Enter an amount"); return }
        AppContainer.integrityBlocks()?.let { fail(it); return }

        requestedAmount = amount
        val eph = X25519.generate() // fresh key per payment: this is what gives forward secrecy
        // The QR lets the payer check it is talking to THIS screen, defeating an impersonating phone.
        qrText = JSONObject().put("v", 1).put("h", sha256(eph.pub).hex()).toString()
        val appCtx = context.applicationContext
        val merchantId = AppContainer.effectiveMerchantName()
        val b = BleMerchant(appCtx, object : BleMerchant.Listener {
            override fun onAdvertising() { status = "Ready - ask the customer to open Pay"; phase = ReceivePhase.ADVERTISING }
            override fun onError(message: String) { fail(message) }
            override fun onPayerConnected(transport: FrameTransport) {
                phase = ReceivePhase.SESSION
                thread(name = "receive-session") {
                    val r = MerchantSession(
                        transport, AppContainer.signer, cred, merchantId, amount, mintPub, w.mintKeys(), w.revokedIds(), w, this@ReceiveController, eph,
                    ).run()
                    ble?.stop()
                    result = r
                    sas = null
                    phase = ReceivePhase.DONE
                    AppContainer.refreshState()
                    if (r.outcome == Outcome.SUCCESS) SyncScheduler.syncNow(appCtx)
                }
            }
        })
        ble = b
        status = "Starting…"
        b.start()
    }

    private fun fail(msg: String) {
        ble?.stop()
        result = SessionResult(Outcome.FAILED, msg)
        phase = ReceivePhase.DONE
    }

    fun stop() {
        pending?.complete(false)
        ble?.stop()
        ble = null
        phase = ReceivePhase.IDLE
        qrText = null
    }

    fun reset() { stop(); result = null; sas = null; status = "" }

    fun answer(ok: Boolean) { pending?.complete(ok) }

    override fun status(msg: String) { status = msg }

    override fun confirmSas(sas: String): Boolean {
        val f = CompletableFuture<Boolean>()
        pending = f
        this.sas = sas
        return try { f.get(Limits.HUMAN_WAIT_MS, TimeUnit.MILLISECONDS) } catch (e: Exception) { false } finally { this.sas = null; pending = null }
    }

    override fun confirmPayment(amount: Int, merchantId: String): Boolean = true // merchants don't confirm; they set the amount
}
