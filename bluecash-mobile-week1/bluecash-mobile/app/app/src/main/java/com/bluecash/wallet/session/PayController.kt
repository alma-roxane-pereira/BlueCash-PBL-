package com.bluecash.wallet.session

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.bluecash.wallet.AppContainer
import com.bluecash.wallet.ble.BleConstants
import com.bluecash.wallet.ble.BlePayer
import com.bluecash.wallet.core.FrameTransport
import com.bluecash.wallet.core.Limits
import com.bluecash.wallet.core.Outcome
import com.bluecash.wallet.core.PayerSession
import com.bluecash.wallet.core.SessionResult
import com.bluecash.wallet.core.SessionUi
import com.bluecash.wallet.core.unhex
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

enum class PayPhase { IDLE, SCANNING, CONNECTING, SESSION, DONE }

/** Drives the paying side: scan -> connect -> run [PayerSession]; exposes state for the Pay screen. */
object PayController : SessionUi {
    var phase by mutableStateOf(PayPhase.IDLE)
    var found by mutableStateOf<List<BlePayer.Found>>(emptyList())
    var status by mutableStateOf("")
    var sas by mutableStateOf<String?>(null)
    var paymentRequest by mutableStateOf<Pair<Int, String>?>(null)
    var result by mutableStateOf<SessionResult?>(null)
    var qrBound by mutableStateOf(false)

    private var qrHash: ByteArray? = null
    private var ble: BlePayer? = null
    private var pending: CompletableFuture<Boolean>? = null

    /** Merchant's QR: {"v":1,"h":"<sha256 of the merchant's session key>"}. */
    fun setQr(text: String): Boolean = try {
        val o = JSONObject(text)
        qrHash = o.getString("h").unhex()
        qrBound = qrHash!!.size == 32
        if (!qrBound) qrHash = null
        qrBound
    } catch (e: Exception) { false }

    fun clearQr() { qrHash = null; qrBound = false }

    fun startScan(context: Context) {
        reset(keepQr = true)
        AppContainer.integrityBlocks()?.let { fail(it); return }
        val p = BlePayer(context.applicationContext)
        ble = p
        phase = PayPhase.SCANNING
        status = "Looking for nearby merchants…"
        p.startScan(object : BlePayer.ScanListener {
            override fun onResults(list: List<BlePayer.Found>) { found = list }
            override fun onError(message: String) { fail(message) }
        })
    }

    fun connect(f: BlePayer.Found) {
        val p = ble ?: return
        val cred = AppContainer.wallet.credential()
        val mintPub = AppContainer.wallet.mintPub()
        if (cred == null || mintPub == null) { fail("Register this device with the mint first (Settings)"); return }
        if (f.rssi < BleConstants.MIN_RSSI) { fail("That merchant's signal is too weak (${f.rssi} dBm). Move closer."); return }
        AppContainer.integrityBlocks()?.let { fail(it); return }
        phase = PayPhase.CONNECTING
        status = "Connecting…"
        p.connect(f, object : BlePayer.ConnectListener {
            override fun onReady(transport: FrameTransport) { runSession(transport, cred, mintPub) }
            override fun onFailed(message: String) { fail(message) }
        })
    }

    private fun runSession(transport: FrameTransport, cred: com.bluecash.wallet.core.DeviceCredential, mintPub: ByteArray) {
        phase = PayPhase.SESSION
        thread(name = "pay-session") {
            val r = PayerSession(
                transport, AppContainer.signer, cred, mintPub, AppContainer.wallet.revokedIds(),
                AppContainer.wallet, this, expectedMerchantKeyHash = qrHash,
            ).run()
            ble?.disconnect()
            result = r
            sas = null
            paymentRequest = null
            phase = PayPhase.DONE
            AppContainer.refreshState()
        }
    }

    private fun fail(msg: String) {
        ble?.stopScan()
        ble?.disconnect()
        result = SessionResult(Outcome.FAILED, msg)
        phase = PayPhase.DONE
    }

    fun cancel() {
        pending?.complete(false)
        ble?.stopScan()
        ble?.disconnect()
        if (phase != PayPhase.DONE) { phase = PayPhase.IDLE }
    }

    fun reset(keepQr: Boolean = false) {
        cancel()
        found = emptyList(); status = ""; sas = null; paymentRequest = null; result = null
        if (!keepQr) clearQr()
        phase = PayPhase.IDLE
    }

    fun answer(ok: Boolean) { pending?.complete(ok) }

    // ---- SessionUi (called from the session thread; blocks until the user answers) ----
    override fun status(msg: String) { status = msg }

    private fun ask(show: () -> Unit, hide: () -> Unit): Boolean {
        val f = CompletableFuture<Boolean>()
        pending = f
        show()
        return try { f.get(Limits.HUMAN_WAIT_MS, TimeUnit.MILLISECONDS) } catch (e: Exception) { false } finally { hide(); pending = null }
    }

    override fun confirmSas(sas: String): Boolean = ask({ this.sas = sas }, { this.sas = null })
    override fun confirmPayment(amount: Int, merchantId: String): Boolean =
        ask({ paymentRequest = amount to merchantId }, { paymentRequest = null })
}
