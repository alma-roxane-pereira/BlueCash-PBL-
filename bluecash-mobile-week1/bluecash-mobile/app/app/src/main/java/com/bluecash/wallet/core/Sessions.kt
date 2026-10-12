package com.bluecash.wallet.core

import org.json.JSONArray
import org.json.JSONObject
import java.security.GeneralSecurityException
import java.util.concurrent.TimeoutException

enum class Outcome { SUCCESS, DECLINED, REJECTED, FAILED, UNCERTAIN }

data class SessionResult(val outcome: Outcome, val message: String, val amount: Int = 0)

object Limits {
    /** Round-trip time above this on the app-level challenge is treated as a possible relay attack. */
    const val MAX_RTT_MS = 1000L
    const val HELLO_WAIT_MS = 30_000L
    const val HUMAN_WAIT_MS = 120_000L
    const val STEP_WAIT_MS = 10_000L
    const val PINGS = 3
    const val MAX_TOKENS_PER_PAYMENT = 40
}

/** JSON messages over the encrypted channel. */
private class SecureLink(private val t: FrameTransport, private val ch: SecureChannel) {
    fun send(o: JSONObject) = t.send(ch.seal(utf8(o.toString())))
    fun recv(timeoutMs: Long): JSONObject = JSONObject(String(ch.open(t.receive(timeoutMs)), Charsets.UTF_8))
}

private fun JSONObject.type(): String = optString("t")

private fun peerCredentialError(c: DeviceCredential, mintPub: ByteArray, revoked: Set<String>, nowMs: Long): String? = when {
    !c.verify(mintPub, nowMs) -> "the other device's credential is invalid or expired"
    c.credId in revoked -> "the other device has been revoked for fraud"
    else -> null
}

/**
 * The paying phone. Protocol (everything after REVEAL is AES-256-GCM encrypted):
 *   HELLO(hash of key) -> HELLO_ACK(merchant key) -> REVEAL(payer key)
 *   -> [humans compare the 6-digit code] -> AUTH <-> AUTH
 *   -> PING/PONG x3 (distance check) -> REQUEST -> [user confirms] -> TOKENS -> RECEIPTS
 */
class PayerSession(
    private val transport: FrameTransport,
    private val signer: Signer,
    private val credential: DeviceCredential,
    private val mintPub: ByteArray,
    private val revoked: Set<String>,
    private val vault: SpendVault,
    private val ui: SessionUi,
    private val clock: () -> Long = { System.currentTimeMillis() },
    /** SHA-256 of the merchant's ephemeral key, read from the merchant's QR code (optional extra protection). */
    private val expectedMerchantKeyHash: ByteArray? = null,
) {
    fun run(): SessionResult {
        var locked: List<String> = emptyList()
        var tokensSent = false
        try {
            ui.status("Securing the connection…")
            val eph = X25519.generate()
            // Commit-then-reveal: we first send only a HASH of our key. Whoever answers must therefore pick
            // their key before they can know ours, so nobody can tune keys until the 6-digit codes match.
            transport.send(utf8(JSONObject().put("t", "HELLO").put("v", 2).put("commit", sha256(eph.pub).hex()).toString()))
            val ack = JSONObject(String(transport.receive(Limits.STEP_WAIT_MS), Charsets.UTF_8))
            if (ack.type() != "HELLO_ACK") return SessionResult(Outcome.FAILED, "unexpected reply from merchant")
            val epkM = ack.getString("epk").unhex()
            if (expectedMerchantKeyHash != null && !ctEquals(sha256(epkM), expectedMerchantKeyHash))
                return SessionResult(Outcome.FAILED, "this is not the merchant whose QR code you scanned (possible impersonation)")
            transport.send(utf8(JSONObject().put("t", "REVEAL").put("epk", eph.pub.hex()).toString()))

            val keys = Handshake.derive(X25519.agree(eph.priv, epkM), eph.pub, epkM, isPayer = true)
            val link = SecureLink(transport, SecureChannel(keys.sendKey, keys.recvKey))

            ui.status("Compare the code on both phones")
            if (!ui.confirmSas(keys.sas)) {
                runCatching { link.send(JSONObject().put("t", "ABORT").put("reason", "code mismatch")) }
                return SessionResult(Outcome.DECLINED, "codes did not match - cancelled")
            }

            link.send(JSONObject().put("t", "AUTH").put("cred", credential.toJson())
                .put("sig", signer.sign(Handshake.authMessage("payer", keys.transcript)).hex()))
            val auth = link.recv(Limits.HUMAN_WAIT_MS)
            if (auth.type() != "AUTH") return SessionResult(Outcome.DECLINED, auth.optString("reason", "merchant cancelled"))
            val merchantCred = DeviceCredential.fromJson(auth.getJSONObject("cred"))
            peerCredentialError(merchantCred, mintPub, revoked, clock())?.let { return SessionResult(Outcome.FAILED, it) }
            if (!Ed25519.verify(merchantCred.devicePub.unhex(), Handshake.authMessage("merchant", keys.transcript), auth.getString("sig").unhex()))
                return SessionResult(Outcome.FAILED, "merchant could not prove its identity")

            ui.status("Waiting for the payment request…")
            var req: JSONObject
            while (true) {
                req = link.recv(Limits.HUMAN_WAIT_MS)
                when (req.type()) {
                    "PING" -> link.send(JSONObject().put("t", "PONG").put("n", req.getString("n")))
                    "REQUEST" -> break
                    "ABORT" -> return SessionResult(Outcome.DECLINED, req.optString("reason", "merchant cancelled"))
                    else -> return SessionResult(Outcome.FAILED, "unexpected message")
                }
            }
            val amount = req.getInt("amount")
            val merchantId = req.getString("merchant_id")
            val nCtx = req.getString("n_ctx")
            if (amount <= 0) return SessionResult(Outcome.FAILED, "invalid amount requested")

            if (!ui.confirmPayment(amount, merchantId)) {
                runCatching { link.send(JSONObject().put("t", "ABORT").put("reason", "payer declined")) }
                return SessionResult(Outcome.DECLINED, "payment cancelled")
            }
            val chosen = vault.selectExact(amount)
            if (chosen == null) {
                runCatching { link.send(JSONObject().put("t", "ABORT").put("reason", "payer cannot make exact amount")) }
                return SessionResult(Outcome.FAILED, "you can't make exactly ₹$amount from your tokens (offline payments can't give change)")
            }
            if (chosen.size > Limits.MAX_TOKENS_PER_PAYMENT) return SessionResult(Outcome.FAILED, "too many tokens needed for this amount")

            val a0 = vault.identitySecret()
            val items = JSONArray()
            val ids = chosen.map { it.token.tokenId }
            vault.lock(ids)
            locked = ids
            for (st in chosen) {
                val x = Group.challengeX(st.token.tokenId, nCtx)
                val y = Group.evalShare(a0, bigFromHex(st.a1), x)
                items.put(JSONObject().put("token", st.token.toJson()).put("x", x.toHexString()).put("y", y.toHexString())
                    .put("sig", signer.sign(Msg.spend(st.token.tokenId, nCtx, st.token.amount)).hex()))
            }
            ui.status("Sending payment…")
            link.send(JSONObject().put("t", "TOKENS").put("items", items))
            tokensSent = true

            val resp = link.recv(Limits.HUMAN_WAIT_MS)
            if (resp.type() == "REJECT") {
                vault.unlock(ids)
                return SessionResult(Outcome.REJECTED, resp.optString("reason", "merchant rejected the payment"))
            }
            if (resp.type() != "RECEIPTS") return SessionResult(Outcome.UNCERTAIN, "no receipt received - tokens kept locked")
            val receipts = resp.getJSONArray("receipts").objects().map { Receipt.fromJson(it) }
            val sent = chosen.associateBy { it.token.tokenId }
            val ok = receipts.size == chosen.size && receipts.all { r ->
                val st = sent[r.token.tokenId]
                st != null && r.nCtx == nCtx && r.amount == st.token.amount && r.merchantId == merchantId &&
                    r.merchantCred.devicePub == merchantCred.devicePub &&
                    Ed25519.verify(merchantCred.devicePub.unhex(), r.merchantSigned(), r.merchantSig.unhex())
            }
            if (!ok) return SessionResult(Outcome.UNCERTAIN, "receipt did not verify - tokens kept locked")
            vault.markSpent(ids)
            vault.recordLedger("PAY_SENT", JSONObject().put("amount", amount).put("merchant_id", merchantId)
                .put("receipts", receipts.map { it.receiptId }.toJsonArray { it }))
            return SessionResult(Outcome.SUCCESS, "paid ₹$amount", amount)
        } catch (e: TimeoutException) {
            return if (tokensSent) SessionResult(Outcome.UNCERTAIN, "no reply after sending - tokens kept locked") else SessionResult(Outcome.FAILED, "the other phone stopped responding")
        } catch (e: TransportClosedException) {
            return if (tokensSent) SessionResult(Outcome.UNCERTAIN, "connection lost after sending - tokens kept locked") else {
                if (locked.isNotEmpty()) vault.unlock(locked)
                SessionResult(Outcome.FAILED, "connection lost")
            }
        } catch (e: GeneralSecurityException) {
            return SessionResult(if (tokensSent) Outcome.UNCERTAIN else Outcome.FAILED, "secure channel check failed")
        } catch (e: Exception) {
            return SessionResult(if (tokensSent) Outcome.UNCERTAIN else Outcome.FAILED, e.message ?: "unexpected error")
        } finally {
            runCatching { transport.close() }
        }
    }
}

/** The receiving phone (merchant). Mirror image of [PayerSession]. */
class MerchantSession(
    private val transport: FrameTransport,
    private val signer: Signer,
    private val credential: DeviceCredential,
    private val merchantId: String,
    private val amount: Int,
    private val mintPub: ByteArray,
    private val mintKeys: List<MintKey>,
    private val revoked: Set<String>,
    private val store: MerchantStore,
    private val ui: SessionUi,
    private val ephemeral: X25519.KeyPair,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val maxRttMs: Long = Limits.MAX_RTT_MS,
) {
    fun run(): SessionResult {
        try {
            ui.status("Phone connected - securing…")
            val hello = JSONObject(String(transport.receive(Limits.HELLO_WAIT_MS), Charsets.UTF_8))
            if (hello.type() != "HELLO") return SessionResult(Outcome.FAILED, "unexpected first message")
            if (hello.optInt("v") != 2) return SessionResult(Outcome.FAILED, "the payer's app version is not compatible")
            val commit = hello.getString("commit").unhex()
            transport.send(utf8(JSONObject().put("t", "HELLO_ACK").put("epk", ephemeral.pub.hex()).toString()))
            val reveal = JSONObject(String(transport.receive(Limits.STEP_WAIT_MS), Charsets.UTF_8))
            if (reveal.type() != "REVEAL") return SessionResult(Outcome.FAILED, "unexpected message during handshake")
            val epkP = reveal.getString("epk").unhex()
            if (!ctEquals(sha256(epkP), commit)) return SessionResult(Outcome.FAILED, "the payer's key does not match what it committed to (possible attack)")

            val keys = Handshake.derive(X25519.agree(ephemeral.priv, epkP), epkP, ephemeral.pub, isPayer = false)
            val link = SecureLink(transport, SecureChannel(keys.sendKey, keys.recvKey))

            ui.status("Compare the code on both phones")
            if (!ui.confirmSas(keys.sas)) {
                runCatching { link.send(JSONObject().put("t", "ABORT").put("reason", "code mismatch")) }
                return SessionResult(Outcome.DECLINED, "codes did not match - cancelled")
            }
            link.send(JSONObject().put("t", "AUTH").put("cred", credential.toJson())
                .put("sig", signer.sign(Handshake.authMessage("merchant", keys.transcript)).hex()))
            val auth = link.recv(Limits.HUMAN_WAIT_MS)
            if (auth.type() != "AUTH") return SessionResult(Outcome.DECLINED, auth.optString("reason", "payer cancelled"))
            val payerCred = DeviceCredential.fromJson(auth.getJSONObject("cred"))
            peerCredentialError(payerCred, mintPub, revoked, clock())?.let {
                runCatching { link.send(JSONObject().put("t", "ABORT").put("reason", "credential rejected")) }
                return SessionResult(Outcome.FAILED, it)
            }
            if (!Ed25519.verify(payerCred.devicePub.unhex(), Handshake.authMessage("payer", keys.transcript), auth.getString("sig").unhex()))
                return SessionResult(Outcome.FAILED, "payer could not prove its identity")

            // Distance check: a relay (someone forwarding messages from far away) adds delay.
            ui.status("Checking distance…")
            var best = Long.MAX_VALUE
            repeat(Limits.PINGS) {
                val n = Rand.bytes(8).hex()
                val t0 = System.nanoTime()
                link.send(JSONObject().put("t", "PING").put("n", n))
                val pong = link.recv(Limits.STEP_WAIT_MS)
                val rtt = (System.nanoTime() - t0) / 1_000_000
                if (pong.type() != "PONG" || pong.optString("n") != n) return SessionResult(Outcome.FAILED, "distance check failed")
                best = minOf(best, rtt)
            }
            if (best > maxRttMs) {
                runCatching { link.send(JSONObject().put("t", "ABORT").put("reason", "too slow")) }
                return SessionResult(Outcome.FAILED, "connection too slow (${best} ms) - possible relay attack, refused")
            }

            val nCtx = "$merchantId|${clock()}|${Rand.bytes(8).hex()}"
            link.send(JSONObject().put("t", "REQUEST").put("merchant_id", merchantId).put("amount", amount).put("n_ctx", nCtx))
            ui.status("Waiting for the payer to confirm…")
            val msg = link.recv(Limits.HUMAN_WAIT_MS)
            if (msg.type() == "ABORT") return SessionResult(Outcome.DECLINED, msg.optString("reason", "payer cancelled"))
            if (msg.type() != "TOKENS") return SessionResult(Outcome.FAILED, "unexpected message")

            ui.status("Verifying tokens…")
            val items = msg.getJSONArray("items").objects()
            fun reject(reason: String): SessionResult {
                runCatching { link.send(JSONObject().put("t", "REJECT").put("reason", reason)) }
                return SessionResult(Outcome.REJECTED, reason)
            }
            if (items.isEmpty() || items.size > Limits.MAX_TOKENS_PER_PAYMENT) return reject("bad number of tokens")
            val now = clock()
            var total = 0
            val ids = HashSet<String>()
            val parsed = ArrayList<Triple<Token, JSONObject, Int>>()
            for (it in items) {
                val token = Token.fromJson(it.getJSONObject("token"))
                if (!ids.add(token.tokenId)) return reject("same token sent twice")
                Verify.token(token, mintKeys, now)?.let { e -> return reject(e) }
                Verify.spend(token, nCtx, it.getString("x"), it.getString("y"), payerCred, it.getString("sig"))?.let { e -> return reject(e) }
                if (store.hasSeen(token.tokenId)) return reject("this token was already spent here")
                total += token.amount
                parsed.add(Triple(token, it, token.amount))
            }
            if (total != amount) return reject("amount is ₹$total but ₹$amount was requested")

            val receipts = parsed.map { (token, it, amt) ->
                val receiptId = java.util.UUID.randomUUID().toString()
                val ts = clock()
                val x = it.getString("x"); val y = it.getString("y")
                val sig = signer.sign(Msg.receipt(receiptId, token.tokenId, nCtx, x, y, amt, merchantId, ts)).hex()
                Receipt(receiptId, token, nCtx, x, y, amt, payerCred, it.getString("sig"), merchantId, credential, sig, ts)
            }
            // Persist BEFORE replying, so a crash can never lose money that was already accepted.
            for (r in receipts) { store.markSeen(r.token.tokenId); store.saveReceipt(r) }
            store.recordLedger("PAY_RECEIVED", JSONObject().put("amount", amount)
                .put("receipts", receipts.map { it.receiptId }.toJsonArray { it }))
            link.send(JSONObject().put("t", "RECEIPTS").put("receipts", receipts.toJsonArray { it.toJson() }))
            return SessionResult(Outcome.SUCCESS, "received ₹$amount", amount)
        } catch (e: TimeoutException) {
            return SessionResult(Outcome.FAILED, "the other phone stopped responding")
        } catch (e: TransportClosedException) {
            return SessionResult(Outcome.FAILED, "connection lost")
        } catch (e: GeneralSecurityException) {
            return SessionResult(Outcome.FAILED, "secure channel check failed")
        } catch (e: Exception) {
            return SessionResult(Outcome.FAILED, e.message ?: "unexpected error")
        } finally {
            runCatching { transport.close() }
        }
    }
}
