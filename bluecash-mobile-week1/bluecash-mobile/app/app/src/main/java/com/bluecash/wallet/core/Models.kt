package com.bluecash.wallet.core

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger

/** Exact byte strings that get signed. Each has a distinct label so a signature for one purpose can't be reused for another. */
object Msg {
    fun token(keyId: String, tokenId: String, c0: String, c1: String) = utf8("BCTOKEN|v1|$keyId|$tokenId|$c0|$c1")
    fun cred(credId: String, devicePub: String, c0: String, expiryMs: Long) = utf8("BCCRED|v1|$credId|$devicePub|$c0|$expiryMs")
    fun register(devicePub: String, c0: String, ts: Long) = utf8("BCREG|v1|$devicePub|$c0|$ts")
    fun issue(credId: String, keyId: String, blinded: String, c0: String, ts: Long) = utf8("BCISSUE|v1|$credId|$keyId|$blinded|$c0|$ts")
    fun spend(tokenId: String, nCtx: String, amount: Int) = utf8("BCSPEND|v1|$tokenId|$nCtx|$amount")
    fun receipt(receiptId: String, tokenId: String, nCtx: String, x: String, y: String, amount: Int, merchantId: String, ts: Long) =
        utf8("BCRECEIPT|v1|$receiptId|$tokenId|$nCtx|$x|$y|$amount|$merchantId|$ts")
}

data class MintKey(
    val keyId: String, val amount: Int, val currency: String, val expiryMs: Long,
    val nHex: String, val eHex: String,
) {
    val n: BigInteger get() = bigFromHex(nHex)
    val e: BigInteger get() = bigFromHex(eHex)

    fun toJson() = JSONObject().put("key_id", keyId).put("amount", amount).put("currency", currency)
        .put("expiry_ms", expiryMs).put("n", nHex).put("e", eHex)

    companion object {
        fun fromJson(o: JSONObject) = MintKey(
            o.getString("key_id"), o.getInt("amount"), o.optString("currency", "INR"),
            o.getLong("expiry_ms"), o.getString("n"), o.getString("e"),
        )
    }
}

data class Token(
    val tokenId: String, val keyId: String, val amount: Int, val currency: String, val expiryMs: Long,
    val c0: String, val c1: String, val sig: String,
) {
    fun signedMessage() = Msg.token(keyId, tokenId, c0, c1)

    fun toJson() = JSONObject().put("token_id", tokenId).put("key_id", keyId).put("amount", amount)
        .put("currency", currency).put("expiry_ms", expiryMs).put("c0", c0).put("c1", c1).put("sig", sig)

    companion object {
        fun fromJson(o: JSONObject) = Token(
            o.getString("token_id"), o.getString("key_id"), o.getInt("amount"), o.getString("currency"),
            o.getLong("expiry_ms"), o.getString("c0"), o.getString("c1"), o.getString("sig"),
        )
    }
}

object TokenState {
    const val UNSPENT = "UNSPENT"
    const val PENDING = "PENDING" // handed to a merchant, receipt not yet confirmed
    const val SPENT = "SPENT"
}

/** A token plus the wallet's private part (a1) and its state. */
data class StoredToken(val token: Token, val a1: String, val state: String) {
    fun toJson() = JSONObject().put("token", token.toJson()).put("a1", a1).put("state", state)

    companion object {
        fun fromJson(o: JSONObject) = StoredToken(Token.fromJson(o.getJSONObject("token")), o.getString("a1"), o.getString("state"))
    }
}

/** Issued by the mint at registration; proves "this is a registered, non-revoked device". */
data class DeviceCredential(
    val credId: String, val devicePub: String, val c0: String, val expiryMs: Long, val mintSig: String,
) {
    fun verify(mintPub: ByteArray, nowMs: Long): Boolean =
        expiryMs > nowMs && Ed25519.verify(mintPub, Msg.cred(credId, devicePub, c0, expiryMs), mintSig.unhex())

    fun toJson() = JSONObject().put("cred_id", credId).put("device_pub", devicePub).put("c0", c0)
        .put("expiry_ms", expiryMs).put("mint_sig", mintSig)

    companion object {
        fun fromJson(o: JSONObject) = DeviceCredential(
            o.getString("cred_id"), o.getString("device_pub"), o.getString("c0"), o.getLong("expiry_ms"), o.getString("mint_sig"),
        )
    }
}

/** One token spent at one merchant. This is what gets uploaded for settlement. */
data class Receipt(
    val receiptId: String, val token: Token, val nCtx: String, val x: String, val y: String, val amount: Int,
    val payerCred: DeviceCredential, val payerSig: String,
    val merchantId: String, val merchantCred: DeviceCredential, val merchantSig: String, val timestampMs: Long,
) {
    fun merchantSigned() = Msg.receipt(receiptId, token.tokenId, nCtx, x, y, amount, merchantId, timestampMs)

    fun toJson() = JSONObject().put("receipt_id", receiptId).put("token", token.toJson()).put("n_ctx", nCtx)
        .put("x", x).put("y", y).put("amount", amount).put("payer_cred", payerCred.toJson())
        .put("payer_sig", payerSig).put("merchant_id", merchantId).put("merchant_cred", merchantCred.toJson())
        .put("merchant_sig", merchantSig).put("timestamp_ms", timestampMs)

    companion object {
        fun fromJson(o: JSONObject) = Receipt(
            o.getString("receipt_id"), Token.fromJson(o.getJSONObject("token")), o.getString("n_ctx"),
            o.getString("x"), o.getString("y"), o.getInt("amount"),
            DeviceCredential.fromJson(o.getJSONObject("payer_cred")), o.getString("payer_sig"),
            o.getString("merchant_id"), DeviceCredential.fromJson(o.getJSONObject("merchant_cred")),
            o.getString("merchant_sig"), o.getLong("timestamp_ms"),
        )
    }
}

fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
fun <T> List<T>.toJsonArray(f: (T) -> Any): JSONArray = JSONArray().also { a -> forEach { a.put(f(it)) } }
