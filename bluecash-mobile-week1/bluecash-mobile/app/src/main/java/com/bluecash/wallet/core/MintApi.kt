package com.bluecash.wallet.core

class MintApiException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class MintInfo(val keys: List<MintKey>, val mintPubHex: String)
data class RegisterRequest(val devicePub: String, val c0: String, val ts: Long, val sig: String, val integrityToken: String?)
data class IssueRequest(val credId: String, val keyId: String, val blinded: String, val c0: String, val ts: Long, val sig: String)
data class IssueResponse(val blindSig: String, val leafIndex: Int, val treeSize: Int, val proof: List<String>, val root: String)
data class AuditRoot(val root: String, val treeSize: Int, val ts: Long)
data class ReceiptResult(val receiptId: String, val status: String, val detail: String)
data class Revocation(val credId: String, val reason: String, val ts: Long)
data class SettlementResponse(val results: List<ReceiptResult>, val revoked: List<Revocation>)

object SettlementStatus {
    const val ACCEPTED = "ACCEPTED"
    const val DUPLICATE = "DUPLICATE" // same receipt uploaded twice: harmless
    const val FRAUD = "FRAUD"         // token spent in two different contexts: identity recovered
    const val INVALID = "INVALID"
}

/**
 * Everything the wallet needs from the mint/settlement/audit servers. Two implementations:
 * [SimulatedMint] (inside the app, for demos and tests) and HttpMintApi (the real backend).
 * Calls block, so run them off the main thread.
 */
interface MintApi {
    fun getInfo(): MintInfo
    fun registerDevice(req: RegisterRequest): DeviceCredential
    fun issue(req: IssueRequest): IssueResponse
    fun latestRoot(): AuditRoot
    fun uploadBatch(receipts: List<Receipt>): SettlementResponse
    fun getRevocations(): List<Revocation>
}

/** Checks the mint, the settlement server and merchants all apply to tokens and receipts. */
object Verify {
    fun token(t: Token, keys: List<MintKey>, nowMs: Long): String? {
        if (t.expiryMs <= nowMs) return "token expired"
        val key = keys.find { it.keyId == t.keyId } ?: return "unknown mint key"
        if (key.amount != t.amount || key.expiryMs != t.expiryMs || key.currency != t.currency) return "token does not match its mint key"
        if (!RsaBlind.verify(t.signedMessage(), bigFromHex(t.sig), key.n, key.e)) return "invalid mint signature"
        if (!Group.isElement(bigFromHex(t.c0)) || !Group.isElement(bigFromHex(t.c1))) return "invalid commitments"
        return null
    }

    /** One spend: the share must be for THIS context, lie on the token's committed line, and be signed by the payer. */
    fun spend(t: Token, nCtx: String, xHex: String, yHex: String, payerCred: DeviceCredential, payerSigHex: String): String? {
        if (bigFromHex(t.c0) != bigFromHex(payerCred.c0)) return "token does not belong to this payer"
        val x = Group.challengeX(t.tokenId, nCtx)
        if (bigFromHex(xHex) != x) return "wrong share coordinate for this context"
        if (!Group.verifyShare(bigFromHex(t.c0), bigFromHex(t.c1), x, bigFromHex(yHex))) return "share is not on the committed line"
        if (!Ed25519.verify(payerCred.devicePub.unhex(), Msg.spend(t.tokenId, nCtx, t.amount), payerSigHex.unhex())) return "bad payer signature"
        return null
    }

    fun receipt(r: Receipt, keys: List<MintKey>, mintPub: ByteArray): String? {
        if (!r.payerCred.verify(mintPub, r.timestampMs)) return "payer credential invalid"
        if (!r.merchantCred.verify(mintPub, r.timestampMs)) return "merchant credential invalid"
        Verify.token(r.token, keys, r.timestampMs)?.let { return it }
        spend(r.token, r.nCtx, r.x, r.y, r.payerCred, r.payerSig)?.let { return it }
        if (r.amount != r.token.amount) return "amount mismatch"
        if (!Ed25519.verify(r.merchantCred.devicePub.unhex(), r.merchantSigned(), r.merchantSig.unhex())) return "bad merchant signature"
        return null
    }
}
