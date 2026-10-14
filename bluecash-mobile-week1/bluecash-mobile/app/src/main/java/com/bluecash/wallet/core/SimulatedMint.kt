package com.bluecash.wallet.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * A complete mint + settlement + fraud + audit server running inside the app, so every
 * feature can be demonstrated with no backend. It is also an executable specification of
 * what Person A's server has to do (see API_CONTRACT.md).
 *
 * NOTE: each phone has its own copy of this state, so it can only detect a double-spend
 * whose two receipts were both uploaded to the same phone's copy. Cross-phone detection
 * needs the real shared server.
 */
class SimulatedMint(private val kv: SecureKV, private val clock: () -> Long = { System.currentTimeMillis() }) : MintApi {
    private val signer = SeedSigner(DemoMintKeys.edSeed)
    private val keys = DemoMintKeys.keys

    companion object {
        /**
         * The demo mint's public key. It comes from a seed hardcoded in the app, so every
         * install shares it and nobody chose it. `Wallet.refreshMintInfo` uses this to tell a
         * demo key apart from a mint the user actually configured.
         */
        val DEMO_MINT_PUB_HEX: String by lazy { SeedSigner(DemoMintKeys.edSeed).publicKey.hex() }
    }

    private fun obj(k: String) = kv.get(k)?.let { JSONObject(it) } ?: JSONObject()
    private fun arr(k: String) = kv.get(k)?.let { JSONArray(it) } ?: JSONArray()

    override fun getInfo() = MintInfo(keys, signer.publicKey.hex())

    @Synchronized
    override fun registerDevice(req: RegisterRequest): DeviceCredential {
        if (!Ed25519.verify(req.devicePub.unhex(), Msg.register(req.devicePub, req.c0, req.ts), req.sig.unhex()))
            throw MintApiException("registration signature invalid")
        if (!Group.isElement(bigFromHex(req.c0))) throw MintApiException("invalid identity commitment")
        val credId = sha256(utf8("cred|${req.devicePub}")).hex().take(32)
        val expiry = clock() + 180L * 24 * 3600 * 1000
        val cred = DeviceCredential(credId, req.devicePub, req.c0, expiry, "")
        val sig = signer.sign(Msg.cred(credId, req.devicePub, req.c0, expiry)).hex()
        val devices = obj("sim:devices")
        devices.put(credId, JSONObject().put("pub", req.devicePub).put("c0", req.c0))
        kv.put("sim:devices", devices.toString())
        return cred.copy(mintSig = sig)
    }

    @Synchronized
    override fun issue(req: IssueRequest): IssueResponse {
        val dev = obj("sim:devices").optJSONObject(req.credId) ?: throw MintApiException("device not registered")
        if (obj("sim:revoked").has(req.credId)) throw MintApiException("device revoked")
        if (!Ed25519.verify(dev.getString("pub").unhex(), Msg.issue(req.credId, req.keyId, req.blinded, req.c0, req.ts), req.sig.unhex()))
            throw MintApiException("issue request signature invalid")
        if (bigFromHex(req.c0) != bigFromHex(dev.getString("c0"))) throw MintApiException("identity commitment mismatch")
        val key = keys.find { it.keyId == req.keyId } ?: throw MintApiException("unknown key")
        val d = DemoMintKeys.privateExponent(key.keyId) ?: throw MintApiException("unknown key")
        val blindedBytes = req.blinded.unhex()
        val blindSig = RsaBlind.signBlinded(bigFromHex(req.blinded), key.n, d).toHexString()
        // Append to the public audit log: leaf = H(blinded message || blind signature).
        val leaves = leaves()
        leaves.add(sha256(blindedBytes, blindSig.unhex()))
        kv.put("sim:leaves", leaves.joinToString("\n") { it.hex() })
        val index = leaves.size - 1
        val root = Merkle.root(leaves)
        val proof = Merkle.proof(leaves, index).map { it.hex() }
        return IssueResponse(blindSig, index, leaves.size, proof, root.hex())
    }

    private fun leaves(): MutableList<ByteArray> =
        (kv.get("sim:leaves") ?: "").split("\n").filter { it.isNotEmpty() }.map { it.unhex() }.toMutableList()

    @Synchronized
    override fun latestRoot(): AuditRoot {
        val l = leaves()
        return AuditRoot(if (l.isEmpty()) "" else Merkle.root(l).hex(), l.size, clock())
    }

    @Synchronized
    override fun getRevocations(): List<Revocation> {
        val o = obj("sim:revoked")
        return o.keys().asSequence().map { id ->
            val r = o.getJSONObject(id); Revocation(id, r.getString("reason"), r.getLong("ts"))
        }.toList()
    }

    @Synchronized
    override fun uploadBatch(receipts: List<Receipt>): SettlementResponse {
        val results = ArrayList<ReceiptResult>()
        val mintPub = signer.publicKey
        val spent = obj("sim:spent")
        val devices = obj("sim:devices")
        val revoked = obj("sim:revoked")
        for (r in receipts) {
            val err = Verify.receipt(r, keys, mintPub)
            if (err != null) { results.add(ReceiptResult(r.receiptId, SettlementStatus.INVALID, err)); continue }
            val prev = spent.optJSONObject(r.token.tokenId)
            if (prev == null) {
                spent.put(r.token.tokenId, JSONObject().put("receipt_id", r.receiptId).put("x", r.x).put("y", r.y).put("c0", r.token.c0))
                results.add(ReceiptResult(r.receiptId, SettlementStatus.ACCEPTED, "settled"))
            } else if (prev.getString("receipt_id") == r.receiptId) {
                results.add(ReceiptResult(r.receiptId, SettlementStatus.DUPLICATE, "already settled"))
            } else {
                // The same token was spent twice: two different points on the same line.
                val secret = Group.recoverSecret(bigFromHex(prev.getString("x")), bigFromHex(prev.getString("y")), bigFromHex(r.x), bigFromHex(r.y))
                val c0 = bigFromHex(r.token.c0)
                var detail = "double-spend detected"
                if (secret != null && Group.commit(secret) == c0) {
                    val credId = devices.keys().asSequence().firstOrNull { bigFromHex(devices.getJSONObject(it).getString("c0")) == c0 }
                    if (credId != null) {
                        revoked.put(credId, JSONObject().put("reason", "double-spend of token ${r.token.tokenId.take(12)}").put("ts", clock()))
                        detail = "double-spend: identity secret recovered, credential $credId revoked"
                    }
                }
                results.add(ReceiptResult(r.receiptId, SettlementStatus.FRAUD, detail))
            }
        }
        kv.put("sim:spent", spent.toString())
        kv.put("sim:revoked", revoked.toString())
        return SettlementResponse(results, getRevocations())
    }
}
