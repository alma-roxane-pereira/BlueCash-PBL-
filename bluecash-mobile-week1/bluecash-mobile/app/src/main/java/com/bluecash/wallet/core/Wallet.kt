package com.bluecash.wallet.core

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger

/** What a paying session needs from the wallet. */
interface SpendVault {
    fun identitySecret(): BigInteger
    fun selectExact(amount: Int): List<StoredToken>?
    fun lock(tokenIds: List<String>)
    fun unlock(tokenIds: List<String>)
    fun markSpent(tokenIds: List<String>)
    fun recordLedger(type: String, payload: JSONObject)
}

/** What a receiving session needs from the wallet. */
interface MerchantStore {
    fun hasSeen(tokenId: String): Boolean
    fun markSeen(tokenId: String)
    fun saveReceipt(r: Receipt)
    fun recordLedger(type: String, payload: JSONObject)
}

data class SyncResult(val uploaded: Int, val accepted: Int, val alerts: List<String>)

/**
 * The wallet: identity secret, token vault, minting, merchant receipts and settlement.
 * All state lives in the encrypted [SecureKV].
 */
class Wallet(
    private val kv: SecureKV,
    private val signer: Signer,
    private val clock: () -> Long = { System.currentTimeMillis() },
) : SpendVault, MerchantStore {

    val ledger = HashChainLedger(kv)
    private val lock = Any()

    // ---- identity ----------------------------------------------------------------------

    /** The long-term secret a0. Revealed only if the owner double-spends. Never leaves the device. */
    override fun identitySecret(): BigInteger = synchronized(lock) {
        kv.get("id_secret")?.let { return bigFromHex(it) }
        val s = Group.randomScalar()
        kv.put("id_secret", s.toHexString())
        s
    }

    fun c0Hex(): String = synchronized(lock) {
        kv.get("c0") ?: Group.commit(identitySecret()).toHexString().also { kv.put("c0", it) }
    }

    fun credential(): DeviceCredential? = kv.get("cred")?.let { DeviceCredential.fromJson(JSONObject(it)) }

    /**
     * The stored credential, but only when the mint that is configured now issued it and it
     * has not expired. Credentials are signed by the mint, so a credential the in-app
     * simulated mint produced does not verify under a real mint's key: after switching to a
     * real backend the wallet reports itself unregistered and offers to register again,
     * instead of keeping a "Registered" badge for a credential the real mint answers with
     * `403 device not registered`.
     *
     * Nothing is erased. The old credential stays in storage until a successful
     * registration overwrites it, and identity, tokens, receipts and history are untouched.
     */
    fun credentialForCurrentMint(): DeviceCredential? {
        val cred = credential() ?: return null
        val pub = mintPub() ?: return null
        return if (cred.verify(pub, clock())) cred else null
    }

    fun isRegistered(): Boolean = credentialForCurrentMint() != null

    // ---- cached mint info ---------------------------------------------------------------

    fun mintKeys(): List<MintKey> = kv.get("mint_keys")?.let { JSONArray(it).objects().map { o -> MintKey.fromJson(o) } } ?: emptyList()
    fun mintPub(): ByteArray? = kv.get("mint_pub")?.unhex()
    fun revokedIds(): Set<String> = kv.get("revoked")?.let { JSONArray(it).strings().toSet() } ?: emptySet()
    fun auditRoot(): String? = kv.get("audit_root")

    fun refreshMintInfo(api: MintApi) {
        val info = api.getInfo()
        val pinned = kv.get("mint_pub")
        // Trust-on-first-use, but only for a mint the user actually chose. The simulated
        // mint inside the app signs with a demo seed shipped in the APK, and a background
        // sync can store that key before any backend is configured -- so treating it as a
        // trust anchor would lock the wallet out of every real mint, with a full wallet
        // wipe as the only escape. A demo key is therefore replaceable; a real mint's key
        // is pinned, and a different one is still refused.
        if (pinned != null && pinned != SimulatedMint.DEMO_MINT_PUB_HEX && pinned != info.mintPubHex)
            throw MintApiException("the mint's signing key changed - refusing (reset the wallet to trust a new mint)")
        kv.put("mint_pub", info.mintPubHex)
        kv.put("mint_keys", info.keys.toJsonArray { it.toJson() }.toString())
        mergeRevocations(api.getRevocations())
        api.latestRoot().let { kv.put("audit_root", it.root) }
    }

    private fun mergeRevocations(list: List<Revocation>) {
        val ids = (revokedIds() + list.map { it.credId })
        kv.put("revoked", ids.toList().toJsonArray { it }.toString())
    }

    // ---- registration -------------------------------------------------------------------

    fun register(api: MintApi, integrityToken: String? = null): DeviceCredential {
        refreshMintInfo(api)
        val pub = signer.publicKey.hex()
        val c0 = c0Hex()
        val ts = clock()
        val sig = signer.sign(Msg.register(pub, c0, ts)).hex()
        val cred = api.registerDevice(RegisterRequest(pub, c0, ts, sig, integrityToken))
        val mintPub = mintPub() ?: throw MintApiException("no mint key")
        if (cred.devicePub != pub || bigFromHex(cred.c0) != bigFromHex(c0) || !cred.verify(mintPub, clock()))
            throw MintApiException("the mint returned an invalid credential")
        kv.put("cred", cred.toJson().toString())
        recordLedger("REGISTER", JSONObject().put("cred_id", cred.credId))
        return cred
    }

    // ---- minting (withdrawal) -----------------------------------------------------------

    /** Fewest tokens that add up to exactly [amount], or null if the denominations can't. */
    fun planDenominations(amount: Int, keys: List<MintKey>): List<MintKey>? {
        val usable = keys.filter { it.expiryMs > clock() }.sortedByDescending { it.amount }
        if (amount <= 0 || usable.isEmpty()) return null
        val best = arrayOfNulls<List<MintKey>>(amount + 1)
        best[0] = emptyList()
        for (a in 1..amount) {
            for (k in usable) {
                if (k.amount <= a) {
                    val prev = best[a - k.amount] ?: continue
                    val cur = best[a]
                    if (cur == null || prev.size + 1 < cur.size) best[a] = prev + k
                }
            }
        }
        return best[amount]
    }

    fun mint(api: MintApi, amount: Int, progress: (String) -> Unit = {}): List<Token> {
        val cred = credentialForCurrentMint() ?: throw MintApiException("register this device with the mint first")
        refreshMintInfo(api)
        val plan = planDenominations(amount, mintKeys())
            ?: throw MintApiException("$amount can't be made from the mint's denominations (${mintKeys().joinToString { it.amount.toString() }})")
        val c0 = c0Hex()
        val out = ArrayList<Token>()
        for ((i, key) in plan.withIndex()) {
            progress("Minting token ${i + 1} of ${plan.size} (${key.amount})")
            val tokenId = Rand.bytes(32).hex()
            val a1 = Group.randomScalar()
            val c1 = Group.commit(a1).toHexString()
            val blinded = RsaBlind.blind(Msg.token(key.keyId, tokenId, c0, c1), key.n, key.e)
            val blindedHex = blinded.blindedMessage.toHexString()
            val ts = clock()
            val sig = signer.sign(Msg.issue(cred.credId, key.keyId, blindedHex, c0, ts)).hex()
            val resp = api.issue(IssueRequest(cred.credId, key.keyId, blindedHex, c0, ts, sig))

            // Audit: the mint's public log must contain this issuance (it can't over-issue in secret).
            val leaf = sha256(blindedHex.unhex(), resp.blindSig.unhex())
            if (!Merkle.verifyInclusion(leaf, resp.leafIndex, resp.treeSize, resp.proof.map { it.unhex() }, resp.root.unhex()))
                throw MintApiException("audit log proof failed - the mint's issuance is not in its public log")
            kv.put("audit_root", resp.root)

            val sigInt = RsaBlind.unblind(bigFromHex(resp.blindSig), blinded.r, key.n)
            val token = Token(tokenId, key.keyId, key.amount, key.currency, key.expiryMs, c0, c1, sigInt.toHexString())
            Verify.token(token, mintKeys(), clock())?.let { throw MintApiException("mint returned a bad signature: $it") }
            synchronized(lock) { kv.put("token:$tokenId", StoredToken(token, a1.toHexString(), TokenState.UNSPENT).toJson().toString()) }
            out.add(token)
        }
        recordLedger("MINT", JSONObject().put("amount", amount).put("tokens", out.size))
        return out
    }

    // ---- vault --------------------------------------------------------------------------

    fun tokens(): List<StoredToken> = kv.keys("token:").mapNotNull { k ->
        kv.get(k)?.let { StoredToken.fromJson(JSONObject(it)) }
    }

    private fun spendable() = tokens().filter { it.state == TokenState.UNSPENT && it.token.expiryMs > clock() }
    fun balance(): Int = spendable().sumOf { it.token.amount }
    fun pendingAmount(): Int = tokens().filter { it.state == TokenState.PENDING }.sumOf { it.token.amount }

    override fun selectExact(amount: Int): List<StoredToken>? {
        val toks = spendable().sortedByDescending { it.token.amount }
        val best = HashMap<Int, List<StoredToken>>()
        best[0] = emptyList()
        for (t in toks) {
            for ((sum, list) in best.entries.toList()) {
                val ns = sum + t.token.amount
                if (ns <= amount) {
                    val cur = best[ns]
                    if (cur == null || list.size + 1 < cur.size) best[ns] = list + t
                }
            }
        }
        return best[amount]
    }

    private fun setState(ids: List<String>, state: String, wipeSecret: Boolean = false) = synchronized(lock) {
        for (id in ids) {
            val cur = kv.get("token:$id")?.let { StoredToken.fromJson(JSONObject(it)) } ?: continue
            // Once spent, the per-token secret is no longer needed: delete it.
            kv.put("token:$id", cur.copy(state = state, a1 = if (wipeSecret) "" else cur.a1).toJson().toString())
        }
    }

    override fun lock(tokenIds: List<String>) = setState(tokenIds, TokenState.PENDING)
    override fun unlock(tokenIds: List<String>) = setState(tokenIds, TokenState.UNSPENT)
    override fun markSpent(tokenIds: List<String>) = setState(tokenIds, TokenState.SPENT, wipeSecret = true)

    /** Escape hatch for tokens stuck in PENDING after a dropped connection. Risky: see UI warning. */
    fun releasePending(): Int {
        val ids = tokens().filter { it.state == TokenState.PENDING }.map { it.token.tokenId }
        unlock(ids)
        return ids.size
    }

    // ---- merchant side ------------------------------------------------------------------

    private val seen: MutableSet<String> by lazy {
        (kv.get("seen")?.let { JSONArray(it).strings() } ?: emptyList()).toMutableSet()
    }
    private val bloom: BloomFilter by lazy { BloomFilter().also { b -> seen.forEach { b.add(it) } } }

    /** Bloom filter answers "no" instantly; a "maybe" is confirmed against the exact set so honest tokens are never falsely rejected. */
    override fun hasSeen(tokenId: String): Boolean = synchronized(lock) { bloom.mightContain(tokenId) && seen.contains(tokenId) }

    override fun markSeen(tokenId: String) = synchronized(lock) {
        if (seen.add(tokenId)) {
            bloom.add(tokenId)
            kv.put("seen", seen.toList().toJsonArray { it }.toString())
        }
    }

    override fun saveReceipt(r: Receipt) { kv.put("receipt:${r.receiptId}", r.toJson().toString()) }

    fun pendingReceipts(): List<Receipt> = kv.keys("receipt:").mapNotNull { k ->
        kv.get(k)?.let { Receipt.fromJson(JSONObject(it)) }
    }

    override fun recordLedger(type: String, payload: JSONObject) { ledger.append(type, payload, clock()) }

    // ---- sync ---------------------------------------------------------------------------

    fun alerts(): List<String> = kv.get("alerts")?.let { JSONArray(it).strings() } ?: emptyList()

    private fun addAlert(text: String) {
        val list = (alerts() + text).takeLast(30)
        kv.put("alerts", list.toJsonArray { it }.toString())
    }

    /** Refresh mint info and revocations, then upload merchant receipts for settlement. */
    fun sync(api: MintApi): SyncResult {
        refreshMintInfo(api)
        val pending = pendingReceipts()
        if (pending.isEmpty()) return SyncResult(0, 0, emptyList())
        val resp = api.uploadBatch(pending)
        mergeRevocations(resp.revoked)
        var accepted = 0
        val alerts = ArrayList<String>()
        for (res in resp.results) {
            when (res.status) {
                SettlementStatus.ACCEPTED, SettlementStatus.DUPLICATE -> { accepted++; kv.remove("receipt:${res.receiptId}") }
                SettlementStatus.FRAUD -> { alerts.add("Receipt ${res.receiptId.take(8)}: ${res.detail}"); kv.remove("receipt:${res.receiptId}") }
                else -> alerts.add("Receipt ${res.receiptId.take(8)} rejected: ${res.detail}")
            }
        }
        alerts.forEach { addAlert(it) }
        recordLedger("SETTLE", JSONObject().put("uploaded", pending.size).put("accepted", accepted).put("alerts", alerts.size))
        return SyncResult(pending.size, accepted, alerts)
    }

    /** Wipe everything except the device's signing key. */
    fun resetData() {
        for (p in listOf("token:", "receipt:", "sim:")) kv.keys(p).forEach { kv.remove(it) }
        listOf("cred", "mint_keys", "mint_pub", "revoked", "audit_root", "seen", "alerts", "ledger").forEach { kv.remove(it) }
    }
}
