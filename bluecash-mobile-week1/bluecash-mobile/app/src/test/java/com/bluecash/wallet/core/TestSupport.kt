package com.bluecash.wallet.core

import org.json.JSONObject

class AutoUi(val sasOk: Boolean = true, val pay: Boolean = true) : SessionUi {
    @Volatile var sas: String? = null
    val log = java.util.concurrent.CopyOnWriteArrayList<String>()
    override fun status(msg: String) { log.add(msg) }
    override fun confirmSas(sas: String): Boolean { this.sas = sas; return sasOk }
    override fun confirmPayment(amount: Int, merchantId: String) = pay
}

class Phone(val name: String, val mint: MintApi, val clock: () -> Long = { System.currentTimeMillis() }) {
    val kv = MemoryKV()
    val seed = Ed25519.newSeed()
    val signer = SeedSigner(seed)
    val wallet = Wallet(kv, signer, clock)
    fun setup(fund: Int = 0): Phone {
        wallet.register(mint)
        if (fund > 0) wallet.mint(mint, fund)
        return this
    }
}

class Outcomes(val payer: SessionResult, val merchant: SessionResult, val payerUi: AutoUi, val merchantUi: AutoUi)

fun transact(
    payer: Phone, merchant: Phone, amount: Int, merchantId: String = "shop-1",
    payerUi: AutoUi = AutoUi(), merchantUi: AutoUi = AutoUi(),
    payerKeyHash: ((ByteArray) -> ByteArray?)? = null, delayMs: Long = 0, maxRtt: Long = Limits.MAX_RTT_MS,
): Outcomes {
    val (a, b) = pipe()
    a.delayMs = delayMs; b.delayMs = delayMs
    val eph = X25519.generate()
    var mr: SessionResult? = null
    var pr: SessionResult? = null
    val mt = Thread {
        mr = MerchantSession(b, merchant.signer, merchant.wallet.credential()!!, merchantId, amount, merchant.wallet.mintPub()!!,
            merchant.wallet.mintKeys(), merchant.wallet.revokedIds(), merchant.wallet, merchantUi, eph, maxRttMs = maxRtt).run()
    }
    val pt = Thread {
        pr = PayerSession(a, payer.signer, payer.wallet.credential()!!, payer.wallet.mintPub()!!, payer.wallet.revokedIds(),
            payer.wallet, payerUi, expectedMerchantKeyHash = payerKeyHash?.invoke(eph.pub)).run()
    }
    mt.start(); pt.start(); mt.join(60000); pt.join(60000)
    return Outcomes(pr!!, mr!!, payerUi, merchantUi)
}
