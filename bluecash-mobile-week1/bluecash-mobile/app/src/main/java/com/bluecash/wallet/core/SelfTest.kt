package com.bluecash.wallet.core

/**
 * Runs the whole protocol on this phone with three in-memory wallets (no Bluetooth, no
 * server): mint, pay, then a deliberate cross-merchant double-spend that must be caught and
 * the cheater's identity recovered. Doubles as a speed check of the crypto on real hardware.
 */
object SelfTest {
    private class Auto : SessionUi {
        override fun status(msg: String) {}
        override fun confirmSas(sas: String) = true
        override fun confirmPayment(amount: Int, merchantId: String) = true
    }

    private class P(val mint: MintApi) {
        val kv = MemoryKV()
        val signer = SeedSigner(Ed25519.newSeed())
        val wallet = Wallet(kv, signer)
    }

    private fun pay(payerWallet: Wallet, payerSigner: Signer, shop: P, amount: Int, shopId: String): Pair<SessionResult, SessionResult> {
        val (a, b) = pipe()
        val eph = X25519.generate()
        var mr: SessionResult? = null
        var pr: SessionResult? = null
        val mt = Thread {
            mr = MerchantSession(b, shop.signer, shop.wallet.credential()!!, shopId, amount, shop.wallet.mintPub()!!,
                shop.wallet.mintKeys(), shop.wallet.revokedIds(), shop.wallet, Auto(), eph).run()
        }
        val pt = Thread {
            pr = PayerSession(a, payerSigner, payerWallet.credential()!!, payerWallet.mintPub()!!, payerWallet.revokedIds(), payerWallet, Auto()).run()
        }
        mt.start(); pt.start(); mt.join(120_000); pt.join(120_000)
        return (pr ?: SessionResult(Outcome.FAILED, "timeout")) to (mr ?: SessionResult(Outcome.FAILED, "timeout"))
    }

    fun run(log: (String) -> Unit): Boolean {
        fun <T> timed(label: String, f: () -> T): T {
            val t0 = System.nanoTime(); val r = f()
            log("$label  (${(System.nanoTime() - t0) / 1_000_000} ms)"); return r
        }
        return try {
            val mint = SimulatedMint(MemoryKV())
            val alice = P(mint); val shopA = P(mint); val shopB = P(mint)
            timed("Registered 3 devices") { listOf(alice, shopA, shopB).forEach { it.wallet.register(mint) } }
            timed("Minted ₹100 (blind-signed, audit-log verified)") { alice.wallet.mint(mint, 100) }
            val clone = Wallet(MemoryKV().also { it.copyFrom(alice.kv) }, alice.signer)
            val (p1, m1) = timed("Paid ₹100 to shop A over the secure channel") { pay(alice.wallet, alice.signer, shopA, 100, "shopA") }
            if (m1.outcome != Outcome.SUCCESS || p1.outcome != Outcome.SUCCESS) { log("FAIL: honest payment: ${m1.message} / ${p1.message}"); return false }
            val (_, m2) = timed("Alice replays the SAME token at shop B (offline, undetectable)") { pay(clone, alice.signer, shopB, 100, "shopB") }
            if (m2.outcome != Outcome.SUCCESS) { log("FAIL: shop B should accept offline: ${m2.message}"); return false }
            val sa = shopA.wallet.sync(mint)
            val sb = timed("Both shops go online and settle") { shopB.wallet.sync(mint) }
            if (sa.accepted != 1 || sb.alerts.isEmpty()) { log("FAIL: double-spend not detected"); return false }
            log("Detected: ${sb.alerts[0]}")
            val revoked = mint.getRevocations().any { it.credId == alice.wallet.credential()!!.credId }
            log(if (revoked) "PASS: cheater's credential revoked; honest merchant A paid in full" else "FAIL: not revoked")
            revoked
        } catch (e: Exception) {
            log("FAIL: ${e.message}"); false
        }
    }
}
