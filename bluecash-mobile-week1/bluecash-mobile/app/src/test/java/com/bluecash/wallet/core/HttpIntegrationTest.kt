package com.bluecash.wallet.core

import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Runs the Android client logic against a REAL backend over HTTP. Skipped unless the
 * environment variable BLUECASH_TEST_URL is set, e.g.
 *
 *     cd reference-server && uvicorn server:app --port 8765
 *     BLUECASH_TEST_URL=http://localhost:8765 ./gradlew test
 *
 * Use this to check Person A's server against the contract: if her crypto, hashing or JSON
 * differ from the client's anywhere, one of these steps fails and says which.
 */
class HttpIntegrationTest {
    private fun api(): MintApi {
        val url = System.getenv("BLUECASH_TEST_URL")
        assumeTrue("BLUECASH_TEST_URL not set - skipping server integration test", !url.isNullOrBlank())
        return HttpMintApi(url!!)
    }

    @Test fun fullStoryAgainstRealServer() {
        val mint = api()
        val alice = Phone("alice", mint).setup(fund = 160)      // register + blind-mint + audit-proof check
        val shopA = Phone("A", mint).setup()
        val shopB = Phone("B", mint).setup()
        assertEquals(160, alice.wallet.balance())

        val backup = MemoryKV().also { it.copyFrom(alice.kv) }  // Alice keeps a copy of her tokens
        val o1 = transact(alice, shopA, 100, "shopA")
        assertEquals(o1.merchant.message, Outcome.SUCCESS, o1.merchant.outcome)

        // Replay the same token at shop B while "offline".
        val clone = Wallet(backup, alice.signer)
        val (a, b) = pipe(); val eph = X25519.generate()
        var mr: SessionResult? = null
        val t1 = Thread { mr = MerchantSession(b, shopB.signer, shopB.wallet.credential()!!, "shopB", 100, shopB.wallet.mintPub()!!, shopB.wallet.mintKeys(), shopB.wallet.revokedIds(), shopB.wallet, AutoUi(), eph).run() }
        val t2 = Thread { PayerSession(a, alice.signer, clone.credential()!!, clone.mintPub()!!, emptySet(), clone, AutoUi()).run() }
        t1.start(); t2.start(); t1.join(60000); t2.join(60000)
        assertEquals(mr!!.message, Outcome.SUCCESS, mr!!.outcome)

        // Back online: settlement through the real server.
        val sa = shopA.wallet.sync(mint)
        assertEquals("shop A is paid", 1, sa.accepted)
        val sb = shopB.wallet.sync(mint)
        assertEquals("shop B's receipt is flagged", 1, sb.alerts.size)
        assertTrue(sb.alerts[0], sb.alerts[0].contains("revoked"))
        assertEquals("re-upload is idempotent", 0, shopA.wallet.sync(mint).alerts.size)

        // The server now lists Alice's credential as revoked, and a fresh client learns it.
        val aliceCred = alice.wallet.credential()!!.credId
        assertTrue(mint.getRevocations().any { it.credId == aliceCred })
        val fresh = Phone("fresh", mint).setup()
        assertTrue(aliceCred in fresh.wallet.revokedIds())
        assertThrows(MintApiException::class.java) { alice.wallet.mint(mint, 10) } // can't mint any more
    }

    @Test fun serverRejectsForgedReceipt() {
        val mint = api()
        val alice = Phone("alice", mint).setup(fund = 10)
        val shop = Phone("shop", mint).setup()
        assertEquals(Outcome.SUCCESS, transact(alice, shop, 10).merchant.outcome)
        val r = shop.wallet.pendingReceipts().single()
        val forged = r.copy(amount = 500)
        val res = mint.uploadBatch(listOf(forged)).results.single()
        assertEquals(SettlementStatus.INVALID, res.status)
    }
}
