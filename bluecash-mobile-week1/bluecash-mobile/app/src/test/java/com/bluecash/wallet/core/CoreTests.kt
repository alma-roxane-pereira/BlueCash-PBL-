package com.bluecash.wallet.core

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger

class PrimitiveTests {
    @Test fun hkdfMatchesRfc5869TestCase1() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = "000102030405060708090a0b0c".unhex()
        val info = "f0f1f2f3f4f5f6f7f8f9".unhex()
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            Hkdf.derive(ikm, salt, info, 42).hex())
    }

    @Test fun rsaBlindSignatureRoundTripAndUnlinkability() {
        val key = DemoMintKeys.keys.first { it.amount == 100 }
        val d = DemoMintKeys.privateExponent(key.keyId)!!
        val msg = utf8("hello token")
        val b1 = RsaBlind.blind(msg, key.n, key.e)
        val b2 = RsaBlind.blind(msg, key.n, key.e)
        assertNotEquals("blinding must randomise what the mint sees", b1.blindedMessage, b2.blindedMessage)
        val sig = RsaBlind.unblind(RsaBlind.signBlinded(b1.blindedMessage, key.n, d), b1.r, key.n)
        assertTrue(RsaBlind.verify(msg, sig, key.n, key.e))
        assertFalse(RsaBlind.verify(utf8("other"), sig, key.n, key.e))
        assertFalse(RsaBlind.verify(msg, sig.add(BigInteger.ONE), key.n, key.e))
    }

    @Test fun groupIsSafePrimeAndJacobiMatchesDefinition() {
        assertTrue(Group.P.isProbablePrime(40))
        assertTrue(Group.Q.isProbablePrime(40))
        assertEquals(2048, Group.P.bitLength())
        repeat(5) {
            val v = BigInteger(2040, Rand.rnd).add(BigInteger.valueOf(3))
            val viaPow = v.modPow(Group.Q, Group.P) == BigInteger.ONE
            assertEquals(viaPow, Group.isElement(v))
        }
        assertTrue(Group.isElement(Group.commit(Group.randomScalar())))
    }

    @Test fun shareVerifiesAndTwoSharesRecoverSecret() {
        val a0 = Group.randomScalar(); val a1 = Group.randomScalar()
        val c0 = Group.commit(a0); val c1 = Group.commit(a1)
        val x1 = Group.challengeX("tok", "ctx-1"); val x2 = Group.challengeX("tok", "ctx-2")
        val y1 = Group.evalShare(a0, a1, x1); val y2 = Group.evalShare(a0, a1, x2)
        assertTrue(Group.verifyShare(c0, c1, x1, y1))
        assertTrue(Group.verifyShare(c0, c1, x2, y2))
        assertFalse(Group.verifyShare(c0, c1, x1, y1.add(BigInteger.ONE)))
        assertFalse("a point for a different x must not verify", Group.verifyShare(c0, c1, x2, y1))
        assertEquals(a0, Group.recoverSecret(x1, y1, x2, y2))
        assertNull(Group.recoverSecret(x1, y1, x1, y1))
    }

    @Test fun merkleInclusionProofsForManySizes() {
        for (n in 1..40) {
            val leaves = (0 until n).map { utf8("leaf-$it") }
            val root = Merkle.root(leaves)
            for (i in 0 until n) {
                val proof = Merkle.proof(leaves, i)
                assertTrue("n=$n i=$i", Merkle.verifyInclusion(leaves[i], i, n, proof, root))
                assertFalse(Merkle.verifyInclusion(utf8("forged"), i, n, proof, root))
                if (n > 1) assertFalse(Merkle.verifyInclusion(leaves[i], (i + 1) % n, n, proof, root))
            }
        }
    }

    @Test fun bloomHasNoFalseNegativesAndFewFalsePositives() {
        val b = BloomFilter()
        val ids = (0 until 5000).map { Rand.bytes(16).hex() }
        ids.forEach { b.add(it) }
        assertTrue(ids.all { b.mightContain(it) })
        val fp = (0 until 5000).count { b.mightContain(Rand.bytes(16).hex()) }
        assertTrue("false positives: $fp", fp < 50)
    }

    @Test fun framingRoundTripsAnySize() {
        for (size in listOf(0, 1, 5, 19, 20, 21, 239, 240, 5000)) {
            val msg = Rand.bytes(size)
            val r = Framing.Reassembler()
            var out: ByteArray? = null
            for (p in Framing.chunk(msg, 20)) { assertTrue(p.size <= 20); out = r.feed(p) ?: out }
            assertArrayEquals("size $size", msg, out)
        }
    }

    // ---- BLE packet sizing ------------------------------------------------------------
    //
    // GATT caps an attribute value at 512 bytes however large the ATT MTU gets. Phones
    // negotiate 517, and the old packet size of `mtu - 3` came to 514 -- so the first
    // message bigger than one packet (AUTH, which carries a 2048-bit c0) was refused with
    // "notification should not be longer than max length of an attribute value".

    @Test fun packetSizeFollowsTheMtuButNeverPassesTheGattLimit() {
        assertEquals(20, Framing.packetSize(23))      // smallest MTU: the 20-byte floor
        assertEquals(244, Framing.packetSize(247))    // what the app asks for
        assertEquals(512, Framing.packetSize(517))    // what phones actually agree: capped
        assertEquals(512, Framing.MAX_ATTRIBUTE_LEN)
    }

    @Test fun noChunkExceedsTheGattLimitAtAnyMtu() {
        val msg = Rand.bytes(4096)
        for (mtu in 23..517) {
            val size = Framing.packetSize(mtu)
            assertTrue("mtu $mtu gave packet size $size", size <= Framing.MAX_ATTRIBUTE_LEN)
            for (p in Framing.chunk(msg, size)) {
                assertTrue("mtu $mtu produced a ${p.size}-byte packet", p.size <= Framing.MAX_ATTRIBUTE_LEN)
            }
        }
    }

    @Test fun authSizedAndLargeMessagesRoundTripAtTheNegotiatedMtu() {
        // 900 bytes stands in for AUTH (credential with a 512-hex c0 plus signatures);
        // 8 KB stands in for a multi-token TOKENS or RECEIPTS payload.
        for (size in listOf(513, 900, 8192)) {
            val msg = Rand.bytes(size)
            val r = Framing.Reassembler()
            var out: ByteArray? = null
            for (p in Framing.chunk(msg, Framing.packetSize(517))) {
                assertTrue(p.size <= Framing.MAX_ATTRIBUTE_LEN)
                out = r.feed(p) ?: out
            }
            assertArrayEquals("size $size", msg, out)
        }
    }

    @Test fun anAbandonedTransferLeavesNothingBehind() {
        val r = Framing.Reassembler()
        val abandoned = Framing.chunk(Rand.bytes(2000), Framing.packetSize(517))
        assertNull("a partial transfer must not complete", r.feed(abandoned.first()))

        // A new transfer starts with a FIRST packet, which must discard the stale bytes.
        val msg = Rand.bytes(900)
        var out: ByteArray? = null
        for (p in Framing.chunk(msg, Framing.packetSize(517))) out = r.feed(p) ?: out
        assertArrayEquals(msg, out)
    }

    @Test fun secureChannelDetectsTamperReplayAndReorder() {
        val k1 = Rand.bytes(32); val k2 = Rand.bytes(32)
        val a = SecureChannel(k1, k2); val b = SecureChannel(k2, k1)
        val c1 = a.seal(utf8("one")); val c2 = a.seal(utf8("two"))
        assertEquals("one", String(b.open(c1)))
        assertEquals("two", String(b.open(c2)))
        assertThrows(Exception::class.java) { b.open(c2) } // replay
        val a2 = SecureChannel(k1, k2); val b2 = SecureChannel(k2, k1)
        val t = a2.seal(utf8("x")); t[0] = (t[0].toInt() xor 1).toByte()
        assertThrows(Exception::class.java) { b2.open(t) } // tamper
        val a3 = SecureChannel(k1, k2); val b3 = SecureChannel(k2, k1)
        a3.seal(utf8("first")); val second = a3.seal(utf8("second"))
        assertThrows(Exception::class.java) { b3.open(second) } // dropped/reordered
    }

    @Test fun x25519BothSidesAgreeAndSasMatches() {
        val p = X25519.generate(); val m = X25519.generate()
        val s1 = X25519.agree(p.priv, m.pub); val s2 = X25519.agree(m.priv, p.pub)
        assertArrayEquals(s1, s2)
        val kp = Handshake.derive(s1, p.pub, m.pub, true); val km = Handshake.derive(s2, p.pub, m.pub, false)
        assertEquals(kp.sas, km.sas)
        assertArrayEquals(kp.sendKey, km.recvKey); assertArrayEquals(kp.recvKey, km.sendKey)
        val mitm = X25519.generate()
        val kEve = Handshake.derive(X25519.agree(p.priv, mitm.pub), p.pub, mitm.pub, true)
        assertNotEquals("a man in the middle changes the code the humans compare", kp.sas, kEve.sas)
    }

    @Test fun ed25519SignVerify() {
        val s = SeedSigner(Ed25519.newSeed())
        val sig = s.sign(utf8("m"))
        assertTrue(Ed25519.verify(s.publicKey, utf8("m"), sig))
        assertFalse(Ed25519.verify(s.publicKey, utf8("n"), sig))
    }

    @Test fun ledgerDetectsTampering() {
        val kv = MemoryKV(); val l = HashChainLedger(kv)
        repeat(4) { l.append("T", JSONObject().put("n", it), 1000L + it) }
        assertTrue(l.verify())
        kv.put("ledger", kv.get("ledger")!!.replace("\"n\\\":2", "\"n\\\":9"))
        assertFalse(l.verify())
    }
}

class EndToEndTests {
    private fun world(): Triple<MintApi, Phone, Phone> {
        val mint = SimulatedMint(MemoryKV())
        return Triple(mint, Phone("alice", mint).setup(fund = 160), Phone("shop", mint).setup())
    }

    @Test fun mintingBuildsValidTokensAndAuditProofs() {
        val (_, alice, _) = world()
        assertEquals(160, alice.wallet.balance())
        assertEquals(listOf(10, 50, 100), alice.wallet.tokens().map { it.token.amount }.sorted())
        alice.wallet.tokens().forEach { assertNull(Verify.token(it.token, alice.wallet.mintKeys(), System.currentTimeMillis())) }
    }

    @Test fun mintRejectsAmountsItCannotMake() {
        val (mint, alice, _) = world()
        assertThrows(MintApiException::class.java) { alice.wallet.mint(mint, 7) }
    }

    @Test fun happyPathPaymentAndSettlement() {
        val (mint, alice, shop) = world()
        val o = transact(alice, shop, 110)
        assertEquals(o.payer.message, Outcome.SUCCESS, o.payer.outcome)
        assertEquals(o.merchant.message, Outcome.SUCCESS, o.merchant.outcome)
        assertEquals(o.payerUi.sas, o.merchantUi.sas)
        assertEquals(50, alice.wallet.balance())
        assertEquals(2, shop.wallet.pendingReceipts().size)
        assertTrue(alice.wallet.ledger.verify() && shop.wallet.ledger.verify())
        val sync = shop.wallet.sync(mint)
        assertEquals(2, sync.accepted)
        assertTrue(sync.alerts.isEmpty())
        assertEquals(0, shop.wallet.pendingReceipts().size)
        assertEquals(0, shop.wallet.sync(mint).uploaded)
    }

    @Test fun merchantSeesNoMoreThanOnePointOfTheSecret() {
        val (_, alice, shop) = world()
        transact(alice, shop, 100)
        val r = shop.wallet.pendingReceipts().single()
        val a0 = alice.wallet.identitySecret()
        assertNotEquals(a0, bigFromHex(r.y))
    }

    @Test fun sameMerchantRejectsAReplayedToken() {
        // The only double-spend defence that works while both phones are offline: the
        // merchant remembers the tokens it has already taken. Across merchants the fraud
        // is caught later, at settlement; here it has to be refused on the spot.
        val mint = SimulatedMint(MemoryKV())
        val alice = Phone("alice", mint).setup(fund = 100)
        val shop = Phone("shop", mint).setup()

        // Alice keeps a copy of her vault from before the payment, so the clone still
        // believes the token is unspent -- a payer who kept a backup, not a protocol flaw.
        val backup = MemoryKV().also { it.copyFrom(alice.kv) }
        val cloneWallet = Wallet(backup, alice.signer)

        val first = transact(alice, shop, 100, "shop")
        assertEquals(Outcome.SUCCESS, first.merchant.outcome)
        assertEquals(1, shop.wallet.pendingReceipts().size)

        // Same token, same merchant, second time.
        val (a, b) = pipe(); val eph = X25519.generate()
        var mr: SessionResult? = null; var pr: SessionResult? = null
        val t1 = Thread {
            mr = MerchantSession(
                b, shop.signer, shop.wallet.credential()!!, "shop", 100, shop.wallet.mintPub()!!,
                shop.wallet.mintKeys(), shop.wallet.revokedIds(), shop.wallet, AutoUi(), eph,
            ).run()
        }
        val t2 = Thread {
            pr = PayerSession(
                a, alice.signer, cloneWallet.credential()!!, cloneWallet.mintPub()!!,
                emptySet(), cloneWallet, AutoUi(),
            ).run()
        }
        t1.start(); t2.start(); t1.join(60000); t2.join(60000)

        assertEquals(mr!!.message, Outcome.REJECTED, mr!!.outcome)
        assertTrue(mr!!.message, mr!!.message.contains("already spent here"))
        // The payer is told too, so the tokens are not left locked.
        assertEquals(pr!!.message, Outcome.REJECTED, pr!!.outcome)

        // Nothing was taken the second time: no extra receipt to settle, and the
        // merchant's balance of receipts is exactly what the first payment left.
        assertEquals(1, shop.wallet.pendingReceipts().size)
    }

    @Test fun crossMerchantDoubleSpendIsDetectedAndIdentityRevoked() {
        val mint = SimulatedMint(MemoryKV())
        val alice = Phone("alice", mint).setup(fund = 100)
        val shopA = Phone("A", mint).setup(); val shopB = Phone("B", mint).setup()
        // Alice copies her vault before paying, to later replay the same tokens elsewhere.
        val backup = MemoryKV().also { it.copyFrom(alice.kv) }
        val aliceClone = Phone("alice-clone", mint)
        val cloneWallet = Wallet(backup, alice.signer)
        val o1 = transact(alice, shopA, 100, "shopA")
        assertEquals(Outcome.SUCCESS, o1.merchant.outcome)
        // Offline, shop B has no way to know: it accepts the very same token.
        val (a, b) = pipe(); val eph = X25519.generate()
        var mr: SessionResult? = null; var pr: SessionResult? = null
        val t1 = Thread { mr = MerchantSession(b, shopB.signer, shopB.wallet.credential()!!, "shopB", 100, shopB.wallet.mintPub()!!, shopB.wallet.mintKeys(), shopB.wallet.revokedIds(), shopB.wallet, AutoUi(), eph).run() }
        val t2 = Thread { pr = PayerSession(a, alice.signer, cloneWallet.credential()!!, cloneWallet.mintPub()!!, emptySet(), cloneWallet, AutoUi()).run() }
        t1.start(); t2.start(); t1.join(60000); t2.join(60000)
        assertEquals(mr!!.message, Outcome.SUCCESS, mr!!.outcome)
        // Back online: both merchants settle. The second upload exposes the cheater.
        assertEquals(1, shopA.wallet.sync(mint).accepted)
        val s = shopB.wallet.sync(mint)
        assertEquals(0, s.accepted)
        assertEquals(1, s.alerts.size)
        assertTrue(s.alerts[0], s.alerts[0].contains("revoked"))
        val aliceCred = alice.wallet.credential()!!.credId
        assertTrue(mint.getRevocations().any { it.credId == aliceCred })
        // Once the merchants learn of the revocation, Alice can't transact any more.
        shopA.wallet.sync(mint)
        val o3 = transact(Phone("p", mint).setup(fund = 10), shopA, 10)
        assertEquals(Outcome.SUCCESS, o3.merchant.outcome) // honest users unaffected
        val o4 = transact(alice, shopA, 10)
        assertEquals(Outcome.FAILED, o4.merchant.outcome)
        assertTrue(o4.merchant.message, o4.merchant.message.contains("revoked"))
    }

    @Test fun sameMerchantReplayRejectedOffline() {
        val mint = SimulatedMint(MemoryKV())
        val alice = Phone("alice", mint).setup(fund = 50)
        val shop = Phone("shop", mint).setup()
        val backup = MemoryKV().also { it.copyFrom(alice.kv) }
        assertEquals(Outcome.SUCCESS, transact(alice, shop, 50).merchant.outcome)
        val replayer = Phone("alice2", mint); replayer.kv.copyFrom(backup)
        val w = Wallet(backup, alice.signer)
        val (a, b) = pipe(); val eph = X25519.generate()
        var mr: SessionResult? = null; var pr: SessionResult? = null
        val t1 = Thread { mr = MerchantSession(b, shop.signer, shop.wallet.credential()!!, "shop", 50, shop.wallet.mintPub()!!, shop.wallet.mintKeys(), shop.wallet.revokedIds(), shop.wallet, AutoUi(), eph).run() }
        val t2 = Thread { pr = PayerSession(a, alice.signer, w.credential()!!, w.mintPub()!!, emptySet(), w, AutoUi()).run() }
        t1.start(); t2.start(); t1.join(60000); t2.join(60000)
        assertEquals(Outcome.REJECTED, mr!!.outcome)
        assertTrue(mr!!.message, mr!!.message.contains("already spent"))
        assertEquals(Outcome.REJECTED, pr!!.outcome)
    }

    @Test fun codeCannotBeGroundToAMatchBecauseKeysAreCommittedFirst() {
        // An attacker acting as "payer" towards a real merchant commits to one key, then tries to
        // reveal a different one (chosen after seeing the merchant's key) to steer the 6-digit code.
        val mint = SimulatedMint(MemoryKV())
        val shop = Phone("shop", mint).setup()
        val (a, b) = pipe(); val eph = X25519.generate()
        var mr: SessionResult? = null
        val t = Thread { mr = MerchantSession(b, shop.signer, shop.wallet.credential()!!, "shop", 10, shop.wallet.mintPub()!!, shop.wallet.mintKeys(), shop.wallet.revokedIds(), shop.wallet, AutoUi(), eph).run() }
        t.start()
        val committed = X25519.generate()
        a.send(utf8(JSONObject().put("t", "HELLO").put("v", 2).put("commit", sha256(committed.pub).hex()).toString()))
        a.receive(5000) // merchant's HELLO_ACK: the attacker now knows the merchant's key
        val ground = X25519.generate() // ...and swaps in a key chosen with that knowledge
        a.send(utf8(JSONObject().put("t", "REVEAL").put("epk", ground.pub.hex()).toString()))
        t.join(20000)
        assertEquals(Outcome.FAILED, mr!!.outcome)
        assertTrue(mr!!.message, mr!!.message.contains("committed"))
    }

    @Test fun oldProtocolVersionIsRefused() {
        val mint = SimulatedMint(MemoryKV())
        val shop = Phone("shop", mint).setup()
        val (a, b) = pipe(); val eph = X25519.generate()
        var mr: SessionResult? = null
        val t = Thread { mr = MerchantSession(b, shop.signer, shop.wallet.credential()!!, "shop", 10, shop.wallet.mintPub()!!, shop.wallet.mintKeys(), shop.wallet.revokedIds(), shop.wallet, AutoUi(), eph).run() }
        t.start()
        a.send(utf8(JSONObject().put("t", "HELLO").put("v", 1).put("epk", X25519.generate().pub.hex()).toString()))
        t.join(20000)
        assertEquals(Outcome.FAILED, mr!!.outcome)
    }

    @Test fun cannotMakeExactChangeOffline() {
        val (_, alice, shop) = world()
        val o = transact(alice, shop, 20)
        assertEquals(Outcome.FAILED, o.payer.outcome)
        assertEquals(160, alice.wallet.balance())
    }

    @Test fun sasMismatchAbortsBothSides() {
        val (_, alice, shop) = world()
        val o = transact(alice, shop, 100, payerUi = AutoUi(sasOk = false))
        assertEquals(Outcome.DECLINED, o.payer.outcome)
        assertNotEquals(Outcome.SUCCESS, o.merchant.outcome)
        assertEquals(160, alice.wallet.balance())
    }

    @Test fun payerCanDeclineAtPaymentPrompt() {
        val (_, alice, shop) = world()
        val o = transact(alice, shop, 100, payerUi = AutoUi(pay = false))
        assertEquals(Outcome.DECLINED, o.payer.outcome)
        assertEquals(160, alice.wallet.balance())
    }

    @Test fun slowLinkLooksLikeRelayAndIsRefused() {
        val (_, alice, shop) = world()
        val o = transact(alice, shop, 100, delayMs = 700, maxRtt = 500)
        assertEquals(Outcome.FAILED, o.merchant.outcome)
        assertTrue(o.merchant.message, o.merchant.message.contains("relay"))
        assertEquals(160, alice.wallet.balance())
    }

    @Test fun qrBindingStopsImpersonation() {
        val (_, alice, shop) = world()
        val good = transact(alice, shop, 100, payerKeyHash = { pub -> sha256(pub) })
        assertEquals(Outcome.SUCCESS, good.payer.outcome)
        val (_, alice2, shop2) = world()
        val bad = transact(alice2, shop2, 100, payerKeyHash = { _ -> sha256(utf8("someone else")) })
        assertEquals(Outcome.FAILED, bad.payer.outcome)
        assertTrue(bad.payer.message, bad.payer.message.contains("QR"))
        assertEquals(160, alice2.wallet.balance())
    }

    @Test fun peerWithExpiredCredentialIsRefused() {
        // Alice registered 400 days ago, so her 180-day credential has since expired.
        var mintNow = System.currentTimeMillis() - 400L * 24 * 3600 * 1000
        val mint = SimulatedMint(MemoryKV()) { mintNow }
        val alice = Phone("alice", mint, clock = { mintNow }).setup(fund = 100)
        mintNow = System.currentTimeMillis()
        val shop = Phone("shop", mint).setup()
        val o = transact(alice, shop, 100)
        assertEquals(Outcome.FAILED, o.merchant.outcome)
        assertTrue(o.merchant.message, o.merchant.message.contains("expired"))
        assertNotEquals(Outcome.SUCCESS, o.payer.outcome)
        assertEquals(100, alice.wallet.balance())
    }

    @Test fun tamperedTokenIsRejectedByMerchant() {
        // Funded with 60 -- a 50 and a 10 -- rather than the usual 160, so the
        // wallet holds no genuine 100-token. `selectExact` sorts by descending
        // amount and breaks ties by the order of randomly generated token ids, so
        // with a real 100 also present it would sometimes spend that one instead
        // and the payment would legitimately succeed.
        val mint = SimulatedMint(MemoryKV())
        val alice = Phone("alice", mint).setup(fund = 60)
        val shop = Phone("shop", mint).setup()
        assertEquals(listOf(10, 50), alice.wallet.tokens().map { it.token.amount }.sorted())

        // Alice inflates her 10-token to look like a 100-token. It keeps the
        // 10-denomination key id, so Verify.token rejects it on `key.amount !=
        // t.amount`, and it is now the only token that can fund a payment of 100.
        val ten = alice.wallet.tokens().first { it.token.amount == 10 }
        val bad = ten.copy(token = ten.token.copy(amount = 100))
        alice.kv.put("token:${ten.token.tokenId}", bad.toJson().toString())
        val o = transact(alice, shop, 100)
        assertEquals(Outcome.REJECTED, o.merchant.outcome)
    }

    @Test fun walletRefusesAMintWhoseKeyChanges() {
        val (mint, alice, _) = world()
        alice.kv.put("mint_pub", "00".repeat(32))
        assertThrows(MintApiException::class.java) { alice.wallet.refreshMintInfo(mint) }
    }

    // ---- mint-key pinning ------------------------------------------------------------
    //
    // A background sync can reach the in-app simulated mint before any backend is
    // configured. Its key must not become a trust anchor, or the first real mint is
    // refused and only a full wallet wipe clears it.

    /** A mint that is not the demo one: same behaviour, a different signing key. */
    private fun realMint(pubHex: String): MintApi {
        val sim = SimulatedMint(MemoryKV())
        return object : MintApi by sim {
            override fun getInfo(): MintInfo = MintInfo(sim.getInfo().keys, pubHex)
        }
    }

    @Test fun simulatedMintKeyDoesNotBecomeATrustAnchor() {
        val (sim, alice, _) = world()
        alice.wallet.refreshMintInfo(sim)
        assertEquals(SimulatedMint.DEMO_MINT_PUB_HEX, alice.kv.get("mint_pub"))

        // Configuring a real backend must now succeed, not be refused.
        val real = realMint("ab".repeat(32))
        alice.wallet.refreshMintInfo(real)
        assertEquals("ab".repeat(32), alice.kv.get("mint_pub"))
    }

    @Test fun firstRealMintKeyIsPinned() {
        val (_, alice, _) = world()
        val real = realMint("ab".repeat(32))
        alice.wallet.refreshMintInfo(real)
        assertEquals("ab".repeat(32), alice.kv.get("mint_pub"))

        // The same mint again is fine.
        alice.wallet.refreshMintInfo(real)
        assertEquals("ab".repeat(32), alice.kv.get("mint_pub"))
    }

    @Test fun changedRealMintKeyIsStillRejected() {
        val (_, alice, _) = world()
        alice.wallet.refreshMintInfo(realMint("ab".repeat(32)))
        assertThrows(MintApiException::class.java) {
            alice.wallet.refreshMintInfo(realMint("cd".repeat(32)))
        }
        // The pinned key is untouched by the refusal.
        assertEquals("ab".repeat(32), alice.kv.get("mint_pub"))
    }

    @Test fun realMintKeyIsNotOverwrittenByTheSimulatedMint() {
        val (sim, alice, _) = world()
        alice.wallet.refreshMintInfo(realMint("ab".repeat(32)))
        assertThrows(MintApiException::class.java) { alice.wallet.refreshMintInfo(sim) }
        assertEquals("ab".repeat(32), alice.kv.get("mint_pub"))
    }

    // ---- credential scoping ----------------------------------------------------------
    //
    // A credential is signed by the mint that issued it, so it only verifies under that
    // mint's key. After moving from the demo mint to a real one the wallet must offer to
    // register again rather than keep a credential the real mint answers with 403.

    /**
     * A mint with its own Ed25519 key, so its credentials verify under its key and not the
     * demo mint's. Only the calls `register` and `refreshMintInfo` make are implemented.
     */
    private class OtherMint(private val seedByte: Byte) : MintApi {
        private val signer = SeedSigner(ByteArray(32) { seedByte })
        val pubHex: String get() = signer.publicKey.hex()
        override fun getInfo() = MintInfo(DemoMintKeys.keys, pubHex)
        override fun registerDevice(req: RegisterRequest): DeviceCredential {
            val credId = sha256(utf8("other|$seedByte|${req.devicePub}")).hex().take(32)
            val expiry = System.currentTimeMillis() + 86_400_000L
            val sig = signer.sign(Msg.cred(credId, req.devicePub, req.c0, expiry)).hex()
            return DeviceCredential(credId, req.devicePub, req.c0, expiry, sig)
        }
        override fun latestRoot() = AuditRoot("", 0, System.currentTimeMillis())
        override fun getRevocations(): List<Revocation> = emptyList()
        override fun issue(req: IssueRequest): IssueResponse = throw MintApiException("not used")
        override fun uploadBatch(receipts: List<Receipt>): SettlementResponse =
            throw MintApiException("not used")
    }

    @Test fun simulatedCredentialDoesNotCountAsRegisteredOnARealMint() {
        val (sim, alice, _) = world()
        alice.wallet.register(sim)
        assertTrue("registered against the demo mint", alice.wallet.isRegistered())

        // Point at a real backend: its key is adopted over the demo key ...
        val real = OtherMint(1)
        alice.wallet.refreshMintInfo(real)
        assertEquals(real.pubHex, alice.kv.get("mint_pub"))

        // ... and the demo credential no longer counts as registration.
        assertFalse("demo credential must not satisfy a real mint", alice.wallet.isRegistered())
        assertNull(alice.wallet.credentialForCurrentMint())
        // It is not erased -- only a successful registration overwrites it.
        assertNotNull(alice.wallet.credential())
    }

    @Test fun mintingRefusesAStaleCredentialRatherThanCallingTheMint() {
        val (sim, alice, _) = world()
        alice.wallet.register(sim)
        val real = OtherMint(1)
        alice.wallet.refreshMintInfo(real)

        val e = assertThrows(MintApiException::class.java) { alice.wallet.mint(real, 10) }
        assertTrue(e.message!!, e.message!!.contains("register this device"))
    }

    @Test fun registrationStateIsCorrectAfterRegisteringWithTheRealMint() {
        val (sim, alice, _) = world()
        alice.wallet.register(sim)
        val demoCredId = alice.wallet.credential()!!.credId

        val real = OtherMint(1)
        alice.wallet.register(real)

        assertTrue(alice.wallet.isRegistered())
        assertEquals(real.pubHex, alice.kv.get("mint_pub"))
        assertNotNull(alice.wallet.credentialForCurrentMint())
        assertNotEquals("a new credential must replace the demo one", demoCredId, alice.wallet.credential()!!.credId)
    }

    @Test fun aValidCredentialForTheCurrentMintIsNotDiscarded() {
        val (sim, alice, _) = world()
        alice.wallet.register(sim)
        val credId = alice.wallet.credential()!!.credId

        // Re-reading state, and refreshing against the same mint, must not drop or reissue it.
        assertTrue(alice.wallet.isRegistered())
        assertEquals(credId, alice.wallet.credentialForCurrentMint()!!.credId)
        alice.wallet.refreshMintInfo(sim)
        assertTrue(alice.wallet.isRegistered())
        assertEquals(credId, alice.wallet.credential()!!.credId)
    }

    @Test fun switchingBetweenTwoRealMintsIsStillRejected() {
        val (_, alice, _) = world()
        val first = OtherMint(1)
        alice.wallet.refreshMintInfo(first)
        assertThrows(MintApiException::class.java) { alice.wallet.refreshMintInfo(OtherMint(2)) }
        assertEquals("the first real mint stays pinned", first.pubHex, alice.kv.get("mint_pub"))
    }

    @Test fun dishonestMintAuditProofIsCaught() {
        val real = SimulatedMint(MemoryKV())
        val liar = object : MintApi by real {
            override fun issue(req: IssueRequest): IssueResponse {
                val r = real.issue(req); return r.copy(root = "11".repeat(32))
            }
        }
        val alice = Phone("alice", liar).also { it.wallet.register(liar) }
        assertThrows(MintApiException::class.java) { alice.wallet.mint(liar, 10) }
    }

    @Test fun planningAndExactSelection() {
        val (_, alice, _) = world()
        assertEquals(listOf(100, 10), alice.wallet.selectExact(110)!!.map { it.token.amount }.sortedDescending())
        assertNull(alice.wallet.selectExact(70))
        val keys = alice.wallet.mintKeys()
        assertEquals(listOf(500, 500, 100, 50, 10), alice.wallet.planDenominations(1160, keys)!!.map { it.amount }.sortedDescending())
        assertNull(alice.wallet.planDenominations(5, keys))
    }
}
