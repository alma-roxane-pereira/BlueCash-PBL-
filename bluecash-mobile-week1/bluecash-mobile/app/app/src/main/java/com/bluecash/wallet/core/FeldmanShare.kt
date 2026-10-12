package com.bluecash.wallet.core

import java.math.BigInteger

/**
 * Double-spend detection math ("Shamir share reveal" with Feldman commitments).
 *
 * Each token carries a secret line  P(x) = a0 + a1*x  (mod Q)  where a0 is the owner's
 * identity secret and a1 is fresh per token. Public commitments C0 = g^a0 and C1 = g^a1 are
 * baked into the mint-signed token. Every spend reveals ONE point (x, y = P(x)) where x
 * depends on the spend context:
 *   - one point alone says nothing about a0 (a1 is uniform, so y is uniform),
 *   - the merchant can check the point lies on the committed line: g^y == C0 * C1^x,
 *   - two points from two different spends recover a0, which exposes the cheater.
 *
 * Group: the 2048-bit safe-prime MODP group from RFC 3526 (group 14); we work in the
 * subgroup of quadratic residues, which has prime order Q = (P-1)/2 and generator 2.
 */
object Group {
    val P: BigInteger = BigInteger("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16)
    val Q: BigInteger = P.subtract(BigInteger.ONE).shiftRight(1)
    val G: BigInteger = BigInteger.valueOf(2)

    fun randomScalar(): BigInteger {
        var s: BigInteger
        do {
            s = BigInteger(Q.bitLength() + 64, Rand.rnd).mod(Q)
        } while (s.signum() == 0)
        return s
    }

    fun commit(a: BigInteger): BigInteger = G.modPow(a, P)

    /** The x-coordinate for a spend, bound to the token and the spend context. Never zero. */
    fun challengeX(tokenId: String, nCtx: String): BigInteger {
        val h = BigInteger(1, sha256(utf8("BCSHARE|v1|$tokenId|$nCtx")))
        return if (h.signum() == 0) BigInteger.ONE else h
    }

    fun evalShare(a0: BigInteger, a1: BigInteger, x: BigInteger): BigInteger =
        a0.add(a1.multiply(x)).mod(Q)

    fun verifyShare(c0: BigInteger, c1: BigInteger, x: BigInteger, y: BigInteger): Boolean {
        if (!isElement(c0) || !isElement(c1)) return false
        if (x.signum() <= 0 || y.signum() < 0 || y >= Q) return false
        return G.modPow(y, P) == c0.multiply(c1.modPow(x, P)).mod(P)
    }

    /** Two distinct points on the line reveal a0 (the identity secret). */
    fun recoverSecret(x1: BigInteger, y1: BigInteger, x2: BigInteger, y2: BigInteger): BigInteger? {
        val dx = x2.subtract(x1).mod(Q)
        if (dx.signum() == 0) return null
        val a1 = y2.subtract(y1).mod(Q).multiply(dx.modInverse(Q)).mod(Q)
        return y1.subtract(a1.multiply(x1)).mod(Q)
    }

    /** Is v in the prime-order subgroup (a quadratic residue mod P)? Uses the Jacobi symbol. */
    fun isElement(v: BigInteger): Boolean {
        if (v <= BigInteger.ONE || v >= P.subtract(BigInteger.ONE)) return false
        return jacobi(v, P) == 1
    }

    fun jacobi(a0: BigInteger, n0: BigInteger): Int {
        var a = a0.mod(n0)
        var n = n0
        var result = 1
        val three = BigInteger.valueOf(3)
        val four = BigInteger.valueOf(4)
        val five = BigInteger.valueOf(5)
        val eight = BigInteger.valueOf(8)
        while (a.signum() != 0) {
            while (!a.testBit(0)) {
                a = a.shiftRight(1)
                val r = n.mod(eight)
                if (r == three || r == five) result = -result
            }
            val t = a; a = n; n = t
            if (a.mod(four) == three && n.mod(four) == three) result = -result
            a = a.mod(n)
        }
        return if (n == BigInteger.ONE) result else 0
    }
}
