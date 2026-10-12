package com.bluecash.wallet.core

/**
 * Merkle tree in the style of RFC 6962 / RFC 9162 (Certificate Transparency).
 * Leaves and inner nodes are hashed with different prefixes so a leaf can never be
 * confused with an inner node. The mint publishes a root over everything it has issued;
 * a wallet checks its own issuance is included, so the mint cannot quietly hide issuance.
 */
object Merkle {
    fun leafHash(data: ByteArray): ByteArray = sha256(byteArrayOf(0), data)
    private fun nodeHash(l: ByteArray, r: ByteArray): ByteArray = sha256(byteArrayOf(1), l, r)

    /** Largest power of two strictly less than n (n >= 2). */
    private fun split(n: Int): Int {
        var k = 1
        while (k * 2 < n) k *= 2
        return k
    }

    fun root(leaves: List<ByteArray>): ByteArray {
        require(leaves.isNotEmpty())
        return mth(leaves.map { leafHash(it) })
    }

    private fun mth(h: List<ByteArray>): ByteArray {
        if (h.size == 1) return h[0]
        val k = split(h.size)
        return nodeHash(mth(h.subList(0, k)), mth(h.subList(k, h.size)))
    }

    /** Audit path for leaf [index]. */
    fun proof(leaves: List<ByteArray>, index: Int): List<ByteArray> {
        require(index in leaves.indices)
        return path(index, leaves.map { leafHash(it) })
    }

    private fun path(m: Int, h: List<ByteArray>): List<ByteArray> {
        if (h.size == 1) return emptyList()
        val k = split(h.size)
        return if (m < k) path(m, h.subList(0, k)) + mth(h.subList(k, h.size))
        else path(m - k, h.subList(k, h.size)) + mth(h.subList(0, k))
    }

    /** RFC 9162 section 2.1.3.2 verification. [leafData] is the raw (unhashed) leaf. */
    fun verifyInclusion(leafData: ByteArray, index: Int, treeSize: Int, proof: List<ByteArray>, root: ByteArray): Boolean {
        if (index < 0 || index >= treeSize) return false
        var fn = index
        var sn = treeSize - 1
        var r = leafHash(leafData)
        for (p in proof) {
            if (sn == 0) return false
            if ((fn and 1) == 1 || fn == sn) {
                r = nodeHash(p, r)
                if ((fn and 1) == 0) {
                    while ((fn and 1) == 0 && fn != 0) {
                        fn = fn shr 1
                        sn = sn shr 1
                    }
                }
            } else {
                r = nodeHash(r, p)
            }
            fn = fn shr 1
            sn = sn shr 1
        }
        return sn == 0 && ctEquals(r, root)
    }
}
