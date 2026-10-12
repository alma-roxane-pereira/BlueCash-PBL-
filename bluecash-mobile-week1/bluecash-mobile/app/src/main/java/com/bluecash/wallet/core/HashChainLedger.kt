package com.bluecash.wallet.core

import org.json.JSONArray
import org.json.JSONObject

data class LedgerEntry(val index: Int, val type: String, val payload: String, val ts: Long, val prevHash: String, val hash: String)

/**
 * Tamper-evident local history. Every entry's hash covers the previous entry's hash, so
 * editing or deleting any past entry breaks the chain from that point on.
 */
class HashChainLedger(private val kv: SecureKV) {
    private val key = "ledger"
    private val genesis = "00".repeat(32)

    private fun load(): List<LedgerEntry> {
        val raw = kv.get(key) ?: return emptyList()
        return JSONArray(raw).objects().map {
            LedgerEntry(it.getInt("i"), it.getString("t"), it.getString("p"), it.getLong("ts"), it.getString("prev"), it.getString("h"))
        }
    }

    private fun hashOf(i: Int, type: String, payload: String, ts: Long, prev: String) =
        sha256(utf8("BCLEDGER|v1|$i|$type|$ts|$prev|"), utf8(payload)).hex()

    @Synchronized
    fun append(type: String, payload: JSONObject, ts: Long): LedgerEntry {
        val list = load()
        val prev = list.lastOrNull()?.hash ?: genesis
        val p = payload.toString()
        val e = LedgerEntry(list.size, type, p, ts, prev, hashOf(list.size, type, p, ts, prev))
        val arr = JSONArray()
        (list + e).forEach {
            arr.put(JSONObject().put("i", it.index).put("t", it.type).put("p", it.payload).put("ts", it.ts).put("prev", it.prevHash).put("h", it.hash))
        }
        kv.put(key, arr.toString())
        return e
    }

    fun entries(): List<LedgerEntry> = load()

    fun verify(): Boolean {
        var prev = genesis
        for ((i, e) in load().withIndex()) {
            if (e.index != i || e.prevHash != prev || e.hash != hashOf(i, e.type, e.payload, e.ts, prev)) return false
            prev = e.hash
        }
        return true
    }
}
