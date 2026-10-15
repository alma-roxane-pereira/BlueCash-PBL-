package com.bluecash.wallet.ui

import com.bluecash.wallet.core.LedgerEntry
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

/**
 * Turns a ledger entry into something a person can read.
 *
 * The history list used to print the stored payload directly — `{"amount":10,
 * "merchant_id":"shop-93d356","receipts":["21c0b7d1-5da4-4a` — truncated
 * mid-string at 70 characters. That is a debugging view, not a wallet.
 *
 * Only the *display* changes. The stored payload is part of a hash chain: each
 * entry commits to the previous one, and the "Ledger integrity: intact" check
 * re-hashes exactly these bytes. Rewriting what gets stored would break that
 * check and destroy the tamper-evidence the ledger exists to provide. So this
 * formats at the point of rendering and leaves the record untouched.
 *
 * Unknown types and malformed payloads fall back to something sensible rather
 * than throwing: a wallet that crashes on a history row it does not recognise
 * is worse than one that shows a plain label.
 */
object HistoryText {

    /** A formatted row: a headline, the detail under it, and a leading glyph. */
    data class Row(val icon: String, val title: String, val detail: String, val time: String)

    private val timeFormat: DateFormat =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)

    fun format(entry: LedgerEntry): Row {
        val json = runCatching { JSONObject(entry.payload) }.getOrNull()
        val time = timeFormat.format(Date(entry.ts))

        return when (entry.type) {
            "MINT" -> {
                val amount = json.rupees("amount")
                val tokens = json?.optInt("tokens", 0) ?: 0
                Row("＋", "Added $amount", plural(tokens, "token", "tokens"), time)
            }

            "PAY_SENT" -> {
                val amount = json.rupees("amount")
                val merchant = json?.optString("merchant_id").orBlank()
                Row("→", "Paid $amount", if (merchant.isEmpty()) "" else "to ${shorten(merchant)}", time)
            }

            "PAY_RECEIVED" -> {
                val amount = json.rupees("amount")
                Row("←", "Received $amount", "", time)
            }

            "SETTLE" -> {
                val accepted = json?.optInt("accepted", 0) ?: 0
                val uploaded = json?.optInt("uploaded", 0) ?: 0
                val alerts = json?.optInt("alerts", 0) ?: 0
                val detail = when {
                    // An alert is the mint reporting a problem with a receipt --
                    // a double spend, most importantly. It must never be buried.
                    alerts > 0 -> "$accepted of $uploaded accepted · ${plural(alerts, "alert", "alerts")}"
                    uploaded == 0 -> "Nothing to send"
                    accepted == uploaded -> plural(accepted, "payment", "payments") + " confirmed"
                    else -> "$accepted of $uploaded accepted"
                }
                Row("↻", "Synced with the mint", detail, time)
            }

            "REGISTER" -> {
                val credId = json?.optString("cred_id").orBlank()
                Row("✓", "This device was registered", if (credId.isEmpty()) "" else "ID ${shorten(credId)}", time)
            }

            // A type this build does not know about: show it plainly rather than
            // hiding the row, since the ledger is meant to be complete.
            else -> Row("•", entry.type.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() }, "", time)
        }
    }

    /** `₹10`, or an empty string when the payload has no usable amount. */
    private fun JSONObject?.rupees(key: String): String {
        val value = this?.opt(key)
        val amount = (value as? Number)?.toInt() ?: return ""
        return "₹$amount"
    }

    /**
     * Identifiers are long and opaque, and the full value is never what someone
     * is reading for. Enough to recognise, short enough not to wrap.
     */
    private fun shorten(id: String): String = if (id.length <= 14) id else id.take(12) + "…"

    private fun plural(n: Int, one: String, many: String): String =
        "$n " + if (n == 1) one else many

    private fun String?.orBlank(): String = if (this == null || this == "null") "" else this
}
