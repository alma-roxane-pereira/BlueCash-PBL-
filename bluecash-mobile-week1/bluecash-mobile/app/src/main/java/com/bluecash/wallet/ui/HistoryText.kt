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

    /**
     * A formatted row.
     *
     * [amount] is kept out of [title] so the list can right-align it in its own
     * column -- that is what lets someone scan a history for "how much" without
     * reading every line. [credit] is true for money in, false for money out,
     * and null for entries that move nothing (registration, sync), which is how
     * the row decides whether to tint the figure.
     */
    data class Row(
        val icon: String,
        val title: String,
        val detail: String,
        val time: String,
        val amount: String = "",
        val credit: Boolean? = null,
    )

    private val timeFormat: DateFormat =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)

    fun format(entry: LedgerEntry): Row {
        val json = runCatching { JSONObject(entry.payload) }.getOrNull()
        val time = timeFormat.format(Date(entry.ts))

        return when (entry.type) {
            "MINT" -> {
                val tokens = json?.optInt("tokens", 0) ?: 0
                Row(
                    icon = "＋",
                    title = "Added money",
                    detail = plural(tokens, "token", "tokens"),
                    time = time,
                    amount = json.signed("amount", credit = true),
                    credit = true,
                )
            }

            "PAY_SENT" -> {
                val merchant = json?.optString("merchant_id").orBlank()
                Row(
                    icon = "↗",
                    title = if (merchant.isEmpty()) "Paid" else "Paid · ${shorten(merchant)}",
                    detail = "",
                    time = time,
                    amount = json.signed("amount", credit = false),
                    credit = false,
                )
            }

            "PAY_RECEIVED" -> {
                Row(
                    icon = "↙",
                    title = "Money received",
                    detail = "",
                    time = time,
                    amount = json.signed("amount", credit = true),
                    credit = true,
                )
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
                Row("✓", "Device registered", if (credId.isEmpty()) "" else "ID ${shorten(credId)}", time)
            }

            // A type this build does not know about: show it plainly rather than
            // hiding the row, since the ledger is meant to be complete.
            else -> Row("•", entry.type.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() }, "", time)
        }
    }

    /** `+ ₹50` or `- ₹10`; empty when the payload carries no usable amount. */
    private fun JSONObject?.signed(key: String, credit: Boolean): String {
        val value = this?.opt(key)
        val amount = (value as? Number)?.toInt() ?: return ""
        return (if (credit) "+ " else "- ") + "₹" + amount
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
