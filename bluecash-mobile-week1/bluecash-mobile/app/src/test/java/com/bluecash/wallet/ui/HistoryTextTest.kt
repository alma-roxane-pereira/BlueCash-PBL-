package com.bluecash.wallet.ui

import com.bluecash.wallet.core.LedgerEntry
import org.junit.Assert.*
import org.junit.Test

/**
 * The history list is the only record a person can actually read, so it has to
 * say what happened in words. These tests use the exact payloads the app
 * writes -- see the `recordLedger` calls in `Wallet.kt` and `Sessions.kt`.
 */
class HistoryTextTest {

    private fun entry(type: String, payload: String) =
        LedgerEntry(0, type, payload, 1_760_000_000_000L, "", "")

    private fun format(type: String, payload: String) = HistoryText.format(entry(type, payload))

    @Test fun mintReadsAsMoneyAdded() {
        val row = format("MINT", """{"amount":160,"tokens":3}""")
        assertEquals("Added ₹160", row.title)
        assertEquals("3 tokens", row.detail)
    }

    @Test fun aSingleTokenIsNotPluralised() {
        assertEquals("1 token", format("MINT", """{"amount":10,"tokens":1}""").detail)
    }

    @Test fun paymentSentNamesTheMerchant() {
        val row = format("PAY_SENT", """{"amount":10,"merchant_id":"shop-93d356","receipts":["21c0b7d1-5da4-4ab0"]}""")
        assertEquals("Paid ₹10", row.title)
        assertEquals("to shop-93d356", row.detail)
    }

    @Test fun paymentReceivedReadsAsIncoming() {
        val row = format("PAY_RECEIVED", """{"amount":10,"receipts":["21c0b7d1-5da4-4ab0-8c7d-c6ef8b976345"]}""")
        assertEquals("Received ₹10", row.title)
    }

    @Test fun aLongIdentifierIsShortenedNotWrapped() {
        val row = format("REGISTER", """{"cred_id":"d738253914a34ab4ae2922ee737f92a7"}""")
        assertEquals("This device was registered", row.title)
        assertTrue("should be elided: ${row.detail}", row.detail.endsWith("…"))
        assertTrue(row.detail.length < 20)
    }

    @Test fun settlementSaysHowManyWereConfirmed() {
        val row = format("SETTLE", """{"uploaded":1,"accepted":1,"alerts":0}""")
        assertEquals("Synced with the mint", row.title)
        assertEquals("1 payment confirmed", row.detail)
    }

    @Test fun settlementAlertsAreNeverHidden() {
        // An alert is the mint reporting a double spend. Burying it in a
        // "synced" row is the one outcome this formatter must not produce.
        val row = format("SETTLE", """{"uploaded":2,"accepted":1,"alerts":1}""")
        assertTrue("alert missing from: ${row.detail}", row.detail.contains("1 alert"))
    }

    @Test fun anEmptySyncSaysSoPlainly() {
        assertEquals("Nothing to send", format("SETTLE", """{"uploaded":0,"accepted":0,"alerts":0}""").detail)
    }

    @Test fun noRowEverShowsRawJson() {
        // The complaint that prompted this: braces and quotes on screen.
        val payloads = listOf(
            "MINT" to """{"amount":160,"tokens":3}""",
            "PAY_SENT" to """{"amount":10,"merchant_id":"shop-93d356","receipts":["21c0b7d1"]}""",
            "PAY_RECEIVED" to """{"amount":10,"receipts":["21c0b7d1"]}""",
            "SETTLE" to """{"uploaded":1,"accepted":1,"alerts":0}""",
            "REGISTER" to """{"cred_id":"d738253914a34ab4"}""",
        )
        for ((type, payload) in payloads) {
            val row = format(type, payload)
            val shown = row.title + row.detail
            assertFalse("$type leaks JSON: $shown", shown.contains("{"))
            assertFalse("$type leaks JSON: $shown", shown.contains("\""))
            assertFalse("$type leaks a key name: $shown", shown.contains("_id\":"))
        }
    }

    @Test fun aMalformedPayloadDoesNotCrash() {
        // A row that cannot be parsed must still render; the ledger is meant to
        // be complete, and a crash here would take the whole screen down.
        val row = format("MINT", "not json at all")
        assertEquals("Added ", row.title.take(6))
    }

    @Test fun anUnknownTypeIsShownPlainly() {
        val row = format("SOME_NEW_EVENT", "{}")
        assertEquals("Some new event", row.title)
    }
}
