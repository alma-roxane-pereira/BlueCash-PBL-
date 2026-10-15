package com.bluecash.wallet.ui

import org.junit.Assert.*
import org.junit.Test

/**
 * Failure messages, checked against the strings the app actually produced on a
 * phone. The two BLE ones below are copied from screenshots of a real failed
 * payment, which is why they are asserted literally rather than paraphrased.
 */
class FriendlyErrorTest {

    @Test fun theGattAttributeLimitIsExplainedInPlainWords() {
        val shown = FriendlyError.of("value should not be longer than max length of an attribute value")
        assertFalse(shown.contains("attribute"))
        assertTrue(shown.contains("closer"))
        assertTrue("must say the money is safe", shown.contains("no money moved", ignoreCase = true))
    }

    @Test fun theNotificationVariantMapsToTheSameAdvice() {
        // The same limit surfaces with a different prefix depending on direction.
        assertEquals(
            FriendlyError.of("value should not be longer than max length of an attribute value"),
            FriendlyError.of("notification should not be longer than max length of an attribute value"),
        )
    }

    @Test fun aChangedMintKeyPointsAtSettings() {
        val shown = FriendlyError.of("the mint's signing key changed - refusing (reset the wallet to trust a new mint)")
        assertTrue(shown.contains("Settings"))
    }

    @Test fun revocationIsStatedDirectly() {
        val shown = FriendlyError.of("identity revoked")
        assertTrue(shown.contains("double-spend"))
        assertTrue(shown.contains("blocked"))
    }

    @Test fun aTimeoutTellsThePersonWhatToDo() {
        val shown = FriendlyError.of("Read timed out")
        assertTrue(shown.contains("no money moved", ignoreCase = true))
    }

    @Test fun anUnreachableMintPointsAtTheAddress() {
        assertTrue(FriendlyError.of("Unable to resolve host \"bluecash\"").contains("server address"))
        assertTrue(FriendlyError.of("Failed to connect to /10.113.248.123:8000").contains("server address"))
    }

    @Test fun anEmptyMessageStillSaysSomethingUseful() {
        assertTrue(FriendlyError.of(null).contains("No money moved"))
        assertTrue(FriendlyError.of("   ").contains("No money moved"))
    }

    @Test fun anUnrecognisedMessageIsPassedThroughNotSwallowed() {
        // Better a technical string than "Something went wrong", which would
        // hide real faults and help nobody.
        val odd = "something genuinely unexpected happened"
        assertEquals(odd, FriendlyError.of(odd))
    }

    @Test fun noMappedMessageLeaksStackOrPackageNames() {
        val raws = listOf(
            "value should not be longer than max length of an attribute value",
            "identity revoked",
            "Read timed out",
            "java.net.ConnectException: Failed to connect to /10.0.2.2:8000",
        )
        for (raw in raws) {
            val shown = FriendlyError.of(raw)
            assertFalse("leaks a package name: $shown", shown.contains("java."))
            assertFalse("leaks a package name: $shown", shown.contains("android."))
        }
    }
}
