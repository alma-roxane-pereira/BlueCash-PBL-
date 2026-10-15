package com.bluecash.wallet.ui

/**
 * Turns an exception message into something worth showing a person.
 *
 * The failure dialog used to print `e.message` straight through, which on a
 * real payment produced lines like:
 *
 *     value should not be longer than max length of an attribute value
 *
 * That is the Android Bluetooth stack talking to itself. It tells the person
 * nothing about what happened, nothing about whether their money moved, and
 * nothing about what to try next.
 *
 * Every mapping here answers the two questions a failed payment actually
 * raises: was I charged, and what do I do now. Where the answer is "no money
 * moved", it says so — that is the single most reassuring thing a payment app
 * can tell someone, and it is cheap to say because an aborted session never
 * reaches settlement.
 *
 * Unrecognised messages are passed through rather than replaced with something
 * vague. A technical string is a poor message, but "Something went wrong" is a
 * worse one, and it would also hide real faults during development.
 */
object FriendlyError {

    fun of(raw: String?): String {
        val message = raw?.trim().orEmpty()
        if (message.isEmpty()) return "Something interrupted the payment. No money moved — try again."

        val lower = message.lowercase()

        return when {
            // The GATT attribute limit. Seen in the field as both "value ..."
            // and "notification should not be longer ...", so match the tail.
            "max length of an attribute value" in lower ->
                "The phones could not exchange the payment data. Move them closer together and try again — no money moved."

            "the mint's signing key changed" in lower ->
                "This is not the same mint this wallet registered with. Check the server address in Settings."

            "identity revoked" in lower ->
                "This device has been blocked by the mint after a double-spend was detected. It cannot pay or register again."

            "timeout" in lower || "timed out" in lower ->
                "The other phone stopped responding. Keep both screens on, stay close, and try again — no money moved."

            "disconnect" in lower || "connection" in lower && "lost" in lower ->
                "The Bluetooth connection dropped before the payment finished. No money moved — try again."

            "bluetooth" in lower && ("off" in lower || "disabled" in lower) ->
                "Turn Bluetooth on to pay nearby devices."

            "permission" in lower ->
                "BlueCash needs Bluetooth permission to find nearby devices. Grant it on the Wallet screen."

            "unable to resolve host" in lower || "failed to connect" in lower ||
                "econnrefused" in lower || "network is unreachable" in lower ->
                "Could not reach the mint. Check the server address in Settings and that you are on the same network."

            // The codes the scan and connect paths surface as bare numbers.
            lower.startsWith("gatt ") || lower.matches(Regex("^status \\d+$")) ->
                "The Bluetooth connection failed. Move the phones closer and try again — no money moved."

            else -> message
        }
    }
}
