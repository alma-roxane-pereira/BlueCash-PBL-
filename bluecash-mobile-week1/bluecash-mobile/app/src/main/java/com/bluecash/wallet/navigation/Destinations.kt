package com.bluecash.wallet.navigation

sealed class Destination(val route: String, val label: String) {
    data object WalletHome : Destination("wallet_home", "Wallet")
    data object Pay : Destination("pay", "Pay")
    data object Receive : Destination("receive", "Receive")
    data object Settings : Destination("settings", "Settings")

    companion object {
        val bottomBarDestinations = listOf(WalletHome, Pay, Receive, Settings)
    }
}
