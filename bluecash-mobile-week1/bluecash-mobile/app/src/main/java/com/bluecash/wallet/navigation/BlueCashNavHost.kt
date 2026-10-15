package com.bluecash.wallet.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalanceWallet
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.bluecash.wallet.ui.screens.PayScreen
import com.bluecash.wallet.ui.screens.ReceiveScreen
import com.bluecash.wallet.ui.screens.SettingsScreen
import com.bluecash.wallet.ui.screens.WalletHomeScreen

@Composable
fun BlueCashNavHost() {
    val navController = rememberNavController()

    Scaffold(
        bottomBar = { BlueCashBottomBar(navController) }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Destination.WalletHome.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Destination.WalletHome.route) {
                // The wallet's Pay and Receive buttons go to the same places the
                // bottom bar does, with the same options, so the two cannot drift
                // into behaving differently.
                WalletHomeScreen(onNavigate = { route -> navController.navigateTab(route) })
            }
            composable(Destination.Pay.route) { PayScreen() }
            composable(Destination.Receive.route) { ReceiveScreen() }
            composable(Destination.Settings.route) { SettingsScreen() }
        }
    }
}

@Composable
private fun BlueCashBottomBar(navController: NavHostController) {
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    NavigationBar {
        Destination.bottomBarDestinations.forEach { destination ->
            NavigationBarItem(
                selected = currentRoute == destination.route,
                onClick = { navController.navigateTab(destination.route) },
                icon = { Icon(iconFor(destination), contentDescription = destination.label) },
                label = { Text(destination.label) }
            )
        }
    }
}

/** Switch top-level tab, preserving each tab's own back stack and state. */
private fun NavHostController.navigateTab(route: String) {
    navigate(route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

private fun iconFor(destination: Destination): ImageVector = when (destination) {
    Destination.WalletHome -> Icons.Filled.AccountBalanceWallet
    Destination.Pay -> Icons.Filled.Send
    Destination.Receive -> Icons.Filled.QrCode
    Destination.Settings -> Icons.Filled.Settings
}
