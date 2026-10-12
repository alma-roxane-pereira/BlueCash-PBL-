package com.bluecash.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.bluecash.wallet.navigation.BlueCashNavHost
import com.bluecash.wallet.ui.theme.BlueCashTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            BlueCashTheme {
                BlueCashNavHost()
            }
        }
    }
}
