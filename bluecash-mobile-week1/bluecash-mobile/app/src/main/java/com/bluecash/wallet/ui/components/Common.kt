package com.bluecash.wallet.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bluecash.wallet.core.Outcome
import com.bluecash.wallet.core.SessionResult
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.ui.graphics.Brush
import com.bluecash.wallet.ui.theme.ErrorDark
import com.bluecash.wallet.ui.theme.ErrorLight
import com.bluecash.wallet.ui.theme.GradientEnd
import com.bluecash.wallet.ui.theme.GradientStart
import com.bluecash.wallet.ui.theme.InkDark
import com.bluecash.wallet.ui.theme.InkLight
import com.bluecash.wallet.ui.theme.NeutralDark
import com.bluecash.wallet.ui.theme.NeutralLight
import com.bluecash.wallet.ui.theme.SuccessDark
import com.bluecash.wallet.ui.theme.SuccessLight
import com.bluecash.wallet.ui.theme.WarningDark
import com.bluecash.wallet.ui.theme.WarningLight

/** A scrolling page with consistent padding and spacing. */
@Composable
fun ScreenColumn(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        content = content,
    )
}


/**
 * The balance, as the thing the screen is about.
 *
 * It was a plain card of text, visually equal to "Bluetooth permissions" below
 * it. A wallet's first job is to answer "how much do I have", so this is the
 * one element given the brand gradient and the largest type on the page.
 */
@Composable
fun BalanceCard(balance: Int, tokens: Int, pending: Int) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(
            Modifier
                .background(Brush.linearGradient(listOf(GradientStart, GradientEnd)))
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                "YOUR BALANCE",
                style = MaterialTheme.typography.labelMedium,
                color = Color.White.copy(alpha = 0.75f),
            )
            Text(
                "₹$balance",
                fontSize = 40.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White,
            )
            Text(
                if (tokens == 1) "1 token" else "$tokens tokens",
                style = MaterialTheme.typography.bodyMedium,
                color = Color.White.copy(alpha = 0.8f),
            )
            if (pending > 0) {
                // Money that has left the wallet but is not yet confirmed by the
                // mint. Saying so plainly beats a balance that silently disagrees
                // with what the person just did.
                Text(
                    "₹$pending awaiting confirmation",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.White.copy(alpha = 0.9f),
                )
            }
        }
    }
}

@Composable
fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

/**
 * The 6-digit code both phones derive from the secure-channel keys. If the codes match, no
 * one is sitting in the middle of the connection. The human comparison is the security step.
 */
@Composable
fun SasCard(sas: String, onAnswer: (Boolean) -> Unit) {
    SectionCard("Check the code") {
        Text("Does this code match the one on the other phone?", style = MaterialTheme.typography.bodyMedium)
        Text(
            sas.substring(0, 3) + " " + sas.substring(3),
            fontSize = 40.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = { onAnswer(true) }) { Text("Matches") }
            OutlinedButton(onClick = { onAnswer(false) }) { Text("Doesn't match") }
        }
    }
}

@Composable
fun ResultCard(result: SessionResult, onDone: () -> Unit) {
    val dark = isSystemInDarkTheme()
    val (title, color) = when (result.outcome) {
        Outcome.SUCCESS -> "Done" to if (dark) SuccessDark else SuccessLight
        Outcome.UNCERTAIN -> "Check this payment" to if (dark) WarningDark else WarningLight
        Outcome.DECLINED -> "Cancelled" to if (dark) NeutralDark else NeutralLight
        else -> "Didn't go through" to if (dark) ErrorDark else ErrorLight
    }
    val ink = if (dark) InkLight else InkDark
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = color)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = ink)
            Text(result.message, style = MaterialTheme.typography.bodyMedium, color = ink)
            Button(onClick = onDone) { Text("OK") }
        }
    }
}
