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
    val (title, color) = when (result.outcome) {
        Outcome.SUCCESS -> "Done" to Color(0xFFDFF3E3)
        Outcome.UNCERTAIN -> "Check this payment" to Color(0xFFFFF1CC)
        Outcome.DECLINED -> "Cancelled" to Color(0xFFEDEDED)
        else -> "Didn't go through" to Color(0xFFFBE1DE)
    }
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = color)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = Color.Black)
            Text(result.message, style = MaterialTheme.typography.bodyMedium, color = Color.Black)
            Button(onClick = onDone) { Text("OK") }
        }
    }
}
