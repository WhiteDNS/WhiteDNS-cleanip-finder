package com.whitescan.app.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.whitescan.app.ScanUiState
import java.io.File

@Composable
fun ResultsScreen(
    state: ScanUiState,
    onBack: () -> Unit,
    onNewScan: () -> Unit,
) {
    val ctx = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {

        // ── Summary ────────────────────────────────────────────────────────
        Text("Results", style = MaterialTheme.typography.titleMedium)

        if (state.error != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(
                    "Error: ${state.error}",
                    modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(
                    "${state.totalResults} endpoint(s) found",
                    style = MaterialTheme.typography.bodyLarge,
                )
                state.savedPath?.let { path ->
                    Text(
                        path.substringAfterLast('/'),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            state.savedPath?.let { path ->
                FilledTonalButton(
                    onClick = { shareFile(ctx, path) },
                    modifier = Modifier.height(40.dp),
                ) {
                    Icon(
                        Icons.Default.Share,
                        contentDescription = "Share",
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(Modifier.width(4.dp))
                    Text("Share")
                }
            }
        }

        HorizontalDivider()

        // ── Result list — only shows last 100 from RAM ─────────────────────
        if (state.totalResults > state.displayResults.size) {
            Text(
                "Showing last ${state.displayResults.size} of ${state.totalResults} — full list saved to file",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth()) {
            items(state.displayResults) { line ->
                Text(
                    line,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFF4CAF50),
                    modifier = Modifier.padding(vertical = 3.dp),
                )
                HorizontalDivider(
                    thickness = 0.5.dp,
                    color = MaterialTheme.colorScheme.outlineVariant,
                )
            }
        }

        // ── Bottom buttons ─────────────────────────────────────────────────
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f).height(48.dp),
            ) { Text("Back") }
            Button(
                onClick = onNewScan,
                modifier = Modifier.weight(1f).height(48.dp),
            ) { Text("New Scan") }
        }
    }
}

private fun shareFile(ctx: Context, path: String) {
    val file = File(path)
    if (!file.exists()) return
    val uri = try {
        FileProvider.getUriForFile(ctx, "${ctx.packageName}.provider", file)
    } catch (_: Exception) { return }
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    ctx.startActivity(Intent.createChooser(intent, "Share scan results"))
}
