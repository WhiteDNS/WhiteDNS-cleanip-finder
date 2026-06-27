package com.whitescan.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.app.ScanUiState

@Composable
fun ScanningScreen(
    state: ScanUiState,
    onPauseResume: () -> Unit,
    onStop: () -> Unit,
    onViewResults: () -> Unit,
) {
    val logListState = rememberLazyListState()

    // Auto-scroll log to newest entry
    LaunchedEffect(state.logs.size) {
        if (state.logs.isNotEmpty()) {
            logListState.animateScrollToItem(state.logs.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {

        // ── Progress bar (cyan → green → orange gradient) ──────────────────
        val pct = if (state.total > 0) state.processed.toFloat() / state.total else 0f
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "${(pct * 100).toInt()}%  ${state.processed}/${state.total}",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (state.etaSec > 0) {
                    val m = state.etaSec / 60; val s = state.etaSec % 60
                    Text("ETA ${m}m${s}s", style = MaterialTheme.typography.bodySmall)
                }
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp)
                    .background(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.shapes.small),
            ) {
                if (pct > 0f) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(pct)
                            .fillMaxHeight()
                            .background(
                                Brush.horizontalGradient(
                                    listOf(
                                        Color(0xFF00BCD4),  // cyan
                                        Color(0xFF4CAF50),  // green
                                        Color(0xFFFF9800),  // orange
                                    )
                                ),
                                MaterialTheme.shapes.small,
                            ),
                    )
                }
            }
        }

        // ── Stats row ──────────────────────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Found: ${state.found}", style = MaterialTheme.typography.bodySmall)
            Text("Unique IPs: ${state.uniqueIPs}", style = MaterialTheme.typography.bodySmall)
        }

        // ── Current target ─────────────────────────────────────────────────
        if (state.currentIP.isNotEmpty()) {
            Text(
                "▶ ${state.currentIP}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        // ── Live hits (last 6) ─────────────────────────────────────────────
        if (state.displayResults.isNotEmpty()) {
            HorizontalDivider()
            Text(
                "Recent hits  (${state.totalResults} total)",
                style = MaterialTheme.typography.labelMedium,
            )
            state.displayResults.takeLast(6).forEach { line ->
                Text(
                    "✓ $line",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFF4CAF50),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        // ── Log tail ───────────────────────────────────────────────────────
        HorizontalDivider()
        Text("Log", style = MaterialTheme.typography.labelMedium)
        LazyColumn(
            state = logListState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(
                    MaterialTheme.colorScheme.surfaceVariant,
                    MaterialTheme.shapes.small,
                )
                .padding(6.dp),
        ) {
            items(state.logs) { line ->
                Text(
                    line,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 14.sp,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        // ── Controls (48 dp touch targets) ────────────────────────────────
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedButton(
                onClick = onPauseResume,
                modifier = Modifier.weight(1f).height(48.dp),
            ) {
                Icon(
                    if (state.paused) Icons.Default.PlayArrow else Icons.Default.Pause,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text(if (state.paused) "Resume" else "Pause")
            }
            Button(
                onClick = onStop,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                ),
                modifier = Modifier.weight(1f).height(48.dp),
            ) {
                Icon(
                    Icons.Default.Stop,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text("Stop")
            }
        }

        if (state.done) {
            Button(
                onClick = onViewResults,
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) {
                Text("View Results (${state.totalResults})")
            }
        }
    }
}
