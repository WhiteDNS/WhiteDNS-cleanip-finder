package com.whitescan.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.whitescan.app.ScanUiState
import com.whitescan.app.ScanViewModel
import java.io.File

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ResultsScreen(
    state: ScanUiState,
    vm: ScanViewModel,
    onBack: () -> Unit,
    onNewScan: () -> Unit,
) {
    val ctx = LocalContext.current
    val haptic = LocalHapticFeedback.current

    // Load the last 100 lines from disk once when savedPath is known.
    LaunchedEffect(state.savedPath) {
        state.savedPath?.let { vm.loadPreview(it) }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {

        Text("Results", style = MaterialTheme.typography.titleMedium)

        if (state.error != null) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                ),
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
                    "${state.found} endpoint(s) found",
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
                    Icon(Icons.Default.Share, contentDescription = "Share",
                        modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Share")
                }
            }
        }

        HorizontalDivider()

        // Show the file preview once loaded; until then (or if the file read is
        // empty) fall back to the live results captured during the scan so a
        // stopped scan still shows what it found immediately.
        val display = if (state.preview.isNotEmpty()) state.preview else state.liveResults
        when {
            state.previewLoading && display.isEmpty() -> {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.padding(24.dp))
                }
            }
            display.isEmpty() -> {
                Text(
                    if (state.found > 0) "Loading ${state.found} result(s)…" else "No results found.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            else -> {
                Text(
                    if (state.found > display.size)
                        "Showing ${display.size} of ${state.found} · long-press an IP to copy"
                    else
                        "Long-press an IP to copy it",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth()) {
                    items(display) { line ->
                        ResultRow(
                            line = line,
                            onCopy = { ip ->
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                copyToClipboard(ctx, ip)
                            },
                        )
                        HorizontalDivider(
                            thickness = 0.5.dp,
                            color = MaterialTheme.colorScheme.outlineVariant,
                        )
                    }
                }
            }
        }

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

// A result line is "IP:port" optionally followed by a TAB and the passed probe
// domains. Long-press copies ONLY the IP:port; the domains are shown as tags but
// never included in the copied text.
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ResultRow(line: String, onCopy: (String) -> Unit) {
    val tab = line.indexOf('\t')
    val ip = (if (tab >= 0) line.substring(0, tab) else line).trim()
    val domains = if (tab >= 0) line.substring(tab + 1).trim() else ""

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = {},
                onLongClick = { onCopy(ip) },
            )
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            ip,
            fontSize = 13.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.SemiBold,
            color = MintGreen,
        )
        if (domains.isNotEmpty()) {
            // Show the important domains first (shortened), cap the count, and
            // collapse the rest into a "+N" tag so busy IPs stay readable.
            val (tags, extra) = shortDomains(domains, max = 3)
            tags.forEach { name ->
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = MaterialTheme.shapes.small,
                ) {
                    Text(
                        name,
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
            }
            if (extra > 0) {
                Text(
                    "+$extra",
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

// Friendly short labels for the common probe domains.
private val DOMAIN_SHORT = mapOf(
    "workers.dev" to "workers",
    "pages.dev" to "pages",
    "claude.ai" to "claude",
    "gemini.google.com" to "gemini",
    "notebooklm.google.com" to "notebook",
    "chatgpt.com" to "chatgpt",
    "instagram.com" to "instagram",
    "web.telegram.org" to "telegram",
    "reddit.com" to "reddit",
)

// Order important domains first; everything else keeps its position after.
private val DOMAIN_PRIORITY = listOf(
    "workers.dev", "pages.dev", "claude.ai", "gemini.google.com",
    "notebooklm.google.com", "chatgpt.com",
)

// Returns (shortened tags to show, count of remaining hidden domains).
private fun shortDomains(raw: String, max: Int): Pair<List<String>, Int> {
    val items = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    val ordered = items.sortedBy { d ->
        DOMAIN_PRIORITY.indexOf(d).let { if (it < 0) Int.MAX_VALUE else it }
    }
    val shown = ordered.take(max).map { DOMAIN_SHORT[it] ?: it.substringBefore('.') }
    val extra = (ordered.size - shown.size).coerceAtLeast(0)
    return shown to extra
}

private fun copyToClipboard(ctx: Context, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    cm.setPrimaryClip(ClipData.newPlainText("ip", text))
    Toast.makeText(ctx, "Copied $text", Toast.LENGTH_SHORT).show()
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
