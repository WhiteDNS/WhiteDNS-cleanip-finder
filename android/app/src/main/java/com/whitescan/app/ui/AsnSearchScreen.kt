package com.whitescan.app.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckBox
import androidx.compose.material.icons.filled.CheckBoxOutlineBlank
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.whitescan.engine.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AsnRow(val asn: String, val name: String, val subnets: Int)

private const val CONSTRAINED_ASN_SEARCH_LIMIT = 80
private const val CONSTRAINED_ASN_MIN_QUERY_CHARS = 2
private const val ASN_SEARCH_DEBOUNCE_MS = 300L

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AsnSearchScreen(
    dataDir: String,
    confirmLabel: String = "Use selection",
    constrainedDevice: Boolean = false,
    // Returns the expanded IPv4 CIDRs for the chosen ASNs (ready to scan/export).
    onSelected: (cidrs: String) -> Unit,
    onCancel: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var rows by remember { mutableStateOf<List<AsnRow>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var expanding by remember { mutableStateOf(false) }
    var expandError by remember { mutableStateOf<String?>(null) }
    val selected = remember { mutableStateMapOf<String, AsnRow>() }
    val haptic = LocalHapticFeedback.current
    val scope = rememberCoroutineScope()
    val trimmedQuery = query.trim()

    // Auto-focus search field so keyboard pops up immediately
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }

    LaunchedEffect(trimmedQuery, constrainedDevice) {
        if (constrainedDevice &&
            trimmedQuery != "*" &&
            trimmedQuery.length < CONSTRAINED_ASN_MIN_QUERY_CHARS
        ) {
            rows = emptyList()
            loading = false
            return@LaunchedEffect
        }

        delay(ASN_SEARCH_DEBOUNCE_MS)
        loading = true
        rows = withContext(Dispatchers.IO) {
            runCatching {
                val search = trimmedQuery.ifBlank { "*" }
                Mobile.asnSearch(dataDir, search)
                    .trimEnd()
                    .lines()
                    .filter { it.isNotBlank() }
                    .let { lines ->
                        if (constrainedDevice) lines.take(CONSTRAINED_ASN_SEARCH_LIMIT) else lines
                    }
                    .mapNotNull { line ->
                        val parts = line.split('\t')
                        if (parts.size >= 3) AsnRow(parts[0], parts[1], parts[2].toIntOrNull() ?: 0)
                        else null
                    }
            }.getOrDefault(emptyList())
        }
        loading = false
    }

    Column(modifier = Modifier.fillMaxSize()) {

        // Search bar — auto-focused so keyboard pops up on entry
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .focusRequester(focusRequester),
            placeholder = { Text("Search ASN name or number…") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            singleLine = true,
        )

        // Selection action bar
        if (selected.isNotEmpty()) {
            Surface(color = MaterialTheme.colorScheme.primaryContainer) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        "${selected.size} selected",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { selected.clear() },
                            modifier = Modifier.height(44.dp),
                            enabled = !expanding,
                        ) { Text("Clear") }
                        Button(
                            onClick = {
                                if (expanding) return@Button
                                expandError = null
                                val ids = selected.values.joinToString("\n") { it.asn }
                                scope.launch {
                                    expanding = true
                                    val result = withContext(Dispatchers.IO) {
                                        runCatching { Mobile.expandASNs(dataDir, ids) }
                                    }
                                    expanding = false
                                    val error = result.exceptionOrNull()
                                    val cidrs = result.getOrNull().orEmpty()
                                    if (error != null) {
                                        expandError = error.message ?: "expand failed"
                                    } else if (cidrs.isBlank()) {
                                        expandError = "No IPv4 ranges found for the selected ASN(s)"
                                    } else {
                                        onSelected(cidrs)
                                    }
                                }
                            },
                            modifier = Modifier.height(44.dp),
                            enabled = !expanding,
                        ) {
                            if (expanding) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.onPrimary,
                                )
                            } else {
                                Text(confirmLabel)
                            }
                        }
                    }
                }
            }
        }

        // Expansion error banner
        expandError?.let { err ->
            Surface(color = MaterialTheme.colorScheme.errorContainer) {
                Text(
                    err,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        if (loading) {
            Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else if (constrainedDevice && rows.isEmpty() && trimmedQuery.isBlank()) {
            Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                Text("Search to load ASN matches", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else if (rows.isEmpty() && query.isNotBlank()) {
            Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                Text("No results for \"$query\"", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        // Hint shown when nothing selected
        if (selected.isEmpty() && rows.isNotEmpty()) {
            Text(
                "Tap to select · Double-tap to deselect · Long-press to select",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
        }

        LazyColumn(modifier = Modifier.weight(1f)) {
            items(rows, key = { it.asn }) { row ->
                val isSelected = selected.containsKey(row.asn)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        // Tap = toggle select/deselect; long-press = select with haptic
                        .combinedClickable(
                            onClick = {
                                if (isSelected) selected.remove(row.asn)
                                else selected[row.asn] = row
                            },
                            onDoubleClick = {
                                selected.remove(row.asn)
                            },
                            onLongClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                selected[row.asn] = row
                            },
                        )
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Icon(
                        if (isSelected) Icons.Default.CheckBox else Icons.Default.CheckBoxOutlineBlank,
                        contentDescription = if (isSelected) "Selected" else "Not selected",
                        tint = if (isSelected) MaterialTheme.colorScheme.primary
                               else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(24.dp),
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            row.name,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                            maxLines = 1,
                        )
                        Text(
                            "${row.asn}  ·  ${row.subnets} subnet(s)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)
            }
        }

        TextButton(
            onClick = onCancel,
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp)
                .height(48.dp),
        ) { Text("Cancel") }
    }
}
