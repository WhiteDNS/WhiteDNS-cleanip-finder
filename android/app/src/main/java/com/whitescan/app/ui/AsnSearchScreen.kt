package com.whitescan.app.ui

import androidx.compose.foundation.clickable
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.whitescan.engine.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class AsnRow(val asn: String, val name: String, val subnets: Int)

// Searchable ASN picker — returns selected CIDRs as newline string to the
// form. Backed by Mobile.asnSearch() which queries the embedded IranASNs CSV.
@Composable
fun AsnSearchScreen(
    dataDir: String,
    onSelected: (targets: String) -> Unit,
    onCancel: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var rows by remember { mutableStateOf<List<AsnRow>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    val selected = remember { mutableStateMapOf<String, AsnRow>() }

    // Trigger search when query changes (debounce via recompose)
    LaunchedEffect(query) {
        loading = true
        rows = withContext(Dispatchers.IO) {
            runCatching {
                Mobile.asnSearch(dataDir, query.ifBlank { "*" })
                    .trimEnd()
                    .lines()
                    .filter { it.isNotBlank() }
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
        // Search bar
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            placeholder = { Text("Search ASN name or number…") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            singleLine = true,
        )

        // Selection count + confirm bar
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
                        "${selected.size} ASN(s) selected",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { selected.clear() },
                            modifier = Modifier.height(40.dp),
                        ) { Text("Clear") }
                        Button(
                            onClick = {
                                // Return the selected ASN numbers as the targets string
                                val cidrs = selected.values.joinToString("\n") { it.asn }
                                onSelected(cidrs)
                            },
                            modifier = Modifier.height(40.dp),
                        ) { Text("Export") }
                    }
                }
            }
        }

        if (loading) {
            Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        }

        LazyColumn(modifier = Modifier.weight(1f)) {
            items(rows, key = { it.asn }) { row ->
                val isSelected = selected.containsKey(row.asn)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            if (isSelected) selected.remove(row.asn) else selected[row.asn] = row
                        }
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Icon(
                        if (isSelected) Icons.Default.CheckBox else Icons.Default.CheckBoxOutlineBlank,
                        contentDescription = null,
                        tint = if (isSelected) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(row.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                        Text(
                            "${row.asn}  ·  ${row.subnets} subnet(s)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Divider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)
            }
        }

        // Cancel row at bottom
        TextButton(
            onClick = onCancel,
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp)
                .height(48.dp),
        ) { Text("Cancel") }
    }
}
