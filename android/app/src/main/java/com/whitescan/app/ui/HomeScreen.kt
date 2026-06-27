package com.whitescan.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.whitescan.app.ScanKind

@Composable
fun HomeScreen(onSelect: (ScanKind) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("WhiteDNS", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Scanner",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.height(8.dp))

        ScanCard(
            icon = Icons.Default.Search,
            title = "IP / CIDR Scan",
            subtitle = "Direct probe of IP ranges on specified ports",
            onClick = { onSelect(ScanKind.IP) },
        )
        ScanCard(
            icon = Icons.Default.Lock,
            title = "SNI Scanner",
            subtitle = "TLS hostname probe / domain-fronting detection",
            onClick = { onSelect(ScanKind.SNI) },
        )
        ScanCard(
            icon = Icons.Default.Http,
            title = "HTTP Proxy Scan",
            subtitle = "3-wave HTTP open-proxy discovery",
            onClick = { onSelect(ScanKind.HTTP) },
        )
        ScanCard(
            icon = Icons.Default.Lan,
            title = "SOCKS5 Scan",
            subtitle = "SOCKS5 proxy verification",
            onClick = { onSelect(ScanKind.SOCKS5) },
        )
        ScanCard(
            icon = Icons.Default.Download,
            title = "ASN Export",
            subtitle = "Search IranASNs, expand CIDRs to IP list",
            onClick = { onSelect(ScanKind.ASN_EXPORT) },
        )
    }
}

@Composable
private fun ScanCard(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    // OutlinedCard provides a large tap area + ripple
    OutlinedCard(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp),
            )
            Column {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
