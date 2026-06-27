package com.whitescan.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.app.ScanKind

@Composable
fun HomeScreen(onSelect: (ScanKind) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // ── Branding — mimics the TUI ASCII banner gradient ──────────────────
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.horizontalGradient(
                        listOf(Color(0xFF00D1FF), Color(0xFF00C8F0), Color(0xFFFF7A00), Color(0xFFF5C400))
                    ),
                    shape = MaterialTheme.shapes.medium,
                )
                .padding(vertical = 14.dp, horizontal = 20.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    "WHITEDNS",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Black,
                    fontSize = 26.sp,
                    color = Color(0xFF001820),
                    letterSpacing = 4.sp,
                )
                Text(
                    "v1.2  ·  developed by TAjirax",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = Color(0xFF003040),
                    letterSpacing = 1.sp,
                )
            }
        }

        Spacer(Modifier.height(4.dp))

        ScanCard(
            icon = Icons.Default.Search,
            title = "IP / CIDR Scan",
            subtitle = "Direct probe of IP ranges on specified ports",
            accentColor = CyanAccent,
            onClick = { onSelect(ScanKind.IP) },
        )
        ScanCard(
            icon = Icons.Default.Lock,
            title = "SNI Scanner",
            subtitle = "TLS hostname probe / domain-fronting detection",
            accentColor = Lavender,
            onClick = { onSelect(ScanKind.SNI) },
        )
        ScanCard(
            icon = Icons.Default.Http,
            title = "HTTP Proxy Scan",
            subtitle = "3-wave HTTP open-proxy discovery",
            accentColor = MintGreen,
            onClick = { onSelect(ScanKind.HTTP) },
        )
        ScanCard(
            icon = Icons.Default.Lan,
            title = "SOCKS5 Scan",
            subtitle = "SOCKS5 proxy verification",
            accentColor = Amber,
            onClick = { onSelect(ScanKind.SOCKS5) },
        )
        ScanCard(
            icon = Icons.Default.Download,
            title = "ASN Export",
            subtitle = "Search IranASNs, expand CIDRs to IP list",
            accentColor = CoralRed,
            onClick = { onSelect(ScanKind.ASN_EXPORT) },
        )
    }
}

@Composable
private fun ScanCard(
    icon: ImageVector,
    title: String,
    subtitle: String,
    accentColor: Color,
    onClick: () -> Unit,
) {
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
            // Coloured icon
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(accentColor.copy(alpha = 0.12f), MaterialTheme.shapes.small),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(24.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                Icons.Default.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}
