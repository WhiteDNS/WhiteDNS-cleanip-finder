package com.whitescan.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.platform.LocalUriHandler
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
fun HomeScreen(onSelect: (ScanKind) -> Unit, onConfigMaker: () -> Unit) {
    val uriHandler = LocalUriHandler.current
    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
        contentAlignment = Alignment.TopCenter,
    ) {
    // Center the menu when it fits on screen, but scroll when it doesn't (large
    // system fonts, low-resolution displays, small screens). Giving the
    // scrollable Column a minimum height equal to the viewport lets the centered
    // arrangement work while still allowing overflow to scroll.
    val viewportHeight = maxHeight
    Column(
        modifier = Modifier
            // Cap the width so the menu doesn't stretch awkwardly wide on tablets.
            .widthIn(max = 560.dp)
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .heightIn(min = viewportHeight)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // Branding mimics the TUI ASCII banner gradient.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.horizontalGradient(
                        listOf(
                            Color(0xFF00D1FF),
                            Color(0xFF00C8F0),
                            Color(0xFFFF7A00),
                            Color(0xFFF5C400),
                        )
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
                    "v1.3.6  ·  developed by TAjirax",
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
            icon = Icons.Default.Speed,
            title = "Speed & Loss Rank",
            subtitle = "Rank clean IPs by download/upload speed & packet loss",
            accentColor = MintGreen,
            onClick = { onSelect(ScanKind.SPEED) },
        )
        ScanCard(
            icon = Icons.Default.Public,
            title = "DNS Resolver / Tunnel Scan",
            subtitle = "Probe resolvers for open recursion, EDNS0 & tunnel-readiness",
            accentColor = CyanAccent,
            onClick = { onSelect(ScanKind.DNS) },
        )
        ScanCard(
            icon = Icons.Default.Download,
            title = "ASN Export",
            subtitle = "Search IranASNs, expand CIDRs to IP list",
            accentColor = CoralRed,
            onClick = { onSelect(ScanKind.ASN_EXPORT) },
        )
        ScanCard(
            icon = Icons.Default.Build,
            title = "Config Maker",
            subtitle = "Rewrite proxy configs with clean IPs / extract IP:ports",
            accentColor = CyanAccent,
            onClick = onConfigMaker,
        )

        // Telegram channel link, centered at the bottom of the menu.
        Spacer(Modifier.height(6.dp))
        Row(
            modifier = Modifier
                .clickable { uriHandler.openUri("https://t.me/whitedns") }
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                Icons.Default.Send,
                contentDescription = "Telegram",
                tint = CyanAccent,
                modifier = Modifier.size(18.dp),
            )
            Text(
                "t.me/whitedns",
                style = MaterialTheme.typography.bodyMedium,
                color = CyanAccent,
            )
        }
    }
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
