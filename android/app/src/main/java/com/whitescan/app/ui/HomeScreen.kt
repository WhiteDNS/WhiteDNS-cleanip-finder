package com.whitescan.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.app.R
import com.whitescan.app.ScanKind

@Composable
fun HomeScreen(onSelect: (ScanKind) -> Unit, onConfigMaker: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp, Alignment.Top),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Image(
            painter = painterResource(R.drawable.whitedns_logo),
            contentDescription = "WhiteDNS IP Scanner",
            contentScale = ContentScale.Fit,
            modifier = Modifier.size(156.dp),
        )

        Text(
            "v1.2  ·  developed by TAjirax",
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            letterSpacing = 1.sp,
        )

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
        ScanCard(
            icon = Icons.Default.Build,
            title = "Config Maker",
            subtitle = "Rewrite proxy configs with clean IPs / extract IP:ports",
            accentColor = CyanAccent,
            onClick = onConfigMaker,
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
