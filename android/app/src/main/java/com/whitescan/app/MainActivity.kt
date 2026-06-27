package com.whitescan.app

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.whitescan.app.ui.*
import com.whitescan.engine.mobile.ScanConfig

sealed class Screen {
    object Home : Screen()
    data class Config(val kind: ScanKind) : Screen()
    object AsnPicker : Screen()              // searchable ASN picker for any kind
    data class Scanning(val kind: ScanKind) : Screen()
    object Results : Screen()
}

class MainActivity : ComponentActivity() {

    private val vm: ScanViewModel by viewModels()

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                var screen by remember { mutableStateOf<Screen>(Screen.Home) }
                // pendingKind holds which scan type we navigated from when going to AsnPicker
                var pendingKind by remember { mutableStateOf(ScanKind.IP) }
                var form by remember { mutableStateOf(FormState()) }
                val scanState by vm.state.collectAsStateWithLifecycle()

                // Auto-advance to results when scan finishes
                LaunchedEffect(scanState.done) {
                    if (scanState.done && screen is Screen.Scanning) {
                        screen = Screen.Results
                        stopForegroundScanService()
                    }
                }

                // Update foreground service notification with live found count
                LaunchedEffect(scanState.found) {
                    if (scanState.running) {
                        val label = (screen as? Screen.Scanning)?.kind?.name ?: "Scan"
                        startService(ScanService.intentUpdate(this@MainActivity, label, scanState.found))
                    }
                }

                val screenTitle = when (screen) {
                    Screen.Home -> "WhiteDNS"
                    is Screen.Config -> "${(screen as Screen.Config).kind.label()} · Config"
                    Screen.AsnPicker -> "Select ASNs"
                    is Screen.Scanning -> "${(screen as Screen.Scanning).kind.label()} · Scanning"
                    Screen.Results -> "Results"
                }
                val showBack = screen != Screen.Home

                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text(screenTitle) },
                            navigationIcon = {
                                if (showBack) {
                                    IconButton(onClick = {
                                        when (screen) {
                                            is Screen.Scanning -> {
                                                vm.stop()
                                                stopForegroundScanService()
                                                screen = Screen.Home
                                            }
                                            Screen.Results -> screen = Screen.Home
                                            Screen.AsnPicker -> screen = Screen.Config(pendingKind)
                                            else -> screen = Screen.Home
                                        }
                                    }) {
                                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                                    }
                                }
                            },
                        )
                    },
                ) { padding ->
                    Box(Modifier.padding(padding).fillMaxSize()) {
                        when (val s = screen) {
                            Screen.Home -> HomeScreen { kind ->
                                vm.reset()
                                form = FormState()
                                screen = if (kind == ScanKind.ASN_EXPORT) {
                                    pendingKind = kind
                                    Screen.AsnPicker
                                } else {
                                    Screen.Config(kind)
                                }
                            }

                            is Screen.Config -> ScanConfigForm(
                                kind = s.kind,
                                form = form,
                                onFormChange = { form = it },
                                onStart = {
                                    screen = Screen.Scanning(s.kind)
                                    startForegroundScanService(s.kind)
                                    vm.start(s.kind, filesDir.absolutePath, form.toEngineConfig())
                                },
                                onPickASN = {
                                    pendingKind = s.kind
                                    screen = Screen.AsnPicker
                                },
                            )

                            Screen.AsnPicker -> AsnSearchScreen(
                                dataDir = filesDir.absolutePath,
                                onSelected = { targets ->
                                    form = form.copy(targets = targets)
                                    screen = if (pendingKind == ScanKind.ASN_EXPORT) {
                                        // For export: start immediately after selection
                                        vm.reset()
                                        vm.start(ScanKind.ASN_EXPORT, filesDir.absolutePath, form.copy(targets = targets).toEngineConfig())
                                        startForegroundScanService(ScanKind.ASN_EXPORT)
                                        Screen.Scanning(ScanKind.ASN_EXPORT)
                                    } else {
                                        Screen.Config(pendingKind)
                                    }
                                },
                                onCancel = {
                                    screen = if (pendingKind == ScanKind.ASN_EXPORT) Screen.Home
                                    else Screen.Config(pendingKind)
                                },
                            )

                            is Screen.Scanning -> ScanningScreen(
                                state = scanState,
                                onPauseResume = { vm.pauseResume() },
                                onStop = {
                                    vm.stop()
                                    stopForegroundScanService()
                                    screen = Screen.Results
                                },
                                onViewResults = { screen = Screen.Results },
                            )

                            Screen.Results -> ResultsScreen(
                                state = scanState,
                                onBack = { screen = Screen.Home },
                                onNewScan = {
                                    vm.reset()
                                    form = FormState()
                                    screen = Screen.Home
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    private fun startForegroundScanService(kind: ScanKind) {
        val intent = ScanService.intentStart(this, kind.label())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopForegroundScanService() {
        startService(ScanService.intentStop(this))
    }
}

private fun ScanKind.label(): String = when (this) {
    ScanKind.IP -> "IP Scan"
    ScanKind.SNI -> "SNI Scan"
    ScanKind.HTTP -> "HTTP Proxy"
    ScanKind.SOCKS5 -> "SOCKS5"
    ScanKind.ASN_EXPORT -> "ASN Export"
}

// Map the Compose form into the gomobile-generated ScanConfig.
// gomobile lowercases the first letter of each Go field name.
private fun FormState.toEngineConfig(): ScanConfig {
    val cfg = ScanConfig()
    cfg.targets = targets.trim()
    cfg.ports = ports.trim()
    cfg.concurrency = concurrency.toIntOrNull() ?: 250
    cfg.lowBandwidth = lowBandwidth
    cfg.transferModel = transferModel
    // Go field SNIDomains → Java getter getSNIDomains() → Kotlin property sNIDomains
    cfg.setSNIDomains(sniDomains.trim())
    cfg.setSNIStrict(sniStrict)
    return cfg
}
