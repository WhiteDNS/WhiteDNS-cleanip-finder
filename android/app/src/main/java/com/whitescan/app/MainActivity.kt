package com.whitescan.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.widget.Toast
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.whitescan.app.ui.*
import com.whitescan.engine.mobile.Mobile
import com.whitescan.engine.mobile.ScanConfig
import java.io.File

sealed class Screen {
    object Home : Screen()
    data class Config(val kind: ScanKind) : Screen()
    object AsnPicker : Screen()
    object ConfigMaker : Screen()
    data class Scanning(val kind: ScanKind) : Screen()
    object Results : Screen()
}

class MainActivity : ComponentActivity() {

    private val vm: ScanViewModel by viewModels()

    // Launcher for the legacy (API <= 29) WRITE_EXTERNAL_STORAGE runtime prompt.
    private val legacyStoragePerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* result handled lazily */ }

    // Android 13+ runtime notification permission, so the foreground-service
    // scan notification can actually be shown.
    private val notificationPerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* result ignored */ }

    // True when we can write to the public storage root.
    private fun hasAllFilesAccess(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            Environment.isExternalStorageManager()
        else
            ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED

    // Ask for storage access so outputs land in a user-visible folder. On API 30+
    // this is "All files access" (Settings screen); on older it's a normal prompt.
    private fun requestStorageAccess() {
        if (hasAllFilesAccess()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:$packageName"),
                    )
                )
            } catch (_: Exception) {
                try { startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) }
                catch (_: Exception) {}
            }
        } else {
            legacyStoragePerm.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }
    }

    // Where all results/logs/exports go. If storage permission is granted, use a
    // user-visible "WhiteDNS Scanner" folder at the root of shared storage;
    // otherwise fall back to the app-specific dir (always writable, just hidden).
    private fun currentScanDir(): File {
        val base = if (hasAllFilesAccess())
            File(Environment.getExternalStorageDirectory(), "WhiteDNS Scanner")
        else
            (getExternalFilesDir(null) ?: filesDir).resolve("WhiteDNS Scanner")
        base.mkdirs()
        return base
    }

    private fun shouldUseConstrainedScanDefaults(): Boolean {
        val arch = System.getProperty("os.arch")?.lowercase().orEmpty()
        val is32BitRuntime = arch == "arm" ||
            arch.startsWith("armv7") ||
            arch == "i686" ||
            arch == "x86"
        return is32BitRuntime || Build.SUPPORTED_64_BIT_ABIS.isEmpty()
    }

    private fun defaultFormState(): FormState =
        if (shouldUseConstrainedScanDefaults())
            FormState(concurrency = "8", lowBandwidth = true, liteMode = true)
        else
            FormState()

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestStorageAccess()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            WhiteDNSTheme {
                // Clamp the font scale so very large system "font size" / "display
                // size" accessibility settings can't warp/clip the layout on some
                // devices, while still allowing moderate enlargement.
                val baseDensity = LocalDensity.current
                CompositionLocalProvider(
                    LocalDensity provides Density(
                        density = baseDensity.density,
                        fontScale = baseDensity.fontScale.coerceIn(0.85f, 1.30f),
                    )
                ) {
                var screen by remember { mutableStateOf<Screen>(Screen.Home) }
                var pendingKind by remember { mutableStateOf(ScanKind.IP) }
                var form by remember { mutableStateOf(defaultFormState()) }
                val scanState by vm.state.collectAsStateWithLifecycle()

                // Auto-advance to results when scan finishes
                LaunchedEffect(scanState.done) {
                    if (scanState.done && screen is Screen.Scanning) {
                        screen = Screen.Results
                        stopForegroundScanService()
                        // Kick off preview load immediately
                        scanState.savedPath?.let { vm.loadPreview(it) }
                    }
                }

                // Keep foreground-service notification updated
                LaunchedEffect(scanState.found) {
                    if (scanState.running) {
                        val label = (screen as? Screen.Scanning)?.kind?.label() ?: "Scan"
                        startService(ScanService.intentUpdate(this@MainActivity, label, scanState.found))
                    }
                }

                val screenTitle = when (screen) {
                    Screen.Home -> ""   // banner inside HomeScreen shows branding
                    is Screen.Config -> "${(screen as Screen.Config).kind.label()} · Config"
                    Screen.AsnPicker -> "Select ASNs"
                    Screen.ConfigMaker -> "Config Maker"
                    is Screen.Scanning -> "${(screen as Screen.Scanning).kind.label()} · Scanning"
                    Screen.Results -> "Results"
                }

                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text(screenTitle) },
                            navigationIcon = {
                                if (screen != Screen.Home) {
                                    IconButton(onClick = {
                                        when (screen) {
                                            is Screen.Scanning -> {
                                                vm.stop()
                                                stopForegroundScanService()
                                                screen = Screen.Home
                                            }
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
                    Box(
                        Modifier
                            .padding(padding)
                            .fillMaxSize()
                            // Keeps content above the soft keyboard
                            .imePadding()
                    ) {
                        when (val s = screen) {
                            Screen.Home -> HomeScreen(
                                onSelect = { kind ->
                                    vm.reset()
                                    form = defaultFormState()
                                    pendingKind = kind
                                    screen = if (kind == ScanKind.ASN_EXPORT) Screen.AsnPicker
                                             else Screen.Config(kind)
                                },
                                onConfigMaker = { screen = Screen.ConfigMaker },
                            )

                            Screen.ConfigMaker -> ConfigMakerScreen(dataDir = currentScanDir().absolutePath)

                            is Screen.Config -> ScanConfigForm(
                                kind = s.kind,
                                form = form,
                                onFormChange = { form = it },
                                onPickASN = {
                                    pendingKind = s.kind
                                    screen = Screen.AsnPicker
                                },
                                onStart = {
                                    // Build everything that can throw BEFORE navigating, and guard
                                    // the whole launch so a failure shows a message instead of
                                    // crashing the app (some users hit immediate crashes on scan
                                    // start before any logging begins).
                                    try {
                                        val dir = currentScanDir().absolutePath
                                        val engineCfg = form.toEngineConfig(shouldUseConstrainedScanDefaults())
                                        screen = Screen.Scanning(s.kind)
                                        startForegroundScanService(s.kind)
                                        vm.start(s.kind, dir, engineCfg)
                                    } catch (e: Throwable) {
                                        Log.e("MainActivity", "Failed to start scan", e)
                                        Toast.makeText(
                                            this@MainActivity,
                                            "Could not start scan: ${e.message ?: e.javaClass.simpleName}",
                                            Toast.LENGTH_LONG,
                                        ).show()
                                        screen = Screen.Config(s.kind)
                                    }
                                },
                            )

                            Screen.AsnPicker -> AsnSearchScreen(
                                dataDir = currentScanDir().absolutePath,
                                confirmLabel = if (pendingKind == ScanKind.ASN_EXPORT) "Export IPs" else "Use selection",
                                constrainedDevice = shouldUseConstrainedScanDefaults(),
                                onSelected = { targets ->
                                    val constrainedDevice = shouldUseConstrainedScanDefaults()
                                    val targetRef = try {
                                        targetsForDevice(currentScanDir(), targets, constrainedDevice)
                                    } catch (e: Throwable) {
                                        Log.w("MainActivity", "Could not persist ASN targets; falling back to inline targets", e)
                                        targets
                                    }
                                    form = form.copy(targets = targetRef)
                                    if (pendingKind == ScanKind.ASN_EXPORT) {
                                        vm.reset()
                                        startForegroundScanService(ScanKind.ASN_EXPORT)
                                        vm.start(ScanKind.ASN_EXPORT, currentScanDir().absolutePath,
                                            form.copy(targets = targetRef).toEngineConfig(constrainedDevice))
                                        screen = Screen.Scanning(ScanKind.ASN_EXPORT)
                                    } else {
                                        screen = Screen.Config(pendingKind)
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
                                onViewResults = {
                                    screen = Screen.Results
                                    scanState.savedPath?.let { vm.loadPreview(it) }
                                },
                            )

                            Screen.Results -> ResultsScreen(
                                state = scanState,
                                vm = vm,
                                onBack = { screen = Screen.Home },
                                onNewScan = {
                                    vm.reset()
                                    form = defaultFormState()
                                    screen = Screen.Home
                                },
                            )
                        }
                    }
                }
                }
            }
        }
    }

    private fun startForegroundScanService(kind: ScanKind) {
        // Starting a foreground service can throw on some OEM ROMs
        // (MIUI/ColorOS/HyperOS), under Android 12+ background-start rules, or
        // when notifications are restricted (ForegroundServiceStartNotAllowed-
        // Exception / SecurityException). The scan itself runs in-process via the
        // ViewModel, so a failure here must NOT crash the app — we just lose the
        // persistent notification while the app is backgrounded.
        try {
            val intent = ScanService.intentStart(this, kind.label())
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
            else startService(intent)
        } catch (e: Throwable) {
            Log.w("MainActivity", "Foreground service start failed; continuing without it", e)
        }
    }

    private fun stopForegroundScanService() {
        try {
            startService(ScanService.intentStop(this))
        } catch (e: Throwable) {
            Log.w("MainActivity", "Foreground service stop failed", e)
        }
    }

    private fun targetsForDevice(dataDir: File, targets: String, constrainedDevice: Boolean): String {
        if (!constrainedDevice) return targets
        val trimmed = targets.trim()
        if (trimmed.isBlank()) return trimmed

        val tmpDir = dataDir.resolve("tmp")
        tmpDir.mkdirs()
        val out = tmpDir.resolve("asn-targets-${System.currentTimeMillis()}.txt")
        out.writeText(trimmed + "\n")
        return "@${out.absolutePath}"
    }
}

private fun ScanKind.label() = when (this) {
    ScanKind.IP         -> "IP Scan"
    ScanKind.SNI        -> "SNI Scan"
    ScanKind.HTTP       -> "HTTP Proxy"
    ScanKind.SOCKS5     -> "SOCKS5"
    ScanKind.SPEED      -> "Speed & Loss"
    ScanKind.ASN_EXPORT -> "ASN Export"
}

// Maps FormState → gomobile ScanConfig (setter names from gomobile Java codegen).
private fun FormState.toEngineConfig(constrainedDevice: Boolean = false): ScanConfig {
    // newScanConfig() is the gomobile factory (struct construction from Kotlin
    // is unreliable). Concurrency/TimeoutMs are Go int -> Java long -> Kotlin Long.
    val cfg = Mobile.newScanConfig()
    val requestedConcurrency = concurrency.toIntOrNull() ?: 50
    val effectiveLiteMode = liteMode || constrainedDevice
    val effectiveConcurrency =
        if (effectiveLiteMode) requestedConcurrency.coerceAtMost(8)
        else requestedConcurrency
    cfg.targets       = targets.trim()
    cfg.ports         = ports.trim()
    cfg.concurrency   = effectiveConcurrency.toLong()
    cfg.lowBandwidth  = lowBandwidth || effectiveLiteMode
    cfg.transferModel = transferModel
    cfg.setSNIDomains(sniDomains.trim())
    cfg.setSNIStrict(sniStrict)
    cfg.setVerboseLog(verboseLog)
    cfg.setLiteMode(effectiveLiteMode)
    return cfg
}
