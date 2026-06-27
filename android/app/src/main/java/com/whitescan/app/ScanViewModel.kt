package com.whitescan.app

import androidx.lifecycle.ViewModel
import com.whitescan.engine.mobile.Mobile
import com.whitescan.engine.mobile.ScanConfig
import com.whitescan.engine.mobile.ScanHandle
import com.whitescan.engine.mobile.ScanListener
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

// NOTE: the imports above come from the gomobile-generated whitescan.aar. The
// package is "<javapkg>.<gopkg>" = com.whitescan.engine.mobile (see build-aar.ps1
// -javapkg flag). Generated method names are lowerCamelCase of the Go names.

enum class ScanKind { IP, SNI, HTTP, SOCKS5, ASN_EXPORT }

data class ScanUiState(
    val running: Boolean = false,
    val paused: Boolean = false,
    val processed: Int = 0,
    val total: Int = 0,
    val found: Int = 0,
    val uniqueIPs: Int = 0,
    val currentIP: String = "",
    val etaSec: Int = 0,
    val results: List<String> = emptyList(),
    val logs: List<String> = emptyList(),
    val savedPath: String? = null,
    val error: String? = null,
    val done: Boolean = false,
)

class ScanViewModel : ViewModel(), ScanListener {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state

    private var handle: ScanHandle? = null

    /** dataDir should be context.filesDir.absolutePath. */
    fun start(kind: ScanKind, dataDir: String, cfg: ScanConfig) {
        if (_state.value.running) return
        _state.value = ScanUiState(running = true)
        handle = when (kind) {
            ScanKind.IP -> Mobile.startIPScan(dataDir, cfg, this)
            ScanKind.SNI -> Mobile.startSNIScan(dataDir, cfg, this)
            ScanKind.HTTP -> Mobile.startHTTPProxyScan(dataDir, cfg, this)
            ScanKind.SOCKS5 -> Mobile.startSOCKS5Scan(dataDir, cfg, this)
            ScanKind.ASN_EXPORT -> {
                // Synchronous export; no streaming handle.
                runCatching { Mobile.exportASN(dataDir, cfg.targets) }
                    .onSuccess { onDone(it, "") }
                    .onFailure { onDone("", it.message ?: "export failed") }
                null
            }
        }
    }

    fun pauseResume() {
        val h = handle ?: return
        if (_state.value.paused) {
            h.resume(); _state.update { it.copy(paused = false) }
        } else {
            h.pause(); _state.update { it.copy(paused = true) }
        }
    }

    fun stop() {
        handle?.stop()
        _state.update { it.copy(running = false) }
    }

    // ---- ScanListener (called from Go background goroutines) ----------------

    override fun onProgress(
        processed: Long, total: Long, found: Long, uniqueIPs: Long,
        currentIP: String, etaSec: Long,
    ) {
        _state.update {
            it.copy(
                processed = processed.toInt(), total = total.toInt(),
                found = found.toInt(), uniqueIPs = uniqueIPs.toInt(),
                currentIP = currentIP, etaSec = etaSec.toInt(),
            )
        }
    }

    override fun onResult(line: String) {
        _state.update { it.copy(results = it.results + line) }
    }

    override fun onLog(line: String) {
        _state.update { it.copy(logs = (it.logs + line).takeLast(200)) }
    }

    override fun onDone(savedPath: String, errMsg: String) {
        _state.update {
            it.copy(
                running = false, done = true,
                savedPath = savedPath.ifEmpty { null },
                error = errMsg.ifEmpty { null },
            )
        }
    }
}
