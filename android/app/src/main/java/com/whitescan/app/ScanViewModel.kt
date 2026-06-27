package com.whitescan.app

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.whitescan.engine.mobile.Mobile
import com.whitescan.engine.mobile.ScanConfig
import com.whitescan.engine.mobile.ScanHandle
import com.whitescan.engine.mobile.ScanListener
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

// How many result lines to keep in RAM for display. The full set is on disk.
private const val MAX_DISPLAY_RESULTS = 100
// How many log lines to keep in RAM.
private const val MAX_LOG_LINES = 100

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
    // Last MAX_DISPLAY_RESULTS results only — full list is in savedPath
    val displayResults: List<String> = emptyList(),
    val totalResults: Int = 0,
    val logs: List<String> = emptyList(),
    val savedPath: String? = null,
    val error: String? = null,
    val done: Boolean = false,
)

class ScanViewModel : ViewModel(), ScanListener {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state

    private var handle: ScanHandle? = null

    fun start(kind: ScanKind, dataDir: String, cfg: ScanConfig) {
        if (_state.value.running) return
        _state.value = ScanUiState(running = true)
        handle = when (kind) {
            ScanKind.ASN_EXPORT -> {
                // Synchronous and potentially slow — run on IO thread
                viewModelScope.launch(Dispatchers.IO) {
                    runCatching { Mobile.exportASN(dataDir, cfg.targets) }
                        .onSuccess { path -> onDone(path ?: "", "") }
                        .onFailure { e -> onDone("", e.message ?: "export failed") }
                }
                null
            }
            ScanKind.IP -> Mobile.startIPScan(dataDir, cfg, this)
            ScanKind.SNI -> Mobile.startSNIScan(dataDir, cfg, this)
            ScanKind.HTTP -> Mobile.startHTTPProxyScan(dataDir, cfg, this)
            ScanKind.SOCKS5 -> Mobile.startSOCKS5Scan(dataDir, cfg, this)
        }
    }

    fun pauseResume() {
        val h = handle ?: return
        if (_state.value.paused) {
            h.resume()
            _state.update { it.copy(paused = false) }
        } else {
            h.pause()
            _state.update { it.copy(paused = true) }
        }
    }

    fun stop() {
        handle?.stop()
        handle = null
        _state.update { it.copy(running = false) }
    }

    fun reset() {
        handle?.stop()
        handle = null
        _state.value = ScanUiState()
    }

    // ---- ScanListener — called from Go background goroutines ----------------
    // StateFlow.update is thread-safe (uses CAS), so these can fire from any thread.

    override fun onProgress(
        processed: Long, total: Long, found: Long, uniqueIPs: Long,
        currentIP: String, etaSec: Long,
    ) {
        _state.update {
            it.copy(
                processed = processed.toInt(),
                total = total.toInt(),
                found = found.toInt(),
                uniqueIPs = uniqueIPs.toInt(),
                currentIP = currentIP,
                etaSec = etaSec.toInt(),
            )
        }
    }

    // onResult: live streaming (proxy wave hits only — kept minimal)
    override fun onResult(line: String) {
        _state.update { s ->
            val updated = (s.displayResults + line).takeLast(MAX_DISPLAY_RESULTS)
            s.copy(displayResults = updated, totalResults = s.totalResults + 1)
        }
    }

    // onResultBatch: bulk delivery at end — parse newlines, keep tail for display
    override fun onResultBatch(lines: String) {
        if (lines.isBlank()) return
        val all = lines.split('\n').filter { it.isNotBlank() }
        _state.update { s ->
            s.copy(
                displayResults = all.takeLast(MAX_DISPLAY_RESULTS),
                totalResults = s.totalResults + all.size,
            )
        }
    }

    override fun onLog(line: String) {
        if (line.isBlank()) return
        _state.update { s ->
            s.copy(logs = (s.logs + line).takeLast(MAX_LOG_LINES))
        }
    }

    override fun onDone(savedPath: String, errMsg: String) {
        Log.d("ScanViewModel", "onDone: saved=$savedPath err=$errMsg")
        _state.update {
            it.copy(
                running = false,
                done = true,
                savedPath = savedPath.ifEmpty { null },
                error = errMsg.ifEmpty { null },
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        handle?.stop()
    }
}
