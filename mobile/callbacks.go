package mobile

// ScanListener receives streaming updates during a scan. gomobile maps this Go
// interface to a Kotlin/Java interface; implement it on the Android side and
// pass it into the Start* functions.
//
// All callbacks fire from background goroutines — marshal onto the main thread
// before touching UI state.
type ScanListener interface {
	// OnProgress reports cumulative progress. etaSec is best-effort (0 if unknown).
	OnProgress(processed, total, found, uniqueIPs int, currentIP string, etaSec int)
	// OnResult delivers one accepted endpoint, formatted like the desktop TUI.
	OnResult(line string)
	// OnLog delivers a scanner diagnostic / activity line.
	OnLog(line string)
	// OnDone signals completion. savedPath is the results file ("" if none);
	// errMsg is "" on success.
	OnDone(savedPath string, errMsg string)
}
