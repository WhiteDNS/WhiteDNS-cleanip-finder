package mobile

import (
	"context"
	"sync/atomic"

	"whitedns-go/internal/scanner"
)

// ScanHandle controls a running scan. Returned immediately from each Start*
// call; the scan itself runs on a background goroutine and streams via the
// ScanListener.
//
// Note: the underlying engine supports cooperative pause/resume. A hard cancel
// is best-effort — Stop() pauses the engine and detaches the listener so no
// further callbacks fire; any in-flight probes drain in the background.
type ScanHandle struct {
	ctx     context.Context
	cancel  context.CancelFunc
	sc      *scanner.Scanner
	stopped int32
	paused  int32
}

func newScanHandle(sc *scanner.Scanner) *ScanHandle {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScanHandle{ctx: ctx, cancel: cancel, sc: sc}
}

// Pause halts new probes (cooperative).
func (h *ScanHandle) Pause() {
	if h == nil {
		return
	}
	atomic.StoreInt32(&h.paused, 1)
	if h.sc != nil {
		h.sc.Pause()
	}
}

// Resume continues a paused scan.
func (h *ScanHandle) Resume() {
	if h == nil {
		return
	}
	atomic.StoreInt32(&h.paused, 0)
	if h.sc != nil {
		h.sc.Resume()
	}
}

// Stop requests cancellation. Listener callbacks stop firing after this returns.
func (h *ScanHandle) Stop() {
	if h == nil {
		return
	}
	atomic.StoreInt32(&h.stopped, 1)
	if h.cancel != nil {
		h.cancel()
	}
	if h.sc != nil {
		h.sc.Pause()
	}
}

func (h *ScanHandle) isStopped() bool {
	return h != nil && atomic.LoadInt32(&h.stopped) == 1
}

func (h *ScanHandle) isPaused() bool {
	if h == nil {
		return false
	}
	return atomic.LoadInt32(&h.paused) == 1
}
