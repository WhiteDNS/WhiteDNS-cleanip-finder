package mobile

import (
	"sync"
	"testing"
	"time"
)

// captureListener records callback activity for assertions.
type captureListener struct {
	mu        sync.Mutex
	progress  int
	results   []string
	logs      int
	doneErr   string
	savedPath string
	done      chan struct{}
}

func newCaptureListener() *captureListener { return &captureListener{done: make(chan struct{})} }

func (c *captureListener) OnProgress(processed, total, found, uniqueIPs int, currentIP string, etaSec int) {
	c.mu.Lock()
	c.progress++
	c.mu.Unlock()
}
func (c *captureListener) OnResult(line string) {
	c.mu.Lock()
	c.results = append(c.results, line)
	c.mu.Unlock()
}
func (c *captureListener) OnLog(line string) {
	c.mu.Lock()
	c.logs++
	c.mu.Unlock()
}
func (c *captureListener) OnDone(savedPath, errMsg string) {
	c.mu.Lock()
	c.savedPath = savedPath
	c.doneErr = errMsg
	c.mu.Unlock()
	close(c.done)
}

func TestStartIPScanDirect(t *testing.T) {
	if testing.Short() {
		t.Skip("network scan skipped in -short mode")
	}
	l := newCaptureListener()
	cfg := &ScanConfig{
		Targets:     "1.1.1.0/30",
		Ports:       "443",
		Concurrency: 16,
		TimeoutMs:   6000,
	}
	StartIPScan(t.TempDir(), cfg, l)

	select {
	case <-l.done:
	case <-time.After(60 * time.Second):
		t.Fatal("scan did not complete within 60s")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.doneErr != "" {
		t.Fatalf("scan reported error: %s", l.doneErr)
	}
	if l.progress == 0 {
		t.Error("expected at least one OnProgress callback")
	}
	t.Logf("progress=%d logs=%d results=%d saved=%q", l.progress, l.logs, len(l.results), l.savedPath)
}

func TestParsePortsCSV(t *testing.T) {
	got := parsePortsCSV("443,8000-8002,443")
	want := []int{443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestSplitTargets(t *testing.T) {
	got := splitTargets("1.1.1.1, 8.8.8.8\n9.9.9.9  10.0.0.0/24")
	if len(got) != 4 {
		t.Fatalf("expected 4 targets, got %v", got)
	}
}
