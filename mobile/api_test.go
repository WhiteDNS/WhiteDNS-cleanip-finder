package mobile

import (
	"os"
	"path/filepath"
	"strings"
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

func TestSplitTargetsFileReferenceWithSpaces(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "WhiteDNS Scanner")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "asn targets.txt")
	if err := os.WriteFile(path, []byte("1.1.1.0/24\n8.8.8.8, 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := splitTargets("@" + path)
	want := []string{"1.1.1.0/24", "8.8.8.8", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestASNSearchAndExpand(t *testing.T) {
	rows, err := ASNSearch(t.TempDir(), "*")
	if err != nil {
		t.Fatalf("ASNSearch failed: %v", err)
	}
	lines := strings.FieldsFunc(strings.TrimSpace(rows), func(r rune) bool { return r == '\n' || r == '\r' })
	if len(lines) == 0 {
		t.Fatal("expected at least one ASN row")
	}

	parts := strings.Split(lines[0], "\t")
	if len(parts) < 3 {
		t.Fatalf("bad ASN row %q", lines[0])
	}

	cidrs, err := ExpandASNs(t.TempDir(), parts[0])
	if err != nil {
		t.Fatalf("ExpandASNs(%q) failed: %v", parts[0], err)
	}
	if strings.TrimSpace(cidrs) == "" {
		t.Fatalf("expected CIDRs for %q", parts[0])
	}
	if strings.Contains(cidrs, ":") {
		t.Fatalf("expected IPv4-only CIDRs, got %q", cidrs)
	}
}

func TestExpandTargetsLimited(t *testing.T) {
	got := expandTargetsLimited([]string{"192.0.2.0/24", "198.51.100.10"}, 3)
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestFileBackedTargetsStageSameIPs(t *testing.T) {
	dir := t.TempDir()
	targetText := "192.0.2.0/30\n198.51.100.10\n"
	refPath := filepath.Join(dir, "WhiteDNS Scanner", "tmp", "asn-targets.txt")
	if err := os.MkdirAll(filepath.Dir(refPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refPath, []byte(targetText), 0o644); err != nil {
		t.Fatal(err)
	}

	inlineTargets := splitTargets(targetText)
	fileTargets := splitTargets("@" + refPath)
	inlineOut := filepath.Join(dir, "inline.txt")
	fileOut := filepath.Join(dir, "file.txt")

	inlineCount, err := expandTargetsToFile(inlineTargets, inlineOut, liteDedupCap)
	if err != nil {
		t.Fatal(err)
	}
	fileCount, err := expandTargetsToFile(fileTargets, fileOut, liteDedupCap)
	if err != nil {
		t.Fatal(err)
	}
	if inlineCount != fileCount {
		t.Fatalf("inline staged %d IPs, file-backed staged %d", inlineCount, fileCount)
	}

	inlineBytes, err := os.ReadFile(inlineOut)
	if err != nil {
		t.Fatal(err)
	}
	fileBytes, err := os.ReadFile(fileOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(inlineBytes) != string(fileBytes) {
		t.Fatalf("file-backed staged different IPs\ninline:\n%s\nfile:\n%s", inlineBytes, fileBytes)
	}
}

func TestASNSelectionFileBackedTargetsStageSameIPs(t *testing.T) {
	dir := t.TempDir()
	rows, err := ASNSearch(dir, "*")
	if err != nil {
		t.Fatalf("ASNSearch failed: %v", err)
	}
	firstRow, _, ok := strings.Cut(strings.TrimSpace(rows), "\n")
	if !ok && strings.TrimSpace(firstRow) == "" {
		t.Fatal("expected at least one ASN row")
	}
	parts := strings.Split(firstRow, "\t")
	if len(parts) < 1 {
		t.Fatalf("bad ASN row %q", firstRow)
	}
	cidrs, err := ExpandASNs(dir, parts[0])
	if err != nil {
		t.Fatalf("ExpandASNs(%q) failed: %v", parts[0], err)
	}

	refPath := filepath.Join(dir, "WhiteDNS Scanner", "tmp", "asn-targets.txt")
	if err := os.MkdirAll(filepath.Dir(refPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refPath, []byte(strings.TrimSpace(cidrs)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	inlineOut := filepath.Join(dir, "asn-inline.txt")
	fileOut := filepath.Join(dir, "asn-file.txt")
	inlineCount, err := expandTargetsToFile(splitTargets(cidrs), inlineOut, liteDedupCap)
	if err != nil {
		t.Fatal(err)
	}
	fileCount, err := expandTargetsToFile(splitTargets("@"+refPath), fileOut, liteDedupCap)
	if err != nil {
		t.Fatal(err)
	}
	if inlineCount != fileCount {
		t.Fatalf("inline ASN staged %d IPs, file-backed ASN staged %d", inlineCount, fileCount)
	}
}
