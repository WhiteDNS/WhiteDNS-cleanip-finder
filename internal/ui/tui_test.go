package ui

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppendTransferLogLineFromScanLogCapturesBenchmarkLines(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "whitedns logs", "transfer-http-20260524-000000.txt")

	m := &tuiModel{
		transferLogPath: logPath,
		transferLogMu:   &sync.Mutex{},
	}

	benchmarkLine := "[+] http 1.2.3.4:8080 lat=12ms ↓123.4KB/s ↑56.7KB/s [telegram]"
	m.appendTransferLogLineFromScanLog(benchmarkLine)

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read transfer log: %v", err)
	}
	if got := string(content); !strings.Contains(got, benchmarkLine) {
		t.Fatalf("transfer log missing benchmark line: %q", got)
	}

	ignoredLine := "[INFO] scan started"
	m.appendTransferLogLineFromScanLog(ignoredLine)
	content, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read transfer log after ignored line: %v", err)
	}
	if strings.Contains(string(content), ignoredLine) {
		t.Fatalf("non-transfer line should not be appended: %q", string(content))
	}
}

func TestParseDomainPassFromScannerLog(t *testing.T) {
	line := "[ACCEPT] 203.0.113.10:443 status=accept domains=9/9 domain_score=3 passed=[reddit.com,workers.dev,chatgpt.com]"

	ipPort, domains, passed, total, ok := parseDomainPassFromScannerLog(line)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if ipPort != "203.0.113.10:443" {
		t.Fatalf("unexpected ipPort: %s", ipPort)
	}
	if passed != 3 || total != 9 {
		t.Fatalf("unexpected score: got %d/%d want 3/9", passed, total)
	}
	expectedDomains := []string{"chatgpt.com", "reddit.com", "workers.dev"}
	if !reflect.DeepEqual(domains, expectedDomains) {
		t.Fatalf("unexpected domains: got %v want %v", domains, expectedDomains)
	}
}

func TestAppendDomainPassLineFromScanLogWritesExpectedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	domainPassPath := filepath.Join(tmpDir, "whitedns logs", "domain-passes-ipscan-test.txt")

	m := &tuiModel{
		scanDomainPassPath:    domainPassPath,
		scanOutputMu:          &sync.Mutex{},
		scanDomainPassWritten: make(map[string]bool),
		scanLogMu:             &sync.Mutex{},
	}

	line := "[ACCEPT] 198.51.100.8:2053 status=accept domains=9/9 domain_score=2 passed=[workers.dev,reddit.com]"
	m.appendDomainPassLineFromScanLog(line)
	// second append should be deduped
	m.appendDomainPassLineFromScanLog(line)

	content, err := os.ReadFile(domainPassPath)
	if err != nil {
		t.Fatalf("read domain pass file: %v", err)
	}
	got := strings.TrimSpace(string(content))
	want := "198.51.100.8:2053 | 2/9 | reddit.com,workers.dev"
	if got != want {
		t.Fatalf("unexpected domain pass output: got %q want %q", got, want)
	}
}

func TestAppendNewScanResultsToFileWritesPlainIPPortForIPScan(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "whitedns logs", "passed-ipscan-test.txt")

	m := &tuiModel{
		operationType:     "ipscan",
		scanOutputPath:    outputPath,
		scanOutputMu:      &sync.Mutex{},
		scanOutputWritten: make(map[string]bool),
	}
	m.scanResults = []string{"[ACCEPT] 198.51.100.8:2053 status=accept domains=9/9 domain_score=2 passed=[workers.dev,reddit.com]"}

	m.appendNewScanResultsToFile()

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read passed output: %v", err)
	}
	got := strings.TrimSpace(string(content))
	want := "198.51.100.8:2053"
	if got != want {
		t.Fatalf("unexpected passed output: got %q want %q", got, want)
	}
}

func TestStartScanLogFileCreatesDomainPassOutputForIPScan(t *testing.T) {
	tmpDir := t.TempDir()
	m := &tuiModel{
		app:           &App{DataDir: tmpDir},
		scanLogMu:     &sync.Mutex{},
		transferLogMu: &sync.Mutex{},
		scanOutputMu:  &sync.Mutex{},
	}

	_ = m.startScanLogFile("ipscan", []string{"example.com"}, []int{443}, 1, time.Second)

	if m.scanDomainPassPath == "" {
		t.Fatalf("expected domain pass path to be set")
	}
	if _, err := os.Stat(m.scanDomainPassPath); err != nil {
		t.Fatalf("expected domain pass file to exist: %v", err)
	}
	if m.scanOutputPath == "" {
		t.Fatalf("expected passed output path to be set")
	}
	if _, err := os.Stat(m.scanOutputPath); err != nil {
		t.Fatalf("expected passed output file to exist: %v", err)
	}
}
