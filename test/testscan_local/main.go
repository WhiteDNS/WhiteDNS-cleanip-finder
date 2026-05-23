package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"whitedns-go/internal/scanner"
)

func main() {
	// Start a simple HTTP server on localhost:9999
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Example Domain</title></head>
<body>
<h1>Example Domain</h1>
<p>This domain is for use in examples and is fingerprinted by the scanner.</p>
</body>
</html>`))
		})
		http.ListenAndServe(":9999", nil)
	}()

	time.Sleep(500 * time.Millisecond) // Let server start

	// Scan localhost on port 9999 (should pass all waves and fingerprint)
	targets := []string{"127.0.0.1/32"}
	cfg := &scanner.ScannerConfig{
		ProbeTimeout:        2500 * time.Millisecond,
		ProbeRetries:        2,
		MaxConcurrentProbes: 250,
		ProbeIntervalMs:     100,
		TargetPorts:         []int{9999},
	}
	s := scanner.NewScanner(cfg)

	opts := scanner.IPScanOptions{
		Ports:             []int{9999},
		Concurrency:       10,
		Timeout:           4 * time.Second,
		ProbeDomainsHTTP:  []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"},
		ProbeDomainsHTTPS: []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"},
	}

	fmt.Println("Starting local HTTP server on 127.0.0.1:9999")
	fmt.Println("Starting IP scan test for", targets)

	progressCb := func(processed, total, accepted int, currentIP string, totalIPs int) {
		fmt.Printf("progress: %d/%d  accepted=%d  current=%s  ips=%d\r", processed, total, accepted, currentIP, totalIPs)
	}

	res, err := s.ScanIPsWithProgress(targets, opts, progressCb)
	fmt.Println()
	if err != nil {
		fmt.Println("Scan error:", err)
		return
	}
	fmt.Println("Results:")
	for _, r := range res {
		fmt.Println(" -", r)
	}

	// Also run a direct ProbeEndpoint for debugging
	fmt.Println("\nRunning direct ProbeEndpoint for 127.0.0.1:9999")
	pr := s.ProbeEndpoint(context.Background(), "127.0.0.1:9999", []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"})
	fmt.Printf("ProbeEndpoint => Success=%v Latency=%v Error=%s\n", pr.Success, pr.Latency, pr.Error)
}
