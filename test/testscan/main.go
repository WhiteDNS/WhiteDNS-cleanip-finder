package main

import (
	"context"
	"fmt"
	"time"

	"whitedns-go/internal/scanner"
)

func main() {
	// target IP: example.com (may respond)
	targets := []string{"93.184.216.34/32"}
	cfg := &scanner.ScannerConfig{
		ProbeTimeout:        2500 * time.Millisecond,
		ProbeRetries:        2,
		MaxConcurrentProbes: 250,
		ProbeIntervalMs:     100,
		TargetPorts:         []int{80, 443},
	}
	s := scanner.NewScanner(cfg)

	opts := scanner.IPScanOptions{
		Ports:             []int{80, 443},
		Concurrency:       50,
		Timeout:           4 * time.Second,
		ProbeDomainsHTTP:  []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"},
		ProbeDomainsHTTPS: []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"},
	}

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
	fmt.Println("\nRunning direct ProbeEndpoint for 93.184.216.34:80")
	pr := s.ProbeEndpoint(context.Background(), "93.184.216.34:80", []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"})
	fmt.Printf("ProbeEndpoint => Success=%v Latency=%v Error=%s\n", pr.Success, pr.Latency, pr.Error)
}
