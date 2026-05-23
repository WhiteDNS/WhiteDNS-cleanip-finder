package main

import (
	"fmt"
	"time"

	"whitedns-go/internal/scanner"
)

func main() {
	// Simulate multiple ASNs with multiple /24 networks
	// These are fake networks for testing
	cidrs := []string{
		"10.0.0.0/24",
		"10.0.1.0/24",
		"10.0.2.0/24",
	}

	cfg := &scanner.ScannerConfig{
		ProbeTimeout:        2500 * time.Millisecond,
		ProbeRetries:        2,
		MaxConcurrentProbes: 250,
		ProbeIntervalMs:     100,
		TargetPorts:         []int{443},
	}
	s := scanner.NewScanner(cfg)

	opts := scanner.IPScanOptions{
		Ports:             []int{443},
		Concurrency:       50,
		Timeout:           4 * time.Second,
		ProbeDomainsHTTP:  []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"},
		ProbeDomainsHTTPS: []string{"instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai", "pages.dev", "workers.dev", "gemini.google.com", "notebooklm.google.com"},
	}

	fmt.Printf("Testing multi-ASN CIDR expansion with %d CIDRs\n", len(cidrs))

	progressCb := func(processed, total, accepted int, currentIP string, totalIPs int) {
		if processed%100 == 0 {
			fmt.Printf("progress: processed=%d total=%d accepted=%d totalIPs=%d currentIP=%s\n", processed, total, accepted, totalIPs, currentIP)
		}
	}

	fmt.Println("\nCalling ScanIPsWithProgress...")
	res, err := s.ScanIPsWithProgress(cidrs, opts, progressCb)
	fmt.Println()
	if err != nil {
		fmt.Printf("Scan error: %v\n", err)
		return
	}
	fmt.Printf("Found %d results\n", len(res))
	if len(res) > 0 {
		fmt.Println("Sample results:")
		for i := 0; i < 5 && i < len(res); i++ {
			fmt.Printf("  - %s\n", res[i])
		}
	}
}
