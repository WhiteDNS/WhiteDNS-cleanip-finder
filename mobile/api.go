package mobile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"whitedns-go/internal/asn"
	"whitedns-go/internal/asnexport"
	"whitedns-go/internal/scanner"
	"whitedns-go/internal/tlsprobe"
)

// ---- helpers ---------------------------------------------------------------

// splitTargets splits a free-form targets blob on newlines, spaces and commas.
func splitTargets(blob string) []string {
	fields := strings.FieldsFunc(blob, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ','
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// parsePortsCSV mirrors the desktop TUI port parser (comma list + a-b ranges).
func parsePortsCSV(portStr string) []int {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return []int{443, 2053, 2083, 2087, 2096, 8443}
	}
	seen := make(map[int]bool)
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rng := strings.SplitN(part, "-", 2)
			s, _ := strconv.Atoi(strings.TrimSpace(rng[0]))
			e, _ := strconv.Atoi(strings.TrimSpace(rng[1]))
			for p := s; p <= e; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	if len(ports) == 0 {
		return []int{80, 443, 8080}
	}
	sort.Ints(ports)
	return ports
}

func timeoutOrDefault(ms int, def time.Duration, lowBandwidth bool) time.Duration {
	t := def
	if ms > 0 {
		t = time.Duration(ms) * time.Millisecond
	}
	if lowBandwidth && t < 12*time.Second {
		t = 12 * time.Second
	}
	return t
}

func concurrencyOrDefault(c, def int) int {
	if c <= 0 {
		return def
	}
	if c > 10000 {
		return 10000
	}
	return c
}

func resultsFilePath(dataDir, kind string) string {
	if dataDir == "" {
		dataDir = "."
	}
	stamp := time.Now().Format("20060102-150405")
	return filepath.Join(dataDir, "results", fmt.Sprintf("scan-%s-%s.txt", kind, stamp))
}

func saveResults(path string, lines []string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := fmt.Fprintln(f, l); err != nil {
			return "", err
		}
	}
	return path, nil
}

// emit forwards results+done to the listener unless the handle was stopped.
func finish(h *ScanHandle, l ScanListener, dataDir, kind string, results []string, scanErr error) {
	if l == nil {
		return
	}
	if scanErr != nil {
		l.OnDone("", scanErr.Error())
		return
	}
	if h.isStopped() {
		l.OnDone("", "stopped")
		return
	}
	for _, r := range results {
		l.OnResult(r)
	}
	saved := ""
	if len(results) > 0 {
		if p, err := saveResults(resultsFilePath(dataDir, kind), results); err == nil {
			saved = p
		}
	}
	l.OnDone(saved, "")
}

// ---- IP / CIDR scan --------------------------------------------------------

// StartIPScan begins a direct IP/CIDR scan. Returns immediately; updates stream
// via the listener.
func StartIPScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	h := newScanHandle(sc)

	targets := splitTargets(cfg.Targets)
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 250)
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, cfg.LowBandwidth)

	sc.SetTargetPorts(ports)
	sc.SetLogCallback(func(msg string) {
		if !h.isStopped() {
			l.OnLog(strings.TrimRight(msg, "\n"))
		}
	})

	opts := scanner.IPScanOptions{
		Ports:         ports,
		Concurrency:   conc,
		Timeout:       timeout,
		EndpointCount: len(targets) * len(ports),
		LowBandwidth:  cfg.LowBandwidth,
	}
	if cfg.LowBandwidth {
		opts.AdaptiveDomainConcurrency = 1
	}

	start := time.Now()
	progressCb := func(processed, totalProbes, accepted int, currentIP string, totalIPs int) {
		if h.isStopped() {
			return
		}
		eta := 0
		if processed > 0 && processed < totalProbes {
			elapsed := time.Since(start).Seconds()
			rate := float64(processed) / elapsed
			if rate > 0 {
				eta = int(float64(totalProbes-processed) / rate)
			}
		}
		l.OnProgress(processed, totalProbes, accepted, totalIPs, currentIP, eta)
	}

	go func() {
		defer sc.SetLogCallback(nil)
		results, err := sc.ScanIPsWithProgress(targets, opts, progressCb)
		finish(h, l, dataDir, "ip", results, err)
	}()
	return h
}

// ---- HTTP / SOCKS5 proxy scans ---------------------------------------------

func startProxyScan(dataDir, kind string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	h := newScanHandle(sc)

	targets := splitTargets(cfg.Targets)
	conc := concurrencyOrDefault(cfg.Concurrency, 500)
	timeout := timeoutOrDefault(cfg.TimeoutMs, 8*time.Second, cfg.LowBandwidth)

	opts := scanner.ProxyScanOptions{
		Ports:         parsePortsOrEmpty(cfg.Ports),
		Discovery:     "direct",
		Concurrency:   conc,
		Timeout:       timeout,
		TransferModel: strings.TrimSpace(cfg.TransferModel),
	}

	sc.SetLogCallback(func(msg string) {
		if !h.isStopped() {
			l.OnLog(strings.TrimRight(msg, "\n"))
		}
	})
	start := time.Now()
	sc.SetProxyProgressCallback(func(processed, total, hits int, currentIP string, totalIPs int) {
		if h.isStopped() {
			return
		}
		eta := 0
		if processed > 0 && processed < total {
			elapsed := time.Since(start).Seconds()
			rate := float64(processed) / elapsed
			if rate > 0 {
				eta = int(float64(total-processed) / rate)
			}
		}
		l.OnProgress(processed, total, hits, totalIPs, currentIP, eta)
	})

	go func() {
		defer func() {
			sc.SetLogCallback(nil)
			sc.SetProxyProgressCallback(nil)
		}()
		var results []string
		var err error
		if kind == "socks5" {
			results, err = sc.ScanSOCKS5Proxies(targets, opts)
		} else {
			results, err = sc.ScanHTTPProxies(targets, opts)
		}
		finish(h, l, dataDir, kind, results, err)
	}()
	return h
}

// parsePortsOrEmpty returns nil for empty input so the proxy scanner falls back
// to its own protocol-specific default port list.
func parsePortsOrEmpty(portStr string) []int {
	if strings.TrimSpace(portStr) == "" {
		return nil
	}
	return parsePortsCSV(portStr)
}

// StartHTTPProxyScan begins a direct HTTP-proxy scan.
func StartHTTPProxyScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	return startProxyScan(dataDir, "http", cfg, l)
}

// StartSOCKS5Scan begins a direct SOCKS5-proxy scan.
func StartSOCKS5Scan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	return startProxyScan(dataDir, "socks5", cfg, l)
}

// ---- SNI scan --------------------------------------------------------------

// StartSNIScan begins a TLS/SNI hostname probe over the given targets.
func StartSNIScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	h := newScanHandle(nil)
	targets := splitTargets(cfg.Targets)
	domains := splitTargets(cfg.SNIDomains)
	if len(domains) == 0 {
		domains = tlsprobe.GetDomains(dataDir)
	}
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 250)
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, cfg.LowBandwidth)

	go func() {
		if len(targets) == 0 || len(domains) == 0 {
			reason := "no IP targets selected"
			if len(domains) == 0 {
				reason = "no SNI domains selected"
			}
			l.OnDone("", reason)
			return
		}
		resCh := make(chan tlsprobe.ProbeResult, 1024)
		expanded := len(tlsprobe.ExpandTargets(targets))
		if expanded == 0 {
			expanded = len(targets)
		}
		total := expanded * len(ports) * len(domains)
		l.OnLog(fmt.Sprintf("[SNI] Expanded %d target range(s) to %d IP(s); ports=%d domains=%d total probes=%d", len(targets), expanded, len(ports), len(domains), total))
		l.OnProgress(0, total, 0, expanded, "", 0)

		go func() {
			tlsprobe.RunScanContext(h.ctx, tlsprobe.ScanConfig{
				Targets:     targets,
				Hostnames:   domains,
				Ports:       ports,
				TimeoutSec:  timeout.Seconds(),
				Concurrency: conc,
				StrictSNI:   cfg.SNIStrict,
				PauseFunc:   h.isPaused,
			}, resCh, nil)
		}()

		start := time.Now()
		processed, hits := 0, 0
		certMatchCount := 0
		sniOKCount := 0
		tlsOnlyCount := 0
		failCount := 0
		timeoutCount := 0
		var results []string
		for pr := range resCh {
			processed++
			if h.isStopped() {
				continue // drain to let producer finish
			}
			label := "FAIL"
			if pr.Success {
				label = "OK"
				hits++
			}
			kind := pr.ResultKind
			if kind == "" {
				kind = classifySNIResultKind(pr)
			}
			switch kind {
			case "cert-match":
				certMatchCount++
			case "sni-ok":
				sniOKCount++
			case "tls-only":
				tlsOnlyCount++
			default:
				failCount++
			}
			if isSNITimeout(pr) {
				timeoutCount++
			}
			text := fmt.Sprintf("%s %s:%d %s %s %dms %s %d", pr.Hostname, pr.IP, pr.Port, label, kind, int(pr.LatencyMs), pr.TLSVersion, pr.HTTPStatus)
			l.OnLog(text)
			if pr.Success {
				results = append(results, text)
				l.OnResult(text)
			}
			eta := 0
			if processed > 0 && processed < total {
				rate := float64(processed) / time.Since(start).Seconds()
				if rate > 0 {
					eta = int(float64(total-processed) / rate)
				}
			}
			l.OnProgress(processed, total, hits, expanded, pr.IP, eta)
		}
		summary := fmt.Sprintf("[SNI-SUMMARY] ips=%d ports=%d domains=%d probes=%d processed=%d ok=%d cert-match=%d sni-ok=%d tls-only=%d fail=%d timeouts=%d",
			expanded, len(ports), len(domains), total, processed, hits, certMatchCount, sniOKCount, tlsOnlyCount, failCount, timeoutCount)
		l.OnLog(summary)
		if h.isStopped() {
			l.OnDone("", "stopped")
			return
		}
		saved := ""
		if len(results) > 0 {
			if p, err := saveResults(resultsFilePath(dataDir, "sni"), results); err == nil {
				saved = p
			}
		}
		l.OnDone(saved, "")
	}()
	return h
}

func classifySNIResultKind(pr tlsprobe.ProbeResult) string {
	if pr.CertMatchesSNI {
		return "cert-match"
	}
	if pr.SNIAccepted {
		return "sni-ok"
	}
	if pr.Success {
		return "tls-only"
	}
	return "fail"
}

func isSNITimeout(pr tlsprobe.ProbeResult) bool {
	errText := strings.ToLower(pr.Error)
	return strings.Contains(errText, "timeout") ||
		strings.Contains(errText, "deadline") ||
		strings.Contains(errText, "i/o timeout")
}

// ---- ASN export & lookup ---------------------------------------------------

// ExportASN expands every ASN matching `query` to a flat IP list written under
// dataDir. Returns the output path; the number of IPs is appended to OnLog-style
// callers via the returned string is not used — see error for failures.
func ExportASN(dataDir, query string) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.Load(); err != nil {
		return "", err
	}
	groups, err := eng.SearchGroups(query)
	if err != nil {
		return "", err
	}
	if len(groups) == 0 {
		return "", fmt.Errorf("no ASNs matched %q", query)
	}
	cidrs := make([]string, 0)
	for _, g := range groups {
		cidrs = append(cidrs, g.CIDRs...)
	}
	path, _, err := asnexport.ExportTargetsToTXT(dataDir, cidrs, "")
	return path, err
}

// ASNSearch returns matching ASNs as newline-separated "ASN\tName\tsubnetCount"
// rows for populating a selection list.
func ASNSearch(dataDir, query string) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.Load(); err != nil {
		return "", err
	}
	groups, err := eng.SearchGroups(query)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, g := range groups {
		fmt.Fprintf(&b, "%s\t%s\t%d\n", g.ASN, g.Name, g.SubnetCount)
	}
	return b.String(), nil
}
